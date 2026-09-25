import re
from typing import List, Optional

from .patterns import PATTERNS, luhn_valid
from .entropy import shannon_entropy, has_nearby_context


def _confidence_for(value: str, text: str, match_start: int, high_confidence: bool) -> int:
    if high_confidence:
        return 95
    entropy = shannon_entropy(value)
    context = has_nearby_context(text, match_start)
    score = 30
    if entropy >= 4.2:
        score += 35
    elif entropy >= 3.3:
        score += 15
    if context:
        score += 30
    return min(score, 90)


def extract_entities(text: str, custom_rules: Optional[List[dict]] = None, min_confidence: int = 40) -> List[dict]:
    """
    custom_rules: list of dicts with keys name/regex/category/risk/enabled,
    as stored in CustomRule rows. Returns findings sorted by risk severity,
    each carrying a `confidence` (0-100) so the UI/analyst can triage —
    instead of the old approach of silently dropping or silently trusting
    every regex hit equally.
    """
    findings = []
    seen = set()
    catalogue = list(PATTERNS)
    for r in (custom_rules or []):
        if not r.get("enabled", True):
            continue
        catalogue.append({
            "id": "custom-" + r["id"], "name": r["name"], "cat": r.get("category", "custom"),
            "risk": r.get("risk", "medium"), "re": r["regex"], "high_confidence": False, "custom": True,
        })

    for p in catalogue:
        try:
            regex = re.compile(p["re"], re.IGNORECASE if p["id"] in ("iban",) else 0)
        except re.error:
            continue  # bad custom regex — skip rather than 500
        for m in regex.finditer(text):
            value = m.group(p.get("cap", 0)) if p.get("cap") else m.group(0)
            if not value:
                continue
            if p.get("validate") == "luhn" and not luhn_valid(value):
                continue
            key = (p["name"], value.lower())
            if key in seen:
                continue

            confidence = _confidence_for(value, text, m.start(), p.get("high_confidence", False))
            if confidence < min_confidence:
                continue
            seen.add(key)

            start = max(0, m.start() - 40)
            end = min(len(text), m.start() + len(value) + 40)
            ctx = re.sub(r"\s+", " ", text[start:end]).strip()
            if start > 0:
                ctx = "…" + ctx
            if end < len(text):
                ctx = ctx + "…"

            findings.append({
                "type": p["name"], "category": p["cat"], "risk": p["risk"],
                "value": value, "context": ctx, "confidence": confidence,
                "custom": bool(p.get("custom")),
            })
            if len(findings) > 3000:
                break

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    findings.sort(key=lambda f: (order.get(f["risk"], 0), f["confidence"]), reverse=True)
    return findings
