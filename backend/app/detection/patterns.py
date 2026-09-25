"""
Pattern catalogue. Each pattern is tagged `high_confidence=True` when the
format itself is distinctive enough that a regex hit alone is reliable
(AWS/Stripe/GitHub key *prefixes* are essentially unique). Everything else
(bare hex/base64 blobs, generic "password=" assignments) is
`high_confidence=False` and gets run through entropy + context-proximity
scoring in engine.py before it's trusted — this is the fix for the
regex-only false-positive problem in the original tool.
"""

PATTERNS = [
    # --- high confidence: distinctive formats ---
    {"id": "aws", "name": "AWS Access Key", "cat": "secrets", "risk": "critical",
     "re": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "high_confidence": True},
    {"id": "stripe", "name": "Stripe Secret Key", "cat": "secrets", "risk": "critical",
     "re": r"\bsk_live_[0-9a-zA-Z]{24,}\b", "high_confidence": True},
    {"id": "gh_token", "name": "GitHub Token", "cat": "secrets", "risk": "critical",
     "re": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high_confidence": True},
    {"id": "private_key", "name": "Private Key Block", "cat": "secrets", "risk": "critical",
     "re": r"-----BEGIN [A-Z ]+PRIVATE KEY-----", "high_confidence": True},
    {"id": "jwt", "name": "JWT Token", "cat": "secrets", "risk": "high",
     "re": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "high_confidence": True},
    {"id": "slack_token", "name": "Slack Token", "cat": "secrets", "risk": "critical",
     "re": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "high_confidence": True},

    # --- needs entropy + context scoring ---
    {"id": "generic_pass", "name": "Password Assignment", "cat": "secrets", "risk": "critical",
     "re": r"\b(?:password|passwd|pwd)\s*[:=]\s*[\"']?([^\s\"',;]{6,})", "cap": 1, "high_confidence": False},
    {"id": "generic_apikey", "name": "Generic API Key", "cat": "secrets", "risk": "high",
     "re": r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})",
     "cap": 1, "high_confidence": False},
    {"id": "sha256", "name": "SHA-256-shaped Hash", "cat": "network", "risk": "medium",
     "re": r"\b[a-f0-9]{64}\b", "high_confidence": False},
    {"id": "md5", "name": "MD5-shaped Hash", "cat": "network", "risk": "low",
     "re": r"\b[a-f0-9]{32}\b", "high_confidence": False},

    # --- network / infra indicators (format-reliable, not secrets) ---
    {"id": "ipv4", "name": "IPv4 Address", "cat": "network", "risk": "low",
     "re": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "high_confidence": True},
    {"id": "email", "name": "Email Address", "cat": "network", "risk": "medium",
     "re": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "high_confidence": True},
    {"id": "url", "name": "URL", "cat": "network", "risk": "medium",
     "re": r"https?://[^\s<>\"')]+", "high_confidence": True},
    {"id": "cve", "name": "CVE ID", "cat": "network", "risk": "high",
     "re": r"\bCVE-\d{4}-\d{4,7}\b", "high_confidence": True},

    # --- compliance / PII (format + checksum validated where possible) ---
    {"id": "ssn", "name": "US SSN", "cat": "compliance", "risk": "critical",
     "re": r"\b\d{3}-\d{2}-\d{4}\b", "high_confidence": True},
    {"id": "iban", "name": "IBAN Account", "cat": "compliance", "risk": "high",
     "re": r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", "high_confidence": True},
    {"id": "cc", "name": "Credit Card (Luhn-valid)", "cat": "compliance", "risk": "critical",
     "re": r"\b(?:\d[ -]?){13,19}\b", "high_confidence": True, "validate": "luhn"},
]


def luhn_valid(value: str) -> bool:
    digits = [c for c in value if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0
