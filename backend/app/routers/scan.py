import hashlib
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ScanBatch, Finding, CustomRule, User
from ..schemas import ScanRequest, ScanResult, FindingOut
from ..security import require_roles, get_current_user
from ..detection.engine import extract_entities
from ..audit import add_audit_log

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("", response_model=ScanResult, dependencies=[Depends(require_roles("admin", "analyst"))])
def run_scan(payload: ScanRequest, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    rules = db.query(CustomRule).filter(
        CustomRule.workspace_id == current.workspace_id, CustomRule.enabled == True  # noqa: E712
    ).all()
    custom_rules = [
        {"id": r.id, "name": r.name, "regex": r.regex, "category": r.category, "risk": r.risk, "enabled": r.enabled}
        for r in rules
    ]

    raw_findings = extract_entities(payload.text, custom_rules)

    batch = ScanBatch(
        workspace_id=current.workspace_id, submitted_by=current.id,
        source_label=payload.source_label, char_count=len(payload.text),
    )
    db.add(batch)
    db.flush()

    saved = []
    ts = datetime.utcnow().isoformat()
    for f in raw_findings:
        custody_seed = f"{batch.id}|{f['value']}|{ts}|{current.email}"
        custody_hash = hashlib.sha256(custody_seed.encode()).hexdigest()
        row = Finding(
            batch_id=batch.id, workspace_id=current.workspace_id,
            type=f["type"], category=f["category"], risk=f["risk"], value=f["value"],
            context=f["context"], confidence=f["confidence"], custody_hash=custody_hash,
        )
        db.add(row)
        saved.append(row)
    db.commit()
    for row in saved:
        db.refresh(row)

    add_audit_log(
        db, current.workspace_id, current.email, "SCAN_RUN",
        f"batch={batch.id} chars={len(payload.text)} findings={len(saved)}",
    )

    return ScanResult(batch_id=batch.id, total=len(saved), findings=saved)


@router.get("", response_model=list[FindingOut], dependencies=[Depends(require_roles("admin", "analyst", "auditor", "viewer"))])
def list_findings(db: Session = Depends(get_db), current: User = Depends(get_current_user), limit: int = 500):
    return (
        db.query(Finding)
        .filter(Finding.workspace_id == current.workspace_id)
        .order_by(Finding.created_at.desc())
        .limit(min(limit, 2000))
        .all()
    )
