from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog, User
from ..schemas import AuditOut, AuditVerifyResult
from ..security import require_roles, get_current_user
from ..audit import verify_chain

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut], dependencies=[Depends(require_roles("admin", "auditor"))])
def list_audit(db: Session = Depends(get_db), current: User = Depends(get_current_user), limit: int = 500):
    return (
        db.query(AuditLog)
        .filter(AuditLog.workspace_id == current.workspace_id)
        .order_by(AuditLog.seq.desc())
        .limit(min(limit, 5000))
        .all()
    )


@router.get("/verify", response_model=AuditVerifyResult, dependencies=[Depends(require_roles("admin", "auditor"))])
def verify(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    valid, checked, broken_at = verify_chain(db, current.workspace_id)
    return AuditVerifyResult(valid=valid, entries_checked=checked, broken_at_seq=broken_at)
