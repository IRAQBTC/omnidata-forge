from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Case, CaseStatus, User
from ..schemas import CaseCreate, CaseUpdate, CaseOut
from ..security import require_roles, get_current_user
from ..audit import add_audit_log

router = APIRouter(prefix="/cases", tags=["cases"])

SLA_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168}


@router.get("", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(Case).filter(Case.workspace_id == current.workspace_id).order_by(Case.created_at.desc()).all()


@router.post("", response_model=CaseOut, dependencies=[Depends(require_roles("admin", "analyst"))])
def create_case(payload: CaseCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    case = Case(
        workspace_id=current.workspace_id, title=payload.title, description=payload.description,
        priority=payload.priority, status=CaseStatus(payload.status), owner_id=payload.owner_id,
        sla_at=datetime.utcnow() + timedelta(hours=SLA_HOURS.get(payload.priority, 24)),
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    add_audit_log(db, current.workspace_id, current.email, "CASE_CREATE", payload.title)
    return case


@router.patch("/{case_id}", response_model=CaseOut, dependencies=[Depends(require_roles("admin", "analyst"))])
def update_case(case_id: str, payload: CaseUpdate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    case = db.query(Case).filter(Case.id == case_id, Case.workspace_id == current.workspace_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="القضية غير موجودة")
    data = payload.model_dump(exclude_unset=True)
    if "status" in data:
        data["status"] = CaseStatus(data["status"])
    for k, v in data.items():
        setattr(case, k, v)
    case.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case)
    add_audit_log(db, current.workspace_id, current.email, "CASE_UPDATE", f"{case_id} -> {case.status.value}")
    return case


@router.delete("/{case_id}", dependencies=[Depends(require_roles("admin"))])
def delete_case(case_id: str, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    case = db.query(Case).filter(Case.id == case_id, Case.workspace_id == current.workspace_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="القضية غير موجودة")
    db.delete(case)
    db.commit()
    add_audit_log(db, current.workspace_id, current.email, "CASE_DELETE", case_id)
    return {"deleted": True}
