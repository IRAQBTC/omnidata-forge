import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import CustomRule, User
from ..schemas import RuleCreate, RuleOut
from ..security import require_roles, get_current_user
from ..audit import add_audit_log

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=list[RuleOut])
def list_rules(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(CustomRule).filter(CustomRule.workspace_id == current.workspace_id).all()


@router.post("", response_model=RuleOut, dependencies=[Depends(require_roles("admin"))])
def create_rule(payload: RuleCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    try:
        re.compile(payload.regex)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Regex غير صالح: {e}")
    rule = CustomRule(workspace_id=current.workspace_id, created_by=current.id, **payload.model_dump())
    db.add(rule)
    db.commit()
    db.refresh(rule)
    add_audit_log(db, current.workspace_id, current.email, "RULE_CREATE", payload.name)
    return rule


@router.patch("/{rule_id}/toggle", response_model=RuleOut, dependencies=[Depends(require_roles("admin"))])
def toggle_rule(rule_id: str, enabled: bool, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    rule = db.query(CustomRule).filter(CustomRule.id == rule_id, CustomRule.workspace_id == current.workspace_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="غير موجود")
    rule.enabled = enabled
    db.commit()
    db.refresh(rule)
    add_audit_log(db, current.workspace_id, current.email, "RULE_TOGGLE", f"{rule.name}={enabled}")
    return rule


@router.delete("/{rule_id}", dependencies=[Depends(require_roles("admin"))])
def delete_rule(rule_id: str, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    rule = db.query(CustomRule).filter(CustomRule.id == rule_id, CustomRule.workspace_id == current.workspace_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="غير موجود")
    db.delete(rule)
    db.commit()
    add_audit_log(db, current.workspace_id, current.email, "RULE_DELETE", rule_id)
    return {"deleted": True}
