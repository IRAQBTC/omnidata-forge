from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import WatchlistItem, User
from ..schemas import WatchlistCreate, WatchlistOut
from ..security import require_roles, get_current_user
from ..audit import add_audit_log

router = APIRouter(prefix="/watchlist", tags=["watchlist"])


@router.get("", response_model=list[WatchlistOut])
def list_watchlist(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    return db.query(WatchlistItem).filter(WatchlistItem.workspace_id == current.workspace_id).all()


@router.post("", response_model=WatchlistOut, dependencies=[Depends(require_roles("admin", "analyst"))])
def add_watch(payload: WatchlistCreate, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    item = WatchlistItem(workspace_id=current.workspace_id, added_by=current.id, **payload.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    add_audit_log(db, current.workspace_id, current.email, "WATCH_ADD", payload.value)
    return item


@router.delete("/{item_id}", dependencies=[Depends(require_roles("admin", "analyst"))])
def remove_watch(item_id: str, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    item = db.query(WatchlistItem).filter(WatchlistItem.id == item_id, WatchlistItem.workspace_id == current.workspace_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="غير موجود")
    db.delete(item)
    db.commit()
    add_audit_log(db, current.workspace_id, current.email, "WATCH_REMOVE", item_id)
    return {"deleted": True}
