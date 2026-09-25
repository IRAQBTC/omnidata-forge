from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, Workspace, Role
from ..schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from ..security import verify_password, create_access_token, hash_password, require_roles, get_current_user
from ..audit import add_audit_log

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="بريد إلكتروني أو كلمة مرور غير صحيحة")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="الحساب موقوف")
    token = create_access_token(user)
    add_audit_log(db, user.workspace_id, user.email, "LOGIN", "")
    role_val = user.role.value if isinstance(user.role, Role) else user.role
    return TokenResponse(access_token=token, role=role_val, full_name=user.full_name)


@router.post("/bootstrap", response_model=TokenResponse)
def bootstrap_first_admin(payload: UserCreate, db: Session = Depends(get_db)):
    """One-time setup endpoint: creates the first workspace + admin user.
    Disable or protect this route (e.g. behind a setup token) once your
    first admin exists — see README 'Post-install hardening'."""
    if db.query(User).count() > 0:
        raise HTTPException(status_code=400, detail="النظام مُهيّأ مسبقاً — استخدم /users لإضافة مستخدمين جدد")
    ws = Workspace(name="Default Workspace")
    db.add(ws)
    db.flush()
    user = User(
        workspace_id=ws.id, email=payload.email, full_name=payload.full_name,
        password_hash=hash_password(payload.password), role=Role.ADMIN,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    add_audit_log(db, ws.id, user.email, "WORKSPACE_BOOTSTRAP", ws.id)
    token = create_access_token(user)
    return TokenResponse(access_token=token, role=Role.ADMIN.value, full_name=user.full_name)


@router.post("/users", response_model=UserOut, dependencies=[Depends(require_roles("admin"))])
def create_user(payload: UserCreate, db: Session = Depends(get_db), current=Depends(get_current_user)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="البريد الإلكتروني مستخدم مسبقاً")
    user = User(
        workspace_id=current.workspace_id, email=payload.email, full_name=payload.full_name,
        password_hash=hash_password(payload.password), role=Role(payload.role),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    add_audit_log(db, current.workspace_id, current.email, "USER_CREATE", payload.email)
    return user


@router.get("/users", response_model=list[UserOut], dependencies=[Depends(require_roles("admin", "auditor"))])
def list_users(db: Session = Depends(get_db), current=Depends(get_current_user)):
    return db.query(User).filter(User.workspace_id == current.workspace_id).all()
