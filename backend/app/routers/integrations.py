"""
Real (optional) threat-intel integration instead of the old hardcoded
fake IOC table. If no API key is configured for the workspace, the
endpoint says so explicitly — it never fabricates a score. This is what
the zero-fabrication principle looks like at the API layer, not just in
report copy.
"""
import requests
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import IntegrationConfig, User
from ..schemas import IntegrationSet, IPCheckResult
from ..security import require_roles, get_current_user
from ..audit import add_audit_log

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.post("/config", dependencies=[Depends(require_roles("admin"))])
def set_integration(payload: IntegrationSet, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    # NOTE: for production, encrypt api_key at rest (Fernet with a KMS-held
    # key) rather than storing plaintext — see README "Secrets at rest".
    existing = (
        db.query(IntegrationConfig)
        .filter(IntegrationConfig.workspace_id == current.workspace_id, IntegrationConfig.provider == payload.provider)
        .first()
    )
    if existing:
        existing.api_key = payload.api_key
    else:
        db.add(IntegrationConfig(workspace_id=current.workspace_id, provider=payload.provider, api_key=payload.api_key))
    db.commit()
    add_audit_log(db, current.workspace_id, current.email, "INTEGRATION_CONFIGURED", payload.provider)
    return {"ok": True}


@router.get("/ip-check/{ip}", response_model=IPCheckResult)
def check_ip(ip: str, db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    cfg = (
        db.query(IntegrationConfig)
        .filter(IntegrationConfig.workspace_id == current.workspace_id, IntegrationConfig.provider == "abuseipdb")
        .first()
    )
    if not cfg:
        return IPCheckResult(
            ip=ip, configured=False,
            note="لا يوجد اشتراك AbuseIPDB مفعّل لهذا الـ workspace — أضف مفتاح API من الإعدادات لتفعيل الفحص الحي.",
        )
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": cfg.api_key, "Accept": "application/json"},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return IPCheckResult(
            ip=ip, configured=True,
            abuse_score=data.get("abuseConfidenceScore"),
            reports=data.get("totalReports"),
            country=data.get("countryCode"),
            note="نتيجة حية من AbuseIPDB.",
        )
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"تعذّر الاتصال بمزوّد التهديدات: {e}")
