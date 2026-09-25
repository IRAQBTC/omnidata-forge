from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field


# ---- Auth ----
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str = Field(min_length=10)
    role: str = "viewer"


class UserOut(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool

    class Config:
        from_attributes = True


# ---- Scan / Findings ----
class ScanRequest(BaseModel):
    text: str
    source_label: str = "pasted-text"


class FindingOut(BaseModel):
    id: str
    type: str
    category: str
    risk: str
    value: str
    context: str
    confidence: int
    watched: bool
    custody_hash: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResult(BaseModel):
    batch_id: str
    total: int
    findings: List[FindingOut]


# ---- Cases ----
class CaseCreate(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"
    status: str = "NEW"
    owner_id: Optional[str] = None


class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    owner_id: Optional[str] = None


class CaseOut(BaseModel):
    id: str
    title: str
    description: str
    priority: str
    status: str
    owner_id: Optional[str]
    sla_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ---- Watchlist ----
class WatchlistCreate(BaseModel):
    value: str
    type: str = "Other"
    source: str = "Internal"
    severity: str = "medium"


class WatchlistOut(BaseModel):
    id: str
    value: str
    type: str
    source: str
    severity: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---- Rules ----
class RuleCreate(BaseModel):
    name: str
    regex: str
    category: str = "custom"
    risk: str = "medium"


class RuleOut(BaseModel):
    id: str
    name: str
    regex: str
    category: str
    risk: str
    enabled: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ---- Audit ----
class AuditOut(BaseModel):
    seq: int
    user_email: str
    action: str
    details: str
    prev_hash: str
    hash: str
    created_at: datetime

    class Config:
        from_attributes = True


class AuditVerifyResult(BaseModel):
    valid: bool
    entries_checked: int
    broken_at_seq: Optional[int] = None


# ---- Integrations ----
class IntegrationSet(BaseModel):
    provider: str
    api_key: str


class IPCheckResult(BaseModel):
    ip: str
    configured: bool
    abuse_score: Optional[int] = None
    reports: Optional[int] = None
    country: Optional[str] = None
    note: str
