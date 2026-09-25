import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, Enum
)
from sqlalchemy.orm import relationship

from .database import Base


def gen_id() -> str:
    return uuid.uuid4().hex


class Role(str, enum.Enum):
    ADMIN = "admin"       # manage users, integrations, rules
    ANALYST = "analyst"   # run scans, manage cases/watchlist
    AUDITOR = "auditor"   # read-only, full audit log access
    VIEWER = "viewer"     # read-only findings/cases, no audit access


class Workspace(Base):
    __tablename__ = "workspaces"
    id = Column(String, primary_key=True, default=gen_id)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    users = relationship("User", back_populates="workspace")


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    full_name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(Role), default=Role.VIEWER, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    workspace = relationship("Workspace", back_populates="users")


class ScanBatch(Base):
    """One 'run analysis' event. Findings belong to a batch for provenance."""
    __tablename__ = "scan_batches"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    submitted_by = Column(String, ForeignKey("users.id"), nullable=False)
    source_label = Column(String, default="pasted-text")  # filename or "pasted-text"
    char_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(String, primary_key=True, default=gen_id)
    batch_id = Column(String, ForeignKey("scan_batches.id"), nullable=False)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    type = Column(String, nullable=False)
    category = Column(String, nullable=False)  # secrets | network | compliance | custom
    risk = Column(String, nullable=False)       # critical | high | medium | low
    value = Column(Text, nullable=False)
    context = Column(Text, default="")
    confidence = Column(Integer, default=100)   # 0-100, from entropy/context scoring
    watched = Column(Boolean, default=False)
    custody_hash = Column(String, nullable=False)  # sha256(id|value|ts|user), for chain-of-custody
    created_at = Column(DateTime, default=datetime.utcnow)


class CaseStatus(str, enum.Enum):
    NEW = "NEW"
    TRIAGE = "TRIAGE"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"


class Case(Base):
    __tablename__ = "cases"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    priority = Column(String, default="medium")
    status = Column(Enum(CaseStatus), default=CaseStatus.NEW)
    owner_id = Column(String, ForeignKey("users.id"), nullable=True)
    sla_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class WatchlistItem(Base):
    __tablename__ = "watchlist"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    value = Column(String, nullable=False)
    type = Column(String, default="Other")
    source = Column(String, default="Internal")
    severity = Column(String, default="medium")
    added_by = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class CustomRule(Base):
    __tablename__ = "custom_rules"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    name = Column(String, nullable=False)
    regex = Column(String, nullable=False)
    category = Column(String, default="custom")
    risk = Column(String, default="medium")
    enabled = Column(Boolean, default=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """
    Hash-chained, HMAC-signed audit trail. The HMAC key lives only on the
    server (see config.AUDIT_HMAC_KEY), so — unlike a client-side hash —
    an attacker with write access to the DB cannot forge a valid chain
    without also having the server's key.
    """
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    seq = Column(Integer, nullable=False)  # monotonic per-workspace sequence
    user_email = Column(String, nullable=False)
    action = Column(String, nullable=False)
    details = Column(Text, default="")
    prev_hash = Column(String, nullable=False)
    hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class IntegrationConfig(Base):
    """Per-workspace third-party integration credentials (encrypted at rest
    in production — see README for the KMS/Fernet note)."""
    __tablename__ = "integration_config"
    id = Column(String, primary_key=True, default=gen_id)
    workspace_id = Column(String, ForeignKey("workspaces.id"), nullable=False)
    provider = Column(String, nullable=False)  # e.g. "abuseipdb"
    api_key = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
