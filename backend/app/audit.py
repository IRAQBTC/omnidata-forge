"""
Tamper-evident audit trail.

Why this differs from the original client-side version:
the old implementation computed SHA-256 entirely in the browser using data
the browser itself controls — so anyone with devtools could edit an entry
and recompute a "valid" chain. That is a checksum, not a security control.

Here, each entry is signed with HMAC-SHA256 under a key that lives only in
the server process (settings.AUDIT_HMAC_KEY). An attacker who can write to
the database directly still cannot produce a hash that verifies without
also holding that server-side key. Rotate the key deliberately (see
config.py) and export+archive logs before rotating.
"""
import hashlib
import hmac
from typing import Optional

from sqlalchemy.orm import Session
from sqlalchemy import func

from .config import settings
from .models import AuditLog

GENESIS_HASH = "0" * 64


def _sign(prev_hash: str, seq: int, user_email: str, action: str, details: str) -> str:
    msg = f"{prev_hash}|{seq}|{user_email}|{action}|{details}".encode("utf-8")
    return hmac.new(settings.AUDIT_HMAC_KEY.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def add_audit_log(db: Session, workspace_id: str, user_email: str, action: str, details: str = "") -> AuditLog:
    last = (
        db.query(AuditLog)
        .filter(AuditLog.workspace_id == workspace_id)
        .order_by(AuditLog.seq.desc())
        .first()
    )
    seq = (last.seq + 1) if last else 1
    prev_hash = last.hash if last else GENESIS_HASH
    entry_hash = _sign(prev_hash, seq, user_email, action, details)

    entry = AuditLog(
        workspace_id=workspace_id,
        seq=seq,
        user_email=user_email,
        action=action,
        details=details,
        prev_hash=prev_hash,
        hash=entry_hash,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_chain(db: Session, workspace_id: str) -> tuple[bool, int, Optional[int]]:
    """Re-derives every HMAC in sequence. Returns (valid, checked_count, broken_at_seq)."""
    entries = (
        db.query(AuditLog)
        .filter(AuditLog.workspace_id == workspace_id)
        .order_by(AuditLog.seq.asc())
        .all()
    )
    expected_prev = GENESIS_HASH
    for e in entries:
        if e.prev_hash != expected_prev:
            return False, len(entries), e.seq
        recomputed = _sign(e.prev_hash, e.seq, e.user_email, e.action, e.details)
        if recomputed != e.hash:
            return False, len(entries), e.seq
        expected_prev = e.hash
    return True, len(entries), None
