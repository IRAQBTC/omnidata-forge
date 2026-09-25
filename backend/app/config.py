"""
Central configuration. In production every one of these MUST come from
environment variables / a secrets manager (Vault, AWS Secrets Manager, etc).
Never commit real secrets to source control.
"""
import os
import secrets


class Settings:
    # Persistent storage. Swap the sqlite URL for a real Postgres DSN in prod:
    #   postgresql+psycopg2://user:pass@host:5432/omnidata
    DATABASE_URL: str = os.getenv("OMNIDATA_DATABASE_URL", "sqlite:///./omnidata.db")

    # Used to sign JWT access tokens.
    JWT_SECRET: str = os.getenv("OMNIDATA_JWT_SECRET", secrets.token_hex(32))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("OMNIDATA_TOKEN_TTL_MIN", "480"))

    # Used to sign the hash-chained audit log (HMAC key). This key never
    # leaves the server, which is what makes the chain tamper-evident.
    # If this key is missing or rotated, historical entries can no longer be
    # re-verified against a *new* key — rotate deliberately and archive the
    # old key alongside the audit export it was used to sign.
    AUDIT_HMAC_KEY: str = os.getenv("OMNIDATA_AUDIT_KEY", secrets.token_hex(32))

    # Optional third-party threat-intel integration. Left blank = disabled;
    # the API will say so explicitly rather than fabricate a result.
    ABUSEIPDB_API_KEY: str = os.getenv("OMNIDATA_ABUSEIPDB_KEY", "")

    ENV: str = os.getenv("OMNIDATA_ENV", "development")


settings = Settings()

if settings.ENV != "production" and "OMNIDATA_JWT_SECRET" not in os.environ:
    print(
        "[omnidata] WARNING: OMNIDATA_JWT_SECRET not set — using an ephemeral "
        "random key. Tokens will stop validating on restart. Set it explicitly "
        "before deploying."
    )
