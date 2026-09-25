-- OmniData Forge — production schema (PostgreSQL 14+)
-- SQLAlchemy's create_all() handles this automatically against sqlite/postgres
-- alike for development. This file exists so a DBA can review real DDL before
-- go-live, and as the starting point for an Alembic migration if you adopt one.

CREATE TABLE workspaces (
    id            VARCHAR(32) PRIMARY KEY,
    name          VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    email          VARCHAR(255) UNIQUE NOT NULL,
    full_name      VARCHAR(255) NOT NULL,
    password_hash  VARCHAR(255) NOT NULL,
    role           VARCHAR(20) NOT NULL DEFAULT 'viewer',
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX idx_users_email ON users(email);

CREATE TABLE scan_batches (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    submitted_by   VARCHAR(32) NOT NULL REFERENCES users(id),
    source_label   VARCHAR(255) DEFAULT 'pasted-text',
    char_count     INTEGER DEFAULT 0,
    created_at     TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id             VARCHAR(32) PRIMARY KEY,
    batch_id       VARCHAR(32) NOT NULL REFERENCES scan_batches(id),
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    type           VARCHAR(100) NOT NULL,
    category       VARCHAR(50) NOT NULL,
    risk           VARCHAR(20) NOT NULL,
    value          TEXT NOT NULL,
    context        TEXT DEFAULT '',
    confidence     INTEGER DEFAULT 100,
    watched        BOOLEAN DEFAULT FALSE,
    custody_hash   VARCHAR(64) NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX idx_findings_workspace ON findings(workspace_id, created_at DESC);

CREATE TABLE cases (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    title          VARCHAR(500) NOT NULL,
    description    TEXT DEFAULT '',
    priority       VARCHAR(20) DEFAULT 'medium',
    status         VARCHAR(20) DEFAULT 'NEW',
    owner_id       VARCHAR(32) REFERENCES users(id),
    sla_at         TIMESTAMP,
    created_at     TIMESTAMP NOT NULL DEFAULT now(),
    updated_at     TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE watchlist (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    value          VARCHAR(500) NOT NULL,
    type           VARCHAR(50) DEFAULT 'Other',
    source         VARCHAR(255) DEFAULT 'Internal',
    severity       VARCHAR(20) DEFAULT 'medium',
    added_by       VARCHAR(32) REFERENCES users(id),
    created_at     TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE custom_rules (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    name           VARCHAR(255) NOT NULL,
    regex          TEXT NOT NULL,
    category       VARCHAR(50) DEFAULT 'custom',
    risk           VARCHAR(20) DEFAULT 'medium',
    enabled        BOOLEAN DEFAULT TRUE,
    created_by     VARCHAR(32) REFERENCES users(id),
    created_at     TIMESTAMP NOT NULL DEFAULT now()
);

-- Hash-chained audit log. `seq` is monotonic PER WORKSPACE, enforced at the
-- application layer (see app/audit.py) — never update or delete rows here;
-- doing so is exactly the tampering this table exists to detect.
CREATE TABLE audit_log (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    seq            INTEGER NOT NULL,
    user_email     VARCHAR(255) NOT NULL,
    action         VARCHAR(100) NOT NULL,
    details        TEXT DEFAULT '',
    prev_hash      VARCHAR(64) NOT NULL,
    hash           VARCHAR(64) NOT NULL,
    created_at     TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE(workspace_id, seq)
);

CREATE TABLE integration_config (
    id             VARCHAR(32) PRIMARY KEY,
    workspace_id   VARCHAR(32) NOT NULL REFERENCES workspaces(id),
    provider       VARCHAR(50) NOT NULL,
    api_key        VARCHAR(500) NOT NULL,  -- encrypt at rest in prod (see README)
    created_at     TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE(workspace_id, provider)
);
