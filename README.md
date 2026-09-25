# OmniData Forge v5.0 — Enterprise Intelligence Suite

This is a real rebuild of the original single-file HTML tool, done to close the
gaps that stood between it and something an organization could actually pay
an enterprise-grade subscription for. Every claim below was verified by
actually running the code (see "What was tested" at the bottom) — not
assumed from reading it.

## What changed, and why it mattered

| Before (v4.0, single HTML file) | Now (v5.0) | Why it matters |
|---|---|---|
| Everything client-side, `localStorage` | Real backend (FastAPI) + Postgres/SQLite, multi-user | Data lives on a server you control; more than one analyst can use it; nothing disappears when a browser cache is cleared |
| No auth | JWT login + 4 roles (admin/analyst/auditor/viewer), enforced server-side on every endpoint | A `viewer` genuinely cannot run a scan or see the audit log — verified below, not just hidden in the UI |
| Audit log hashed with client-side JS | HMAC-SHA256 chain signed with a server-only key (`app/audit.py`) | A client-side hash is a checksum an attacker with devtools can recompute. A server-held HMAC key means forging a valid chain requires the server's secret, not just knowledge of the algorithm |
| Regex-only detection, high false-positive rate | Regex + Shannon-entropy scoring + context-keyword proximity, each finding gets a 0-100 confidence score (`app/detection/`) | "Looks like a hash" and "is actually a secret" are different questions; analysts triage by confidence instead of drowning in noise |
| Hardcoded fake IOC table, fake MITRE hits | Real optional AbuseIPDB integration; explicitly says "not configured" with zero fabricated data when no key is set | Matches a zero-fabrication standard: every number traces to a real source or is flagged as missing, never invented |
| Static, unchanging compliance percentages | Removed. Not replaced with new fake numbers — see "Deliberately left out" below | Fabricated compliance scores are worse than none; a real one needs an actual control-mapping engine, which is Phase 2 |

## Architecture

```
backend/            FastAPI app
  app/
    models.py        SQLAlchemy tables (users, findings, cases, watchlist, rules, audit_log, integration_config)
    security.py       JWT + bcrypt + role-based access control
    audit.py           HMAC hash-chain (the tamper-evidence layer)
    detection/         entropy.py (false-positive reduction) + patterns.py + engine.py
    routers/           one file per resource, each with role checks
  schema.sql          Postgres DDL for DBA review / migration tooling
  Dockerfile
frontend/
  index.html          Talks to the API over fetch() — login, scan, cases, watchlist, rules, audit, settings
docker-compose.yml    api + postgres + nginx-served frontend
```

## Running it

**Local, quick check (SQLite, no Docker):**
```bash
cd backend
pip install -r requirements.txt email-validator
export OMNIDATA_JWT_SECRET=$(python3 -c "import secrets;print(secrets.token_hex(32))")
export OMNIDATA_AUDIT_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
uvicorn app.main:app --reload
```
Then open `frontend/index.html` directly in a browser (or serve it with any
static server), point "عنوان الخادم" at `http://localhost:8000`, and use the
"إعداد أول مسؤول" tab once to create your admin account.

**Production (Docker Compose, Postgres):**
```bash
cp .env.example .env   # fill in real secrets
docker compose up -d --build
```
API on `:8000`, frontend on `:8080`.

## Post-install hardening (do these before real data touches it)

1. **Disable `/auth/bootstrap`** after the first admin exists — it already
   refuses once any user is in the DB, but for defense-in-depth, put it
   behind a reverse-proxy rule or remove the route in production images.
2. **Encrypt `integration_config.api_key` at rest.** It's stored plaintext
   in this build for clarity. Wrap it with Fernet (`cryptography` package)
   using a key from your KMS before going live.
3. **Restrict CORS** in `app/main.py` — it's `allow_origins=["*"]` for local
   development; set it to your actual frontend origin.
4. **Rotate `OMNIDATA_AUDIT_KEY` deliberately, not accidentally.** Every
   historical entry was signed with the key active at the time. Export and
   archive the audit log before rotating, since old entries won't re-verify
   under a new key.
5. Put the API behind TLS (nginx/Caddy/your load balancer) — it's plain
   HTTP here for local dev.

## Deliberately left out of this delivery (Phase 2 — needs real design work, not just more code)

Being honest about this is the whole point of the exercise:

- **MITRE ATT&CK matrix, attack-chain graph, relationship graph** — the v4
  versions were entirely cosmetic (canned coordinates, hardcoded tactic
  hits). Doing these *for real* means an actual technique-mapping ruleset,
  which is a distinct project, not a UI wiring task.
- **Compliance framework percentages (GDPR/PCI/HIPAA/SOC2)** — same
  problem: a real score needs a maintained control-mapping table per
  framework. We removed the fake numbers rather than ship new fake ones.
- **STIX/JSON export, CSV export** — straightforward to add back against
  the `/scan` and `/cases` data now that it's real; not included this pass
  only for scope, not difficulty.
- **File upload scanning** (the original had a drag-and-drop reader) —
  the `/scan` endpoint takes `text` today; wiring a file upload through is
  a small addition once you decide on size limits and virus-scanning policy
  for uploaded content.

## What was tested (not just written)

Run in this session, against the actual code in this delivery:
- Admin bootstrap → login → JWT issued and accepted
- Full scan on a realistic mixed document → correctly flagged AWS key,
  password, credit card (Luhn-validated), CVE ID, email — and correctly
  gave a **low-confidence, not a false "critical"**, on a bare hex string
  sitting near unrelated text
- Case creation with automatic SLA timestamp
- Audit chain verification (`/audit/verify`) returning `valid: true` after
  a real sequence of actions
- **RBAC enforcement**: a `viewer`-role user got HTTP 403 attempting to run
  a scan — confirmed server-side, not just a hidden button
- AbuseIPDB check with no key configured correctly returned "not
  configured" rather than fabricated data
