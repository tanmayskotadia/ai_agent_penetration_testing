# AegisTrace

An evidence-driven, analyst-controlled Unified VAPT Agent for the DataOps Innovation Hackathon.

**Current status:** The T30 software-only vertical slice is implemented in the open T30 PR and exercises scope-bound intake, recorded Nmap/ZAP/Nikto/OpenAPI imports, reviewer provenance, cross-tool correlation, risk/coverage review and PDF export. Synthetic fixtures are test-only; genuine scanner evidence and an authorized participant demonstration are still required for acceptance. Native scanner execution remains disabled by default.

The participant requires cloud hosting without local setup. A Render Blueprint and Supabase deployment runbook are provided in [free cloud deployment](docs/free-cloud-deployment.md); creating the hosted service and entering database/encryption secrets remains participant-side setup. Local commands below are optional developer workflows. See [T30 prototype status](docs/prototype-status.md), [cloud direction](docs/runtime-input-cloud-direction.md) and [API contracts](docs/api.md).

## Quick start: native API/UI smoke mode

Requires Python 3.12, uv 0.12.13 and Node.js 24/npm. Commands run from the repository root unless noted.

```powershell
uv sync --frozen
python scripts/init_env.py --smoke
uv run alembic upgrade head
uv run uvicorn aegistrace.api:create_app --factory --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173. `/health/live` reports the process; `/health/ready` verifies the database migration. Smoke mode uses SQLite for local API development only; it is not proof of PostgreSQL, queue integration, scanner isolation or a security assessment. No secrets are printed by configuration generation; it refuses to overwrite `.env`.

## PostgreSQL/Redis development profile

Use Docker Engine/Desktop with Linux containers and Compose v2, or provide your own private PostgreSQL/Redis services. Docker is not assumed installed.

For a fresh checkout, `python scripts/init_env.py` creates ignored local credentials. Then `docker compose up --build` starts PostgreSQL, Redis, a migration job, API, diagnostic-only worker and frontend. API/frontend bind only to loopback. Compose overrides the database/broker hostnames for internal connections; do not commit `.env` or expose services publicly. Stop with `docker compose down`; omit volume deletion to retain data. This is a development profile, not a lab-network policy or public deployment.

Without Docker, configure `DATABASE_URL` (`postgresql+psycopg://...`) and `REDIS_URL` locally, migrate, start the API, then run `uv run celery -A aegistrace_workers.cli:app worker --pool=solo --loglevel=WARNING`. Only the diagnostic ping task exists; no scanner command interface is exposed.

## Verification

```powershell
uv run ruff check backend workers reports tests migrations scripts
uv run ruff format --check backend workers reports tests migrations scripts
uv run mypy
uv run pytest -m 'not services'
python scripts/export_requirements.py --check
python scripts/validate_requirements.py
uv run python scripts/export_domain_schemas.py --check
uv run python scripts/export_api_contracts.py --check
uv run python scripts/export_capabilities.py --check
cd frontend
npm run build
```

CI installs from `uv.lock` and `frontend/package-lock.json`, verifies migrations against real PostgreSQL, runs an actual Redis/Celery diagnostic round trip, builds the frontend and validates the baseline. Test inputs are expressly test-only and contain no scanner proof or live targets. A missing `APP_SECRET`/`DATABASE_URL` fails configuration with field names rather than exposing values.

## Repository guide

- `backend/aegistrace`: typed domain/persistence, identity contracts, encrypted evidence, audit, authenticated APIs, import quarantine and shared capabilities.
- `workers/aegistrace_workers`: bounded diagnostic worker scaffold; execution adapters are later work.
- `reports/aegistrace_reports`: typed report-request placeholder; no generated findings.
- `migrations`: reversible platform/domain/evidence/audit/API/ingestion schemas; no seeded vulnerabilities or assessments.
- `frontend`: accessible workspace status and truthful seven-tool roadmap.
- [Requirements](docs/requirements.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [ADRs](docs/adr/README.md), [submission gates](docs/submission-gates.md).
- [Prerequisites and observed resources](docs/prerequisites.md), [licensing assumptions](docs/licensing.md), [model/data policy](docs/model-data-policy.md), [lab authorization](docs/lab-authorization.md), [fixture provenance](docs/fixture-provenance.md).

## Authorization, licenses and limitations

General-purpose implementation collects assessment inputs at runtime and does not require organizer answers to proceed. No live security testing is enabled. A later user must provide valid target authority and satisfy deterministic execution controls; the hackathon profile retains its organizer-authorized-target rule. Active exploitation/offensive validation requires explicit action-bound human approval outside the LLM. Model processing remains disabled; never put credentials in browser variables or public issues.

Tool editions, scanner/feed licenses and model data policy must be documented in T06 before corresponding capabilities are promised. No commercial binary/feed/license or captured sensitive scan output is bundled. Original problem PDF, temporary planning artifacts, credentials and runtime data are excluded from source. Dependency licenses remain their upstream terms; a project redistribution license is not implied.

No participant local setup is required. Hosted CI exercises real PostgreSQL, Redis and fresh container startup. T04/T05 remain open for actual permitted lab/corpus acceptance; M02's clearly labelled handcrafted contract tests do not replace genuine captures or independent accuracy review.

Exact package locks and image digests identify the tested dependency baseline. They do not establish formal security/framework compliance. See issue-specific verification records for what actually ran and what needs manual setup.

[M03 status and remaining runner gate](docs/milestone-3-status.md) documents scope, managed identities, single-use approvals, cancellation and inference guards. These controls do not enable native scanners, model calls or report rendering; genuine deployed-runner acceptance remains open.
