# Free cloud deployment (Render + Supabase)

This deploys the import-first AegisTrace application and its built React UI as one Render web service. It does not deploy scanner workers, enable live scanning, or provide a lab. Uploaded evidence and application records are stored in Supabase PostgreSQL; the Render filesystem is treated as disposable.

## Before creating the Render service

1. Confirm the separate Supabase project named `dataops` is available in the selected Supabase organization. Use its PostgreSQL database for persistence; do not put a production database on Render's temporary free database tier.
2. In Supabase **Project Settings → Database → Connection string**, select **Session pooler** and port **5432**. Copy the URI and replace its scheme `postgresql://` with `postgresql+psycopg://`. Keep the host, database, user and password values intact; percent-encode reserved characters in the username/password if the URI requires it. Session mode is required for IPv4-hosted Render services. Do not use the transaction pooler (port 6543) for this app's migrations.
3. Keep the Supabase project database password private. The application needs a migration-capable database role; the session-pooler connection for the project owner can apply migrations. If you choose to create a separate restricted role, grant it only the application schema permissions required by migrations and runtime before deployment.

## Create the service

1. In Render, select **New → Blueprint**, connect `tanmayskotadia/ai_agent_penetration_testing`, and choose branch `main` after the implementation PR has been merged. Render reads the root `render.yaml` and creates one free Docker web service named `dataops`.
2. When prompted, set `DATABASE_URL` to the Supabase Session-pooler URI from above.
3. Set `EVIDENCE_KEY` to exactly 64 lowercase or uppercase hexadecimal characters representing 32 random bytes. Generate it in a trusted password manager or secret manager; do not put it in the repository, GitHub issues, screenshots or chat. Store a protected backup because previously encrypted originals cannot be decrypted after losing or replacing this key.
4. Keep the generated `APP_SECRET` and `BOOTSTRAP_TOKEN` in Render's secret environment. The service command applies Alembic migrations before starting Uvicorn, and `/health/ready` remains unhealthy until the database reaches the current migration head.
5. Wait for Render's deploy to finish and check `${service-url}/health/ready`. Open `${service-url}/` for the same-origin UI. Free web services may sleep when idle, so the first request after inactivity can take time. Supabase free projects may pause after inactivity; resume the database in Supabase if readiness fails.

## Create the initial administrator once

1. In Render, open the service's **Environment** settings and copy `BOOTSTRAP_TOKEN` privately.
2. Open `${service-url}/docs`, expand `POST /api/v1/auth/bootstrap`, click **Try it out**, and send JSON with a unique username and a strong 12–128 character password. Add request header `X-Bootstrap-Token` with the copied value. The endpoint requires HTTPS and can create only the first administrator once.
3. Save the returned access token only for the current session and sign in through the UI with that username/password.
4. Remove `BOOTSTRAP_TOKEN` from Render's environment and deploy the change. The endpoint becomes disabled; the persistent database claim also prevents another bootstrap if the secret is accidentally restored later.
5. Never share the bootstrap token, password, or returned access token in chat or GitHub.

## What this deployment can and cannot demonstrate

- It supports account login, assessment/scope entry, request-only planning, source imports, reviewer workflows, coverage/risk review, and report export. Importing Nmap XML, ZAP JSON, Nikto JSON, or an OpenAPI definition does not contact the represented target.
- Native Nmap/ZAP/Nikto execution stays disabled. No scanner worker or private default-deny egress network is part of this free deployment. Do not treat hosting or a submitted file as authorization to test a target.
- This is a free-tier demonstration, not a high-availability service. Keep synthetic data in the public demo; do not upload sensitive client evidence. Back up Supabase data and the evidence key separately if retaining data matters.
- Participant-owned genuine authorized scanner captures and review of the resulting report are still required to satisfy T30's genuine-evidence acceptance gate.
