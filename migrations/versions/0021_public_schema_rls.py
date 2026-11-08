"""Protect AegisTrace tables from the Supabase Data API roles.

The application uses its server-side PostgreSQL connection and never accesses
these tables directly from the browser. Keep anon/authenticated from using the
Data API, while enabling RLS as defense in depth. The server's dedicated
database role is expected to have BYPASSRLS (verified for the hosted app).
"""

from alembic import op

revision = "0021_public_schema_rls"
down_revision = "0020_identity_bootstrap"
branch_labels = None
depends_on = None


_PUBLIC_APPLICATION_TABLES = (
    "action_approvals",
    "alembic_version",
    "api_check_secrets",
    "api_checks",
    "approvals",
    "assessment_controls",
    "assessment_members",
    "assessments",
    "assets",
    "audit_events",
    "audit_heads",
    "decisions",
    "dispatch_claims",
    "endpoints",
    "evidence_access_events",
    "evidence_objects",
    "evidence_references",
    "execution_controls",
    "execution_policies",
    "findings",
    "identity_bootstrap_state",
    "identity_sessions",
    "ingestion_inspections",
    "job_outbox",
    "job_output_chunks",
    "job_progress_events",
    "late_job_outputs",
    "login_attempts",
    "mutation_receipts",
    "native_normalizations",
    "observations",
    "occurrences",
    "platform_state",
    "policy_usage",
    "principals",
    "reasoning_proposals",
    "replay_manifests",
    "report_snapshots",
    "result_exports",
    "result_revisions",
    "scan_jobs",
    "scheduler_admissions",
    "scheduler_buckets",
    "scheduler_lock",
    "scope_versions",
    "services",
    "tool_runs",
    "vulnerability_concepts",
    "workflow_resources",
)


def upgrade() -> None:
    for table_name in _PUBLIC_APPLICATION_TABLES:
        op.execute(f'ALTER TABLE public."{table_name}" ENABLE ROW LEVEL SECURITY')

    # The AegisTrace browser talks only to the authenticated FastAPI service.
    # No browser role should read or mutate the database through PostgREST.
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    op.execute("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC")
    op.execute("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC")

    # Supabase creates these roles; ordinary PostgreSQL development databases
    # may not. Guard role-specific revokes so the Alembic chain stays portable.
    op.execute(
        """
        DO $$
        DECLARE api_role text;
        BEGIN
            FOREACH api_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = api_role) THEN
                    EXECUTE format(
                        'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM %I',
                        api_role
                    );
                    EXECUTE format(
                        'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM %I',
                        api_role
                    );
                    EXECUTE format(
                        'REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM %I',
                        api_role
                    );
                    EXECUTE format(
                        'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                        'REVOKE ALL ON TABLES FROM %I',
                        api_role
                    );
                    EXECUTE format(
                        'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                        'REVOKE ALL ON SEQUENCES FROM %I',
                        api_role
                    );
                    EXECUTE format(
                        'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                        'REVOKE EXECUTE ON FUNCTIONS FROM %I',
                        api_role
                    );
                END IF;
            END LOOP;
        END
        $$;
        """
    )

    # Function EXECUTE is granted to PUBLIC by PostgreSQL unless changed.
    # Existing public-schema functions here are trigger-only integrity guards.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE ALL ON TABLES FROM PUBLIC"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE ALL ON SEQUENCES FROM PUBLIC"
    )

    # These integrity guards use no application objects. Pin their search path
    # to pg_catalog so future writable schemas cannot shadow built-ins.
    for function_name in (
        "aegistrace_deny_audit_mutation",
        "aegis_replay_immutable",
        "aegis_results_immutable",
        "aegis_progress_immutable",
    ):
        op.execute(
            f'ALTER FUNCTION public."{function_name}"() '
            "SET search_path = pg_catalog"
        )


def downgrade() -> None:
    raise RuntimeError(
        "This security migration is intentionally irreversible; restore only "
        "explicitly reviewed, least-privilege grants in a new migration."
    )
