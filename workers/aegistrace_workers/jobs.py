"""Internal queue consumer. Native execution stays blocked until runner acceptance."""

from uuid import UUID, uuid4

from aegistrace.db import make_engine
from aegistrace.jobs import finish_job, start_job
from aegistrace.settings import Settings


def consume_job(config: Settings, job_id: str) -> str:
    job_uuid = UUID(job_id)
    worker_id = uuid4()
    engine = make_engine(config)
    try:
        with engine.begin() as connection:
            job = start_job(connection, config, job_uuid, worker_id)
        if job is None:
            return "not-started; duplicate-or-authority-invalid"
        # No native adapter/runner is verified. No external process was submitted.
        with engine.begin() as connection:
            return finish_job(connection, job_uuid, worker_id, job["epoch"], "blocked", True)
    finally:
        engine.dispose()
