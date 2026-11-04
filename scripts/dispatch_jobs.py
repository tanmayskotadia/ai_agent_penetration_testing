"""Trusted hosted dispatcher: one bounded outbox batch, no target or secret output."""

from aegistrace.db import make_engine
from aegistrace.jobs import publish_pending, reconcile_batch
from aegistrace.settings import Settings
from aegistrace_workers.app import create_worker


def main() -> None:
    config = Settings()  # type: ignore[call-arg]
    worker = create_worker(config)
    engine = make_engine(config)
    try:
        reconcile_batch(engine)
        count = publish_pending(
            engine,
            lambda job_id: worker.send_task(
                "aegistrace.jobs.consume", args=[job_id], task_id=job_id, retry=False
            ),
        )
        print(f"Published {count} durable job messages")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
