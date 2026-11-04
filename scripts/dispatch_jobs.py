"""Trusted hosted dispatcher: one bounded outbox batch, no target or secret output."""

from aegistrace.db import make_engine
from aegistrace.jobs import publish_pending, reconcile_batch
from aegistrace.scheduler import queue_for
from aegistrace.settings import Settings
from aegistrace_workers.app import create_worker


def main() -> None:
    config = Settings()  # type: ignore[call-arg]
    worker = create_worker(config)
    engine = make_engine(config)
    try:
        reconcile_batch(engine)

        def publish(job_id: str) -> None:
            with engine.connect() as connection:
                queue = queue_for(connection, job_id)
            worker.send_task(
                "aegistrace.jobs.consume", args=[job_id], task_id=job_id, retry=False, queue=queue
            )

        count = publish_pending(
            engine,
            publish,
        )
        print(f"Published {count} durable job messages")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
