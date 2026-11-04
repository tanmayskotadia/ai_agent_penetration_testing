from aegistrace.settings import Settings
from celery import Celery


def create_worker(settings: Settings | None = None) -> Celery:
    config = settings or Settings()  # type: ignore[call-arg]
    worker = Celery("aegistrace", broker=config.redis_url, backend=config.redis_url)
    worker.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_always_eager=False,
        task_time_limit=30,
        result_expires=60,
        worker_prefetch_multiplier=1,
        broker_connection_timeout=3,
        broker_transport_options={"socket_timeout": 3, "socket_connect_timeout": 3},
    )

    def ping() -> str:
        return "foundation-pong"

    worker.task(name="aegistrace.diagnostic.ping")(ping)

    def consume_job(job_id: str) -> str:
        from aegistrace_workers.jobs import consume_job as consume

        return consume(config, job_id)

    worker.task(
        name="aegistrace.jobs.consume",
        acks_late=True,
        reject_on_worker_lost=True,
        max_retries=0,
        ignore_result=False,
    )(consume_job)
    return worker
