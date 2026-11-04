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
    )

    def ping() -> str:
        return "foundation-pong"

    worker.task(name="aegistrace.diagnostic.ping")(ping)
    return worker
