from sqlalchemy import Engine, create_engine, event

from aegistrace.settings import Settings


def make_engine(settings: Settings) -> Engine:
    options = {"check_same_thread": False} if settings.database_url.startswith("sqlite:") else {}
    engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args=options)
    if settings.database_url.startswith("sqlite:"):

        @event.listens_for(engine, "connect")
        def enforce_foreign_keys(connection: object, _: object) -> None:
            cursor = connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine
