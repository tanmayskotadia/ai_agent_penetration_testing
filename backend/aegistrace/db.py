from sqlalchemy import Engine, create_engine

from aegistrace.settings import Settings


def make_engine(settings: Settings) -> Engine:
    options = {"check_same_thread": False} if settings.database_url.startswith("sqlite:") else {}
    return create_engine(settings.database_url, pool_pre_ping=True, connect_args=options)
