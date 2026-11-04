from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", env_ignore_empty=True, hide_input_in_errors=True
    )

    app_secret: SecretStr = Field(min_length=32)
    database_url: str
    redis_url: str = "redis://127.0.0.1:6379/0"
    environment: Literal["development", "test", "ci"] = "development"

    @field_validator("database_url")
    @classmethod
    def supported_database(cls, value: str) -> str:
        if not value.startswith(("postgresql+psycopg://", "sqlite:///")):
            raise ValueError(
                "DATABASE_URL must use postgresql+psycopg:// or explicit SQLite smoke mode"
            )
        return value
