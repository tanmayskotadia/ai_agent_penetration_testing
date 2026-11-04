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
    evidence_key: SecretStr | None = None
    evidence_key_id: str = Field(default="primary-v1", min_length=1, max_length=100)
    control_plane_networks: tuple[str, ...] = ("127.0.0.0/8", "::1/128")

    @field_validator("evidence_key")
    @classmethod
    def valid_evidence_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None:
            try:
                if (
                    len(value.get_secret_value()) != 64
                    or len(bytes.fromhex(value.get_secret_value())) != 32
                ):
                    raise ValueError("invalid length")
            except ValueError as error:
                raise ValueError("EVIDENCE_KEY must be a 32-byte hexadecimal key") from error
        return value

    @field_validator("database_url")
    @classmethod
    def supported_database(cls, value: str) -> str:
        if not value.startswith(("postgresql+psycopg://", "sqlite:///")):
            raise ValueError(
                "DATABASE_URL must use postgresql+psycopg:// or explicit SQLite smoke mode"
            )
        return value
