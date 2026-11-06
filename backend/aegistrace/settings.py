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
    environment: Literal["development", "test", "ci", "production"] = "development"
    allow_operator_tokens: bool = True
    bootstrap_token: SecretStr | None = Field(default=None, min_length=32)
    evidence_key: SecretStr | None = None
    evidence_key_id: str = Field(default="primary-v1", min_length=1, max_length=100)
    control_plane_networks: tuple[str, ...] = ("127.0.0.0/8", "::1/128")
    web_scanner_candidate_enabled: bool = False
    web_scanner_egress_gate_reference: str | None = Field(default=None, max_length=500)
    zap_executable_path: str | None = Field(default=None, max_length=1000)
    zap_executable_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    nikto_executable_path: str | None = Field(default=None, max_length=1000)
    nikto_executable_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    adaptive_planner_enabled: bool = False
    groq_api_key: SecretStr | None = None
    groq_model: str | None = Field(default=None, min_length=1, max_length=100)
    model_data_policy_reference: str | None = Field(default=None, min_length=1, max_length=300)
    model_timeout_seconds: int = Field(default=20, ge=1, le=60)
    model_max_completion_tokens: int = Field(default=2048, ge=128, le=4096)
    model_max_plan_revisions: int = Field(default=3, ge=1, le=10)
    model_max_assessment_calls: int = Field(default=20, ge=1, le=100)

    @field_validator("groq_model")
    @classmethod
    def text_only_groq_model(cls, value: str | None) -> str | None:
        if value and ("compound" in value.casefold() or any(ord(c) < 33 for c in value)):
            raise ValueError("Select a text-only chat model; compound tool systems are not allowed")
        return value

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
