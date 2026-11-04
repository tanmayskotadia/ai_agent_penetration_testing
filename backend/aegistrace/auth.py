"""Short-lived operator-issued bearer identities; no client-supplied identity headers."""

import base64
import hashlib
import hmac
import json
import time
from typing import Literal

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegistrace.settings import Settings

bearer = HTTPBearer(auto_error=False)
credentials_dependency = Security(bearer)


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)
    role: Literal["analyst", "reviewer", "auditor"] = "analyst"
    expires: int
    purpose: Literal["identity"] = "identity"


def seal(secret: str, purpose: str, payload: dict[str, object]) -> str:
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(
        secret.encode(), f"{purpose}:{encoded}".encode(), hashlib.sha256
    ).hexdigest()
    return encoded + "." + signature


def unseal(secret: str, purpose: str, token: str) -> dict[str, object]:
    try:
        if len(token) > 4096:
            raise ValueError("token too large")
        encoded, signature = token.split(".")
        expected = hmac.new(
            secret.encode(), f"{purpose}:{encoded}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("invalid signature")
        value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if not isinstance(value, dict) or type(value.get("expires")) is not int:
            raise ValueError("invalid claims")
        if value["expires"] <= int(time.time()):
            raise ValueError("expired")
        return value
    except (ValueError, TypeError, UnicodeError) as error:
        raise ValueError("invalid or expired token") from error


def authenticate(config: Settings, credentials: HTTPAuthorizationCredentials | None) -> Identity:
    try:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise ValueError("missing bearer")
        return Identity.model_validate(
            unseal(config.app_secret.get_secret_value(), "identity", credentials.credentials)
        )
    except (ValueError, ValidationError) as error:
        raise HTTPException(
            401, "Authentication required", headers={"WWW-Authenticate": "Bearer"}
        ) from error


def identity_dependency(config: Settings):  # type: ignore[no-untyped-def]
    def identity(
        credentials: HTTPAuthorizationCredentials | None = credentials_dependency,
    ) -> Identity:
        return authenticate(config, credentials)

    return identity


def issue_identity(
    config: Settings,
    subject: str,
    role: Literal["analyst", "reviewer", "auditor"] = "analyst",
    ttl: int = 900,
) -> str:
    if not 1 <= ttl <= 900:
        raise ValueError("identity lifetime must be 1–900 seconds")
    identity = Identity(subject=subject, role=role, expires=int(time.time()) + ttl)
    return seal(config.app_secret.get_secret_value(), "identity", identity.model_dump())
