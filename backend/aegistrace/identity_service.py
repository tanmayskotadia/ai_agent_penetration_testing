"""Argon2 human login and DB-checked scoped sessions. No public self-registration."""

import hashlib
import hmac
import re
import time
from typing import Any
from uuid import UUID, uuid4

from pwdlib import PasswordHash
from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from aegistrace.auth import Identity, Role, seal
from aegistrace.identity_schema import attempts, members, principals, sessions
from aegistrace.settings import Settings

PASSWORDS = PasswordHash.recommended()
DUMMY_HASH = PASSWORDS.hash("not-a-valid-account-password")
HUMAN_ROLES = {"analyst", "reviewer", "admin", "auditor"}
SERVICE_ROLES = {"scanner", "reporter", "planner"}


def username_value(value: str) -> str:
    name = value.casefold().strip()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.@+-]{2,199}", name):
        raise ValueError("invalid username")
    return name


def create_principal(
    connection: Connection, username: str, password: str | None, role: Role, kind: str = "human"
) -> str:
    if (
        kind not in {"human", "service"}
        or (kind == "human" and role not in HUMAN_ROLES)
        or (kind == "service" and role not in SERVICE_ROLES)
    ):
        raise ValueError("identity kind/role mismatch")
    if kind == "human" and (password is None or not 12 <= len(password) <= 128):
        raise ValueError("human password must be 12–128 characters")
    if kind == "service" and password is not None:
        raise ValueError("service identities cannot use password login")
    subject = str(uuid4())
    connection.execute(
        principals.insert().values(
            id=subject,
            username=username_value(username),
            password_hash=PASSWORDS.hash(password) if password is not None else None,
            kind=kind,
            role=role,
            active=True,
            epoch=0,
        )
    )
    return subject


def set_membership(
    connection: Connection, assessment_id: UUID, subject: str, role: Role, active: bool = True
) -> None:
    principal = (
        connection.execute(select(principals).where(principals.c.id == subject))
        .mappings()
        .one_or_none()
    )
    if (
        principal is None
        or (principal["kind"] == "service" and role not in SERVICE_ROLES)
        or (principal["kind"] == "human" and role not in HUMAN_ROLES)
    ):
        raise ValueError("invalid member/role")
    insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
    connection.execute(
        insert(members)
        .values(assessment_id=str(assessment_id), subject=subject, role=role, active=active)
        .on_conflict_do_update(
            index_elements=[members.c.assessment_id, members.c.subject],
            set_={"role": role, "active": active},
        )
    )


def issue_session(
    connection: Connection, config: Settings, subject: str, assessment_id: UUID | None = None
) -> dict[str, Any]:
    principal = (
        connection.execute(
            select(principals).where(principals.c.id == subject, principals.c.active.is_(True))
        )
        .mappings()
        .one()
    )
    if principal["kind"] == "service" and assessment_id is None:
        raise ValueError("service sessions require one assessment")
    ttl = 300 if principal["kind"] == "service" else 900
    identity = Identity.model_validate(
        dict(
            subject=subject,
            role=principal["role"],
            principal_kind=principal["kind"],
            session_id=str(uuid4()),
            epoch=principal["epoch"],
            expires=int(time.time()) + ttl,
        )
    )
    token = seal(config.app_secret.get_secret_value(), "identity", identity.model_dump(mode="json"))
    connection.execute(
        sessions.insert().values(
            id=str(identity.session_id),
            subject=subject,
            token_digest=hashlib.sha256(token.encode()).hexdigest(),
            expires=identity.expires,
            revoked=False,
            assessment_id=str(assessment_id) if assessment_id else None,
        )
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl, "subject": subject}


def resolve_session(
    connection: Connection, identity: Identity, token: str, assessment_id: UUID | None
) -> Identity:
    principal = (
        connection.execute(select(principals).where(principals.c.id == identity.subject))
        .mappings()
        .one_or_none()
    )
    session = (
        connection.execute(
            select(sessions).where(
                sessions.c.id == str(identity.session_id), sessions.c.subject == identity.subject
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        principal is None
        or not principal["active"]
        or session is None
        or session["revoked"]
        or session["expires"] <= time.time()
        or identity.epoch != principal["epoch"]
        or not hmac.compare_digest(
            session["token_digest"], hashlib.sha256(token.encode()).hexdigest()
        )
    ):
        raise ValueError("session revoked or invalid")
    if session["assessment_id"] is not None and str(assessment_id) != session["assessment_id"]:
        raise ValueError("service session assessment mismatch")
    role = principal["role"]
    if assessment_id is not None:
        member = (
            connection.execute(
                select(members).where(
                    members.c.assessment_id == str(assessment_id),
                    members.c.subject == identity.subject,
                    members.c.active.is_(True),
                )
            )
            .mappings()
            .one_or_none()
        )
        if member is None:
            raise ValueError("assessment membership missing or revoked")
        role = member["role"]
    return Identity.model_validate(
        identity.model_dump() | {"role": role, "principal_kind": principal["kind"]}
    )


def login_attempt(connection: Connection, username: str, client: str, secret: str) -> None:
    # Bound both a username and a source address; no plaintext identifier/password is logged.
    insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
    now = time.time()
    for value in ["user:" + username, "source:" + client]:
        key = hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()
        connection.execute(
            insert(attempts).values(key=key, window=now, count=0).on_conflict_do_nothing()
        )
        connection.execute(
            attempts.update().where(attempts.c.key == key).values(count=attempts.c.count)
        )
        row = (
            connection.execute(select(attempts).where(attempts.c.key == key).with_for_update())
            .mappings()
            .one()
        )
        count = 0 if now - row["window"] >= 60 else row["count"]
        if count >= 10:
            raise ValueError("login-rate-limit")
        connection.execute(
            attempts.update()
            .where(attempts.c.key == key)
            .values(window=now if count == 0 else row["window"], count=count + 1)
        )


def verify_password(connection: Connection, username: str, password: str) -> str | None:
    principal = (
        connection.execute(select(principals).where(principals.c.username == username))
        .mappings()
        .one_or_none()
    )
    digest = (
        principal["password_hash"]
        if principal is not None and principal["password_hash"]
        else DUMMY_HASH
    )
    verified = PASSWORDS.verify(password, digest)
    return (
        principal["id"]
        if verified
        and principal is not None
        and principal["active"]
        and principal["kind"] == "human"
        else None
    )
