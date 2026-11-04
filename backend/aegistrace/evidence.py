"""Private, bounded originals with authenticated encryption and separate reviewed derivatives."""

import hashlib
import html
import re
import secrets
from datetime import UTC, datetime
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Connection, select

from aegistrace.audit import AuditEvent, append_event, request_context
from aegistrace.evidence_schema import access_events, objects
from aegistrace.repository import get_record, require_owner
from aegistrace.schema_v1 import report_snapshots
from aegistrace.settings import Settings

MAX_BYTES = 2 * 1024 * 1024


class EvidenceError(ValueError):
    pass


def redacted_snippet(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace")[:65536]
    text = re.sub(
        r"(?is)<(password|passwd|secret|token|api[_-]?key)(?:\s[^>]*)?>.*?</\1\s*>",
        r"<\1>[REDACTED]</\1>",
        text,
    )
    text = re.sub(r"(?im)\b(authorization|cookie|set-cookie)\s*:[^\r\n]*", r"\1: [REDACTED]", text)
    text = re.sub(
        r"""(?i)(["']?\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)["']?\s*[:=]\s*)[^\s<>&,;]+""",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@", r"\1[REDACTED]@", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|AKIA[A-Z0-9]{16})\b", "[REDACTED]", text)
    text = re.sub(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        text,
        flags=re.S,
    )
    text = "".join(c for c in text if c in "\n\t" or ord(c) >= 32)
    return html.escape(text)


class EvidenceStore:
    def __init__(self, config: Settings):
        if config.evidence_key is None:
            raise EvidenceError("evidence storage requires a configured encryption key")
        self.cipher = AESGCM(bytes.fromhex(config.evidence_key.get_secret_value()))
        self.key_id = config.evidence_key_id

    @staticmethod
    def aad(assessment_id: UUID, evidence_id: UUID) -> bytes:
        return f"aegistrace:1:{assessment_id}:{evidence_id}".encode()

    @staticmethod
    def event(
        connection: Connection, assessment_id: UUID, evidence_id: UUID, actor: str, action: str
    ) -> None:
        context = request_context.get() or (uuid4(), uuid4())
        append_event(
            connection,
            AuditEvent(
                assessment_id=assessment_id,
                actor_id=actor,
                request_id=context[0],
                correlation_id=context[1],
                action=f"evidence.{action}",
                resource_id=evidence_id,
                action_digest=hashlib.sha256(f"{action}:{evidence_id}".encode()).hexdigest(),
                outcome="completed",
            ),
        )
        connection.execute(
            access_events.insert().values(
                assessment_id=str(assessment_id),
                evidence_id=str(evidence_id),
                actor_id=actor,
                action=action,
                created_at=datetime.now(UTC).isoformat(),
            )
        )

    def put(
        self,
        connection: Connection,
        assessment_id: UUID,
        evidence_id: UUID,
        actor: str,
        raw: bytes,
        expires_at: datetime,
    ) -> None:
        require_owner(connection, assessment_id, actor)
        reference = get_record(connection, "evidence_references", assessment_id, evidence_id)
        if not 0 < len(raw) <= MAX_BYTES:
            raise EvidenceError("original must be 1 byte to 2 MiB")
        digest = hashlib.sha256(raw).hexdigest()
        if digest != reference["sha256"]:
            raise EvidenceError("original does not match source reference hash")
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            raise EvidenceError("retention expiry must be timezone-aware and in the future")
        nonce = secrets.token_bytes(12)
        connection.execute(
            objects.insert().values(
                id=str(evidence_id),
                assessment_id=str(assessment_id),
                ciphertext=self.cipher.encrypt(nonce, raw, self.aad(assessment_id, evidence_id)),
                nonce=nonce,
                key_id=self.key_id,
                sha256=digest,
                size=len(raw),
                expires_at=expires_at.isoformat(),
                redaction_reviewed=False,
            )
        )
        self.event(connection, assessment_id, evidence_id, actor, "original-stored")

    def read(
        self, connection: Connection, assessment_id: UUID, evidence_id: UUID, actor: str
    ) -> bytes:
        require_owner(connection, assessment_id, actor)
        row = (
            connection.execute(
                select(objects).where(
                    objects.c.id == str(evidence_id), objects.c.assessment_id == str(assessment_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LookupError("resource not found")
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
            raise EvidenceError("evidence retention expired")
        if row["key_id"] != self.key_id:
            raise EvidenceError("evidence decryption key unavailable")
        try:
            raw = self.cipher.decrypt(
                row["nonce"], row["ciphertext"], self.aad(assessment_id, evidence_id)
            )
        except InvalidTag as error:
            raise EvidenceError("evidence integrity failure") from error
        reference = get_record(connection, "evidence_references", assessment_id, evidence_id)
        if hashlib.sha256(raw).hexdigest() != row["sha256"] or row["sha256"] != reference["sha256"]:
            raise EvidenceError("evidence integrity failure")
        self.event(connection, assessment_id, evidence_id, actor, "original-read")
        return raw

    def redact(
        self, connection: Connection, assessment_id: UUID, evidence_id: UUID, actor: str
    ) -> str:
        raw = self.read(connection, assessment_id, evidence_id, actor)
        snippet = redacted_snippet(raw)
        connection.execute(
            objects.update()
            .where(objects.c.id == str(evidence_id))
            .values(redacted=snippet, redaction_reviewed=False)
        )
        self.event(connection, assessment_id, evidence_id, actor, "redaction-generated")
        return snippet

    @staticmethod
    def derivative(
        connection: Connection, assessment_id: UUID, evidence_id: UUID, actor: str
    ) -> str:
        require_owner(connection, assessment_id, actor)
        row = (
            connection.execute(
                select(objects).where(
                    objects.c.id == str(evidence_id), objects.c.assessment_id == str(assessment_id)
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise LookupError("resource not found")
        if not row["redaction_reviewed"] or datetime.fromisoformat(
            row["expires_at"]
        ) <= datetime.now(UTC):
            raise EvidenceError("reviewed unexpired derivative required")
        return str(row["redacted"])

    @staticmethod
    def purge_expired(connection: Connection, assessment_id: UUID, actor: str) -> int:
        require_owner(connection, assessment_id, actor)
        # Conservatively retain all originals if this assessment has any report snapshot.
        if connection.execute(
            select(report_snapshots.c.id).where(
                report_snapshots.c.assessment_id == str(assessment_id)
            )
        ).first():
            return 0
        rows = (
            connection.execute(select(objects).where(objects.c.assessment_id == str(assessment_id)))
            .mappings()
            .all()
        )
        count = 0
        for row in rows:
            if datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
                EvidenceStore.event(
                    connection, assessment_id, UUID(row["id"]), actor, "expired-original-purged"
                )
                connection.execute(objects.delete().where(objects.c.id == row["id"]))
                count += 1
        return count
