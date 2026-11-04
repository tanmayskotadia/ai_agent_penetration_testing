"""Defense in depth: never log request bodies; redact configured secrets and common headers."""

import logging
import re


def safe_log_text(text: str, secret_values: tuple[str, ...] = ()) -> str:
    for value in secret_values:
        if value:
            text = text.replace(value, "[REDACTED]")
    text = re.sub(r"(?im)\b(authorization|cookie|set-cookie)\s*:[^\r\n]*", r"\1: [REDACTED]", text)
    return re.sub(
        r"""(?i)(["']?\b(?:password|passwd|app_secret|evidence_key|secret|token|api[_-]?key)["']?\s*[:=]\s*)[^\s<>&,;]+""",
        r"\1[REDACTED]",
        text,
    )


class SafeFormatter(logging.Formatter):
    def __init__(self, inner: logging.Formatter, secret_values: tuple[str, ...]):
        super().__init__()
        self.inner = inner
        self.secret_values = secret_values

    def format(self, record: logging.LogRecord) -> str:
        return safe_log_text(self.inner.format(record), self.secret_values)


def protect_handlers(secret_values: tuple[str, ...]) -> None:
    for name in ["", "uvicorn", "uvicorn.error", "uvicorn.access", "aegistrace"]:
        for handler in logging.getLogger(name).handlers:
            formatter = handler.formatter or logging.Formatter()
            if isinstance(formatter, SafeFormatter):
                formatter = formatter.inner
            handler.setFormatter(SafeFormatter(formatter, secret_values))
