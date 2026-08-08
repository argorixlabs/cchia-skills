"""Conservative secret redaction for collector outputs and diagnostics."""

from __future__ import annotations

import re
from typing import Any


REDACTED = "[REDACTED]"
MAX_TEXT_EVIDENCE = 32_768

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_\-.])(?:"
    r"authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|token|"
    r"password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|"
    r"private[_-]?key|access[_-]?key|credential|cookie|"
    r"certificate-authority-data|client-key-data"
    r")(?:$|[_\-.])",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"token|password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|"
    r"private[_-]?key|access[_-]?key|credential|cookie)"
    r"(\s*[:=]\s*)(?:Bearer\s+)?([^\s,;]+)"
)
_QUOTED_ASSIGNMENT = re.compile(
    r'''(?i)(["'])(authorization|access[_-]?token|refresh[_-]?token|id[_-]?token|'''
    r'''token|password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|apikey|'''
    r'''private[_-]?key|access[_-]?key|credential|cookie)\1(\s*:\s*)(["']).*?\4'''
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)


def is_sensitive_name(value: object) -> bool:
    return isinstance(value, str) and bool(_SENSITIVE_KEY.search(value))


def redact_text(value: object, *, limit: int = MAX_TEXT_EVIDENCE) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)
    text = _PRIVATE_KEY.sub(REDACTED, text)
    text = _BEARER.sub("Bearer " + REDACTED, text)
    text = _QUOTED_ASSIGNMENT.sub(
        lambda match: f'{match.group(1)}{match.group(2)}{match.group(1)}{match.group(3)}'
        f'{match.group(4)}{REDACTED}{match.group(4)}',
        text,
    )
    text = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", text)
    if len(text) > limit:
        return text[:limit] + f"\n[TRUNCATED {len(text) - limit} CHARACTERS]"
    return text


def redact(value: Any, *, parent: dict[str, Any] | None = None) -> Any:
    """Return a deep-redacted copy without mutating the SDK/CLI response."""

    if isinstance(value, dict):
        output: dict[str, Any] = {}
        kind = str(value.get("kind", "")).casefold()
        sensitive_env = is_sensitive_name(value.get("name")) and "value" in value
        for key, item in value.items():
            key_text = str(key)
            if is_sensitive_name(key_text):
                output[key_text] = REDACTED
            elif kind == "secret" and key_text.casefold() in {"data", "stringdata"}:
                output[key_text] = REDACTED
            elif sensitive_env and key_text == "value":
                output[key_text] = REDACTED
            else:
                output[key_text] = redact(item, parent=value)
        return output
    if isinstance(value, list):
        return [redact(item, parent=parent) for item in value]
    if isinstance(value, tuple):
        return [redact(item, parent=parent) for item in value]
    if isinstance(value, (str, bytes)):
        return redact_text(value)
    return value
