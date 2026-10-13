"""Secret detection with value redaction. Secret values never leave this module."""
from __future__ import annotations

import re
from dataclasses import dataclass

REDACTED = "[REDACTED]"

# (label, compiled pattern). Patterns are heuristics; false positives are expected.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("Generic API key assignment", re.compile(
        r"(?i)\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)"
        r"\b\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{16,})['\"]")),
    ("Hardcoded password assignment", re.compile(
        r"(?i)\b(password|passwd|db_password)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]")),
]

_PLACEHOLDER_HINTS = ("example", "changeme", "your_", "xxxx", "<", "placeholder", "dummy", "test")


@dataclass(frozen=True)
class SecretHit:
    path: str
    line: int
    label: str


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(h in lowered for h in _PLACEHOLDER_HINTS)


def scan_text_for_secrets(path: str, text: str) -> list[SecretHit]:
    """Return locations of likely secrets. The matched value is discarded immediately."""
    hits: list[SecretHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for label, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(line):
                value = m.group(m.lastindex) if m.lastindex else m.group(0)
                if label.startswith(("Generic", "Hardcoded")) and _looks_like_placeholder(value):
                    continue
                hits.append(SecretHit(path=path, line=lineno, label=label))
                break
    return hits


def redact(text: str) -> str:
    """Replace any secret-looking value in free text before it is logged or reported."""
    out = text
    for _, pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: m.group(0).replace(m.group(m.lastindex), REDACTED)
                          if m.lastindex else REDACTED, out)
    return out
