import re


TOKEN_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)

BEARER_PATTERN = re.compile(
    r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"
)

ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(\b(?:api[_-]?key|secret|token|password|credential)\b"
    r"\s*[:=]\s*['\"]?)[^\s'\";,]{8,}"
)


def redact_secrets(value: str) -> str:
    redacted = value
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub("<redacted-secret>", redacted)
    redacted = BEARER_PATTERN.sub(r"\1<redacted-secret>", redacted)
    redacted = ASSIGNMENT_PATTERN.sub(r"\1<redacted-secret>", redacted)
    return redacted
