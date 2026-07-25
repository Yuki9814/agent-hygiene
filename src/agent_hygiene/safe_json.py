import json
import os
import stat
from pathlib import Path
from typing import Optional


class JSONSafetyError(Exception):
    """Raised when untrusted JSON cannot be read and parsed safely."""

    def __init__(self, message: str, line: Optional[int] = None):
        super().__init__(message)
        self.line = line


class _NonStandardConstant(Exception):
    pass


MAX_JSON_NESTING = 128


def strict_json_loads(text: str) -> object:
    _preflight_json_structure(text)
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise JSONSafetyError(
            f"is not valid JSON at line {exc.lineno}",
            line=exc.lineno,
        ) from exc
    except _NonStandardConstant as exc:
        raise JSONSafetyError("contains a non-standard numeric constant") from exc
    except (OverflowError, RecursionError, ValueError) as exc:
        raise JSONSafetyError("JSON exceeds safe parser limits") from exc


def read_bounded_json(path: Path, max_bytes: int) -> object:
    if path.is_symlink():
        raise JSONSafetyError("must not be a symbolic link")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise JSONSafetyError(
            f"could not be opened safely: {exc.__class__.__name__}"
        ) from exc

    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise JSONSafetyError("must be a regular file")
        if info.st_size > max_bytes:
            raise JSONSafetyError(f"exceeds the {max_bytes}-byte limit")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            raw = stream.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(raw) > max_bytes:
        raise JSONSafetyError(f"exceeds the {max_bytes}-byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JSONSafetyError("is not valid UTF-8") from exc
    return strict_json_loads(text)


def _reject_constant(value: str) -> object:
    raise _NonStandardConstant(value)


def _preflight_json_structure(text: str) -> None:
    """Enforce parser-independent depth and trailing-comma behavior."""
    depth = 0
    line = 1
    in_string = False
    escaped = False
    pending_comma = False

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character not in " \t\r\n":
            if pending_comma and character in "]}":
                raise JSONSafetyError(
                    f"is not valid JSON at line {line}",
                    line=line,
                )
            pending_comma = character == ","
            if character == '"':
                in_string = True
            elif character in "[{":
                depth += 1
                if depth > MAX_JSON_NESTING:
                    raise JSONSafetyError(
                        "JSON exceeds safe parser limits",
                        line=line,
                    )
            elif character in "]}" and depth:
                depth -= 1

        if character == "\n":
            line += 1
