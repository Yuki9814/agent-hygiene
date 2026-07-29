import json
from pathlib import Path
from typing import Optional, Tuple

from .line_endings import sarif_line_number
from .safe_files import SafeFileError, read_bounded_regular_file


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
        line = sarif_line_number(text, exc.pos)
        raise JSONSafetyError(
            f"is not valid JSON at line {line}",
            line=line,
        ) from exc
    except _NonStandardConstant as exc:
        raise JSONSafetyError("contains a non-standard numeric constant") from exc
    except (OverflowError, RecursionError, ValueError) as exc:
        raise JSONSafetyError("JSON exceeds safe parser limits") from exc


def read_bounded_json(path: Path, max_bytes: int) -> object:
    data, _ = read_bounded_json_with_size(path, max_bytes)
    return data


def read_bounded_json_with_size(
    path: Path,
    max_bytes: int,
) -> Tuple[object, int]:
    try:
        read_result = read_bounded_regular_file(path, max_bytes)
    except SafeFileError as exc:
        raise _json_safety_error(exc, max_bytes) from exc
    raw = read_result.data
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JSONSafetyError("is not valid UTF-8") from exc
    return strict_json_loads(text), len(raw)


def _json_safety_error(
    error: SafeFileError,
    max_bytes: int,
) -> JSONSafetyError:
    if error.reason == "symlink":
        return JSONSafetyError("must not be a symbolic link")
    if error.reason == "not_regular":
        return JSONSafetyError("must be a regular file")
    if error.reason == "too_large":
        return JSONSafetyError(f"exceeds the {max_bytes}-byte limit")
    if error.reason == "changed":
        return JSONSafetyError("changed while being opened")
    if error.reason in {"missing", "open_error"}:
        return JSONSafetyError(
            "could not be opened safely: "
            f"{error.error_name or error.reason}"
        )
    return JSONSafetyError(
        "could not be read safely: "
        f"{error.error_name or error.reason}"
    )


def _reject_constant(value: str) -> object:
    raise _NonStandardConstant(value)


def _preflight_json_structure(text: str) -> None:
    """Enforce parser-independent depth and trailing-comma behavior."""
    depth = 0
    in_string = False
    escaped = False
    pending_comma = False

    for offset, character in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character not in " \t\r\n":
            if pending_comma and character in "]}":
                line = sarif_line_number(text, offset)
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
                    line = sarif_line_number(text, offset)
                    raise JSONSafetyError(
                        "JSON exceeds safe parser limits",
                        line=line,
                    )
            elif character in "]}" and depth:
                depth -= 1
