#!/usr/bin/env python3
"""Validate composite-action inputs without interpolating them into shell code."""

import os
import re
import sys
from pathlib import Path
from typing import Dict


ALLOWED_FAIL_ON = {"none", "low", "medium", "high", "critical"}


class InputError(ValueError):
    pass


def validate(workspace: Path, values: Dict[str, str]) -> Dict[str, str]:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise InputError("GITHUB_WORKSPACE is not a directory")

    min_score = values.get("min_score", "")
    if not re.fullmatch(r"[0-9]{1,3}", min_score):
        raise InputError("min-score must be an integer from 0 to 100")
    min_score_number = int(min_score)
    if not 0 <= min_score_number <= 100:
        raise InputError("min-score must be an integer from 0 to 100")

    fail_on = values.get("fail_on", "")
    if fail_on not in ALLOWED_FAIL_ON:
        raise InputError(
            "fail-on must be one of none, low, medium, high, or critical"
        )

    scan_path = _inside_workspace(
        workspace,
        values.get("path", ""),
        "path",
        kind="directory",
    )
    baseline = _inside_workspace(
        workspace,
        values.get("baseline", ""),
        "baseline",
        kind="file",
        allow_empty=True,
    )
    sarif = _inside_workspace(
        workspace,
        values.get("sarif", ""),
        "sarif",
        kind="output",
        allow_empty=True,
    )
    json_output = _inside_workspace(
        workspace,
        values.get("json", ""),
        "json",
        kind="output",
        allow_empty=True,
    )
    _ensure_distinct_paths(
        {
            "baseline": baseline,
            "sarif": sarif,
            "json": json_output,
        }
    )
    return {
        "path": scan_path,
        "min_score": str(min_score_number),
        "fail_on": fail_on,
        "baseline": baseline,
        "sarif": sarif,
        "json": json_output,
    }


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: validate_action_inputs.py GITHUB_OUTPUT", file=sys.stderr)
        return 2

    workspace_value = os.environ.get("GITHUB_WORKSPACE", "")
    if not workspace_value:
        print("agent-hygiene action: GITHUB_WORKSPACE is required", file=sys.stderr)
        return 2

    values = {
        "path": os.environ.get("AGENT_HYGIENE_INPUT_PATH", ""),
        "min_score": os.environ.get("AGENT_HYGIENE_INPUT_MIN_SCORE", ""),
        "fail_on": os.environ.get("AGENT_HYGIENE_INPUT_FAIL_ON", ""),
        "sarif": os.environ.get("AGENT_HYGIENE_INPUT_SARIF", ""),
        "json": os.environ.get("AGENT_HYGIENE_INPUT_JSON", ""),
        "baseline": os.environ.get("AGENT_HYGIENE_INPUT_BASELINE", ""),
    }
    try:
        validated = validate(Path(workspace_value), values)
        output_path = Path(args[0])
        with output_path.open("a", encoding="utf-8") as output:
            for key in (
                "path",
                "min_score",
                "fail_on",
                "sarif",
                "json",
                "baseline",
            ):
                output.write(f"{key}={validated[key]}\n")
    except (InputError, OSError) as exc:
        print(f"agent-hygiene action: invalid input: {exc}", file=sys.stderr)
        return 2
    return 0


def _inside_workspace(
    workspace: Path,
    raw: str,
    label: str,
    kind: str,
    allow_empty: bool = False,
) -> str:
    if not raw:
        if allow_empty:
            return ""
        raise InputError(f"{label} must not be empty")
    if any(char in raw for char in ("\0", "\n", "\r")):
        raise InputError(f"{label} contains an invalid character")

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate

    try:
        resolved = candidate.resolve(strict=kind in {"directory", "file"})
        resolved.relative_to(workspace)
    except FileNotFoundError as exc:
        raise InputError(f"{label} does not exist") from exc
    except ValueError as exc:
        raise InputError(f"{label} must stay inside GITHUB_WORKSPACE") from exc

    if kind == "directory" and not resolved.is_dir():
        raise InputError(f"{label} must be a directory")
    if kind == "file":
        if candidate.is_symlink() or not resolved.is_file():
            raise InputError(f"{label} must be a regular file")
    if kind == "output":
        if candidate.is_symlink():
            raise InputError(f"{label} must not be a symbolic link")
        parent = resolved.parent.resolve(strict=True)
        try:
            parent.relative_to(workspace)
        except ValueError as exc:
            raise InputError(f"{label} parent must stay inside GITHUB_WORKSPACE") from exc
        if not parent.is_dir():
            raise InputError(f"{label} parent must be a directory")

    return str(resolved)


def _ensure_distinct_paths(paths: Dict[str, str]) -> None:
    populated = [(label, value) for label, value in paths.items() if value]
    for index, (left_label, left_path) in enumerate(populated):
        for right_label, right_path in populated[index + 1 :]:
            if left_path == right_path:
                raise InputError(
                    f"{left_label} and {right_label} must use different paths"
                )


if __name__ == "__main__":
    raise SystemExit(main())
