import json
from pathlib import Path
from typing import Iterable, Set

from .models import Finding
from .safe_json import JSONSafetyError, read_bounded_json


BASELINE_VERSION = 2
MAX_BASELINE_BYTES = 4 * 1024 * 1024
MAX_BASELINE_ENTRIES = 10_000


class BaselineError(ValueError):
    """Raised when a configured baseline cannot be trusted."""


def baseline_path(root: Path, configured_path: str) -> Path:
    root = root.resolve()
    path = Path(configured_path)
    candidate = path if path.is_absolute() else root / path
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise BaselineError("baseline must stay within the repository") from exc
    return candidate


def load_baseline(root: Path, configured_path: str) -> Set[str]:
    path = baseline_path(root, configured_path)
    if path.is_symlink():
        raise BaselineError("baseline must not be a symbolic link")
    if not path.exists():
        return set()
    try:
        data = read_bounded_json(path, MAX_BASELINE_BYTES)
    except JSONSafetyError as exc:
        raise BaselineError(f"baseline {exc}") from exc

    if isinstance(data, list):
        if not all(isinstance(item, str) for item in data):
            raise BaselineError("legacy baseline entries must be strings")
        _check_entry_count(data)
        return set(data)
    if not isinstance(data, dict):
        raise BaselineError("baseline root must be an object or legacy array")

    fingerprints = data.get("fingerprints")
    if isinstance(fingerprints, list):
        if not all(isinstance(item, str) for item in fingerprints):
            raise BaselineError("baseline fingerprints must be strings")
        _check_entry_count(fingerprints)
        return set(fingerprints)

    findings = data.get("findings")
    if isinstance(findings, list):
        _check_entry_count(findings)
        values = set()
        for item in findings:
            if isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
                values.add(item["fingerprint"])
            else:
                raise BaselineError("baseline findings must contain fingerprints")
        return values

    raise BaselineError("baseline has no supported fingerprint list")


def _check_entry_count(items: list) -> None:
    if len(items) > MAX_BASELINE_ENTRIES:
        raise BaselineError(
            f"baseline cannot contain more than {MAX_BASELINE_ENTRIES} entries"
        )


def render_baseline(findings: Iterable[Finding]) -> str:
    sorted_findings = sorted(findings, key=lambda item: (item.path, item.line, item.rule_id))
    data = {
        "version": BASELINE_VERSION,
        "findings": [
            {
                "fingerprint": finding.fingerprint(),
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "path": finding.path,
                "line": finding.line,
                "message": finding.message,
            }
            for finding in sorted_findings
        ],
    }
    return json.dumps(data, indent=2, sort_keys=True) + "\n"
