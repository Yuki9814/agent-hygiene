import json
from pathlib import Path
from typing import Iterable, Set

from .models import Finding


BASELINE_VERSION = 2


def baseline_path(root: Path, configured_path: str) -> Path:
    path = Path(configured_path)
    if path.is_absolute():
        return path
    return root / path


def load_baseline(root: Path, configured_path: str) -> Set[str]:
    path = baseline_path(root, configured_path)
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()

    if isinstance(data, list):
        return {str(item) for item in data}
    if not isinstance(data, dict):
        return set()

    fingerprints = data.get("fingerprints")
    if isinstance(fingerprints, list):
        return {str(item) for item in fingerprints}

    findings = data.get("findings")
    if isinstance(findings, list):
        values = set()
        for item in findings:
            if isinstance(item, dict) and isinstance(item.get("fingerprint"), str):
                values.add(item["fingerprint"])
        return values

    return set()


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
