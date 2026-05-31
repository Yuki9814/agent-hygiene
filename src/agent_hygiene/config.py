import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List


DEFAULT_EXCLUDES = [
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".turbo",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
]


@dataclass(frozen=True)
class Config:
    exclude: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    ignore: List[str] = field(default_factory=list)
    ignore_rules: List[str] = field(default_factory=list)
    baseline: Optional[str] = ".agent-hygiene-baseline.json"
    min_score: int = 85
    fail_on: str = "high"


def load_config(root: Path) -> Config:
    config_path = root / ".agent-hygiene.json"
    if not config_path.exists():
        return Config()

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return Config()

    exclude = data.get("exclude", DEFAULT_EXCLUDES)
    ignore = data.get("ignore", [])
    ignore_rules = data.get("ignore_rules", [])
    baseline = data.get("baseline", ".agent-hygiene-baseline.json")
    min_score = data.get("min_score", 85)
    fail_on = data.get("fail_on", "high")

    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        exclude = DEFAULT_EXCLUDES
    if not isinstance(ignore, list) or not all(isinstance(item, str) for item in ignore):
        ignore = []
    if not isinstance(ignore_rules, list) or not all(isinstance(item, str) for item in ignore_rules):
        ignore_rules = []
    if baseline is not None and not isinstance(baseline, str):
        baseline = ".agent-hygiene-baseline.json"
    if not isinstance(min_score, int):
        min_score = 85
    if fail_on not in {"none", "low", "medium", "high", "critical"}:
        fail_on = "high"

    return Config(
        exclude=list(exclude),
        ignore=list(ignore),
        ignore_rules=[rule.upper() for rule in ignore_rules],
        baseline=baseline,
        min_score=min_score,
        fail_on=fail_on,
    )


def default_config_text() -> str:
    return json.dumps(
        {
            "exclude": [".git", "node_modules", "dist", "build"],
            "ignore": [],
            "ignore_rules": [],
            "baseline": ".agent-hygiene-baseline.json",
            "min_score": 85,
            "fail_on": "high",
        },
        indent=2,
    ) + "\n"
