import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List

from .safe_json import JSONSafetyError, read_bounded_json


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

MAX_CONFIG_BYTES = 1024 * 1024
MAX_LIST_ITEMS = 1000
MAX_PATTERN_LENGTH = 256


class ConfigError(ValueError):
    """Raised when repository policy configuration is unsafe or invalid."""


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
    if config_path.is_symlink():
        raise ConfigError("configuration must not be a symbolic link")
    if not config_path.exists():
        return Config()

    try:
        data = read_bounded_json(config_path, MAX_CONFIG_BYTES)
    except JSONSafetyError as exc:
        raise ConfigError(f"configuration {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be a JSON object")

    exclude = data.get("exclude", DEFAULT_EXCLUDES)
    ignore = data.get("ignore", [])
    ignore_rules = data.get("ignore_rules", [])
    baseline = data.get("baseline", ".agent-hygiene-baseline.json")
    min_score = data.get("min_score", 85)
    fail_on = data.get("fail_on", "high")

    exclude = _string_list(exclude, "exclude", DEFAULT_EXCLUDES)
    ignore = _string_list(ignore, "ignore", [])
    ignore_rules = _string_list(ignore_rules, "ignore_rules", [])
    if baseline is not None and not isinstance(baseline, str):
        baseline = ".agent-hygiene-baseline.json"
    if (
        isinstance(min_score, bool)
        or not isinstance(min_score, int)
        or not 0 <= min_score <= 100
    ):
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


def _string_list(value: object, label: str, default: List[str]) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return list(default)
    if len(value) > MAX_LIST_ITEMS:
        raise ConfigError(f"{label} cannot contain more than {MAX_LIST_ITEMS} entries")
    if any(
        len(item) > MAX_PATTERN_LENGTH or "\0" in item or "\n" in item or "\r" in item
        for item in value
    ):
        raise ConfigError(
            f"{label} entries must be at most {MAX_PATTERN_LENGTH} safe characters"
        )
    return list(value)


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
