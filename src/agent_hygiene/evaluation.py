import json
import math
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Set, Tuple

from .config import Config
from .discovery import MAX_FILE_BYTES
from .rules import RULES
from .safe_files import SafeFileError, read_bounded_regular_file
from .safe_json import JSONSafetyError, strict_json_loads
from .scanner import scan


MANIFEST_VERSION = 1
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CASES = 1000
MAX_FILES_PER_CASE = 100
MAX_TOTAL_FILE_REFERENCES = 1000
MAX_TOTAL_FIXTURE_BYTES = 64 * 1024 * 1024
CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
FindingKey = Tuple[str, str, int]


class EvaluationError(ValueError):
    """Raised when an evaluation manifest cannot be trusted."""


@dataclass
class EvaluationBudget:
    file_references: int = 0
    fixture_bytes: int = 0

    def consume(self, fixture_size: int) -> None:
        self.file_references += 1
        self.fixture_bytes += fixture_size
        if self.file_references > MAX_TOTAL_FILE_REFERENCES:
            raise EvaluationError(
                "manifest exceeds the total fixture reference budget "
                f"of {MAX_TOTAL_FILE_REFERENCES}"
            )
        if self.fixture_bytes > MAX_TOTAL_FIXTURE_BYTES:
            raise EvaluationError(
                "manifest exceeds the total fixture byte budget "
                f"of {MAX_TOTAL_FIXTURE_BYTES}"
            )


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    expected: Set[FindingKey]
    actual: Set[FindingKey]

    def to_dict(self) -> Dict[str, object]:
        true_positives = self.expected & self.actual
        false_positives = self.actual - self.expected
        false_negatives = self.expected - self.actual
        return {
            "id": self.case_id,
            "expected": [_finding_dict(item) for item in sorted(self.expected)],
            "actual": [_finding_dict(item) for item in sorted(self.actual)],
            "true_positives": len(true_positives),
            "false_positives": [_finding_dict(item) for item in sorted(false_positives)],
            "false_negatives": [_finding_dict(item) for item in sorted(false_negatives)],
            "passed": not false_positives and not false_negatives,
        }


@dataclass(frozen=True)
class EvaluationResult:
    cases: List[EvaluationCase]
    min_precision: float
    min_recall: float

    @property
    def true_positives(self) -> int:
        return sum(len(case.expected & case.actual) for case in self.cases)

    @property
    def false_positives(self) -> int:
        return sum(len(case.actual - case.expected) for case in self.cases)

    @property
    def false_negatives(self) -> int:
        return sum(len(case.expected - case.actual) for case in self.cases)

    @property
    def precision(self) -> float:
        predicted = self.true_positives + self.false_positives
        return self.true_positives / predicted if predicted else 1.0

    @property
    def recall(self) -> float:
        expected = self.true_positives + self.false_negatives
        return self.true_positives / expected if expected else 1.0

    @property
    def passed(self) -> bool:
        return self.precision >= self.min_precision and self.recall >= self.min_recall

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": MANIFEST_VERSION,
            "cases": [case.to_dict() for case in self.cases],
            "metrics": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
                "precision": self.precision,
                "recall": self.recall,
            },
            "gates": {
                "min_precision": self.min_precision,
                "min_recall": self.min_recall,
            },
            "passed": self.passed,
        }


def evaluate_manifest(
    manifest_path: Path,
    min_precision: Optional[float] = None,
    min_recall: Optional[float] = None,
) -> EvaluationResult:
    manifest_path = manifest_path.absolute()
    data = _load_manifest(manifest_path)
    manifest_root = manifest_path.parent.resolve()
    gates = data.get("gates")
    if not isinstance(gates, dict):
        raise EvaluationError("manifest gates must be an object")

    manifest_precision = _ratio(gates.get("min_precision"), "gates.min_precision")
    manifest_recall = _ratio(gates.get("min_recall"), "gates.min_recall")
    effective_precision = manifest_precision if min_precision is None else _ratio(min_precision, "min_precision")
    effective_recall = manifest_recall if min_recall is None else _ratio(min_recall, "min_recall")

    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise EvaluationError("manifest cases must be a non-empty array")
    if len(raw_cases) > MAX_CASES:
        raise EvaluationError(f"manifest cannot contain more than {MAX_CASES} cases")

    seen_ids: Set[str] = set()
    budget = EvaluationBudget()
    evaluated: List[EvaluationCase] = []
    for index, raw_case in enumerate(raw_cases):
        evaluated.append(
            _evaluate_case(
                manifest_root,
                raw_case,
                index,
                seen_ids,
                budget,
            )
        )

    return EvaluationResult(
        cases=evaluated,
        min_precision=effective_precision,
        min_recall=effective_recall,
    )


def render_evaluation(result: EvaluationResult, output_format: str = "text") -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"

    status = "pass" if result.passed else "fail"
    lines = [
        f"agent-hygiene corpus evaluation: {status}",
        (
            f"precision {result.precision:.3f} (gate {result.min_precision:.3f}), "
            f"recall {result.recall:.3f} (gate {result.min_recall:.3f})"
        ),
        (
            f"true-positive={result.true_positives}, "
            f"false-positive={result.false_positives}, "
            f"false-negative={result.false_negatives}, cases={len(result.cases)}"
        ),
    ]
    failed_cases = [case.to_dict() for case in result.cases if not case.to_dict()["passed"]]
    for case in failed_cases:
        lines.append(f"case {case['id']}:")
        for finding in case["false_positives"]:
            lines.append(
                f"  unexpected {finding['rule_id']} {finding['path']}:{finding['line']}"
            )
        for finding in case["false_negatives"]:
            lines.append(
                f"  missing {finding['rule_id']} {finding['path']}:{finding['line']}"
            )
    return "\n".join(lines) + "\n"


def _load_manifest(path: Path) -> Dict[str, object]:
    try:
        read_result = read_bounded_regular_file(path, MAX_MANIFEST_BYTES)
    except SafeFileError as exc:
        if exc.reason == "too_large":
            raise EvaluationError(
                f"manifest exceeds {MAX_MANIFEST_BYTES} bytes"
            ) from exc
        if exc.reason == "missing":
            raise EvaluationError(
                f"manifest does not exist: {path.name}"
            ) from exc
        if exc.reason in {"symlink", "not_regular", "changed"}:
            raise EvaluationError(
                "manifest must be a stable regular file"
            ) from exc
        raise EvaluationError(
            "manifest could not be read safely: "
            f"{exc.error_name or exc.reason}"
        ) from exc

    raw = read_result.data
    if read_result.truncated:
        raise EvaluationError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvaluationError("manifest is not valid UTF-8") from exc
    try:
        data = strict_json_loads(text)
    except JSONSafetyError as exc:
        raise EvaluationError(f"manifest {exc}") from exc

    if not isinstance(data, dict):
        raise EvaluationError("manifest root must be an object")
    if data.get("version") != MANIFEST_VERSION:
        raise EvaluationError(f"manifest version must be {MANIFEST_VERSION}")
    return data


def _evaluate_case(
    manifest_root: Path,
    raw_case: object,
    index: int,
    seen_ids: Set[str],
    budget: EvaluationBudget,
) -> EvaluationCase:
    if not isinstance(raw_case, dict):
        raise EvaluationError(f"cases[{index}] must be an object")
    case_id = raw_case.get("id")
    if not isinstance(case_id, str) or not CASE_ID_PATTERN.fullmatch(case_id):
        raise EvaluationError(
            f"cases[{index}].id must use 1-80 letters, numbers, dots, dashes, or underscores"
        )
    if case_id in seen_ids:
        raise EvaluationError(f"duplicate case id: {case_id}")
    seen_ids.add(case_id)

    raw_files = raw_case.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise EvaluationError(f"case {case_id} files must be a non-empty array")
    if len(raw_files) > MAX_FILES_PER_CASE:
        raise EvaluationError(
            f"case {case_id} cannot contain more than {MAX_FILES_PER_CASE} files"
        )

    copies: List[Tuple[bytes, PurePosixPath]] = []
    targets: Set[str] = set()
    for file_index, raw_file in enumerate(raw_files):
        if not isinstance(raw_file, dict):
            raise EvaluationError(f"case {case_id} files[{file_index}] must be an object")
        source, relative_source = _source_path(
            manifest_root,
            raw_file.get("source"),
            case_id,
        )
        try:
            read_result = read_bounded_regular_file(
                source,
                MAX_FILE_BYTES,
            )
        except SafeFileError as exc:
            if exc.reason == "too_large":
                raise EvaluationError(
                    f"case {case_id} source exceeds {MAX_FILE_BYTES} bytes: "
                    f"{relative_source.as_posix()}"
                ) from exc
            raise EvaluationError(
                f"case {case_id} source could not be read safely: "
                f"{exc.error_name or exc.reason}"
            ) from exc
        budget.consume(len(read_result.data))
        target = _target_path(raw_file.get("target"), case_id)
        if target.as_posix() in targets:
            raise EvaluationError(f"case {case_id} repeats target {target.as_posix()}")
        targets.add(target.as_posix())
        copies.append((read_result.data, target))

    expected = _expected_findings(raw_case.get("expected"), case_id, targets)
    with tempfile.TemporaryDirectory(prefix="agent-hygiene-corpus-") as tmp:
        root = Path(tmp)
        try:
            for content, target in copies:
                destination = root.joinpath(*target.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
        except OSError as exc:
            raise EvaluationError(
                f"case {case_id} could not stage fixtures: {exc.__class__.__name__}"
            ) from exc
        result = scan(root, Config(baseline=None, min_score=0, fail_on="none"))

    if not result.summary.complete:
        reasons = ", ".join(
            f"{issue.path}:{issue.reason}" for issue in result.summary.discovery_issues
        )
        raise EvaluationError(f"case {case_id} produced an incomplete scan: {reasons}")

    actual = {(finding.rule_id, finding.path, finding.line) for finding in result.findings}
    return EvaluationCase(case_id=case_id, expected=expected, actual=actual)


def _source_path(
    manifest_root: Path,
    raw: object,
    case_id: str,
) -> Tuple[Path, PurePosixPath]:
    relative = _relative_path(raw, f"case {case_id} source")
    candidate = manifest_root.joinpath(*relative.parts)
    if candidate.is_symlink():
        raise EvaluationError(
            f"case {case_id} source is not a regular file: {relative.as_posix()}"
        )
    try:
        parent = candidate.parent.resolve(strict=True)
        parent.relative_to(manifest_root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise EvaluationError(f"case {case_id} source escapes the corpus directory") from exc
    source = parent / candidate.name
    return source, relative


def _target_path(raw: object, case_id: str) -> PurePosixPath:
    return _relative_path(raw, f"case {case_id} target")


def _relative_path(raw: object, label: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw:
        raise EvaluationError(f"{label} must be a non-empty relative path")
    if "\\" in raw or "\0" in raw or "\n" in raw or "\r" in raw:
        raise EvaluationError(f"{label} contains an invalid character")
    path = PurePosixPath(raw)
    if (
        not path.parts
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise EvaluationError(f"{label} must stay within the corpus directory")
    return path


def _expected_findings(raw: object, case_id: str, targets: Set[str]) -> Set[FindingKey]:
    if not isinstance(raw, list):
        raise EvaluationError(f"case {case_id} expected must be an array")
    expected: Set[FindingKey] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise EvaluationError(f"case {case_id} expected[{index}] must be an object")
        rule_id = item.get("rule_id")
        path = item.get("path")
        line = item.get("line")
        if not isinstance(rule_id, str) or rule_id not in RULES:
            raise EvaluationError(f"case {case_id} expected[{index}] has an unknown rule")
        if not isinstance(path, str) or path not in targets:
            raise EvaluationError(f"case {case_id} expected[{index}] path is not a case target")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise EvaluationError(f"case {case_id} expected[{index}] line must be positive")
        key = (rule_id, path, line)
        if key in expected:
            raise EvaluationError(f"case {case_id} repeats expected finding {rule_id} {path}:{line}")
        expected.add(key)
    return expected


def _ratio(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvaluationError(f"{label} must be a number from 0 to 1")
    try:
        ratio = float(value)
    except (OverflowError, ValueError) as exc:
        raise EvaluationError(f"{label} must be a number from 0 to 1") from exc
    if not math.isfinite(ratio) or not 0.0 <= ratio <= 1.0:
        raise EvaluationError(f"{label} must be a number from 0 to 1")
    return ratio


def _finding_dict(item: FindingKey) -> Dict[str, object]:
    rule_id, path, line = item
    return {"rule_id": rule_id, "path": path, "line": line}
