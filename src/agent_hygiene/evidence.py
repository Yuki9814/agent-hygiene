"""Bounded, privacy-preserving evidence contracts for public canary reviews."""

import hashlib
import json
import math
import re
from pathlib import Path, PurePosixPath
from typing import Dict, List, Mapping, Sequence, Set, Tuple
from urllib.parse import urlsplit

from .redaction import redact_secrets
from .rules import RULES
from .safe_files import SafeFileError, read_bounded_regular_file
from .safe_json import (
    JSONSafetyError,
    read_bounded_json,
    read_bounded_json_with_size,
)


EVIDENCE_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_EVIDENCE_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_TOTAL_LAYER_BYTES = 64 * 1024 * 1024
MAX_DOCUMENTS_PER_LAYER = 1000
MAX_REPOSITORIES = 1000
MAX_FINDINGS_PER_OBSERVATION = 10000
MAX_REVIEWS = 2000
MAX_JUDGMENTS_PER_REVIEW = 10000
MAX_LIMITATIONS = 100
MAX_LINE_NUMBER = 2147483647
MAX_CASES = 1000
MAX_FILES_PER_CASE = 100
MAX_TOTAL_FILE_REFERENCES = 1000
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_TOTAL_FIXTURE_BYTES = 64 * 1024 * 1024

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
_RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,79}")
_REVISION = re.compile(r"[0-9a-fA-F]{40}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")
_REVIEW_MODES = {"findings-only", "full-surface"}
_VERDICTS = {"true-positive", "false-positive"}
_GITHUB_OWNER = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
)
_GITHUB_REPOSITORY = re.compile(r"[A-Za-z0-9._-]{1,100}")
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9:/])/(?!/)[^\s,;]*"
    r"|(?<![A-Za-z0-9])[A-Za-z]:[\\/]"
    r"|(?<![A-Za-z0-9])~[\\/]"
    r"|(?i:\bfile://)"
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?(?:key|token)|access[_-]?token|secret|token|"
    r"password|credential)\b\s*[:=]\s*['\"]?[^\s'\";,]{8,}"
)


class EvidenceError(ValueError):
    """Raised when evidence cannot be safely loaded or independently verified."""


def load_public_canary_manifest(path: Path) -> Dict[str, object]:
    """Read a bounded manifest using the same contract as evidence validation."""
    return _load_public_canary_manifest(Path(path))


def build_review_pack(manifest_path: Path) -> Dict[str, object]:
    """Build a deterministic blind review pack from an evaluation manifest.

    The returned pack deliberately omits original case identifiers, fixture
    source paths, expected findings, gate labels, and scanner output.
    """

    path = Path(manifest_path)
    data = _read_json(path, MAX_MANIFEST_BYTES, "review manifest")
    manifest = _expect_object(data, "review manifest")
    _exact_fields(manifest, {"version", "gates", "cases"}, "review manifest")
    if _integer(manifest["version"], "review manifest.version") != 1:
        raise EvidenceError("review manifest.version must be 1")

    gates = _expect_object(manifest["gates"], "review manifest.gates")
    _exact_fields(
        gates,
        {"min_precision", "min_recall"},
        "review manifest.gates",
    )
    _ratio(gates["min_precision"], "review manifest.gates.min_precision")
    _ratio(gates["min_recall"], "review manifest.gates.min_recall")

    cases = _expect_list(manifest["cases"], "review manifest.cases")
    if not cases:
        raise EvidenceError("review manifest.cases must not be empty")
    if len(cases) > MAX_CASES:
        raise EvidenceError(
            f"review manifest cannot contain more than {MAX_CASES} cases"
        )

    manifest_root = _resolved_parent(path)
    seen_case_ids: Set[str] = set()
    total_fixture_bytes = 0
    total_file_references = 0
    neutral_case_payloads: List[Tuple[str, str, List[Dict[str, str]]]] = []
    for case_index, raw_case in enumerate(cases):
        label = f"review manifest.cases[{case_index}]"
        case = _expect_object(raw_case, label)
        _exact_fields(case, {"id", "files", "expected"}, label)
        original_id = _identifier(case["id"], f"{label}.id")
        if original_id in seen_case_ids:
            raise EvidenceError(f"duplicate review manifest case id: {original_id}")
        seen_case_ids.add(original_id)

        files = _expect_list(case["files"], f"{label}.files")
        if not files:
            raise EvidenceError(f"{label}.files must not be empty")
        if len(files) > MAX_FILES_PER_CASE:
            raise EvidenceError(
                f"{label}.files cannot contain more than {MAX_FILES_PER_CASE} entries"
            )
        neutral_files: List[Dict[str, str]] = []
        seen_targets: Set[str] = set()
        for file_index, raw_file in enumerate(files):
            total_file_references += 1
            if total_file_references > MAX_TOTAL_FILE_REFERENCES:
                raise EvidenceError(
                    "review manifest exceeds the total fixture reference limit "
                    f"of {MAX_TOTAL_FILE_REFERENCES}"
                )
            file_label = f"{label}.files[{file_index}]"
            file_entry = _expect_object(raw_file, file_label)
            _exact_fields(file_entry, {"source", "target"}, file_label)
            source = _safe_source_path(
                manifest_root,
                _bounded_string(file_entry["source"], f"{file_label}.source", 1024),
                file_label,
            )
            target = _relative_path(
                file_entry["target"],
                f"{file_label}.target",
            )
            if target in seen_targets:
                raise EvidenceError(f"{label} contains duplicate target path: {target}")
            seen_targets.add(target)
            content, size = _read_fixture(source, file_label)
            total_fixture_bytes += size
            if total_fixture_bytes > MAX_TOTAL_FIXTURE_BYTES:
                raise EvidenceError(
                    "review manifest exceeds the total fixture byte limit "
                    f"of {MAX_TOTAL_FIXTURE_BYTES}"
                )
            neutral_files.append({"path": target, "content": content})

        neutral_files.sort(key=lambda item: item["path"])
        _validate_expected(
            case["expected"],
            f"{label}.expected",
            seen_targets,
        )
        canonical_case = json.dumps(
            neutral_files,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        neutral_case_payloads.append(
            (
                hashlib.sha256(canonical_case.encode("utf-8")).hexdigest(),
                canonical_case,
                neutral_files,
            )
        )

    neutral_case_payloads.sort(key=lambda item: (item[0], item[1]))
    neutral_cases = [
        {
            "case_id": f"C{case_index + 1:03d}",
            "files": files,
        }
        for case_index, (_, _, files) in enumerate(neutral_case_payloads)
    ]

    digest_input = json.dumps(
        neutral_cases,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": "review_pack",
        "corpus_sha256": hashlib.sha256(digest_input).hexdigest(),
        "cases": neutral_cases,
    }


def load_evidence_directory(directory: Path) -> Dict[str, object]:
    """Load a layered evidence directory and return a recomputed summary.

    Layout::

        public_canary_manifest.json
        observation/*.json
        review/*.json
        adjudication/*.json
    """

    root = _safe_directory(Path(directory), "evidence directory")
    _validate_root_layout(root)
    manifest_path = root / "public_canary_manifest.json"
    manifest = _load_public_canary_manifest(manifest_path)
    repositories = manifest["repositories"]
    repository_by_id = {
        repository["repository_id"]: repository for repository in repositories
    }

    observation_documents = _load_layer(root, "observation")
    observations = [
        _validate_observation(document, source)
        for source, document in observation_documents
    ]
    observation_by_repository: Dict[str, Dict[str, object]] = {}
    for observation in observations:
        repository_id = observation["repository_id"]
        repository = repository_by_id.get(repository_id)
        if repository is None:
            raise EvidenceError(
                f"observation references unknown repository: {repository_id}"
            )
        if repository_id in observation_by_repository:
            raise EvidenceError(
                f"multiple observations exist for repository: {repository_id}"
            )
        if observation["revision"].lower() != repository["revision"].lower():
            raise EvidenceError(
                f"observation revision does not match manifest for {repository_id}"
            )
        observation_by_repository[repository_id] = observation

    review_documents = _load_layer(root, "review")
    if len(review_documents) > MAX_REVIEWS:
        raise EvidenceError(f"review cannot contain more than {MAX_REVIEWS} documents")
    reviews = [
        _validate_review(document, source, observation_by_repository)
        for source, document in review_documents
    ]
    _ensure_unique(reviews, "review_id", "review")
    seen_reviewer_repository: Set[Tuple[str, str]] = set()
    for review in reviews:
        reviewer_repository = (review["reviewer_id"], review["repository_id"])
        if reviewer_repository in seen_reviewer_repository:
            raise EvidenceError(
                "a reviewer may record only one review per repository: "
                f"{review['reviewer_id']} / {review['repository_id']}"
            )
        seen_reviewer_repository.add(reviewer_repository)

    adjudication_documents = _load_layer(root, "adjudication")
    adjudications = [
        _validate_adjudication(
            document,
            source,
            observation_by_repository,
        )
        for source, document in adjudication_documents
    ]
    _ensure_unique(adjudications, "adjudication_id", "adjudication")

    return _summarize(
        manifest,
        observation_by_repository,
        reviews,
        adjudications,
    )


def render_evidence_json(summary: Mapping[str, object]) -> str:
    """Render an evidence summary as stable, machine-readable JSON."""

    _ensure_summary(summary)
    return json.dumps(
        summary,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def render_evidence_markdown(summary: Mapping[str, object]) -> str:
    """Render a concise evidence status report without repository source data."""

    _ensure_summary(summary)
    metrics = _expect_object(summary["metrics"], "summary.metrics")
    conflicts = _expect_object(summary["conflicts"], "summary.conflicts")
    lines = [
        "# Agent Hygiene Evidence",
        "",
        f"Status: **{summary['status']}**",
        "",
        f"- Consenting repositories: {summary['repository_count']}",
        f"- Recorded reviewers: {summary['reviewer_count']}",
        (
            "- Recorded independent reviewers: "
            f"{summary['independent_reviewer_count']}"
        ),
        (
            "- Complete observations: "
            f"{summary['complete_observation_count']}/{summary['repository_count']}"
        ),
        (
            "- Full-surface reviewed repositories: "
            f"{summary['full_surface_repository_count']}/"
            f"{summary['repository_count']}"
        ),
        (
            "- Unresolved conflicts: "
            f"{len(_expect_list(conflicts['unresolved'], 'summary.conflicts.unresolved'))}"
        ),
        "",
        "## Recomputed metrics",
        "",
        "| Scope | TP | FP | FN | Precision | Recall |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| Global | {metrics['true_positives']} | "
            f"{metrics['false_positives']} | {metrics['false_negatives']} | "
            f"{_display_ratio(metrics['precision'])} | "
            f"{_display_ratio(metrics['recall'])} |"
        ),
    ]
    per_rule = _expect_object(summary["per_rule"], "summary.per_rule")
    for rule_id in sorted(per_rule):
        rule_metrics = _expect_object(
            per_rule[rule_id],
            f"summary.per_rule.{rule_id}",
        )
        lines.append(
            f"| {rule_id} | {rule_metrics['true_positives']} | "
            f"{rule_metrics['false_positives']} | "
            f"{rule_metrics['false_negatives']} | "
            f"{_display_ratio(rule_metrics['precision'])} | "
            f"{_display_ratio(rule_metrics['recall'])} |"
        )

    limitations = _expect_list(summary["limitations"], "summary.limitations")
    lines.extend(["", "## Limitations", ""])
    if limitations:
        lines.extend(f"- {_escape_controls(item)}" for item in limitations)
    else:
        lines.append("- None recorded.")
    return "\n".join(lines) + "\n"


def _load_public_canary_manifest(path: Path) -> Dict[str, object]:
    data = _read_json(path, MAX_MANIFEST_BYTES, "public canary manifest")
    manifest = _expect_object(data, "public canary manifest")
    _exact_fields(
        manifest,
        {"schema_version", "kind", "limitations", "repositories"},
        "public canary manifest",
    )
    _schema_kind(manifest, "public_canary_manifest", "public canary manifest")

    limitations = _limitations(
        manifest["limitations"],
        "public canary manifest.limitations",
    )
    raw_repositories = _expect_list(
        manifest["repositories"],
        "public canary manifest.repositories",
    )
    if len(raw_repositories) > MAX_REPOSITORIES:
        raise EvidenceError(
            "public canary manifest cannot contain more than "
            f"{MAX_REPOSITORIES} repositories"
        )

    repositories: List[Dict[str, str]] = []
    seen_ids: Set[str] = set()
    seen_repository_identities: Set[str] = set()
    for index, raw_repository in enumerate(raw_repositories):
        label = f"public canary manifest.repositories[{index}]"
        repository = _expect_object(raw_repository, label)
        _exact_fields(
            repository,
            {
                "repository_id",
                "repository_url",
                "revision",
                "consent_url",
                "selection_reason",
            },
            label,
        )
        repository_id = _identifier(repository["repository_id"], f"{label}.repository_id")
        repository_url, repository_identity = _github_repository_url(
            repository["repository_url"],
            f"{label}.repository_url",
        )
        revision = _revision(repository["revision"], f"{label}.revision")
        consent_url = _https_url(
            repository["consent_url"],
            f"{label}.consent_url",
        )
        selection_reason = _safe_public_text(
            _bounded_string(
                repository["selection_reason"],
                f"{label}.selection_reason",
                1000,
            ),
            f"{label}.selection_reason",
        )
        if repository_id in seen_ids:
            raise EvidenceError(f"duplicate repository_id: {repository_id}")
        if repository_identity in seen_repository_identities:
            raise EvidenceError(
                "duplicate canonical repository identity: "
                f"{repository_identity}"
            )
        seen_ids.add(repository_id)
        seen_repository_identities.add(repository_identity)
        repositories.append(
            {
                "repository_id": repository_id,
                "repository_url": repository_url,
                "revision": revision,
                "consent_url": consent_url,
                "selection_reason": selection_reason,
            }
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": "public_canary_manifest",
        "limitations": limitations,
        "repositories": repositories,
    }


def _validate_observation(
    raw_document: object,
    source: Path,
) -> Dict[str, object]:
    label = f"observation {_escape_controls(source.name)}"
    document = _expect_object(raw_document, label)
    _exact_fields(
        document,
        {
            "schema_version",
            "kind",
            "repository_id",
            "revision",
            "complete",
            "result_sha256",
            "findings",
        },
        label,
    )
    _schema_kind(document, "observation", label)
    repository_id = _identifier(
        document["repository_id"],
        f"{label}.repository_id",
    )
    revision = _revision(document["revision"], f"{label}.revision")
    complete = _boolean(document["complete"], f"{label}.complete")
    result_sha256 = _sha256(
        document["result_sha256"],
        f"{label}.result_sha256",
    )
    raw_findings = _expect_list(document["findings"], f"{label}.findings")
    if len(raw_findings) > MAX_FINDINGS_PER_OBSERVATION:
        raise EvidenceError(
            f"{label}.findings cannot contain more than "
            f"{MAX_FINDINGS_PER_OBSERVATION} entries"
        )

    findings: List[Dict[str, object]] = []
    seen_finding_ids: Set[str] = set()
    seen_locations: Set[Tuple[str, str, int]] = set()
    for index, raw_finding in enumerate(raw_findings):
        finding_label = f"{label}.findings[{index}]"
        finding = _expect_object(raw_finding, finding_label)
        _exact_fields(
            finding,
            {"finding_id", "rule_id", "path", "line"},
            finding_label,
        )
        finding_id = _identifier(
            finding["finding_id"],
            f"{finding_label}.finding_id",
        )
        rule_id = _rule_id(finding["rule_id"], f"{finding_label}.rule_id")
        path = _relative_path(finding["path"], f"{finding_label}.path")
        line = _positive_integer(finding["line"], f"{finding_label}.line")
        location = (rule_id, path, line)
        if finding_id in seen_finding_ids:
            raise EvidenceError(f"{label} contains duplicate finding_id: {finding_id}")
        if location in seen_locations:
            raise EvidenceError(
                f"{label} contains duplicate finding location: "
                f"{rule_id} {path}:{line}"
            )
        seen_finding_ids.add(finding_id)
        seen_locations.add(location)
        findings.append(
            {
                "finding_id": finding_id,
                "rule_id": rule_id,
                "path": path,
                "line": line,
            }
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": "observation",
        "repository_id": repository_id,
        "revision": revision,
        "complete": complete,
        "result_sha256": result_sha256,
        "findings": findings,
    }


def _validate_review(
    raw_document: object,
    source: Path,
    observations: Mapping[str, Dict[str, object]],
) -> Dict[str, object]:
    label = f"review {_escape_controls(source.name)}"
    document = _expect_object(raw_document, label)
    allowed = {
        "schema_version",
        "kind",
        "review_id",
        "repository_id",
        "reviewer_id",
        "independent",
        "mode",
        "observation_sha256",
        "judgments",
        "false_negatives",
    }
    required = allowed - {"false_negatives"}
    _fields(document, required, allowed, label)
    _schema_kind(document, "review", label)
    review_id = _identifier(document["review_id"], f"{label}.review_id")
    repository_id = _identifier(
        document["repository_id"],
        f"{label}.repository_id",
    )
    reviewer_id = _identifier(document["reviewer_id"], f"{label}.reviewer_id")
    independent = _boolean(document["independent"], f"{label}.independent")
    mode = _bounded_string(document["mode"], f"{label}.mode", 32)
    if mode not in _REVIEW_MODES:
        raise EvidenceError(
            f"{label}.mode must be findings-only or full-surface"
        )
    observation_sha256 = _sha256(
        document["observation_sha256"],
        f"{label}.observation_sha256",
    )
    observation = observations.get(repository_id)
    if observation is None:
        raise EvidenceError(
            f"{label} references a repository without an observation: "
            f"{repository_id}"
        )
    if observation_sha256 != observation["result_sha256"]:
        raise EvidenceError(
            f"{label}.observation_sha256 does not match {repository_id}"
        )

    finding_by_id = {
        finding["finding_id"]: finding
        for finding in observation["findings"]
    }
    raw_judgments = _expect_list(document["judgments"], f"{label}.judgments")
    if len(raw_judgments) > MAX_JUDGMENTS_PER_REVIEW:
        raise EvidenceError(
            f"{label}.judgments cannot contain more than "
            f"{MAX_JUDGMENTS_PER_REVIEW} entries"
        )
    judgments: List[Dict[str, str]] = []
    seen_judgments: Set[str] = set()
    for index, raw_judgment in enumerate(raw_judgments):
        judgment_label = f"{label}.judgments[{index}]"
        judgment = _expect_object(raw_judgment, judgment_label)
        _exact_fields(judgment, {"finding_id", "verdict"}, judgment_label)
        finding_id = _identifier(
            judgment["finding_id"],
            f"{judgment_label}.finding_id",
        )
        verdict = _bounded_string(
            judgment["verdict"],
            f"{judgment_label}.verdict",
            32,
        )
        if verdict not in _VERDICTS:
            raise EvidenceError(
                f"{judgment_label}.verdict must be true-positive or false-positive"
            )
        if finding_id not in finding_by_id:
            raise EvidenceError(
                f"{judgment_label} references unknown finding_id: {finding_id}"
            )
        if finding_id in seen_judgments:
            raise EvidenceError(
                f"{label} contains duplicate judgment for: {finding_id}"
            )
        seen_judgments.add(finding_id)
        judgments.append({"finding_id": finding_id, "verdict": verdict})
    if seen_judgments != set(finding_by_id):
        missing = sorted(set(finding_by_id) - seen_judgments)
        raise EvidenceError(
            f"{label} must judge every observed finding; missing: "
            + ", ".join(missing)
        )

    false_negatives: List[Dict[str, object]] = []
    if "false_negatives" in document:
        raw_false_negatives = _expect_list(
            document["false_negatives"],
            f"{label}.false_negatives",
        )
        if len(raw_false_negatives) > MAX_JUDGMENTS_PER_REVIEW:
            raise EvidenceError(
                f"{label}.false_negatives cannot contain more than "
                f"{MAX_JUDGMENTS_PER_REVIEW} entries"
            )
        seen_false_negatives: Set[Tuple[str, str, int]] = set()
        observed_locations = {
            (finding["rule_id"], finding["path"], finding["line"])
            for finding in observation["findings"]
        }
        for index, raw_false_negative in enumerate(raw_false_negatives):
            item_label = f"{label}.false_negatives[{index}]"
            item = _expect_object(raw_false_negative, item_label)
            _exact_fields(item, {"rule_id", "path", "line"}, item_label)
            rule_id = _rule_id(item["rule_id"], f"{item_label}.rule_id")
            path = _relative_path(item["path"], f"{item_label}.path")
            line = _positive_integer(item["line"], f"{item_label}.line")
            location = (rule_id, path, line)
            if location in observed_locations:
                raise EvidenceError(
                    f"{item_label} duplicates an observed finding"
                )
            if location in seen_false_negatives:
                raise EvidenceError(
                    f"{label} contains duplicate false negative: "
                    f"{rule_id} {path}:{line}"
                )
            seen_false_negatives.add(location)
            false_negatives.append(
                {"rule_id": rule_id, "path": path, "line": line}
            )
    if mode == "full-surface" and "false_negatives" not in document:
        raise EvidenceError(
            f"{label}.false_negatives is required for full-surface reviews"
        )
    if mode == "findings-only" and false_negatives:
        raise EvidenceError(
            f"{label}.false_negatives must be empty for findings-only reviews"
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": "review",
        "review_id": review_id,
        "repository_id": repository_id,
        "reviewer_id": reviewer_id,
        "independent": independent,
        "mode": mode,
        "observation_sha256": observation_sha256,
        "judgments": judgments,
        "false_negatives": false_negatives,
    }


def _validate_adjudication(
    raw_document: object,
    source: Path,
    observations: Mapping[str, Dict[str, object]],
) -> Dict[str, object]:
    label = f"adjudication {_escape_controls(source.name)}"
    document = _expect_object(raw_document, label)
    _exact_fields(
        document,
        {
            "schema_version",
            "kind",
            "adjudication_id",
            "repository_id",
            "finding_id",
            "adjudicator_id",
            "verdict",
        },
        label,
    )
    _schema_kind(document, "adjudication", label)
    adjudication_id = _identifier(
        document["adjudication_id"],
        f"{label}.adjudication_id",
    )
    repository_id = _identifier(
        document["repository_id"],
        f"{label}.repository_id",
    )
    finding_id = _identifier(document["finding_id"], f"{label}.finding_id")
    adjudicator_id = _identifier(
        document["adjudicator_id"],
        f"{label}.adjudicator_id",
    )
    verdict = _bounded_string(document["verdict"], f"{label}.verdict", 32)
    if verdict not in _VERDICTS:
        raise EvidenceError(
            f"{label}.verdict must be true-positive or false-positive"
        )
    observation = observations.get(repository_id)
    if observation is None:
        raise EvidenceError(
            f"{label} references a repository without an observation: "
            f"{repository_id}"
        )
    finding_ids = {
        finding["finding_id"] for finding in observation["findings"]
    }
    if finding_id not in finding_ids:
        raise EvidenceError(
            f"{label} references unknown finding_id: {finding_id}"
        )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": "adjudication",
        "adjudication_id": adjudication_id,
        "repository_id": repository_id,
        "finding_id": finding_id,
        "adjudicator_id": adjudicator_id,
        "verdict": verdict,
    }


def _summarize(
    manifest: Dict[str, object],
    observations: Mapping[str, Dict[str, object]],
    reviews: Sequence[Dict[str, object]],
    adjudications: Sequence[Dict[str, object]],
) -> Dict[str, object]:
    repository_ids = {
        repository["repository_id"] for repository in manifest["repositories"]
    }
    reviewer_ids: Set[str] = set()
    independent_reviewer_ids: Set[str] = set()
    independent_full_surface_reviewers: Set[str] = set()
    for review in reviews:
        reviewer_ids.add(review["reviewer_id"])
        if review["independent"]:
            independent_reviewer_ids.add(review["reviewer_id"])
            if review["mode"] == "full-surface":
                independent_full_surface_reviewers.add(review["reviewer_id"])

    judgments: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
    for review in reviews:
        for judgment in review["judgments"]:
            subject = (review["repository_id"], judgment["finding_id"])
            judgments.setdefault(subject, []).append(
                (review["reviewer_id"], judgment["verdict"])
            )

    adjudication_by_subject: Dict[Tuple[str, str], Dict[str, object]] = {}
    for adjudication in adjudications:
        subject = (
            adjudication["repository_id"],
            adjudication["finding_id"],
        )
        if subject in adjudication_by_subject:
            raise EvidenceError(
                "multiple adjudications exist for "
                f"{subject[0]} / {subject[1]}"
            )
        adjudication_by_subject[subject] = adjudication

    unresolved_conflicts: List[Dict[str, object]] = []
    resolved_conflict_count = 0
    resolved_verdicts: Dict[Tuple[str, str], str] = {}
    for subject, records in sorted(judgments.items()):
        verdicts = {verdict for _, verdict in records}
        adjudication = adjudication_by_subject.get(subject)
        if len(verdicts) == 1:
            if adjudication is not None:
                raise EvidenceError(
                    "adjudication is only allowed for a conflicting finding: "
                    f"{subject[0]} / {subject[1]}"
                )
            resolved_verdicts[subject] = next(iter(verdicts))
        elif adjudication is None:
            unresolved_conflicts.append(
                {
                    "repository_id": subject[0],
                    "finding_id": subject[1],
                    "reviewer_count": len({reviewer for reviewer, _ in records}),
                }
            )
        else:
            resolved_verdicts[subject] = adjudication["verdict"]
            resolved_conflict_count += 1

    unused_adjudications = set(adjudication_by_subject) - set(judgments)
    if unused_adjudications:
        subject = sorted(unused_adjudications)[0]
        raise EvidenceError(
            "adjudication references an unreviewed finding: "
            f"{subject[0]} / {subject[1]}"
        )

    finding_by_subject: Dict[Tuple[str, str], Dict[str, object]] = {}
    for repository_id, observation in observations.items():
        for finding in observation["findings"]:
            finding_by_subject[(repository_id, finding["finding_id"])] = finding

    per_rule_counts: Dict[str, Dict[str, int]] = {}
    for subject, verdict in resolved_verdicts.items():
        finding = finding_by_subject[subject]
        counts = _rule_counts(per_rule_counts, finding["rule_id"])
        if verdict == "true-positive":
            counts["true_positives"] += 1
        else:
            counts["false_positives"] += 1

    false_negative_locations: Set[Tuple[str, str, str, int]] = set()
    for review in reviews:
        if review["mode"] != "full-surface":
            continue
        for finding in review["false_negatives"]:
            false_negative_locations.add(
                (
                    review["repository_id"],
                    finding["rule_id"],
                    finding["path"],
                    finding["line"],
                )
            )
    for _, rule_id, _, _ in false_negative_locations:
        _rule_counts(per_rule_counts, rule_id)["false_negatives"] += 1

    complete_observation_ids = {
        repository_id
        for repository_id, observation in observations.items()
        if observation["complete"]
    }
    full_surface_repository_ids = {
        review["repository_id"]
        for review in reviews
        if review["mode"] == "full-surface"
    }
    independent_full_surface_repository_ids = {
        review["repository_id"]
        for review in reviews
        if review["mode"] == "full-surface" and review["independent"]
    }
    full_surface_coverage = (
        bool(repository_ids)
        and complete_observation_ids == repository_ids
        and full_surface_repository_ids == repository_ids
    )

    global_counts = {
        "true_positives": sum(
            counts["true_positives"] for counts in per_rule_counts.values()
        ),
        "false_positives": sum(
            counts["false_positives"] for counts in per_rule_counts.values()
        ),
        "false_negatives": sum(
            counts["false_negatives"] for counts in per_rule_counts.values()
        ),
    }
    metrics = _metrics(global_counts, full_surface_coverage)
    per_rule = {
        rule_id: _metrics(counts, full_surface_coverage)
        for rule_id, counts in sorted(per_rule_counts.items())
    }

    independently_validated = (
        len(repository_ids) >= 10
        and complete_observation_ids == repository_ids
        and full_surface_repository_ids == repository_ids
        and independent_full_surface_repository_ids == repository_ids
        and len(independent_full_surface_reviewers) >= 2
        and not unresolved_conflicts
        and metrics["precision"] is not None
        and metrics["recall"] is not None
    )
    status = (
        "independently validated"
        if independently_validated
        else "not independently validated"
    )
    return {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "kind": "evidence_summary",
        "repository_count": len(repository_ids),
        "reviewer_count": len(reviewer_ids),
        "independent_reviewer_count": len(independent_reviewer_ids),
        "complete_observation_count": len(complete_observation_ids),
        "full_surface_repository_count": len(full_surface_repository_ids),
        "metrics": metrics,
        "per_rule": per_rule,
        "conflicts": {
            "resolved": resolved_conflict_count,
            "unresolved": unresolved_conflicts,
        },
        "limitations": list(manifest["limitations"]),
        "independently_validated": independently_validated,
        "status": status,
    }


def _metrics(
    counts: Mapping[str, int],
    recall_measured: bool,
) -> Dict[str, object]:
    true_positives = counts["true_positives"]
    false_positives = counts["false_positives"]
    false_negatives = counts["false_negatives"]
    precision_denominator = true_positives + false_positives
    recall_denominator = true_positives + false_negatives
    precision = (
        true_positives / precision_denominator
        if precision_denominator
        else None
    )
    recall = (
        true_positives / recall_denominator
        if recall_measured and recall_denominator
        else None
    )
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
    }


def _rule_counts(
    per_rule: Dict[str, Dict[str, int]],
    rule_id: str,
) -> Dict[str, int]:
    return per_rule.setdefault(
        rule_id,
        {
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
        },
    )


def _load_layer(root: Path, layer: str) -> List[Tuple[Path, object]]:
    path = root / layer
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_dir():
        raise EvidenceError(f"{layer} must be a regular directory")
    json_files: List[Path] = []
    for child in path.iterdir():
        if child.name.startswith("."):
            raise EvidenceError(f"{layer} must not contain hidden files")
        if child.is_symlink():
            raise EvidenceError(
                f"{layer}/{_escape_controls(child.name)} "
                "must not be a symbolic link"
            )
        if child.suffix != ".json":
            raise EvidenceError(f"{layer} may contain only regular .json files")
        json_files.append(child)
        if len(json_files) > MAX_DOCUMENTS_PER_LAYER:
            raise EvidenceError(
                f"{layer} cannot contain more than "
                f"{MAX_DOCUMENTS_PER_LAYER} documents"
            )
    documents: List[Tuple[Path, object]] = []
    total_bytes = 0
    for child in sorted(json_files, key=lambda item: item.name):
        document, document_bytes = _read_json_with_size(
            child,
            MAX_EVIDENCE_DOCUMENT_BYTES,
            f"{layer} document",
        )
        total_bytes += document_bytes
        if total_bytes > MAX_TOTAL_LAYER_BYTES:
            raise EvidenceError(
                f"{layer} exceeds the {MAX_TOTAL_LAYER_BYTES}-byte layer limit"
            )
        documents.append((child, document))
    return documents


def _validate_root_layout(root: Path) -> None:
    allowed = {
        "public_canary_manifest.json",
        "observation",
        "review",
        "adjudication",
    }
    for child in root.iterdir():
        if child.name not in allowed:
            raise EvidenceError(
                "evidence directory contains an unexpected entry: "
                f"{_escape_controls(child.name)}"
            )
        if child.name == "public_canary_manifest.json":
            if child.is_symlink() or not child.is_file():
                raise EvidenceError(
                    "public_canary_manifest.json must be a regular file"
                )
        elif child.is_symlink() or not child.is_dir():
            raise EvidenceError(f"{child.name} must be a regular directory")


def _read_json(path: Path, max_bytes: int, label: str) -> object:
    try:
        return read_bounded_json(path, max_bytes)
    except JSONSafetyError as exc:
        raise EvidenceError(f"{label} {exc}") from exc


def _read_json_with_size(
    path: Path,
    max_bytes: int,
    label: str,
) -> Tuple[object, int]:
    try:
        return read_bounded_json_with_size(path, max_bytes)
    except JSONSafetyError as exc:
        raise EvidenceError(f"{label} {exc}") from exc


def _safe_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise EvidenceError(f"{label} must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EvidenceError(f"{label} could not be resolved safely") from exc
    if not resolved.is_dir():
        raise EvidenceError(f"{label} must be a directory")
    return resolved


def _resolved_parent(path: Path) -> Path:
    if path.is_symlink():
        raise EvidenceError("review manifest must not be a symbolic link")
    try:
        return path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EvidenceError("review manifest could not be resolved safely") from exc


def _safe_source_path(root: Path, raw_path: str, label: str) -> Path:
    relative = _relative_path(raw_path, f"{label}.source")
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    if candidate.is_symlink():
        raise EvidenceError(f"{label}.source must not be a symbolic link")
    try:
        parent = candidate.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise EvidenceError(
            f"{label}.source must stay within the review manifest directory"
        ) from exc
    return parent / candidate.name


def _read_fixture(path: Path, label: str) -> Tuple[str, int]:
    try:
        read_result = read_bounded_regular_file(path, MAX_FIXTURE_BYTES)
    except SafeFileError as exc:
        if exc.reason == "too_large":
            raise EvidenceError(
                f"{label}.source exceeds the {MAX_FIXTURE_BYTES}-byte limit"
            ) from exc
        if exc.reason in {"symlink", "not_regular", "changed"}:
            raise EvidenceError(
                f"{label}.source must be a stable regular file"
            ) from exc
        raise EvidenceError(
            f"{label}.source could not be read safely"
        ) from exc
    raw = read_result.data
    try:
        return raw.decode("utf-8"), len(raw)
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{label}.source must be valid UTF-8") from exc


def _validate_expected(
    raw: object,
    label: str,
    targets: Set[str],
) -> None:
    expected = _expect_list(raw, label)
    if len(expected) > MAX_JUDGMENTS_PER_REVIEW:
        raise EvidenceError(
            f"{label} cannot contain more than {MAX_JUDGMENTS_PER_REVIEW} entries"
        )
    seen: Set[Tuple[str, str, int]] = set()
    for index, raw_finding in enumerate(expected):
        finding_label = f"{label}[{index}]"
        finding = _expect_object(raw_finding, finding_label)
        _exact_fields(finding, {"rule_id", "path", "line"}, finding_label)
        rule_id = _rule_id(finding["rule_id"], f"{finding_label}.rule_id")
        if rule_id not in RULES:
            raise EvidenceError(f"{finding_label}.rule_id is an unknown rule")
        path = _relative_path(finding["path"], f"{finding_label}.path")
        if path not in targets:
            raise EvidenceError(f"{finding_label}.path is not a case target")
        line = _positive_integer(finding["line"], f"{finding_label}.line")
        key = (rule_id, path, line)
        if key in seen:
            raise EvidenceError(
                f"{label} repeats expected finding {rule_id} {path}:{line}"
            )
        seen.add(key)


def _ensure_unique(
    documents: Sequence[Mapping[str, object]],
    field: str,
    label: str,
) -> None:
    seen: Set[object] = set()
    for document in documents:
        value = document[field]
        if value in seen:
            raise EvidenceError(f"duplicate {label} {field}: {value}")
        seen.add(value)


def _ensure_summary(summary: Mapping[str, object]) -> None:
    required = {
        "schema_version",
        "kind",
        "repository_count",
        "reviewer_count",
        "independent_reviewer_count",
        "complete_observation_count",
        "full_surface_repository_count",
        "metrics",
        "per_rule",
        "conflicts",
        "limitations",
        "independently_validated",
        "status",
    }
    if not isinstance(summary, Mapping):
        raise EvidenceError("summary must be an object")
    missing = required - set(summary)
    extra = set(summary) - required
    if missing:
        raise EvidenceError(
            "summary is missing required fields: " + ", ".join(sorted(missing))
        )
    if extra:
        raise EvidenceError(
            "summary contains unexpected fields: " + ", ".join(sorted(extra))
        )
    if summary["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError(
            f"summary.schema_version must be {EVIDENCE_SCHEMA_VERSION}"
        )
    if summary["kind"] != "evidence_summary":
        raise EvidenceError("summary.kind must be evidence_summary")
    _limitations(summary["limitations"], "summary.limitations")
    independently_validated = _boolean(
        summary["independently_validated"],
        "summary.independently_validated",
    )
    expected_status = (
        "independently validated"
        if independently_validated
        else "not independently validated"
    )
    if summary["status"] != expected_status:
        raise EvidenceError(f"summary.status must be {expected_status}")
    metrics = _expect_object(summary["metrics"], "summary.metrics")
    if independently_validated and (
        metrics.get("precision") is None or metrics.get("recall") is None
    ):
        raise EvidenceError(
            "independently validated summaries require precision and recall"
        )


def _schema_kind(
    document: Mapping[str, object],
    kind: str,
    label: str,
) -> None:
    version = _integer(document["schema_version"], f"{label}.schema_version")
    if version != EVIDENCE_SCHEMA_VERSION:
        raise EvidenceError(
            f"{label}.schema_version must be {EVIDENCE_SCHEMA_VERSION}"
        )
    if document["kind"] != kind:
        raise EvidenceError(f"{label}.kind must be {kind}")


def _expect_object(value: object, label: str) -> Dict[str, object]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must be an object")
    return value


def _expect_list(value: object, label: str) -> List[object]:
    if not isinstance(value, list):
        raise EvidenceError(f"{label} must be an array")
    return value


def _exact_fields(
    document: Mapping[str, object],
    expected: Set[str],
    label: str,
) -> None:
    _fields(document, expected, expected, label)


def _fields(
    document: Mapping[str, object],
    required: Set[str],
    allowed: Set[str],
    label: str,
) -> None:
    keys = set(document)
    missing = required - keys
    extra = keys - allowed
    if missing:
        raise EvidenceError(
            f"{label} is missing required fields: " + ", ".join(sorted(missing))
        )
    if extra:
        raise EvidenceError(
            f"{label} contains unexpected fields: " + ", ".join(sorted(extra))
        )


def _identifier(value: object, label: str) -> str:
    text = _bounded_string(value, label, 80)
    if not _IDENTIFIER.fullmatch(text):
        raise EvidenceError(
            f"{label} must use 1-80 letters, numbers, dots, dashes, or underscores"
        )
    return text


def _rule_id(value: object, label: str) -> str:
    text = _bounded_string(value, label, 80)
    if not _RULE_ID.fullmatch(text):
        raise EvidenceError(f"{label} is not a valid rule identifier")
    return text


def _revision(value: object, label: str) -> str:
    text = _bounded_string(value, label, 40)
    if not _REVISION.fullmatch(text):
        raise EvidenceError(f"{label} must be a 40-character hexadecimal revision")
    return text.lower()


def _sha256(value: object, label: str) -> str:
    text = _bounded_string(value, label, 64)
    if not _SHA256.fullmatch(text):
        raise EvidenceError(f"{label} must be a 64-character SHA-256 digest")
    return text.lower()


def _limitations(value: object, label: str) -> List[str]:
    items = _string_list(value, label, MAX_LIMITATIONS, 1000)
    if not items:
        raise EvidenceError(f"{label} must contain at least one entry")
    for index, item in enumerate(items):
        _safe_public_text(item, f"{label}[{index}]")
    return items


def _safe_public_text(value: str, label: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise EvidenceError(f"{label} must not contain control characters")
    if _ABSOLUTE_PATH.search(value):
        raise EvidenceError(f"{label} must not contain an absolute path")
    if redact_secrets(value) != value or _CREDENTIAL_ASSIGNMENT.search(value):
        raise EvidenceError(f"{label} must not contain credential-like text")
    return value


def _https_url(value: object, label: str) -> str:
    text = _bounded_string(value, label, 2048)
    try:
        parsed = urlsplit(text)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise EvidenceError(
            f"{label} must be a public https URL without credentials"
        ) from exc
    if (
        parsed.scheme != "https"
        or not text.startswith("https://")
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() or ord(character) == 127 for character in text)
    ):
        raise EvidenceError(f"{label} must be a public https URL without credentials")
    return text


def _github_repository_url(value: object, label: str) -> Tuple[str, str]:
    text = _https_url(value, label)
    parsed = urlsplit(text)
    if parsed.hostname.lower() != "github.com" or parsed.path.endswith("//"):
        raise EvidenceError(f"{label} must use https://github.com/owner/repository")

    normalized_path = parsed.path.rstrip("/")
    parts = normalized_path.split("/")
    if (
        len(parts) != 3
        or parts[0]
        or not _GITHUB_OWNER.fullmatch(parts[1])
        or not _GITHUB_REPOSITORY.fullmatch(parts[2])
        or parts[2] in {".", ".."}
        or parts[2].lower().endswith(".git")
    ):
        raise EvidenceError(f"{label} must use https://github.com/owner/repository")

    owner, repository = parts[1], parts[2]
    canonical_url = f"https://github.com/{owner}/{repository}"
    identity = f"github.com/{owner.lower()}/{repository.lower()}"
    return canonical_url, identity


def _relative_path(value: object, label: str) -> str:
    text = _bounded_string(value, label, 1024)
    if (
        "\\" in text
        or re.match(r"^[A-Za-z]:/", text)
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise EvidenceError(f"{label} must be a safe POSIX relative path")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or text in {"", "."}
        or path.as_posix() != text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise EvidenceError(f"{label} must be a safe POSIX relative path")
    return path.as_posix()


def _bounded_string(value: object, label: str, max_length: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise EvidenceError(
            f"{label} must be a non-empty string of at most {max_length} characters"
        )
    return value


def _string_list(
    value: object,
    label: str,
    max_items: int,
    max_length: int,
) -> List[str]:
    items = _expect_list(value, label)
    if len(items) > max_items:
        raise EvidenceError(f"{label} cannot contain more than {max_items} entries")
    return [
        _bounded_string(item, f"{label}[{index}]", max_length)
        for index, item in enumerate(items)
    ]


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvidenceError(f"{label} must be an integer")
    return value


def _positive_integer(value: object, label: str) -> int:
    number = _integer(value, label)
    if number < 1 or number > MAX_LINE_NUMBER:
        raise EvidenceError(
            f"{label} must be an integer from 1 to {MAX_LINE_NUMBER}"
        )
    return number


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{label} must be a boolean")
    return value


def _ratio(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"{label} must be a number from 0 to 1")
    try:
        ratio = float(value)
    except (OverflowError, ValueError) as exc:
        raise EvidenceError(f"{label} must be a number from 0 to 1") from exc
    if not math.isfinite(ratio) or ratio < 0 or ratio > 1:
        raise EvidenceError(f"{label} must be a number from 0 to 1")
    return ratio


def _display_ratio(value: object) -> str:
    if value is None:
        return "not measured"
    return f"{float(value):.3f}"


def _escape_controls(value: str) -> str:
    return "".join(
        character
        if ord(character) >= 32 and ord(character) != 127
        else f"\\u{ord(character):04x}"
        for character in value
    )
