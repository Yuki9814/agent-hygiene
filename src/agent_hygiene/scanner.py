from fnmatch import fnmatch
from pathlib import Path
import re
from typing import Dict, List, Set

from .baseline import BaselineError, load_baseline
from .config import Config
from .discovery import discover
from .models import (
    SEVERITY_PENALTY,
    DiscoveryIssue,
    Document,
    Finding,
    ScanResult,
    ScanSummary,
    count_by_severity,
)
from .rules import repository_rules, scan_document
from .scope import repository_scope_fingerprint


def scan(root: Path, config: Config, use_baseline: bool = True) -> ScanResult:
    root = root.resolve()
    discovery = discover(root, config.exclude)
    discovery_issues = list(discovery.issues)
    docs = discovery.documents
    docs_by_path = {doc.relative_path: doc for doc in docs}
    findings: List[Finding] = []

    for doc in docs:
        findings.extend(scan_document(doc, root))
    findings.extend(repository_rules(docs))
    baseline_fingerprints: Set[str] = set()
    if use_baseline and config.baseline:
        try:
            baseline_fingerprints = load_baseline(root, config.baseline)
        except BaselineError as exc:
            discovery_issues.append(
                DiscoveryIssue(
                    path=".agent-hygiene-baseline.json",
                    reason="invalid_baseline",
                    message=str(exc),
                )
            )
    findings = _filter_findings(
        findings,
        docs_by_path,
        config,
        baseline_fingerprints,
    )

    findings.sort(key=lambda item: (-_severity_rank(item.severity), item.path, item.line, item.rule_id))
    score = _score(findings)
    summary = ScanSummary(
        root=str(root),
        scanned_files=len(docs),
        instruction_files=sum(1 for doc in docs if doc.kind == "instructions"),
        mcp_configs=sum(1 for doc in docs if doc.kind == "mcp"),
        workflows=sum(1 for doc in docs if doc.kind == "workflow"),
        score=score,
        status=_status(score) if not discovery_issues else "incomplete",
        scope_fingerprint=repository_scope_fingerprint(root),
        counts=count_by_severity(findings),
        complete=not discovery_issues,
        discovery_issues=discovery_issues,
    )
    return ScanResult(summary=summary, findings=findings)


def _score(findings: List[Finding]) -> int:
    penalty = sum(SEVERITY_PENALTY.get(finding.severity, 0) for finding in findings)
    return max(0, 100 - penalty)


def _status(score: int) -> str:
    if score >= 90:
        return "ready"
    if score >= 75:
        return "watch"
    if score >= 50:
        return "risky"
    return "unsafe"


def _severity_rank(severity: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)


def _filter_findings(
    findings: List[Finding],
    docs_by_path: Dict[str, Document],
    config: Config,
    baseline_fingerprints: Set[str],
) -> List[Finding]:
    ignored_rules = {rule.upper() for rule in config.ignore_rules}

    kept: List[Finding] = []
    for finding in findings:
        if finding.rule_id in ignored_rules:
            continue
        if _matches_ignored_path(finding, config.ignore):
            continue
        if finding.fingerprint() in baseline_fingerprints:
            continue
        doc = docs_by_path.get(finding.path)
        if doc and _line_has_ignore_directive(doc, finding):
            continue
        kept.append(finding)
    return kept


def _matches_ignored_path(finding: Finding, patterns: List[str]) -> bool:
    location = f"{finding.path}:{finding.line}"
    ruled_location = f"{finding.rule_id}:{finding.path}:{finding.line}"
    for pattern in patterns:
        if fnmatch(finding.path, pattern) or fnmatch(location, pattern) or fnmatch(ruled_location, pattern):
            return True
    return False


def _line_has_ignore_directive(doc: Document, finding: Finding) -> bool:
    lines = doc.text.splitlines()
    index = finding.line - 1
    if 0 <= index < len(lines) and _directive_allows(lines[index], finding.rule_id, next_line=False):
        return True
    previous_index = index - 1
    if 0 <= previous_index < len(lines) and _directive_allows(lines[previous_index], finding.rule_id, next_line=True):
        return True
    return False


def _directive_allows(line: str, rule_id: str, next_line: bool) -> bool:
    lowered = line.lower()
    if not next_line and (
        "agent-hygiene-ignore-next-line" in lowered or "agent-hygiene: ignore-next-line" in lowered
    ):
        return False
    marker = "agent-hygiene-ignore-next-line" if next_line else "agent-hygiene-ignore"
    alternate = "agent-hygiene: ignore-next-line" if next_line else "agent-hygiene: ignore"
    if marker not in lowered and alternate not in lowered:
        return False
    allowed = {token.upper() for token in re.findall(r"AH\d{3}|ALL", line, flags=re.IGNORECASE)}
    return not allowed or "ALL" in allowed or rule_id in allowed
