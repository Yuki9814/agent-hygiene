from dataclasses import dataclass, field
import hashlib
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from . import __version__
from .redaction import redact_secrets


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_PENALTY = {
    "info": 0,
    "low": 2,
    "medium": 7,
    "high": 15,
    "critical": 30,
}

# Keep the audit trail useful without allowing a repository full of suppressed
# findings to turn a scan report into an unbounded memory allocation.  The
# summary count remains exact; only per-item detail is capped.
MAX_SUPPRESSION_AUDIT_ITEMS = 10_000


@dataclass(frozen=True)
class Document:
    path: Path
    relative_path: str
    kind: str
    text: str
    truncated: bool = False


@dataclass(frozen=True)
class DiscoveryIssue:
    path: str
    reason: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "path": self.path,
            "reason": self.reason,
            "message": self.message,
        }


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    line: int
    message: str
    remediation: str
    evidence: Optional[str] = None
    primary_location_line_hash: Optional[str] = field(
        default=None,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        for field_name in ("title", "message", "remediation", "evidence"):
            value = getattr(self, field_name)
            if value:
                object.__setattr__(self, field_name, redact_secrets(value))

    def fingerprint(self) -> str:
        key = "\0".join(
            [
                self.rule_id,
                self.path,
                str(self.line),
                self.message,
                self.evidence or "",
            ]
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint(),
        }
        if self.evidence:
            data["evidence"] = self.evidence
        return data


@dataclass(frozen=True)
class SuppressionRecord:
    """A redaction-safe explanation for one suppressed finding."""

    rule_id: str
    path: str
    line: int
    fingerprint: str
    source: str
    reason: str

    def to_dict(self) -> Dict[str, object]:
        # Deliberately keep this contract to identifying metadata only.  In
        # particular, never copy a finding's evidence or a raw config/directive
        # into an audit report.
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "fingerprint": self.fingerprint,
            "source": self.source,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class SuppressionAudit:
    """Bounded, deterministic accounting for all suppression decisions."""

    count: int = 0
    by_source: Dict[str, int] = field(default_factory=dict)
    items: List[SuppressionRecord] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "count": self.count,
            "by_source": dict(self.by_source),
            "truncated": self.truncated,
            "items": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True)
class ScanSummary:
    root: str
    scanned_files: int
    instruction_files: int
    mcp_configs: int
    workflows: int
    score: int
    status: str
    scope_fingerprint: Optional[str] = None
    source_revision: Optional[str] = None
    counts: Dict[str, int] = field(default_factory=dict)
    complete: bool = True
    discovery_issues: List[DiscoveryIssue] = field(default_factory=list)
    suppression_audit: SuppressionAudit = field(default_factory=SuppressionAudit)

    def to_dict(self, portable: bool = False) -> Dict[str, object]:
        data: Dict[str, object] = {
            "scanned_files": self.scanned_files,
            "instruction_files": self.instruction_files,
            "mcp_configs": self.mcp_configs,
            "workflows": self.workflows,
            "score": self.score,
            "status": self.status,
            "counts": self.counts,
            "complete": self.complete,
            "discovery_issues": [issue.to_dict() for issue in self.discovery_issues],
            "suppression_audit": self.suppression_audit.to_dict(),
        }
        if not portable:
            data["root"] = self.root
        if self.scope_fingerprint:
            data["scope_fingerprint"] = self.scope_fingerprint
        if self.source_revision:
            data["source_revision"] = self.source_revision
        return data


@dataclass(frozen=True)
class ScanResult:
    summary: ScanSummary
    findings: List[Finding]

    def to_dict(self, portable: bool = False) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "tool": {
                "name": "agent-hygiene",
                "version": __version__,
            },
            "summary": self.summary.to_dict(portable=portable),
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def highest_severity(self) -> str:
        highest = "info"
        for finding in self.findings:
            if SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[highest]:
                highest = finding.severity
        return highest


def count_by_severity(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in ["critical", "high", "medium", "low", "info"]}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts
