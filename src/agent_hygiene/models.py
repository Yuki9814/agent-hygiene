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


@dataclass(frozen=True)
class Document:
    path: Path
    relative_path: str
    kind: str
    text: str


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
class ScanSummary:
    root: str
    scanned_files: int
    instruction_files: int
    mcp_configs: int
    workflows: int
    score: int
    status: str
    scope_fingerprint: Optional[str] = None
    counts: Dict[str, int] = field(default_factory=dict)
    complete: bool = True
    discovery_issues: List[DiscoveryIssue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "root": self.root,
            "scanned_files": self.scanned_files,
            "instruction_files": self.instruction_files,
            "mcp_configs": self.mcp_configs,
            "workflows": self.workflows,
            "score": self.score,
            "status": self.status,
            "counts": self.counts,
            "complete": self.complete,
            "discovery_issues": [issue.to_dict() for issue in self.discovery_issues],
        }
        if self.scope_fingerprint:
            data["scope_fingerprint"] = self.scope_fingerprint
        return data


@dataclass(frozen=True)
class ScanResult:
    summary: ScanSummary
    findings: List[Finding]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 1,
            "tool": {
                "name": "agent-hygiene",
                "version": __version__,
            },
            "summary": self.summary.to_dict(),
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
