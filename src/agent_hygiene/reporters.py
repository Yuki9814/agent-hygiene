import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from . import __version__
from .models import SEVERITY_ORDER, Finding, ScanResult
from .rules import RULES


def render(result: ScanResult, output_format: str, portable: bool = False) -> str:
    if output_format == "json":
        return (
            json.dumps(
                result.to_dict(portable=portable),
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    if output_format == "markdown":
        return render_markdown(result)
    if output_format == "sarif":
        return render_sarif(result)
    return render_text(result)


def render_text(result: ScanResult) -> str:
    summary = result.summary
    lines = [
        f"agent-hygiene score {summary.score}/100 ({summary.status})",
        f"scanned {summary.scanned_files} files: {summary.instruction_files} instructions, {summary.mcp_configs} MCP configs, {summary.workflows} workflows",
        _count_line(summary.counts),
    ]

    if not summary.complete:
        lines.append(f"scan incomplete: {len(summary.discovery_issues)} file(s) skipped or truncated")
        for issue in summary.discovery_issues:
            lines.append(f"  {_human_text(issue.path)}: {_human_text(issue.message)}")

    if not result.findings:
        lines.append("no findings")
        return "\n".join(lines) + "\n"

    lines.append("")
    for finding in result.findings:
        lines.append(
            f"{finding.severity.upper()} {finding.rule_id} "
            f"{_human_text(finding.path)}:{finding.line}"
        )
        lines.append(f"  {_human_text(finding.message)}")
        if finding.evidence:
            lines.append(f"  Evidence: {_human_text(finding.evidence)}")
        lines.append(f"  Fix: {_human_text(finding.remediation)}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_markdown(result: ScanResult) -> str:
    summary = result.summary
    lines = [
        "# Agent Hygiene Report",
        "",
        f"- Score: **{summary.score}/100** ({summary.status})",
        f"- Scanned files: {summary.scanned_files}",
        f"- Instruction files: {summary.instruction_files}",
        f"- MCP configs: {summary.mcp_configs}",
        f"- Workflows: {summary.workflows}",
        f"- Findings: {_count_line(summary.counts)}",
        f"- Scan complete: {'yes' if summary.complete else 'no'}",
        "",
    ]

    if not summary.complete:
        lines.extend(["## Discovery issues", ""])
        for issue in summary.discovery_issues:
            lines.append(
                f"- `{_markdown_code(issue.path)}` "
                f"({_human_text(issue.reason)}): {_human_text(issue.message)}"
            )
        lines.append("")

    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines.extend(["| Severity | Rule | Location | Finding |", "| --- | --- | --- | --- |"])
    for finding in result.findings:
        location = f"`{_markdown_code(finding.path)}:{finding.line}`"
        message = _escape_table(
            f"{_human_text(finding.message)} "
            f"Fix: {_human_text(finding.remediation)}"
        )
        lines.append(f"| {finding.severity} | {finding.rule_id} | {location} | {message} |")
    return "\n".join(lines) + "\n"


def render_sarif(result: ScanResult) -> str:
    rules = []
    seen = set()
    for finding in result.findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        meta = RULES[finding.rule_id]
        rules.append(
            {
                "id": finding.rule_id,
                "name": meta["name"],
                "shortDescription": {"text": meta["name"]},
                "help": {"text": meta["help"]},
                "defaultConfiguration": {"level": _sarif_level(meta["severity"])},
            }
        )

    sarif: Dict[str, object] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-hygiene",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/Yuki9814/agent-hygiene",
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": result.summary.complete,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        "toolExecutionNotifications": [
                            {
                                "level": "error",
                                "message": {"text": f"{issue.path}: {issue.message}"},
                                "descriptor": {"id": f"discovery/{issue.reason}"},
                            }
                            for issue in result.summary.discovery_issues
                        ],
                    }
                ],
                "results": [_sarif_result(finding) for finding in result.findings],
                "properties": {
                    "score": result.summary.score,
                    "status": result.summary.status,
                    "counts": result.summary.counts,
                    **(
                        {"scopeFingerprint": result.summary.scope_fingerprint}
                        if result.summary.scope_fingerprint
                        else {}
                    ),
                    **(
                        {"sourceRevision": result.summary.source_revision}
                        if result.summary.source_revision
                        else {}
                    ),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True) + "\n"


def should_fail(result: ScanResult, min_score: int, fail_on: str) -> bool:
    if not result.summary.complete:
        return True
    if result.summary.score < min_score:
        return True
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER[finding.severity] >= threshold for finding in result.findings)


def write_output(text: str, destination: str) -> None:
    Path(destination).write_text(text, encoding="utf-8")


def _count_line(counts: Dict[str, int]) -> str:
    ordered = ["critical", "high", "medium", "low", "info"]
    return ", ".join(f"{name}={counts.get(name, 0)}" for name in ordered)


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _human_text(value: str) -> str:
    def replace_control(match: re.Match) -> str:
        character = match.group(0)
        escapes = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}
        return escapes.get(character, f"\\x{ord(character):02x}")

    return re.sub(r"[\x00-\x1f\x7f-\x9f]", replace_control, value)


def _markdown_code(value: str) -> str:
    return _human_text(value).replace("`", "\\`")


def _sarif_result(finding: Finding) -> Dict[str, object]:
    result: Dict[str, object] = {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": f"{finding.message} Fix: {finding.remediation}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {"startLine": finding.line},
                }
            }
        ],
    }
    partial_fingerprints = {
        "agentHygieneFingerprint/v1": finding.fingerprint(),
    }
    if finding.primary_location_line_hash is not None:
        partial_fingerprints[
            "primaryLocationLineHash"
        ] = finding.primary_location_line_hash
    result["partialFingerprints"] = partial_fingerprints
    result["properties"] = {
        "severity": finding.severity,
        "remediation": finding.remediation,
    }
    return result


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
