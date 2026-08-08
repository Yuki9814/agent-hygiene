import re
import unicodedata
from ipaddress import ip_address
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

from .line_endings import split_sarif_lines
from .models import Document, Finding
from .redaction import redact_secrets
from .safe_json import JSONSafetyError, strict_json_loads


RULES: Dict[str, Dict[str, str]] = {
    "AH001": {
        "name": "Hidden Unicode in agent-controlled text",
        "severity": "high",
        "help": "Remove invisible controls or replace them with visible escaped text.",
    },
    "AH002": {
        "name": "Prompt override or secrecy instruction",
        "severity": "high",
        "help": "Delete override language and keep agent instructions explicit and reviewable.",
    },
    "AH003": {
        "name": "Hardcoded credential-like value",
        "severity": "critical",
        "help": "Move secrets to a secret manager or environment reference.",
    },
    "AH004": {
        "name": "Dangerous shell or destructive command",
        "severity": "high",
        "help": "Replace destructive or shell-wrapped snippets with narrow, reviewed commands.",
    },
    "AH005": {
        "name": "Network exfiltration pattern",
        "severity": "critical",
        "help": "Remove outbound transfer of sensitive paths or token-like values.",
    },
    "AH006": {
        "name": "Risky MCP command shape",
        "severity": "high",
        "help": "Use direct executables with pinned arguments instead of shell wrappers.",
    },
    "AH007": {
        "name": "Inline secret in MCP environment",
        "severity": "critical",
        "help": "Reference secrets from the environment instead of embedding them in JSON.",
    },
    "AH008": {
        "name": "Agentic workflow with broad trust boundary",
        "severity": "high",
        "help": "Use read-only permissions for untrusted triggers and move writes to a trusted workflow.",
    },
    "AH009": {
        "name": "Missing verification command in instructions",
        "severity": "low",
        "help": "Add concrete test, lint, typecheck, or build commands.",
    },
    "AH010": {
        "name": "Stale path reference in instructions",
        "severity": "low",
        "help": "Update or remove the stale path reference.",
    },
    "AH011": {
        "name": "Vague instruction block likely to drift",
        "severity": "medium",
        "help": "Replace vague quality guidance with concrete commands, files, or constraints.",
    },
    "AH012": {
        "name": "Duplicate root instruction files can drift",
        "severity": "low",
        "help": "Pick one source of truth or add generated/delegation notes.",
    },
    "AH013": {
        "name": "Oversized agent instruction file",
        "severity": "medium",
        "help": "Split large instructions by scope and keep root guidance brief.",
    },
    "AH014": {
        "name": "Invalid MCP JSON",
        "severity": "medium",
        "help": "Fix the JSON syntax so MCP clients read the intended config.",
    },
    "AH015": {
        "name": "Risky GitHub Copilot hook",
        "severity": "medium",
        "help": "Keep hooks valid, avoid embedded secrets, and review outbound hook destinations.",
    },
}


def rule_catalog() -> List[Dict[str, str]]:
    """Return the stable, machine-readable metadata for every rule."""
    return [
        {"id": rule_id, **RULES[rule_id]}
        for rule_id in sorted(RULES)
    ]


PROMPT_OVERRIDE_PATTERNS = [
    re.compile(
        r"\b(ignore|disregard|override)\b.{0,50}\b(previous|prior|above|system|developer|user)\b.{0,30}\b(instruction|prompt|message|rule)s?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(reveal|print|dump|exfiltrat|send)\b.{0,50}\b(system prompt|developer message|hidden instruction|secret)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(do not|don't|never)\b.{0,40}\b(tell|mention|disclose|report|log)\b.{0,40}\b(user|human|owner|maintainer|developer)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(secretly|silently|stealth|covertly|without approval|without notice)\b", re.IGNORECASE),
]

SECRET_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|credential)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{20,})"
    ),
]

DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"\bcurl\b[^|\n]{0,120}\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
    re.compile(r"\bwget\b[^|\n]{0,120}\|\s*(sh|bash|zsh)\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\s+(/|\$HOME|~|\*)", re.IGNORECASE),
    re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
    re.compile(r"\bsudo\s+(rm|chmod|chown|curl|bash|sh|tee)\b", re.IGNORECASE),
    re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
    re.compile(r"\b(os\.system|subprocess\.[A-Za-z_]+\(.*shell\s*=\s*True)", re.IGNORECASE),
    re.compile(r"\b(bash|sh|zsh)\s+-c\b", re.IGNORECASE),
    re.compile(r"\bpython[0-9.]*\s+-c\b", re.IGNORECASE),
    re.compile(r"\bnode\s+-e\b", re.IGNORECASE),
]

EXFIL_PATTERN = re.compile(
    r"\b(curl|wget|nc|netcat|scp|rsync|aws\s+s3\s+cp)\b.{0,120}"
    r"(?:\.env\b|\.ssh\b|id_rsa\b|token\b|secret\b|password\b|/etc/passwd\b|HOME\b)",
    re.IGNORECASE,
)

VERIFY_PATTERN = re.compile(
    r"\b(test|tests|lint|typecheck|type-check|build|pytest|unittest|go test|cargo test|npm test|pnpm test|yarn test|ruff|mypy|tsc|make test)\b",
    re.IGNORECASE,
)

VAGUE_PATTERN = re.compile(
    r"\b(best practices|clean code|be careful|high quality|production[- ]ready|make sure|as needed|reasonable|obvious)\b",
    re.IGNORECASE,
)

CONCRETE_PATTERN = re.compile(r"(`[^`]+`|[A-Za-z0-9_./-]+\.(py|js|ts|tsx|go|rs|md|json|yml|yaml)|\b(pytest|npm|pnpm|cargo|go|make|ruff|mypy|tsc)\b)")

PATH_SPAN_PATTERN = re.compile(r"`([^`]+)`")

SENSITIVE_ENV_KEYS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")

HOOK_STDIN_UPLOAD_PATTERNS = (
    re.compile(
        r"\bcurl\b[^\n]{0,240}"
        r"(?:(?:--data(?:-ascii|-binary|-raw)?|--json)(?:=|\s+)"
        r"@(?:-|/dev/stdin)|"
        r"-d(?:=|\s*)@(?:-|/dev/stdin)|"
        r"(?:--upload-file|-T)(?:=|\s+)(?:-|/dev/stdin)|"
        r"(?:--form|-F)(?:=|\s+)[\"']?[^=\s\"']+="
        r"@(?:-|/dev/stdin)[\"']?)(?=\s|$)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bwget\b[^\n]{0,240}--post-file(?:=|\s+)-(?=\s|$)",
        re.IGNORECASE,
    ),
)

HOOK_ENV_REFERENCE_PATTERN = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
    r"(?P<bare>[A-Za-z_][A-Za-z0-9_]*))"
)

HTTPS_REQUIRED_HOOK_EVENTS = {
    "preToolUse",
    "PreToolUse",
    "permissionRequest",
    "PermissionRequest",
}


def scan_document(doc: Document, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(hidden_unicode(doc))
    findings.extend(prompt_override(doc))
    findings.extend(secret_literals(doc))
    findings.extend(dangerous_commands(doc))
    findings.extend(network_exfiltration(doc))

    if doc.kind == "instructions":
        findings.extend(instruction_quality(doc, root))
    elif doc.kind == "mcp":
        findings.extend(mcp_config(doc))
    elif doc.kind == "workflow":
        findings.extend(workflow_risks(doc))
    elif doc.kind == "agent_hook":
        findings.extend(agent_hook_config(doc))

    return findings


def repository_rules(docs: List[Document]) -> List[Finding]:
    root_instruction_names = {
        doc.relative_path
        for doc in docs
        if doc.kind == "instructions" and "/" not in doc.relative_path and doc.relative_path in {"AGENTS.md", "CLAUDE.md", "GEMINI.md", "CODEX.md"}
    }
    if len(root_instruction_names) < 2:
        return []

    names = ", ".join(sorted(root_instruction_names))
    return [
        finding(
            "AH012",
            "low",
            sorted(root_instruction_names)[0],
            1,
            f"Multiple root instruction files can drift: {names}.",
            "Choose one source of truth or add generated/delegation notes between files.",
            evidence=names,
        )
    ]


def hidden_unicode(doc: Document) -> Iterator[Finding]:
    for line_no, line in enumerate(split_sarif_lines(doc.text), start=1):
        for char in line:
            codepoint = ord(char)
            category = unicodedata.category(char)
            is_bidi = 0x202A <= codepoint <= 0x202E or 0x2066 <= codepoint <= 0x2069
            is_zero_width = codepoint in {0x200B, 0x200C, 0x200D, 0xFEFF}
            is_tag = 0xE0000 <= codepoint <= 0xE007F
            if is_bidi or is_zero_width or is_tag or (category in {"Cf", "Cc"} and char not in "\t\r\n"):
                yield finding(
                    "AH001",
                    "high",
                    doc.relative_path,
                    line_no,
                    f"Hidden Unicode control U+{codepoint:04X} appears in agent-controlled text.",
                    "Remove the invisible character or replace it with an escaped, visible spelling.",
                    evidence=f"U+{codepoint:04X}",
                )
                return


def prompt_override(doc: Document) -> Iterator[Finding]:
    for line_no, line in enumerate(split_sarif_lines(doc.text), start=1):
        for pattern in PROMPT_OVERRIDE_PATTERNS:
            match = pattern.search(line)
            if match:
                yield finding(
                    "AH002",
                    "high",
                    doc.relative_path,
                    line_no,
                    "Prompt override or secrecy language appears in an agent-controlled file.",
                    "Delete the override language and keep agent behavior explicit and reviewable.",
                    evidence=_clip(match.group(0)),
                )
                break


def secret_literals(doc: Document) -> Iterator[Finding]:
    for line_no, line in enumerate(split_sarif_lines(doc.text), start=1):
        if _looks_like_documentation_placeholder(line):
            continue
        for pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                yield finding(
                    "AH003",
                    "critical",
                    doc.relative_path,
                    line_no,
                    "Credential-like value appears in an agent-controlled file.",
                    "Move the secret to a secret manager or reference it through the environment.",
                    evidence=_redact(match.group(0)),
                )
                break


def dangerous_commands(doc: Document) -> Iterator[Finding]:
    for line_no, line in enumerate(split_sarif_lines(doc.text), start=1):
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            match = pattern.search(line)
            if match:
                yield finding(
                    "AH004",
                    "high",
                    doc.relative_path,
                    line_no,
                    "Dangerous shell or destructive command appears in agent-controlled text.",
                    "Replace it with a narrow, reviewed command and avoid shell wrappers.",
                    evidence=_clip(match.group(0)),
                )
                break


def network_exfiltration(doc: Document) -> Iterator[Finding]:
    for line_no, line in enumerate(split_sarif_lines(doc.text), start=1):
        match = EXFIL_PATTERN.search(line)
        if match:
            yield finding(
                "AH005",
                "critical",
                doc.relative_path,
                line_no,
                "Outbound network command appears near sensitive file or secret terms.",
                "Remove outbound transfer of secrets or sensitive local paths.",
                evidence=_clip(match.group(0)),
            )


def instruction_quality(doc: Document, root: Path) -> Iterator[Finding]:
    if len(doc.text.encode("utf-8", errors="replace")) > 64 * 1024:
        yield finding(
            "AH013",
            "medium",
            doc.relative_path,
            1,
            "Agent instruction file is large enough to be difficult to audit.",
            "Split instructions by scope and keep root guidance brief.",
            evidence=f"{len(doc.text)} characters",
        )

    if len(doc.text.strip()) > 120 and not VERIFY_PATTERN.search(doc.text):
        yield finding(
            "AH009",
            "low",
            doc.relative_path,
            1,
            "Instruction file does not mention a concrete verification command.",
            "Add test, lint, typecheck, or build commands that agents should run.",
        )

    vague_lines = []
    for line_no, line in enumerate(split_sarif_lines(doc.text), start=1):
        if VAGUE_PATTERN.search(line) and not CONCRETE_PATTERN.search(line):
            vague_lines.append((line_no, line.strip()))
    if len(vague_lines) >= 3:
        line_no, line = vague_lines[0]
        yield finding(
            "AH011",
            "medium",
            doc.relative_path,
            line_no,
            "Instruction file leans on vague quality guidance without concrete commands or paths.",
            "Replace vague guidance with specific commands, files, or constraints.",
            evidence=_clip(line),
        )

    for line_no, raw_path in _path_spans(doc.text):
        normalized = raw_path.strip()
        if not _looks_like_repo_path(normalized):
            continue
        candidate = (root / normalized).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if not candidate.exists():
            yield finding(
                "AH010",
                "low",
                doc.relative_path,
                line_no,
                f"Instruction references a path that does not exist: {normalized}.",
                "Update the path or remove the stale reference.",
                evidence=normalized,
            )


def mcp_config(doc: Document) -> Iterator[Finding]:
    try:
        data = strict_json_loads(doc.text)
    except JSONSafetyError as exc:
        yield finding(
            "AH014",
            "medium",
            doc.relative_path,
            exc.line or 1,
            "MCP config is not valid JSON.",
            "Fix the JSON syntax so clients read the intended configuration.",
            evidence=str(exc),
        )
        return
    if not isinstance(data, dict):
        yield finding(
            "AH014",
            "medium",
            doc.relative_path,
            1,
            "MCP config root is not a JSON object.",
            "Use an object containing mcpServers, servers, or a server command.",
            evidence="unsupported JSON root",
        )
        return

    for server_name, server in _iter_mcp_servers(data):
        if not isinstance(server, dict):
            continue
        command = str(server.get("command", ""))
        args = server.get("args", [])
        env = server.get("env", {})
        command_text = " ".join([command] + [str(arg) for arg in args if isinstance(arg, (str, int, float))])
        line_no = _line_for_text(doc.text, command) if command else 1

        if command in {"bash", "sh", "zsh", "powershell", "pwsh", "cmd"} or re.search(r"\b(bash|sh|zsh)\s+-c\b", command_text):
            yield finding(
                "AH006",
                "high",
                doc.relative_path,
                line_no,
                f"MCP server '{server_name}' launches a shell with inline code.",
                "Replace shell wrappers with a direct executable plus fixed arguments.",
                evidence=_clip(command_text),
            )

        if re.search(r"\b(python[0-9.]*\s+-c|node\s+-e|ruby\s+-e|perl\s+-e)\b", command_text):
            yield finding(
                "AH006",
                "high",
                doc.relative_path,
                line_no,
                f"MCP server '{server_name}' runs inline interpreter code.",
                "Move code into a reviewed script and call it directly.",
                evidence=_clip(command_text),
            )

        if command == "npx" and _npx_target_is_unpinned(args):
            yield finding(
                "AH006",
                "medium",
                doc.relative_path,
                line_no,
                f"MCP server '{server_name}' uses npx without a pinned package version.",
                "Pin the package version or vendor a reviewed server entrypoint.",
                evidence=_clip(command_text),
            )

        if "@latest" in command_text:
            yield finding(
                "AH006",
                "medium",
                doc.relative_path,
                line_no,
                f"MCP server '{server_name}' depends on @latest.",
                "Pin MCP server packages to reviewed versions.",
                evidence=_clip(command_text),
            )

        if isinstance(env, dict):
            for key, value in env.items():
                if not isinstance(value, str):
                    continue
                if _is_sensitive_key(key) and _is_inline_secret(value):
                    yield finding(
                        "AH007",
                        "critical",
                        doc.relative_path,
                        _line_for_text(doc.text, key),
                        f"MCP server '{server_name}' embeds a secret-like environment value.",
                        "Reference an environment variable instead of storing the value in JSON.",
                        evidence=f"{key}={_redact(value)}",
                    )


def workflow_risks(doc: Document) -> Iterator[Finding]:
    text = doc.text
    lower = text.lower()
    has_write = bool(re.search(r"permissions:\s*write-all|contents:\s*write|pull-requests:\s*write|issues:\s*write", lower))
    uses_secrets = "secrets." in lower or "${{ secrets" in lower
    has_agent_comment = bool(
        re.search(r"\b(issue_comment|pull_request_review_comment)\b", lower)
    )

    if "pull_request_target" in lower and (has_write or uses_secrets):
        yield finding(
            "AH008",
            "high",
            doc.relative_path,
            _line_for_text(lower, "pull_request_target"),
            "Workflow uses pull_request_target with write permissions or secrets.",
            "Use read-only pull_request checks and move privileged writes to a trusted workflow.",
            evidence="pull_request_target",
        )

    if has_agent_comment and has_write:
        yield finding(
            "AH008",
            "high",
            doc.relative_path,
            _line_for_text(lower, "issue_comment") if "issue_comment" in lower else 1,
            "Workflow appears to run agentic work from comments while holding write permissions.",
            "Gate comment-triggered agent runs behind maintainer approval and least-privilege permissions.",
            evidence="comment trigger with write permissions",
        )

    if re.search(r"permissions:\s*write-all", lower):
        yield finding(
            "AH008",
            "high",
            doc.relative_path,
            _line_for_text(lower, "permissions:"),
            "Workflow grants write-all permissions.",
            "Grant only the specific permissions required for the workflow.",
            evidence="permissions: write-all",
        )


def agent_hook_config(doc: Document) -> Iterator[Finding]:
    try:
        data = strict_json_loads(doc.text)
    except JSONSafetyError as exc:
        yield _hook_finding(
            doc,
            exc.line or 1,
            "GitHub Copilot hook configuration is not valid JSON.",
            "Fix the JSON syntax so Copilot reads the intended hooks.",
            str(exc),
        )
        return
    if not isinstance(data, dict):
        yield _hook_finding(
            doc,
            1,
            "GitHub Copilot hook configuration root is not an object.",
            "Use an object containing a hooks map.",
            "unsupported JSON root",
        )
        return

    standalone = doc.relative_path.startswith(".github/hooks/")
    version = data.get("version")
    if standalone and (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != 1
    ):
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, '"version"'),
            "Repository hook file does not declare version 1.",
            "Set the top-level hook configuration version to 1.",
            f"version={data.get('version')!r}",
        )
        return
    if data.get("disableAllHooks") is True:
        return
    if "hooks" not in data and not standalone:
        return

    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, '"hooks"'),
            "GitHub Copilot hooks must be an object of event arrays.",
            "Map each hook event to an array of hook definitions.",
            "invalid hooks shape",
        )
        return

    claude_settings = doc.relative_path in {
        ".claude/settings.json",
        ".claude/settings.local.json",
    }
    for event, raw_entries in hooks.items():
        if not isinstance(raw_entries, list):
            yield _hook_finding(
                doc,
                _line_for_text(doc.text, f'"{event}"'),
                f"GitHub Copilot hook event '{event}' is not an array.",
                "Wrap hook definitions for each event in an array.",
                "invalid event shape",
            )
            continue
        for index, entry in enumerate(raw_entries):
            if not isinstance(entry, dict):
                yield _hook_finding(
                    doc,
                    _line_for_text(doc.text, f'"{event}"'),
                    f"GitHub Copilot hook event '{event}' contains an invalid item.",
                    "Use an object for every hook definition.",
                    f"item {index + 1}",
                )
                continue
            if "hooks" in entry:
                yield from _nested_hook_group_findings(
                    doc,
                    str(event),
                    entry,
                )
            elif claude_settings:
                yield _hook_finding(
                    doc,
                    _line_for_text(doc.text, f'"{event}"'),
                    f"Claude hook event '{event}' contains an invalid matcher group.",
                    "Nest hook handlers under a hooks array in each matcher group.",
                    f"item {index + 1}",
                )
            else:
                yield from _hook_entry_findings(
                    doc,
                    str(event),
                    entry,
                    claude_format=False,
                )


def _nested_hook_group_findings(
    doc: Document,
    event: str,
    group: Dict[str, object],
) -> Iterator[Finding]:
    handlers = group.get("hooks")
    if not isinstance(handlers, list):
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, f'"{event}"'),
            f"Claude-format hook event '{event}' has an invalid handlers list.",
            "Set hooks to an array of reviewed hook handler objects.",
            "invalid nested hooks shape",
        )
        return
    for index, handler in enumerate(handlers):
        if not isinstance(handler, dict):
            yield _hook_finding(
                doc,
                _line_for_text(doc.text, f'"{event}"'),
                f"Claude-format hook event '{event}' contains an invalid handler.",
                "Use an object for every nested hook handler.",
                f"handler {index + 1}",
            )
            continue
        yield from _hook_entry_findings(
            doc,
            event,
            handler,
            claude_format=True,
        )


def _hook_entry_findings(
    doc: Document,
    event: str,
    entry: Dict[str, object],
    claude_format: bool,
) -> Iterator[Finding]:
    hook_type = entry.get("type", "command")
    if hook_type == "http":
        yield from _http_hook_findings(doc, event, entry)
    elif hook_type == "command":
        yield from _command_hook_findings(doc, event, entry)
    elif hook_type == "prompt":
        if claude_format:
            yield from _claude_prompt_hook_findings(
                doc,
                event,
                entry,
                "prompt",
            )
        else:
            yield from _prompt_hook_findings(doc, event, entry)
    elif claude_format and hook_type == "agent":
        yield from _claude_prompt_hook_findings(
            doc,
            event,
            entry,
            "agent",
        )
    elif claude_format and hook_type == "mcp_tool":
        yield from _claude_mcp_hook_findings(doc, event, entry)
    else:
        supported = (
            "command, HTTP, MCP tool, prompt, or agent"
            if claude_format
            else "command, HTTP, or session-start prompt"
        )
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, str(hook_type)),
            f"GitHub Copilot hook '{event}' uses an unknown hook type.",
            f"Use a supported {supported} hook type.",
            f"type={hook_type!r}",
        )


def _command_hook_findings(
    doc: Document,
    event: str,
    entry: Dict[str, object],
) -> Iterator[Finding]:
    commands = [
        entry.get(field)
        for field in ("bash", "powershell", "command")
        if isinstance(entry.get(field), str) and entry.get(field)
    ]
    if not commands:
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, f'"{event}"'),
            f"GitHub Copilot command hook '{event}' has no executable command.",
            "Set bash, powershell, or command to a reviewed repository script.",
            "missing command",
        )
    for command in commands:
        if any(pattern.search(command) for pattern in HOOK_STDIN_UPLOAD_PATTERNS):
            yield _hook_finding(
                doc,
                _line_for_text(doc.text, command),
                f"GitHub Copilot command hook '{event}' sends hook input to a network client.",
                "Remove inline network uploads or route reviewed, minimized data through an explicit HTTP hook.",
                "inline network upload from hook stdin",
                severity="high",
            )
            break

    env = entry.get("env")
    if not isinstance(env, dict):
        return
    for key, value in env.items():
        if (
            isinstance(value, str)
            and _is_sensitive_key(str(key))
            and _is_inline_secret(value)
        ):
            yield _hook_finding(
                doc,
                _line_for_text(doc.text, str(key)),
                f"GitHub Copilot hook '{event}' embeds a secret-like environment value.",
                "Reference a runtime environment variable instead of storing the value in hook JSON.",
                f"{key}={_redact(value)}",
                severity="critical",
            )


def _http_hook_findings(
    doc: Document,
    event: str,
    entry: Dict[str, object],
) -> Iterator[Finding]:
    allowed = entry.get("allowedEnvVars")
    allowed_env_vars = (
        {name for name in allowed if isinstance(name, str)}
        if isinstance(allowed, list)
        else set()
    )
    headers = entry.get("headers")
    sensitive_headers = (
        [
            str(name)
            for name, value in headers.items()
            if isinstance(value, str)
            and _http_header_contains_inline_secret(
                str(name),
                value,
                allowed_env_vars,
            )
        ]
        if isinstance(headers, dict)
        else []
    )
    if sensitive_headers:
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, sensitive_headers[0]),
            f"GitHub Copilot HTTP hook '{event}' embeds a credential-like header value.",
            "Reference an allowed runtime environment variable instead of storing credentials in hook JSON.",
            ", ".join(sorted(sensitive_headers)),
            severity="critical",
        )
        return

    url = entry.get("url")
    if not isinstance(url, str):
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, f'"{event}"'),
            f"GitHub Copilot HTTP hook '{event}' has no valid URL.",
            "Set url to an explicitly reviewed HTTP or HTTPS endpoint.",
            "missing URL",
        )
        return
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        parsed = None
        port = None
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
    ):
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, url),
            f"GitHub Copilot HTTP hook '{event}' has an invalid URL.",
            "Set url to an explicitly reviewed HTTP or HTTPS endpoint.",
            "invalid URL",
        )
        return
    hostname = parsed.hostname.lower()
    if parsed.username is not None or parsed.password is not None:
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, url),
            f"GitHub Copilot HTTP hook '{event}' embeds credentials in its URL.",
            (
                "Reference an allowed runtime environment variable in a "
                "reviewed header instead of storing credentials in the URL."
            ),
            _http_origin_evidence(parsed.scheme, hostname, port),
            severity="critical",
        )
        return
    loopback = _is_loopback_hostname(hostname)
    if parsed.scheme == "http":
        if event in HTTPS_REQUIRED_HOOK_EVENTS:
            message = (
                f"GitHub Copilot HTTP hook '{event}' requires an HTTPS URL "
                "because it can grant tool permissions."
            )
            remediation = "Use an explicitly reviewed HTTPS endpoint."
        elif loopback:
            message = (
                f"GitHub Copilot HTTP hook '{event}' uses a loopback HTTP URL "
                "that requires explicit local opt-in."
            )
            remediation = (
                "Use HTTPS, or require COPILOT_HOOK_ALLOW_LOCALHOST=1 in the "
                "trusted local environment."
            )
        else:
            message = (
                f"GitHub Copilot HTTP hook '{event}' uses an unsupported "
                "non-TLS external URL."
            )
            remediation = "Use an explicitly reviewed HTTPS endpoint."
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, url),
            message,
            remediation,
            _http_origin_evidence(parsed.scheme, hostname, port),
        )
        return
    if loopback:
        return
    yield _hook_finding(
        doc,
        _line_for_text(doc.text, url),
        f"GitHub Copilot HTTP hook '{event}' sends agent event data to an external endpoint.",
        "Confirm the endpoint, payload, retention, and firewall policy before enabling the hook.",
        _http_origin_evidence(parsed.scheme, hostname, port),
    )


def _prompt_hook_findings(
    doc: Document,
    event: str,
    entry: Dict[str, object],
) -> Iterator[Finding]:
    if event not in {"sessionStart", "SessionStart"}:
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, f'"{event}"'),
            f"GitHub Copilot prompt hook '{event}' uses an unsupported event.",
            "Use prompt hooks only for sessionStart or SessionStart.",
            "unsupported prompt event",
        )
        return

    prompt = entry.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, '"prompt"'),
            "GitHub Copilot session-start prompt hook has no prompt text.",
            "Set prompt to a reviewed natural-language prompt or slash command.",
            "missing prompt",
        )


def _claude_prompt_hook_findings(
    doc: Document,
    event: str,
    entry: Dict[str, object],
    hook_type: str,
) -> Iterator[Finding]:
    prompt = entry.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, '"prompt"'),
            f"Claude-format {hook_type} hook '{event}' has no prompt text.",
            "Set prompt to reviewed text appropriate for the hook event.",
            "missing prompt",
        )


def _claude_mcp_hook_findings(
    doc: Document,
    event: str,
    entry: Dict[str, object],
) -> Iterator[Finding]:
    missing = [
        field
        for field in ("server", "tool")
        if not isinstance(entry.get(field), str)
        or not str(entry.get(field)).strip()
    ]
    if missing:
        yield _hook_finding(
            doc,
            _line_for_text(doc.text, f'"{event}"'),
            f"Claude-format MCP tool hook '{event}' is incomplete.",
            "Set non-empty server and tool names for the MCP hook handler.",
            "missing " + ", ".join(missing),
        )


def _hook_finding(
    doc: Document,
    line: int,
    message: str,
    remediation: str,
    evidence: str,
    severity: str = "medium",
) -> Finding:
    return finding(
        "AH015",
        severity,
        doc.relative_path,
        line,
        message,
        remediation,
        evidence=evidence,
    )


def finding(
    rule_id: str,
    severity: str,
    path: str,
    line: int,
    message: str,
    remediation: str,
    evidence: Optional[str] = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=RULES[rule_id]["name"],
        severity=severity,
        path=path,
        line=max(1, line),
        message=message,
        remediation=remediation,
        evidence=redact_secrets(evidence) if evidence else evidence,
    )


def _iter_mcp_servers(data: object) -> Iterator[Tuple[str, Dict[str, object]]]:
    if not isinstance(data, dict):
        return

    candidates = []
    for key in ("mcpServers", "servers"):
        value = data.get(key)
        if isinstance(value, dict):
            candidates.append(value)

    if not candidates and "command" in data:
        candidates.append({"default": data})

    for group in candidates:
        for name, server in group.items():
            if isinstance(server, dict):
                yield str(name), server


def _npx_target_is_unpinned(args: object) -> bool:
    if not isinstance(args, list):
        return True
    package = None
    skip_next = False
    for raw_arg in args:
        arg = str(raw_arg)
        if skip_next:
            skip_next = False
            continue
        if arg in {"-y", "--yes", "--package", "-p"}:
            skip_next = arg in {"--package", "-p"}
            continue
        if arg.startswith("-"):
            continue
        package = arg
        break
    if package is None:
        return True
    if package.startswith("@"):
        parts = package.rsplit("@", 1)
        return len(parts) < 2 or not parts[-1] or "/" in parts[-1]
    return "@" not in package


def _is_sensitive_key(key: str) -> bool:
    upper = key.upper()
    return any(marker in upper for marker in SENSITIVE_ENV_KEYS)


def _is_inline_secret(value: str) -> bool:
    stripped = value.strip()
    if not stripped or stripped.startswith("$") or stripped.startswith("${"):
        return False
    return len(stripped) >= 12 and not _looks_like_documentation_placeholder(stripped)


def _looks_like_documentation_placeholder(text: str) -> bool:
    lowered = text.lower()
    placeholders = [
        "your_",
        "your-",
        "example",
        "placeholder",
        "changeme",
        "change_me",
        "replace",
        "<token>",
        "xxx",
        "redacted",
    ]
    return any(token in lowered for token in placeholders)


def _path_spans(text: str) -> Iterator[Tuple[int, str]]:
    for line_no, line in enumerate(split_sarif_lines(text), start=1):
        for match in PATH_SPAN_PATTERN.finditer(line):
            yield line_no, match.group(1)


def _looks_like_repo_path(value: str) -> bool:
    if value.startswith(("http://", "https://", "file://", "$", "~", "/")):
        return False
    if " " in value or "\t" in value:
        return False
    if any(char in value for char in "*{}"):
        return False
    if value.startswith("-"):
        return False
    return "/" in value or bool(re.search(r"\.(md|py|js|ts|tsx|go|rs|json|toml|yml|yaml|sh|txt)$", value))


def _line_for_text(text: str, needle: str) -> int:
    if not needle:
        return 1
    for line_no, line in enumerate(split_sarif_lines(text), start=1):
        if needle in line:
            return line_no
    return 1


def _clip(value: str, limit: int = 120) -> str:
    value = " ".join(value.strip().split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _http_origin_evidence(
    scheme: str,
    hostname: str,
    port: Optional[int],
) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        host = f"{host}:{port}"
    return f"{scheme}://{host}"


def _http_header_contains_inline_secret(
    name: str,
    value: str,
    allowed_env_vars: set,
) -> bool:
    normalized_name = name.strip().lower()
    references = {
        match.group("braced") or match.group("bare")
        for match in HOOK_ENV_REFERENCE_PATTERN.finditer(value)
    }
    candidate = HOOK_ENV_REFERENCE_PATTERN.sub(" ", value).strip()
    if normalized_name in {"authorization", "proxy-authorization"}:
        parts = candidate.split(None, 1)
        candidate = parts[1] if len(parts) == 2 else parts[0]
        return _contains_inline_secret_segment(candidate)
    if normalized_name == "cookie":
        cookie_values = [
            part.split("=", 1)[1] if "=" in part else part
            for part in candidate.split(";")
        ]
        return _contains_inline_secret_segment(" ".join(cookie_values))
    header_parts = {
        part
        for part in re.split(r"[^a-z0-9]+", normalized_name)
        if part
    }
    sensitive_parts = {
        "cookie",
        "credential",
        "credentials",
        "key",
        "password",
        "secret",
        "token",
    }
    if not header_parts & sensitive_parts:
        return False
    if references and references.issubset(allowed_env_vars):
        return False
    return _contains_inline_secret_segment(candidate)


def _contains_inline_secret_segment(value: str) -> bool:
    return any(
        _is_inline_secret(segment)
        for segment in re.findall(r"[A-Za-z0-9_./+=-]{12,}", value)
    )


def _is_loopback_hostname(hostname: str) -> bool:
    normalized = hostname.rstrip(".")
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _redact(value: str) -> str:
    clipped = _clip(value, 80)
    redacted = redact_secrets(clipped)
    return redacted if redacted != clipped else "<redacted-secret>"
