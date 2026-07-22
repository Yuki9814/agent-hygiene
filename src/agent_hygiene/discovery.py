from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterable, List, Sequence

from .models import DiscoveryIssue, Document


INSTRUCTION_NAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "CODEX.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
}

MCP_NAMES = {
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
}

MAX_FILE_BYTES = 512 * 1024


@dataclass(frozen=True)
class DiscoveryResult:
    documents: List[Document]
    issues: List[DiscoveryIssue]


def discover(root: Path, excludes: Sequence[str]) -> DiscoveryResult:
    root = root.resolve()
    docs: List[Document] = []
    issues: List[DiscoveryIssue] = []
    for path in sorted(_walk(root, excludes)):
        kind = classify(root, path)
        if kind is None:
            continue
        relative_path = path.relative_to(root).as_posix()
        if path.is_symlink():
            issues.append(
                DiscoveryIssue(
                    path=relative_path,
                    reason="symlink",
                    message="Skipped symbolic link; scan the target explicitly if it is trusted.",
                )
            )
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                text = path.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_BYTES]
                issues.append(
                    DiscoveryIssue(
                        path=relative_path,
                        reason="file_too_large",
                        message=f"Scanned only the first {MAX_FILE_BYTES} characters.",
                    )
                )
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            issues.append(
                DiscoveryIssue(
                    path=relative_path,
                    reason="read_error",
                    message=f"Could not read file: {exc.__class__.__name__}.",
                )
            )
            continue
        docs.append(
            Document(
                path=path,
                relative_path=relative_path,
                kind=kind,
                text=text,
            )
        )
    return DiscoveryResult(documents=docs, issues=issues)


def classify(root: Path, path: Path) -> str:
    rel = path.relative_to(root).as_posix()
    name = path.name

    if rel.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
        return "workflow"

    if name in INSTRUCTION_NAMES:
        return "instructions"

    if rel == ".github/copilot-instructions.md":
        return "instructions"
    if rel.startswith(".github/instructions/") and rel.endswith(".instructions.md"):
        return "instructions"
    if rel.startswith(".github/agents/") and rel.endswith(".md"):
        return "instructions"
    if rel.startswith(".cursor/rules/") and path.suffix == ".mdc":
        return "instructions"
    if "/skills/" in f"/{rel}" and name == "SKILL.md":
        return "instructions"

    if name in MCP_NAMES:
        return "mcp"
    if rel in {".vscode/mcp.json", ".cursor/mcp.json"}:
        return "mcp"

    return None


def _walk(root: Path, excludes: Sequence[str]) -> Iterable[Path]:
    exclude_set = set(excludes)
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        dirnames[:] = sorted(name for name in dirnames if name not in exclude_set)
        for filename in sorted(filenames):
            path = directory_path / filename
            parts = set(path.relative_to(root).parts)
            if not parts.intersection(exclude_set):
                yield path
