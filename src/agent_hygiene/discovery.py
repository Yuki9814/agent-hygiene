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
    issues: List[DiscoveryIssue] = list(_relevant_directory_symlink_issues(root, excludes))
    for path in sorted(_walk(root, excludes, issues)):
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
            declared_size = path.stat().st_size
            with path.open("rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            if declared_size > MAX_FILE_BYTES or len(data) > MAX_FILE_BYTES:
                text = data[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
                issues.append(
                    DiscoveryIssue(
                        path=relative_path,
                        reason="file_too_large",
                        message=f"Scanned only the first {MAX_FILE_BYTES} bytes.",
                    )
                )
            else:
                text = data.decode("utf-8", errors="replace")
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


def _walk(
    root: Path,
    excludes: Sequence[str],
    issues: List[DiscoveryIssue],
) -> Iterable[Path]:
    exclude_set = set(excludes)

    def record_error(exc: OSError) -> None:
        raw_path = Path(exc.filename) if exc.filename else root
        try:
            relative_path = raw_path.relative_to(root).as_posix()
        except ValueError:
            relative_path = "."
        issues.append(
            DiscoveryIssue(
                path=relative_path,
                reason="walk_error",
                message=f"Could not inspect directory: {exc.__class__.__name__}.",
            )
        )

    for directory, dirnames, filenames in os.walk(
        root,
        followlinks=False,
        onerror=record_error,
    ):
        directory_path = Path(directory)
        dirnames[:] = sorted(name for name in dirnames if name not in exclude_set)
        for filename in sorted(filenames):
            path = directory_path / filename
            parts = set(path.relative_to(root).parts)
            if not parts.intersection(exclude_set):
                yield path


def _relevant_directory_symlink_issues(
    root: Path, excludes: Sequence[str]
) -> Iterable[DiscoveryIssue]:
    exclude_set = set(excludes)
    for directory, dirnames, _ in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        kept = []
        for name in sorted(dirnames):
            candidate = directory_path / name
            relative = candidate.relative_to(root)
            if set(relative.parts).intersection(exclude_set):
                continue
            if candidate.is_symlink():
                yield DiscoveryIssue(
                    path=relative.as_posix(),
                    reason="symlink",
                    message=(
                        "Skipped symbolic-link directory; it can hide "
                        "agent-controlled files at any depth."
                    ),
                )
                continue
            kept.append(name)
        dirnames[:] = kept
