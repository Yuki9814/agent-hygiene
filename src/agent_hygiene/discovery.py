import codecs
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Iterable, List, Sequence

from .models import DiscoveryIssue, Document
from .safe_files import SafeFileError, read_bounded_regular_file


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
    for path in _walk(root, excludes, issues):
        kind = classify(root, path)
        if kind is None:
            continue
        relative_path = path.relative_to(root).as_posix()
        try:
            read_result = read_bounded_regular_file(
                path,
                MAX_FILE_BYTES,
                truncate=True,
            )
        except SafeFileError as exc:
            if exc.reason == "symlink":
                issues.append(
                    DiscoveryIssue(
                        path=relative_path,
                        reason="symlink",
                        message=(
                            "Skipped symbolic link; scan the target explicitly "
                            "if it is trusted."
                        ),
                    )
                )
                continue
            if exc.reason == "not_regular":
                issues.append(
                    DiscoveryIssue(
                        path=relative_path,
                        reason="read_error",
                        message=(
                            "Skipped non-regular file; agent-controlled inputs "
                            "must be regular files."
                        ),
                    )
                )
                continue
            issues.append(
                DiscoveryIssue(
                    path=relative_path,
                    reason="read_error",
                    message=(
                        "Could not read file: "
                        f"{exc.error_name or exc.reason}."
                    ),
                )
            )
            continue
        if read_result.truncated:
            decoder = codecs.getincrementaldecoder("utf-8")(
                errors="replace"
            )
            text = decoder.decode(
                read_result.data,
                final=False,
            )
            issues.append(
                DiscoveryIssue(
                    path=relative_path,
                    reason="file_too_large",
                    message=f"Scanned only the first {MAX_FILE_BYTES} bytes.",
                )
            )
        else:
            text = read_result.data.decode("utf-8", errors="replace")
        docs.append(
            Document(
                path=path,
                relative_path=relative_path,
                kind=kind,
                text=text,
                truncated=read_result.truncated,
            )
        )
    return DiscoveryResult(documents=docs, issues=issues)


def classify(root: Path, path: Path) -> str:
    rel = path.relative_to(root).as_posix()
    directory_parts = path.relative_to(root).parent.parts
    name = path.name

    if rel.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}:
        return "workflow"

    if name in INSTRUCTION_NAMES:
        return "instructions"

    if (
        name == "copilot-instructions.md"
        and directory_parts
        and directory_parts[-1] == ".github"
    ):
        return "instructions"
    if name.endswith(".instructions.md") and _has_directory_path(
        directory_parts,
        (".github", "instructions"),
    ):
        return "instructions"
    if name.endswith(".md") and _has_directory_path(
        directory_parts,
        (".github", "agents"),
    ):
        return "instructions"
    if name.endswith(".prompt.md") and _has_directory_path(
        directory_parts,
        (".github", "prompts"),
    ):
        return "instructions"
    if name.endswith(".md") and _has_directory_path(
        directory_parts,
        (".claude", "agents"),
    ):
        return "instructions"
    if path.suffix == ".mdc" and _has_directory_path(
        directory_parts,
        (".cursor", "rules"),
    ):
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
        relative_directory = directory_path.relative_to(root)
        kept_directories = []
        for name in sorted(dirnames):
            if name in exclude_set:
                continue
            candidate = directory_path / name
            relative = relative_directory / name
            if candidate.is_symlink():
                issues.append(
                    DiscoveryIssue(
                        path=relative.as_posix(),
                        reason="symlink",
                        message=(
                            "Skipped symbolic-link directory; it can hide "
                            "agent-controlled files at any depth."
                        ),
                    )
                )
                continue
            kept_directories.append(name)
        dirnames[:] = kept_directories

        for filename in sorted(filenames):
            if filename in exclude_set:
                continue
            if not _could_be_relevant(relative_directory.parts, filename):
                continue
            yield directory_path / filename


def _could_be_relevant(directory_parts: Sequence[str], filename: str) -> bool:
    if filename in INSTRUCTION_NAMES or filename in MCP_NAMES:
        return True

    prefix = tuple(directory_parts[:2])
    if prefix == (".github", "workflows"):
        return filename.endswith((".yml", ".yaml"))
    if (
        filename == "copilot-instructions.md"
        and directory_parts
        and directory_parts[-1] == ".github"
    ):
        return True
    if filename.endswith(".instructions.md") and _has_directory_path(
        directory_parts,
        (".github", "instructions"),
    ):
        return True
    if filename.endswith(".md") and _has_directory_path(
        directory_parts,
        (".github", "agents"),
    ):
        return True
    if filename.endswith(".prompt.md") and _has_directory_path(
        directory_parts,
        (".github", "prompts"),
    ):
        return True
    if filename.endswith(".md") and _has_directory_path(
        directory_parts,
        (".claude", "agents"),
    ):
        return True
    if filename.endswith(".mdc") and _has_directory_path(
        directory_parts,
        (".cursor", "rules"),
    ):
        return True
    return filename == "SKILL.md" and "skills" in directory_parts


def _has_directory_path(
    directory_parts: Sequence[str],
    expected: Sequence[str],
) -> bool:
    expected_tuple = tuple(expected)
    expected_length = len(expected_tuple)
    if expected_length == 0:
        return False

    for index in range(len(directory_parts) - expected_length + 1):
        if tuple(directory_parts[index : index + expected_length]) == expected_tuple:
            return True

    return False
