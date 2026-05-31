from pathlib import Path
from typing import Iterable, List, Sequence

from .models import Document


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


def discover(root: Path, excludes: Sequence[str]) -> List[Document]:
    root = root.resolve()
    docs: List[Document] = []
    for path in sorted(_walk(root, excludes)):
        kind = classify(root, path)
        if kind is None:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                text = path.read_text(encoding="utf-8", errors="replace")[:MAX_FILE_BYTES]
            else:
                text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        docs.append(
            Document(
                path=path,
                relative_path=path.relative_to(root).as_posix(),
                kind=kind,
                text=text,
            )
        )
    return docs


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
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        parts = set(path.relative_to(root).parts)
        if parts.intersection(exclude_set):
            continue
        yield path
