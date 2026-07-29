import configparser
import hashlib
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from .safe_files import SafeFileError, read_bounded_regular_file


MAX_GIT_CONFIG_BYTES = 256 * 1024
GITHUB_REPOSITORY_PATTERN = re.compile(
    r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}"
)


def repository_scope_fingerprint(root: Path) -> Optional[str]:
    identity = _github_environment_identity() or _origin_identity(root)
    if not identity:
        return None
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _github_environment_identity() -> Optional[str]:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not GITHUB_REPOSITORY_PATTERN.fullmatch(repository):
        return None
    return f"remote:github.com/{repository.lower()}"


def _origin_identity(root: Path) -> Optional[str]:
    git_directory = root.resolve() / ".git"
    if git_directory.is_symlink() or not git_directory.is_dir():
        return None
    config_path = git_directory / "config"
    text = _read_bounded_regular_text(config_path)
    if text is None:
        return None

    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
        origin = parser.get('remote "origin"', "url")
    except (configparser.Error, KeyError, ValueError):
        return None
    return _normalize_remote(origin)


def _normalize_remote(value: str) -> Optional[str]:
    remote = value.strip()
    scp_match = re.fullmatch(
        r"(?:[^@\s/:]+@)?([A-Za-z0-9.-]+):([^\s?#]+)",
        remote,
    )
    if scp_match:
        host, path = scp_match.groups()
        return _remote_identity(host, path)

    try:
        parsed = urlsplit(remote)
    except ValueError:
        return None
    if parsed.scheme not in {"git", "http", "https", "ssh"} or not parsed.hostname:
        return None
    return _remote_identity(parsed.hostname, parsed.path)


def _remote_identity(host: str, path: str) -> Optional[str]:
    normalized_host = host.lower()
    normalized_path = path.strip().strip("/")
    if normalized_path.endswith(".git"):
        normalized_path = normalized_path[:-4]
    if not normalized_path or any(character in normalized_path for character in "\0\r\n"):
        return None
    if normalized_host == "github.com":
        normalized_path = normalized_path.lower()
    return f"remote:{normalized_host}/{normalized_path}"


def _read_bounded_regular_text(path: Path) -> Optional[str]:
    try:
        read_result = read_bounded_regular_file(
            path,
            MAX_GIT_CONFIG_BYTES,
        )
    except SafeFileError:
        return None
    try:
        return read_result.data.decode("utf-8")
    except UnicodeDecodeError:
        return None
