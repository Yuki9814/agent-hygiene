"""Collect a pinned local Git snapshot without executing repository code."""

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import threading
import unicodedata
from urllib.parse import urlsplit

from .config import ConfigError, load_config
from .evidence import (
    EvidenceError,
    load_evidence_directory,
    load_public_canary_manifest,
)
from .reporters import render
from .scanner import scan


MAX_TREE_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOT_FILES = 10_000
MAX_BLOB_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 30
_OBJECT_ID = re.compile(r"[0-9a-f]{40}")


class CollectionError(ValueError):
    """The requested snapshot could not be collected safely."""


def _git_read(checkout, arguments, limit, input_bytes=b""):
    # Ignore inherited Git routing/config overrides. These commands read objects
    # only: no checkout, filters, hooks, network fetch, or project subprocesses.
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OBJECT_DIRECTORY": str(checkout / ".git" / "objects"),
        "LC_ALL": "C",
    })
    # An isolated Git directory prevents the source clone's config, includes,
    # promisor remotes, replacement refs, and hooks from affecting object reads.
    with tempfile.TemporaryDirectory(prefix="agent-hygiene-git-") as git_directory, tempfile.TemporaryFile() as requests:
        git_root = Path(git_directory)
        (git_root / "refs").mkdir()
        (git_root / "objects").mkdir()
        (git_root / "HEAD").write_text("ref: refs/heads/unused\n", encoding="ascii")
        requests.write(input_bytes)
        requests.seek(0)
        try:
            process = subprocess.Popen(
                ["git", "--no-replace-objects", "--git-dir", git_directory,
                 *arguments],
                stdin=requests, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=environment,
            )
        except OSError as exc:
            raise CollectionError("Git is unavailable") from exc
        timer = threading.Timer(GIT_TIMEOUT_SECONDS, process.kill)
        timer.daemon = True
        timer.start()
        try:
            data = process.stdout.read(limit + 1)
            if len(data) > limit:
                raise CollectionError("Git output exceeds the collection limit")
            if process.wait() != 0:
                raise CollectionError("Git object read failed or timed out")
            return data
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()


def _snapshot_entries(tree):
    entries = []
    names = {}
    total_size = 0
    for record in tree.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id, raw_size = metadata.split()
            path = raw_path.decode("utf-8")
            object_id = object_id.decode("ascii")
            size = int(raw_size)
        except (ValueError, UnicodeError) as exc:
            raise CollectionError("unsupported Git tree entry") from exc
        if mode not in (b"100644", b"100755") or kind != b"blob":
            raise CollectionError("snapshot must contain regular files only; links are unsupported")
        if not _OBJECT_ID.fullmatch(object_id) or size < 0:
            raise CollectionError("invalid Git blob metadata")
        parts = path.split("/")
        if (len(path) > 1024 or "\\" in path or ":" in path
                or any(ord(char) < 32 or ord(char) == 127 for char in path)
                or any(part in ("", ".", "..") or part.casefold() == ".git"
                       or part.endswith((".", " ")) for part in parts)
                or PurePosixPath(path).is_absolute()):
            raise CollectionError("snapshot contains an unsafe or nonportable path")
        for index in range(1, len(parts) + 1):
            prefix = "/".join(parts[:index])
            key = unicodedata.normalize("NFC", prefix).casefold()
            if key in names and names[key] != prefix:
                raise CollectionError("snapshot contains case or Unicode path collisions")
            names[key] = prefix
        if size > MAX_BLOB_BYTES:
            raise CollectionError("snapshot file exceeds the per-file byte limit")
        total_size += size
        entries.append((path, object_id, size))
        if len(entries) > MAX_SNAPSHOT_FILES or total_size > MAX_SNAPSHOT_BYTES:
            raise CollectionError("snapshot exceeds the file count or total byte limit")
    return entries


def _materialize(checkout, revision, destination):
    commit = _git_read(checkout, ["cat-file", "commit", revision], MAX_TREE_BYTES)
    actual = hashlib.sha1(b"commit " + str(len(commit)).encode() + b"\0" + commit).hexdigest()
    if actual != revision:
        raise CollectionError("commit bytes do not match the manifest revision")
    tree = _git_read(checkout, ["ls-tree", "-r", "-l", "-z", revision], MAX_TREE_BYTES)
    entries = _snapshot_entries(tree)
    requests = "".join(object_id + "\n" for _, object_id, _ in entries).encode("ascii")
    blob_limit = sum(size for _, _, size in entries) + 100 * len(entries)
    blobs = _git_read(checkout, ["cat-file", "--batch"], blob_limit, requests)
    offset = 0
    for path, object_id, size in entries:
        newline = blobs.find(b"\n", offset)
        expected = f"{object_id} blob {size}".encode("ascii")
        if newline < 0 or blobs[offset:newline] != expected:
            raise CollectionError("Git blob response does not match the pinned tree")
        start = newline + 1
        data = blobs[start:start + size]
        if len(data) != size or blobs[start + size:start + size + 1] != b"\n":
            raise CollectionError("Git blob response is incomplete")
        digest = hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest()
        if digest != object_id:
            raise CollectionError("blob bytes do not match the pinned tree")
        target = destination.joinpath(*path.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        offset = start + size + 1
    if offset != len(blobs):
        raise CollectionError("unexpected trailing Git blob data")


def _write_json(path, document):
    data = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(data)
    path.chmod(0o600)


def collect_canary(checkout: Path, manifest_path: Path, repository_id: str, output: Path) -> bool:
    """Write a new local bundle; return whether the observation is complete.

    Source identity and public consent are manifest declarations, not verified
    network attestations. Only committed objects are scanned, never the working
    tree, and no reviewers or accuracy judgments are generated.
    """
    checkout = Path(checkout).absolute()
    output = Path(output).absolute()
    if (not (checkout / ".git").is_dir() or (checkout / ".git").is_symlink()
            or not (checkout / ".git" / "objects").is_dir()):
        raise CollectionError("checkout must be an ordinary local Git clone")
    if output.exists() or output.is_symlink():
        raise CollectionError("output already exists; choose a new bundle directory")
    if not output.parent.is_dir():
        raise CollectionError("output parent must already exist")
    try:
        manifest = load_public_canary_manifest(Path(manifest_path))
    except EvidenceError as exc:
        raise CollectionError("public canary manifest is invalid or unreadable") from exc
    repository = next((item for item in manifest["repositories"]
                       if item["repository_id"] == repository_id), None)
    if repository is None:
        raise CollectionError("repository id is absent from the public canary manifest")
    revision = repository["revision"].lower()
    selected_manifest = {**manifest, "repositories": [repository]}
    with tempfile.TemporaryDirectory(prefix="agent-hygiene-snapshot-") as scratch:
        snapshot = Path(scratch)
        _materialize(checkout, revision, snapshot)
        try:
            result = scan(snapshot, load_config(snapshot), use_baseline=False)
        except ConfigError as exc:
            raise CollectionError("snapshot scanner configuration is invalid") from exc
        identity = "remote:github.com/" + urlsplit(repository["repository_url"]).path.strip("/").lower()
        result = replace(result, summary=replace(
            result.summary, source_revision=revision,
            scope_fingerprint=hashlib.sha256(identity.encode()).hexdigest()[:20],
        ))
        result_bytes = render(result, "json", portable=True).encode("utf-8")
    locations = sorted({(finding.rule_id, finding.path, finding.line) for finding in result.findings})
    observation = {
        "schema_version": 1, "kind": "observation", "repository_id": repository_id,
        "revision": revision, "complete": result.summary.complete,
        "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "findings": [{
            "finding_id": "F" + hashlib.sha256(json.dumps(location).encode()).hexdigest()[:20],
            "rule_id": location[0], "path": location[1], "line": location[2],
        } for location in locations],
    }
    # Stage all bytes and validate the public layer before creating the new
    # destination. Exclusive mkdir protects existing files and directories.
    with tempfile.TemporaryDirectory(prefix=".agent-hygiene-collect-", dir=output.parent) as scratch:
        staged = Path(scratch)
        evidence = staged / "evidence"
        observations = evidence / "observation"
        observations.mkdir(parents=True)
        private = staged / "private"
        private.mkdir(mode=0o700)
        _write_json(evidence / "public_canary_manifest.json", selected_manifest)
        _write_json(observations / f"{repository_id}.json", observation)
        raw_result = private / "result.json"
        raw_result.write_bytes(result_bytes)
        raw_result.chmod(0o600)
        (staged / ".gitignore").write_text("/private/\n", encoding="utf-8")
        try:
            load_evidence_directory(evidence)
        except EvidenceError as exc:
            raise CollectionError("generated observation cannot satisfy the evidence contract") from exc
        output.mkdir(mode=0o700)
        try:
            for name in (".gitignore", "private", "evidence"):
                (staged / name).rename(output / name)
        except OSError:
            shutil.rmtree(output)
            raise
    return result.summary.complete
