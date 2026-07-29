"""Descriptor-verified, bounded reads for untrusted local files."""

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class BoundedRead:
    data: bytes
    truncated: bool


class SafeFileError(Exception):
    """Raised when a path cannot be read as the same bounded regular file."""

    def __init__(
        self,
        reason: str,
        error_name: Optional[str] = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.error_name = error_name


def read_bounded_regular_file(
    path: Path,
    max_bytes: int,
    *,
    truncate: bool = False,
) -> BoundedRead:
    """Read one regular file through a single verified descriptor.

    A pre-open lstat rejects stable special files. The post-open fstat and
    identity comparison reject final-component replacements before any bytes
    are read. On POSIX, O_NONBLOCK is required so a swap to a special file
    cannot block the open. Non-POSIX fallbacks still verify regular-file type
    and identity before reading.
    """

    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a non-negative integer")

    try:
        path_info = os.lstat(path)
    except OSError as exc:
        reason = (
            "missing"
            if exc.errno in {errno.ENOENT, errno.ENOTDIR}
            else "open_error"
        )
        raise SafeFileError(reason, exc.__class__.__name__) from exc
    if stat.S_ISLNK(path_info.st_mode):
        raise SafeFileError("symlink")
    if not stat.S_ISREG(path_info.st_mode):
        raise SafeFileError("not_regular")

    optional_flags = _optional_open_flags()
    nonblocking = getattr(os, "O_NONBLOCK", 0)
    if (
        _requires_nonblocking_open()
        and (not nonblocking or not optional_flags & nonblocking)
    ):
        raise SafeFileError("unsupported_platform")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | optional_flags
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        reason = (
            "changed"
            if exc.errno in {errno.ELOOP, errno.ENOENT, errno.ENOTDIR}
            else "open_error"
        )
        raise SafeFileError(reason, exc.__class__.__name__) from exc

    try:
        try:
            descriptor_info = os.fstat(descriptor)
        except OSError as exc:
            raise SafeFileError("inspect_error", exc.__class__.__name__) from exc
        if not stat.S_ISREG(descriptor_info.st_mode):
            raise SafeFileError("not_regular")
        if not os.path.samestat(path_info, descriptor_info):
            raise SafeFileError("changed")
        if descriptor_info.st_size > max_bytes and not truncate:
            raise SafeFileError("too_large")

        try:
            data = _read_at_most(descriptor, max_bytes + 1)
        except OSError as exc:
            raise SafeFileError("read_error", exc.__class__.__name__) from exc
    finally:
        os.close(descriptor)

    was_truncated = descriptor_info.st_size > max_bytes or len(data) > max_bytes
    if was_truncated and not truncate:
        raise SafeFileError("too_large")
    return BoundedRead(data=data[:max_bytes], truncated=was_truncated)


def _optional_open_flags() -> int:
    flags = 0
    for name in (
        "O_NONBLOCK",
        "O_NOFOLLOW",
        "O_CLOEXEC",
        "O_NOINHERIT",
    ):
        flags |= getattr(os, name, 0)
    return flags


def _requires_nonblocking_open() -> bool:
    return os.name == "posix"


def _read_at_most(descriptor: int, byte_count: int) -> bytes:
    chunks = []
    remaining = byte_count
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
