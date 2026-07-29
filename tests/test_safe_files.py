import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_hygiene.safe_files import (
    SafeFileError,
    _optional_open_flags,
    read_bounded_regular_file,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class SafeFileTests(unittest.TestCase):
    def test_regular_file_bounds_distinguish_exact_and_overflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input"
            path.write_bytes(b"abcd")

            exact = read_bounded_regular_file(path, 4)
            empty_prefix = read_bounded_regular_file(path, 0, truncate=True)

            self.assertEqual(exact.data, b"abcd")
            self.assertFalse(exact.truncated)
            self.assertEqual(empty_prefix.data, b"")
            self.assertTrue(empty_prefix.truncated)

            path.write_bytes(b"abcde")
            with self.assertRaises(SafeFileError) as raised:
                read_bounded_regular_file(path, 4)
            prefix = read_bounded_regular_file(path, 4, truncate=True)

            self.assertEqual(raised.exception.reason, "too_large")
            self.assertEqual(prefix.data, b"abcd")
            self.assertTrue(prefix.truncated)

    def test_oversized_sparse_file_is_rejected_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sparse"
            with path.open("wb") as stream:
                stream.truncate(1024 * 1024)

            with mock.patch(
                "agent_hygiene.safe_files._read_at_most",
            ) as read_bytes:
                with self.assertRaises(SafeFileError) as raised:
                    read_bounded_regular_file(path, 4)

            self.assertEqual(raised.exception.reason, "too_large")
            read_bytes.assert_not_called()

    def test_invalid_byte_limit_is_rejected_before_inspection(self):
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            read_bounded_regular_file(Path("unused"), "4")

    def test_supported_open_safety_flags_are_requested(self):
        flags = _optional_open_flags()

        for name in (
            "O_NONBLOCK",
            "O_NOFOLLOW",
            "O_CLOEXEC",
            "O_NOINHERIT",
        ):
            value = getattr(os, name, 0)
            if value:
                with self.subTest(flag=name):
                    self.assertEqual(flags & value, value)

    def test_posix_without_nonblocking_open_fails_before_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input"
            path.write_bytes(b"safe")
            with mock.patch(
                "agent_hygiene.safe_files._optional_open_flags",
                return_value=0,
            ), mock.patch(
                "agent_hygiene.safe_files._requires_nonblocking_open",
                return_value=True,
            ), mock.patch("agent_hygiene.safe_files.os.open") as opened:
                with self.assertRaises(SafeFileError) as raised:
                    read_bounded_regular_file(path, 4)

            self.assertEqual(raised.exception.reason, "unsupported_platform")
            opened.assert_not_called()

    def test_non_posix_fallback_still_verifies_a_regular_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "input"
            path.write_bytes(b"safe")
            with mock.patch(
                "agent_hygiene.safe_files._optional_open_flags",
                return_value=0,
            ), mock.patch(
                "agent_hygiene.safe_files._requires_nonblocking_open",
                return_value=False,
            ):
                result = read_bounded_regular_file(path, 4)

            self.assertEqual(result.data, b"safe")
            self.assertFalse(result.truncated)

    @unittest.skipIf(
        os.name == "nt",
        "symlink creation requires elevated Windows privileges",
    )
    def test_final_symlink_swap_is_rejected_before_read(self):
        for use_optional_flags in (True, False):
            with self.subTest(use_optional_flags=use_optional_flags):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    path = root / "input"
                    replacement = root / "replacement"
                    path.write_bytes(b"trusted")
                    replacement.write_bytes(b"outside")
                    original_open = os.open

                    def swap_then_open(raw_path, flags):
                        path.unlink()
                        path.symlink_to(replacement)
                        return original_open(raw_path, flags)

                    patches = [
                        mock.patch(
                            "agent_hygiene.safe_files.os.open",
                            side_effect=swap_then_open,
                        ),
                        mock.patch(
                            "agent_hygiene.safe_files._read_at_most",
                        ),
                    ]
                    if not use_optional_flags:
                        patches.extend(
                            [
                                mock.patch(
                                    "agent_hygiene.safe_files._optional_open_flags",
                                    return_value=0,
                                ),
                                mock.patch(
                                    "agent_hygiene.safe_files._requires_nonblocking_open",
                                    return_value=False,
                                ),
                            ]
                        )

                    with patches[0], patches[1] as read_bytes:
                        if not use_optional_flags:
                            with patches[2], patches[3]:
                                with self.assertRaises(SafeFileError) as raised:
                                    read_bounded_regular_file(path, 16)
                        else:
                            with self.assertRaises(SafeFileError) as raised:
                                read_bounded_regular_file(path, 16)

                    self.assertEqual(raised.exception.reason, "changed")
                    read_bytes.assert_not_called()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO requires POSIX")
    def test_fifo_inputs_fail_closed_without_hanging(self):
        cases = (
            "scan",
            "config",
            "baseline",
            "evaluation-manifest",
            "evaluation-fixture",
            "review-fixture",
            "scope",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                result = self._run_fifo_case(root, case)

                if case == "scope":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    payload = json.loads(result.stdout)
                    self.assertTrue(payload["summary"]["complete"])
                    self.assertNotIn(
                        "scope_fingerprint",
                        payload["summary"],
                    )
                else:
                    self.assertEqual(result.returncode, 2, result.stderr)
                    if case in {"scan", "baseline"}:
                        payload = json.loads(result.stdout)
                        self.assertFalse(payload["summary"]["complete"])
                        issue = payload["summary"]["discovery_issues"][0]
                        if case == "scan":
                            self.assertEqual(issue["reason"], "read_error")
                            self.assertIn("non-regular", issue["message"])
                        else:
                            self.assertEqual(
                                issue["reason"],
                                "invalid_baseline",
                            )
                    else:
                        self.assertTrue(result.stderr)
                        if case == "config":
                            self.assertIn(
                                "must be a regular file",
                                result.stderr,
                            )
                        elif case == "evaluation-manifest":
                            self.assertIn(
                                "stable regular file",
                                result.stderr,
                            )
                        elif case == "evaluation-fixture":
                            self.assertIn(
                                "could not be read safely",
                                result.stderr,
                            )
                        elif case == "review-fixture":
                            self.assertIn(
                                "stable regular file",
                                result.stderr,
                            )

    @unittest.skipUnless(
        hasattr(socket, "AF_UNIX"),
        "Unix-domain sockets are unavailable",
    )
    def test_unix_socket_scan_fails_closed_without_hanging(self):
        with tempfile.TemporaryDirectory(
            prefix="ah-socket-",
            dir="/tmp",
        ) as tmp:
            root = Path(tmp)
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(root / "AGENTS.md"))
                result = self._run_cli(
                    "scan",
                    str(root),
                    "--format",
                    "json",
                    "--min-score",
                    "0",
                    "--fail-on",
                    "none",
                )
            finally:
                server.close()

            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(
                payload["summary"]["discovery_issues"][0]["reason"],
                "read_error",
            )

    def _run_fifo_case(self, root: Path, case: str):
        if case == "scan":
            os.mkfifo(root / "AGENTS.md")
            return self._run_scan(root)
        if case == "config":
            os.mkfifo(root / ".agent-hygiene.json")
            return self._run_cli("scan", str(root), "--quiet")
        if case == "baseline":
            (root / "AGENTS.md").write_text("safe\n", encoding="utf-8")
            os.mkfifo(root / ".agent-hygiene-baseline.json")
            return self._run_scan(root)
        if case == "evaluation-manifest":
            manifest = root / "manifest.json"
            os.mkfifo(manifest)
            return self._run_cli("evaluate", str(manifest))
        if case in {"evaluation-fixture", "review-fixture"}:
            fixture = root / "case.fixture"
            os.mkfifo(fixture)
            manifest = self._write_manifest(root)
            if case == "evaluation-fixture":
                return self._run_cli("evaluate", str(manifest))
            return self._run_cli(
                "review-pack",
                str(manifest),
                "--output",
                str(root / "review.json"),
            )
        if case == "scope":
            git_directory = root / ".git"
            git_directory.mkdir()
            os.mkfifo(git_directory / "config")
            (root / "AGENTS.md").write_text("safe\n", encoding="utf-8")
            return self._run_scan(root, "--no-baseline")
        raise AssertionError(f"unknown FIFO case: {case}")

    def _run_scan(self, root: Path, *extra):
        return self._run_cli(
            "scan",
            str(root),
            "--format",
            "json",
            "--min-score",
            "0",
            "--fail-on",
            "none",
            *extra,
        )

    @staticmethod
    def _write_manifest(root: Path) -> Path:
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "gates": {
                        "min_precision": 1.0,
                        "min_recall": 1.0,
                    },
                    "cases": [
                        {
                            "id": "special-file",
                            "files": [
                                {
                                    "source": "case.fixture",
                                    "target": "AGENTS.md",
                                }
                            ],
                            "expected": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return manifest

    @staticmethod
    def _run_cli(*arguments):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment.pop("GITHUB_REPOSITORY", None)
        return subprocess.run(
            [sys.executable, "-m", "agent_hygiene", *arguments],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
