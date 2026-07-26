import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_hygiene.config import Config
from agent_hygiene.discovery import discover


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = REPOSITORY_ROOT / "tools" / "benchmark_large_repo.py"


class PerformanceContractTests(unittest.TestCase):
    def test_discovery_order_remains_deterministic_without_global_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory_name in ("z-last", "a-first"):
                directory = root / directory_name
                directory.mkdir()
                (directory / "AGENTS.md").write_text(
                    "Run `python -m unittest`.\n",
                    encoding="utf-8",
                )

            first = [
                document.relative_path
                for document in discover(root, Config().exclude).documents
            ]
            second = [
                document.relative_path
                for document in discover(root, Config().exclude).documents
            ]

            self.assertEqual(first, ["a-first/AGENTS.md", "z-last/AGENTS.md"])
            self.assertEqual(second, first)

    def test_discovery_uses_one_walk_and_keeps_every_supported_surface(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = [
                "AGENTS.md",
                ".github/workflows/nested/check.yml",
                ".github/copilot-instructions.md",
                ".github/instructions/nested/team.instructions.md",
                ".github/agents/nested/reviewer.md",
                ".cursor/rules/nested/style.mdc",
                "packages/demo/skills/review/SKILL.md",
                "packages/demo/mcp.json",
            ]
            for relative_path in paths:
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Run tests before accepting changes.\n", encoding="utf-8")
            (root / "noise.txt").write_text("unrelated\n", encoding="utf-8")

            with patch(
                "agent_hygiene.discovery.os.walk",
                wraps=os.walk,
            ) as walk:
                result = discover(root, Config().exclude)

            self.assertEqual(walk.call_count, 1)
            self.assertEqual(
                {document.relative_path for document in result.documents},
                set(paths),
            )
            self.assertEqual(result.issues, [])

    def test_small_benchmark_emits_versioned_json_and_passes(self):
        process = self._run_benchmark(
            "--files",
            "30",
            "--warmups",
            "0",
            "--runs",
            "2",
            "--max-p95-seconds",
            "30",
            "--max-rss-mib",
            "1024",
        )

        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(
            payload["kind"],
            "agent-hygiene-large-repo-benchmark",
        )
        self.assertEqual(payload["tool"]["name"], "agent-hygiene")
        self.assertEqual(payload["fixture"]["total_files"], 30)
        self.assertEqual(payload["fixture"]["relevant_files"], 3)
        self.assertEqual(payload["method"]["runs"], 2)
        self.assertFalse(payload["method"]["child_startup_included"])
        self.assertEqual(payload["metrics"]["scanned_relevant_files"], 3)
        self.assertTrue(payload["passed"])

    def test_benchmark_gate_failure_returns_one(self):
        process = self._run_benchmark(
            "--files",
            "3",
            "--warmups",
            "0",
            "--runs",
            "1",
            "--max-p95-seconds",
            "0.000001",
            "--max-rss-mib",
            "0.000001",
        )

        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertFalse(json.loads(process.stdout)["passed"])

    def test_benchmark_rejects_less_than_three_files(self):
        process = self._run_benchmark("--files", "2")

        self.assertEqual(process.returncode, 2)
        self.assertIn("files must be from 3", process.stderr)

    @staticmethod
    def _run_benchmark(*arguments):
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "src")
        return subprocess.run(
            [sys.executable, "-B", str(BENCHMARK), *arguments],
            cwd=REPOSITORY_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
