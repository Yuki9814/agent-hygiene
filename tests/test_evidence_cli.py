import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_hygiene.cli import main


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class EvidenceCLITests(unittest.TestCase):
    def test_canonical_empty_evidence_is_machine_readable(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                [
                    "evidence",
                    str(REPOSITORY_ROOT / "evidence" / "v0.4.0"),
                    "--format",
                    "json",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["kind"], "evidence_summary")
        self.assertEqual(payload["repository_count"], 0)
        self.assertEqual(payload["reviewer_count"], 0)
        self.assertIsNone(payload["metrics"]["precision"])
        self.assertIsNone(payload["metrics"]["recall"])
        self.assertFalse(payload["independently_validated"])
        self.assertNotIn(str(REPOSITORY_ROOT), stdout.getvalue())

    def test_review_pack_cli_writes_only_neutral_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "review-pack.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "review-pack",
                        str(REPOSITORY_ROOT / "tests" / "corpus" / "manifest.json"),
                        "--output",
                        str(destination),
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(payload["kind"], "review_pack")
            self.assertEqual(payload["cases"][0]["case_id"], "C001")
            serialized = destination.read_text(encoding="utf-8")
            self.assertNotIn('"expected"', serialized)
            self.assertNotIn('"source"', serialized)
            self.assertNotIn('"actual"', serialized)
            manifest = json.loads(
                (REPOSITORY_ROOT / "tests" / "corpus" / "manifest.json").read_text(
                    encoding="utf-8"
                )
            )
            for case in manifest["cases"]:
                self.assertNotIn(json.dumps(case["id"]), serialized)

    def test_invalid_evidence_returns_usage_error_without_traceback(self):
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            with redirect_stderr(stderr):
                exit_code = main(["evidence", temporary])

        self.assertEqual(exit_code, 2)
        self.assertIn("evidence validation failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_malformed_url_returns_usage_error_without_traceback(self):
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "public_canary_manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "public_canary_manifest",
                        "limitations": ["Malformed URL regression case."],
                        "repositories": [
                            {
                                "repository_id": "R001",
                                "repository_url": "https://[invalid",
                                "revision": "a" * 40,
                                "consent_url": (
                                    "https://github.com/example/repository/issues/1"
                                ),
                                "selection_reason": "Regression test.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with redirect_stderr(stderr):
                exit_code = main(["evidence", temporary])

        self.assertEqual(exit_code, 2)
        self.assertIn("evidence validation failed", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertNotIn(str(REPOSITORY_ROOT), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
