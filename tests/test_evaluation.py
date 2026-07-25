import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_hygiene.cli import main
from agent_hygiene.evaluation import (
    EvaluationError,
    evaluate_manifest,
    render_evaluation,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CORPUS_MANIFEST = REPOSITORY_ROOT / "tests" / "corpus" / "manifest.json"


class EvaluationTests(unittest.TestCase):
    def test_repository_corpus_passes_declared_gates(self):
        result = evaluate_manifest(CORPUS_MANIFEST)

        self.assertTrue(result.passed)
        self.assertEqual(result.precision, 1.0)
        self.assertEqual(result.recall, 1.0)
        self.assertEqual(result.true_positives, 13)
        self.assertEqual(result.false_positives, 0)
        self.assertEqual(result.false_negatives, 0)
        self.assertEqual(len(result.cases), 18)

    def test_evaluation_json_has_a_versioned_stable_shape(self):
        payload = json.loads(render_evaluation(evaluate_manifest(CORPUS_MANIFEST), "json"))

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(
            set(payload),
            {"schema_version", "cases", "metrics", "gates", "passed"},
        )
        self.assertEqual(
            set(payload["metrics"]),
            {
                "true_positives",
                "false_positives",
                "false_negatives",
                "precision",
                "recall",
            },
        )

    def test_evaluate_cli_prints_metrics_and_passes(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = main(["evaluate", str(CORPUS_MANIFEST)])

        self.assertEqual(exit_code, 0)
        self.assertIn("precision 1.000", stdout.getvalue())
        self.assertIn("recall 1.000", stdout.getvalue())

    def test_missing_expected_finding_fails_recall_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "safe.fixture").write_text("Run `python -m unittest`.\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "known-miss",
                        "files": [{"source": "safe.fixture", "target": "AGENTS.md"}],
                        "expected": [
                            {"rule_id": "AH002", "path": "AGENTS.md", "line": 1}
                        ],
                    }
                ],
            )

            result = evaluate_manifest(manifest)

            self.assertFalse(result.passed)
            self.assertEqual(result.recall, 0.0)
            self.assertEqual(result.false_negatives, 1)

    def test_manifest_source_cannot_escape_corpus_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            corpus.mkdir()
            (root / "outside.fixture").write_text("safe\n", encoding="utf-8")
            manifest = self._write_manifest(
                corpus,
                [
                    {
                        "id": "escape",
                        "files": [
                            {"source": "../outside.fixture", "target": "AGENTS.md"}
                        ],
                        "expected": [],
                    }
                ],
            )

            with self.assertRaisesRegex(EvaluationError, "stay within"):
                evaluate_manifest(manifest)

    def test_unknown_rule_in_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case.fixture").write_text("safe\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "unknown-rule",
                        "files": [{"source": "case.fixture", "target": "AGENTS.md"}],
                        "expected": [
                            {"rule_id": "AH999", "path": "AGENTS.md", "line": 1}
                        ],
                    }
                ],
            )

            with self.assertRaisesRegex(EvaluationError, "unknown rule"):
                evaluate_manifest(manifest)

    def test_manifest_must_be_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_bytes(b"\xff")

            with self.assertRaisesRegex(EvaluationError, "UTF-8"):
                evaluate_manifest(manifest)

    def test_case_id_cannot_inject_output_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case.fixture").write_text("safe\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "case\nspoofed",
                        "files": [{"source": "case.fixture", "target": "AGENTS.md"}],
                        "expected": [],
                    }
                ],
            )

            with self.assertRaisesRegex(EvaluationError, "1-80"):
                evaluate_manifest(manifest)

    def test_conflicting_target_shapes_are_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "first.fixture").write_text("safe\n", encoding="utf-8")
            (root / "second.fixture").write_text("safe\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "conflict",
                        "files": [
                            {"source": "first.fixture", "target": "AGENTS.md"},
                            {
                                "source": "second.fixture",
                                "target": "AGENTS.md/child.txt",
                            },
                        ],
                        "expected": [],
                    }
                ],
            )

            with self.assertRaisesRegex(EvaluationError, "could not stage"):
                evaluate_manifest(manifest)

    def test_total_fixture_reference_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case.fixture").write_text("safe\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "bounded-references",
                        "files": [
                            {
                                "source": "case.fixture",
                                "target": f"case-{index}/AGENTS.md",
                            }
                            for index in range(3)
                        ],
                        "expected": [],
                    }
                ],
            )

            with mock.patch(
                "agent_hygiene.evaluation.MAX_TOTAL_FILE_REFERENCES",
                2,
            ):
                with self.assertRaisesRegex(EvaluationError, "reference budget"):
                    evaluate_manifest(manifest)

    def test_total_fixture_byte_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case.fixture").write_text("bounded fixture\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "bounded-bytes",
                        "files": [
                            {"source": "case.fixture", "target": "AGENTS.md"}
                        ],
                        "expected": [],
                    }
                ],
            )

            with mock.patch(
                "agent_hygiene.evaluation.MAX_TOTAL_FIXTURE_BYTES",
                4,
            ):
                with self.assertRaisesRegex(EvaluationError, "byte budget"):
                    evaluate_manifest(manifest)

    def test_invalid_ratio_numbers_are_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case.fixture").write_text("safe\n", encoding="utf-8")
            manifest = self._write_manifest(
                root,
                [
                    {
                        "id": "bounded-ratio",
                        "files": [{"source": "case.fixture", "target": "AGENTS.md"}],
                        "expected": [],
                    }
                ],
            )

            invalid_values = (
                (float("nan"), "non-standard numeric constant"),
                (float("inf"), "non-standard numeric constant"),
                (10**1000, "number from 0 to 1"),
            )
            for invalid, expected_error in invalid_values:
                with self.subTest(invalid=repr(invalid)[:20]):
                    payload = json.loads(manifest.read_text(encoding="utf-8"))
                    payload["gates"]["min_precision"] = invalid
                    manifest.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(EvaluationError, expected_error):
                        evaluate_manifest(manifest)

    def test_excessively_nested_json_is_reported_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(
                '{"version":1,"gates":{"min_precision":1,"min_recall":1},'
                '"cases":[],"padding":' + "[" * 2000 + "0" + "]" * 2000 + "}",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(EvaluationError, "safe parser limits"):
                evaluate_manifest(manifest)

    @staticmethod
    def _write_manifest(root: Path, cases):
        path = root / "manifest.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "gates": {"min_precision": 1.0, "min_recall": 1.0},
                    "cases": cases,
                }
            ),
            encoding="utf-8",
        )
        return path


if __name__ == "__main__":
    unittest.main()
