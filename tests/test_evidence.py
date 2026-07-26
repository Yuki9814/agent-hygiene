import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_hygiene.evidence import (
    EvidenceError,
    build_review_pack,
    load_evidence_directory,
    render_evidence_json,
    render_evidence_markdown,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CORPUS_MANIFEST = REPOSITORY_ROOT / "tests" / "corpus" / "manifest.json"
EVIDENCE_SCHEMA = REPOSITORY_ROOT / "schemas" / "evidence-v1.schema.json"


class EvidenceContractTests(unittest.TestCase):
    def test_empty_manifest_reports_unvalidated_zero_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, [])

            summary = load_evidence_directory(root)

            self.assertEqual(summary["repository_count"], 0)
            self.assertEqual(summary["reviewer_count"], 0)
            self.assertEqual(summary["independent_reviewer_count"], 0)
            self.assertEqual(summary["complete_observation_count"], 0)
            self.assertEqual(summary["full_surface_repository_count"], 0)
            self.assertEqual(
                summary["metrics"],
                {
                    "true_positives": 0,
                    "false_positives": 0,
                    "false_negatives": 0,
                    "precision": None,
                    "recall": None,
                },
            )
            self.assertFalse(summary["independently_validated"])
            self.assertEqual(summary["status"], "not independently validated")
            self.assertIn(
                "0/0",
                render_evidence_markdown(summary),
            )
            self.assertEqual(
                render_evidence_markdown(summary).count("# Agent Hygiene Evidence"),
                1,
            )
            self.assertEqual(
                json.loads(render_evidence_json(summary)),
                summary,
            )
            with self.assertRaisesRegex(EvidenceError, "unexpected fields"):
                render_evidence_json(dict(summary, handwritten_total=100))
            with self.assertRaisesRegex(EvidenceError, "absolute path"):
                render_evidence_json(
                    dict(summary, limitations=["Result at /Users/alice/private."])
                )
            with self.assertRaisesRegex(EvidenceError, "precision and recall"):
                render_evidence_json(
                    dict(
                        summary,
                        independently_validated=True,
                        status="independently validated",
                    )
                )

    def test_manifest_requires_consent_and_full_revision_and_rejects_extras(self):
        repository = self._repository(1)
        invalid_documents = []

        missing_consent = dict(repository)
        del missing_consent["consent_url"]
        invalid_documents.append((missing_consent, "consent_url"))

        short_revision = dict(repository)
        short_revision["revision"] = "a" * 39
        invalid_documents.append((short_revision, "40-character"))

        extra_field = dict(repository)
        extra_field["claim"] = "validated"
        invalid_documents.append((extra_field, "unexpected fields"))

        sensitive_selection = dict(repository)
        sensitive_selection["selection_reason"] = (
            "Selected from /Users/private/repository for review."
        )
        invalid_documents.append((sensitive_selection, "absolute path"))

        for invalid, expected_error in invalid_documents:
            with self.subTest(expected_error=expected_error):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self._write_manifest(root, [invalid])
                    with self.assertRaisesRegex(EvidenceError, expected_error):
                        load_evidence_directory(root)

    def test_manifest_canonicalizes_github_urls_and_rejects_repository_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = self._repository(1)
            first["repository_url"] = (
                "https://GITHUB.COM/Example/Repository/"
            )
            second = self._repository(2)
            second["repository_url"] = (
                "https://github.com/example/repository"
            )
            self._write_manifest(root, [first, second])

            with self.assertRaisesRegex(
                EvidenceError,
                "duplicate canonical repository identity",
            ):
                load_evidence_directory(root)

        invalid_urls = (
            "https://gitlab.com/example/repository",
            "https://github.com/example/repository?copy=1",
            "https://github.com/example/repository#readme",
            "https://user:password@github.com/example/repository",
            "https://github.com/example/repository/extra",
            "https://github.com/example/repository//",
            "https://github.com/example/repository.git",
            "https://github.com/example/repository name",
        )
        for invalid_url in invalid_urls:
            with self.subTest(url=invalid_url):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    repository = self._repository(1)
                    repository["repository_url"] = invalid_url
                    self._write_manifest(root, [repository])
                    with self.assertRaisesRegex(EvidenceError, "repository_url"):
                        load_evidence_directory(root)

        invalid_consent_urls = (
            "https://github.com/example/repository/issues/1?token=secret",
            "https://github.com/example/repository/issues/1#comment",
            "https://github.com/example/repository/issues/1 bad",
        )
        for invalid_url in invalid_consent_urls:
            with self.subTest(consent_url=invalid_url):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    repository = self._repository(1)
                    repository["consent_url"] = invalid_url
                    self._write_manifest(root, [repository])
                    with self.assertRaisesRegex(EvidenceError, "consent_url"):
                        load_evidence_directory(root)

    def test_manifest_limitations_reject_private_material(self):
        invalid_limitations = (
            [],
            ["Raw result at /Users/alice/private/repository."],
            ["root=/private/repository"],
            ["Use C:\\Users\\alice\\private\\result.json."],
            ["Open file:///Users/alice/private/result.json."],
            ["token=abcdefghijklmnopqrstuvwx"],
            ["line one\nline two"],
        )
        for limitations in invalid_limitations:
            with self.subTest(limitations=limitations):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "public_canary_manifest.json").write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "kind": "public_canary_manifest",
                                "limitations": limitations,
                                "repositories": [],
                            }
                        ),
                        encoding="utf-8",
                    )
                    with self.assertRaises(EvidenceError):
                        load_evidence_directory(root)

    def test_observation_is_privacy_bounded_and_paths_are_relative(self):
        invalid_changes = (
            ({"root": "/private/repository"}, "unexpected fields"),
            ({"evidence": "raw source"}, "unexpected fields"),
        )
        for changes, expected_error in invalid_changes:
            with self.subTest(field=next(iter(changes))):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    repository = self._repository(1)
                    self._write_manifest(root, [repository])
                    observation = self._observation(repository)
                    observation.update(changes)
                    self._write_layer(root, "observation", "one.json", observation)
                    with self.assertRaisesRegex(EvidenceError, expected_error):
                        load_evidence_directory(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = self._repository(1)
            self._write_manifest(root, [repository])
            observation = self._observation(repository)
            observation["findings"][0]["path"] = "/private/repository/AGENTS.md"
            self._write_layer(root, "observation", "one.json", observation)
            with self.assertRaisesRegex(EvidenceError, "relative path"):
                load_evidence_directory(root)

    def test_evidence_json_is_bounded_and_strict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = self._repository(1)
            self._write_manifest(root, [repository])
            observation = self._observation(repository)
            self._write_layer(root, "observation", "one.json", observation)

            with mock.patch(
                "agent_hygiene.evidence.MAX_EVIDENCE_DOCUMENT_BYTES",
                32,
            ):
                with self.assertRaisesRegex(EvidenceError, "byte limit"):
                    load_evidence_directory(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, [])
            layer = root / "observation"
            layer.mkdir()
            (layer / "deep.json").write_text(
                '{"padding":' + "[" * 200 + "0" + "]" * 200 + "}",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EvidenceError, "safe parser limits"):
                load_evidence_directory(root)

    def test_directory_layout_rejects_raw_extra_and_hidden_files(self):
        invalid_entries = (
            ("raw-result.json", "unexpected entry"),
            (".raw.json", "unexpected entry"),
        )
        for name, expected_error in invalid_entries:
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    self._write_manifest(root, [])
                    (root / name).write_text("{}", encoding="utf-8")
                    with self.assertRaisesRegex(EvidenceError, expected_error):
                        load_evidence_directory(root)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_manifest(root, [])
            layer = root / "observation"
            layer.mkdir()
            (layer / ".raw.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "hidden files"):
                load_evidence_directory(root)

    def test_paths_must_be_canonical_posix_relative_paths(self):
        invalid_paths = (
            "./AGENTS.md",
            "nested//AGENTS.md",
            "nested/../AGENTS.md",
        )
        for invalid_path in invalid_paths:
            with self.subTest(path=invalid_path):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    repository = self._repository(1)
                    self._write_manifest(root, [repository])
                    observation = self._observation(repository)
                    observation["findings"][0]["path"] = invalid_path
                    self._write_layer(root, "observation", "one.json", observation)
                    with self.assertRaisesRegex(EvidenceError, "relative path"):
                        load_evidence_directory(root)

    def test_findings_only_precision_is_measured_but_recall_is_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = self._repository(1)
            observation = self._observation(repository)
            review = self._review(
                repository,
                observation,
                reviewer_id="reviewer-a",
                mode="findings-only",
                verdicts=["true-positive"],
            )
            self._write_manifest(root, [repository])
            self._write_layer(root, "observation", "one.json", observation)
            self._write_layer(root, "review", "one.json", review)

            summary = load_evidence_directory(root)

            self.assertEqual(summary["metrics"]["true_positives"], 1)
            self.assertEqual(summary["metrics"]["precision"], 1.0)
            self.assertIsNone(summary["metrics"]["recall"])
            self.assertIsNone(summary["per_rule"]["AH001"]["recall"])
            self.assertFalse(summary["independently_validated"])

    def test_full_surface_metrics_are_recomputed_globally_and_per_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = self._repository(1)
            observation = self._observation(
                repository,
                findings=[
                    {
                        "finding_id": "F001",
                        "rule_id": "AH001",
                        "path": "AGENTS.md",
                        "line": 1,
                    },
                    {
                        "finding_id": "F002",
                        "rule_id": "AH002",
                        "path": "AGENTS.md",
                        "line": 2,
                    },
                ],
            )
            review = self._review(
                repository,
                observation,
                reviewer_id="reviewer-a",
                mode="full-surface",
                verdicts=["true-positive", "false-positive"],
                false_negatives=[
                    {
                        "rule_id": "AH001",
                        "path": "nested/AGENTS.md",
                        "line": 3,
                    }
                ],
            )
            self._write_manifest(root, [repository])
            self._write_layer(root, "observation", "one.json", observation)
            self._write_layer(root, "review", "one.json", review)

            summary = load_evidence_directory(root)

            self.assertEqual(
                summary["metrics"],
                {
                    "true_positives": 1,
                    "false_positives": 1,
                    "false_negatives": 1,
                    "precision": 0.5,
                    "recall": 0.5,
                },
            )
            self.assertEqual(
                summary["per_rule"]["AH001"],
                {
                    "true_positives": 1,
                    "false_positives": 0,
                    "false_negatives": 1,
                    "precision": 1.0,
                    "recall": 0.5,
                },
            )
            self.assertEqual(
                summary["per_rule"]["AH002"],
                {
                    "true_positives": 0,
                    "false_positives": 1,
                    "false_negatives": 0,
                    "precision": 0.0,
                    "recall": None,
                },
            )

    def test_zero_denominators_are_null_even_for_full_surface_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = self._repository(1)
            observation = self._observation(repository, findings=[])
            review = self._review(
                repository,
                observation,
                reviewer_id="reviewer-a",
                mode="full-surface",
                verdicts=[],
                false_negatives=[],
            )
            self._write_manifest(root, [repository])
            self._write_layer(root, "observation", "one.json", observation)
            self._write_layer(root, "review", "one.json", review)

            summary = load_evidence_directory(root)

            self.assertIsNone(summary["metrics"]["precision"])
            self.assertIsNone(summary["metrics"]["recall"])
            self.assertFalse(summary["independently_validated"])

    def test_conflicting_reviews_require_an_adjudication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = self._repository(1)
            observation = self._observation(repository)
            reviews = [
                self._review(
                    repository,
                    observation,
                    reviewer_id="reviewer-a",
                    mode="full-surface",
                    verdicts=["true-positive"],
                    false_negatives=[],
                ),
                self._review(
                    repository,
                    observation,
                    reviewer_id="reviewer-b",
                    mode="full-surface",
                    verdicts=["false-positive"],
                    false_negatives=[],
                ),
            ]
            reviews[1]["review_id"] = "review-reviewer-b"
            self._write_manifest(root, [repository])
            self._write_layer(root, "observation", "one.json", observation)
            self._write_layer(root, "review", "one.json", reviews[0])
            self._write_layer(root, "review", "two.json", reviews[1])

            unresolved = load_evidence_directory(root)

            self.assertEqual(len(unresolved["conflicts"]["unresolved"]), 1)
            self.assertEqual(unresolved["metrics"]["true_positives"], 0)
            self.assertFalse(unresolved["independently_validated"])
            self.assertEqual(
                unresolved["status"],
                "not independently validated",
            )

            adjudication = {
                "schema_version": 1,
                "kind": "adjudication",
                "adjudication_id": "decision-1",
                "repository_id": repository["repository_id"],
                "finding_id": "F001",
                "adjudicator_id": "adjudicator-a",
                "verdict": "true-positive",
            }
            self._write_layer(
                root,
                "adjudication",
                "one.json",
                adjudication,
            )

            resolved = load_evidence_directory(root)

            self.assertEqual(resolved["conflicts"]["resolved"], 1)
            self.assertEqual(resolved["conflicts"]["unresolved"], [])
            self.assertEqual(resolved["metrics"]["true_positives"], 1)

    def test_independent_validation_requires_ten_repositories_and_two_reviewers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repositories = [self._repository(index) for index in range(1, 11)]
            self._write_manifest(root, repositories)
            for index, repository in enumerate(repositories, start=1):
                observation = self._observation(repository)
                observation["result_sha256"] = f"{index:064x}"
                review = self._review(
                    repository,
                    observation,
                    reviewer_id="reviewer-a" if index <= 5 else "reviewer-b",
                    mode="full-surface",
                    verdicts=["true-positive"],
                    false_negatives=[],
                )
                review["review_id"] = f"review-{index}"
                self._write_layer(
                    root,
                    "observation",
                    f"{index:02d}.json",
                    observation,
                )
                self._write_layer(
                    root,
                    "review",
                    f"{index:02d}.json",
                    review,
                )

            summary = load_evidence_directory(root)

            self.assertEqual(summary["repository_count"], 10)
            self.assertEqual(summary["independent_reviewer_count"], 2)
            self.assertEqual(summary["complete_observation_count"], 10)
            self.assertEqual(summary["full_surface_repository_count"], 10)
            self.assertEqual(summary["metrics"]["true_positives"], 10)
            self.assertTrue(summary["independently_validated"])
            self.assertEqual(summary["status"], "independently validated")

    def test_independent_validation_requires_independent_coverage_and_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repositories = [self._repository(index) for index in range(1, 11)]
            self._write_manifest(root, repositories)
            for index, repository in enumerate(repositories, start=1):
                observation = self._observation(repository)
                observation["result_sha256"] = f"{index:064x}"
                review = self._review(
                    repository,
                    observation,
                    reviewer_id="reviewer-a" if index <= 5 else "reviewer-b",
                    mode="full-surface",
                    verdicts=["true-positive"],
                    false_negatives=[],
                )
                review["review_id"] = f"review-{index}"
                if index == 10:
                    review["independent"] = False
                self._write_layer(
                    root,
                    "observation",
                    f"{index:02d}.json",
                    observation,
                )
                self._write_layer(
                    root,
                    "review",
                    f"{index:02d}.json",
                    review,
                )

            summary = load_evidence_directory(root)

            self.assertEqual(summary["metrics"]["precision"], 1.0)
            self.assertEqual(summary["metrics"]["recall"], 1.0)
            self.assertFalse(summary["independently_validated"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repositories = [self._repository(index) for index in range(1, 11)]
            self._write_manifest(root, repositories)
            for index, repository in enumerate(repositories, start=1):
                observation = self._observation(repository, findings=[])
                observation["result_sha256"] = f"{index:064x}"
                review = self._review(
                    repository,
                    observation,
                    reviewer_id="reviewer-a" if index <= 5 else "reviewer-b",
                    mode="full-surface",
                    verdicts=[],
                    false_negatives=[],
                )
                review["review_id"] = f"review-{index}"
                self._write_layer(
                    root,
                    "observation",
                    f"{index:02d}.json",
                    observation,
                )
                self._write_layer(
                    root,
                    "review",
                    f"{index:02d}.json",
                    review,
                )

            summary = load_evidence_directory(root)

            self.assertIsNone(summary["metrics"]["precision"])
            self.assertIsNone(summary["metrics"]["recall"])
            self.assertFalse(summary["independently_validated"])

    def test_review_pack_is_deterministic_and_contains_only_neutral_metadata(self):
        first = build_review_pack(CORPUS_MANIFEST)
        second = build_review_pack(CORPUS_MANIFEST)

        self.assertEqual(first, second)
        self.assertRegex(first["corpus_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(first["cases"][0]["case_id"], "C001")
        self.assertEqual(first["cases"][-1]["case_id"], "C018")
        self.assertEqual(
            set(first["cases"][0]),
            {"case_id", "files"},
        )
        self.assertEqual(
            set(first["cases"][0]["files"][0]),
            {"path", "content"},
        )
        serialized = json.dumps(first, sort_keys=True)
        for forbidden in (
            '"expected"',
            "fixtures/positive",
            "fixtures/negative",
            "hidden-unicode",
            "prompt-override",
            "scanner_output",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_review_pack_digest_does_not_depend_on_labels_or_expectations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture = root / "case.fixture"
            fixture.write_text("review this content\n", encoding="utf-8")
            manifest = root / "manifest.json"

            self._write_corpus_manifest(
                manifest,
                case_id="positive-label",
                expected=[
                    {"rule_id": "AH001", "path": "AGENTS.md", "line": 1}
                ],
            )
            first = build_review_pack(manifest)
            self._write_corpus_manifest(
                manifest,
                case_id="negative-label",
                expected=[],
            )
            second = build_review_pack(manifest)

            self.assertEqual(first["corpus_sha256"], second["corpus_sha256"])
            self.assertEqual(first["cases"], second["cases"])

    def test_review_pack_order_depends_only_on_case_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "first.fixture").write_text("first content\n", encoding="utf-8")
            (root / "second.fixture").write_text("second content\n", encoding="utf-8")
            manifest = root / "manifest.json"
            cases = [
                {
                    "id": "positive-label",
                    "files": [
                        {
                            "source": "first.fixture",
                            "target": "AGENTS.md",
                        }
                    ],
                    "expected": [
                        {"rule_id": "AH001", "path": "AGENTS.md", "line": 1}
                    ],
                },
                {
                    "id": "negative-label",
                    "files": [
                        {
                            "source": "second.fixture",
                            "target": "AGENTS.md",
                        }
                    ],
                    "expected": [],
                },
            ]
            payload = {
                "version": 1,
                "gates": {"min_precision": 1, "min_recall": 1},
                "cases": cases,
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            first = build_review_pack(manifest)
            payload["cases"] = list(reversed(cases))
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            second = build_review_pack(manifest)

            self.assertEqual(first, second)

    def test_review_pack_rejects_source_escape_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corpus = root / "corpus"
            corpus.mkdir()
            (root / "outside.fixture").write_text("outside\n", encoding="utf-8")
            manifest = corpus / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "gates": {"min_precision": 1, "min_recall": 1},
                        "cases": [
                            {
                                "id": "escape",
                                "files": [
                                    {
                                        "source": "../outside.fixture",
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
            with self.assertRaisesRegex(EvidenceError, "relative path"):
                build_review_pack(manifest)

            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["scanner_output"] = []
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "unexpected fields"):
                build_review_pack(manifest)

    def test_review_pack_enforces_evaluation_expectation_contract(self):
        invalid_expected = (
            (
                [{"rule_id": "AH999", "path": "AGENTS.md", "line": 1}],
                "unknown rule",
            ),
            (
                [{"rule_id": "AH001", "path": "CLAUDE.md", "line": 1}],
                "not a case target",
            ),
            (
                [
                    {"rule_id": "AH001", "path": "AGENTS.md", "line": 1},
                    {"rule_id": "AH001", "path": "AGENTS.md", "line": 1},
                ],
                "repeats expected",
            ),
        )
        for expected, expected_error in invalid_expected:
            with self.subTest(expected_error=expected_error):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "case.fixture").write_text("content\n", encoding="utf-8")
                    manifest = root / "manifest.json"
                    self._write_corpus_manifest(
                        manifest,
                        case_id="bounded-case",
                        expected=expected,
                    )
                    with self.assertRaisesRegex(EvidenceError, expected_error):
                        build_review_pack(manifest)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case.fixture").write_text("content\n", encoding="utf-8")
            manifest = root / "manifest.json"
            self._write_corpus_manifest(
                manifest,
                case_id="bounded-case",
                expected=[],
            )
            with mock.patch(
                "agent_hygiene.evidence.MAX_TOTAL_FILE_REFERENCES",
                0,
            ):
                with self.assertRaisesRegex(EvidenceError, "reference limit"):
                    build_review_pack(manifest)

    def test_published_schema_is_strict_json_and_has_all_document_kinds(self):
        schema = json.loads(EVIDENCE_SCHEMA.read_text(encoding="utf-8"))

        self.assertEqual(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        for definition in (
            "public_canary_manifest",
            "observation",
            "review",
            "adjudication",
            "evidence_summary",
            "review_pack",
        ):
            self.assertFalse(schema["$defs"][definition]["additionalProperties"])
        path_pattern = re.compile(schema["$defs"]["relative_path"]["pattern"])
        self.assertIsNotNone(path_pattern.fullmatch("nested/AGENTS.md"))
        for invalid in ("./a", "a//b", "a/../b", "C:/repo/file", "a\tb"):
            self.assertIsNone(path_pattern.fullmatch(invalid))
        repository_pattern = re.compile(
            schema["$defs"]["github_repository_url"]["pattern"]
        )
        https_pattern = re.compile(schema["$defs"]["https_url"]["pattern"])
        self.assertIsNone(
            https_pattern.fullmatch("https://example.com/consent?token=value")
        )
        self.assertIsNone(
            https_pattern.fullmatch("https://example.com/consent path")
        )
        self.assertIsNotNone(
            repository_pattern.fullmatch(
                "https://github.com/example/repository/"
            )
        )
        self.assertIsNone(
            repository_pattern.fullmatch(
                "https://github.com/example/repository?copy=1"
            )
        )
        self.assertIsNone(
            repository_pattern.fullmatch(
                "https://github.com/example/repository.git"
            )
        )
        self.assertEqual(
            schema["$defs"]["public_canary_manifest"]["properties"][
                "limitations"
            ]["minItems"],
            1,
        )
        limitation_schema = schema["$defs"]["safe_public_text"]
        self.assertIsNotNone(
            re.fullmatch(
                limitation_schema["pattern"],
                "No external canary evidence is recorded.",
            )
        )
        for forbidden in limitation_schema["not"]["anyOf"]:
            self.assertIsNotNone(re.compile(forbidden["pattern"]))
        validated_metrics = schema["$defs"]["evidence_summary"]["allOf"][0][
            "then"
        ]["properties"]["metrics"]["properties"]
        self.assertEqual(validated_metrics["precision"]["type"], "number")
        self.assertEqual(validated_metrics["recall"]["type"], "number")
        self.assertEqual(
            schema["$defs"]["review_pack_file"]["properties"]["content"][
                "maxLength"
            ],
            1024 * 1024,
        )

    @staticmethod
    def _repository(index):
        return {
            "repository_id": f"R{index:03d}",
            "repository_url": f"https://github.com/example/repository-{index}",
            "revision": f"{index:040x}",
            "consent_url": (
                f"https://github.com/example/repository-{index}/issues/1"
            ),
            "selection_reason": "Public canary selected with recorded consent.",
        }

    @staticmethod
    def _observation(repository, findings=None):
        if findings is None:
            findings = [
                {
                    "finding_id": "F001",
                    "rule_id": "AH001",
                    "path": "AGENTS.md",
                    "line": 1,
                }
            ]
        return {
            "schema_version": 1,
            "kind": "observation",
            "repository_id": repository["repository_id"],
            "revision": repository["revision"],
            "complete": True,
            "result_sha256": "a" * 64,
            "findings": findings,
        }

    @staticmethod
    def _review(
        repository,
        observation,
        reviewer_id,
        mode,
        verdicts,
        false_negatives=None,
    ):
        review = {
            "schema_version": 1,
            "kind": "review",
            "review_id": "review-reviewer-a",
            "repository_id": repository["repository_id"],
            "reviewer_id": reviewer_id,
            "independent": True,
            "mode": mode,
            "observation_sha256": observation["result_sha256"],
            "judgments": [
                {
                    "finding_id": finding["finding_id"],
                    "verdict": verdict,
                }
                for finding, verdict in zip(observation["findings"], verdicts)
            ],
        }
        if false_negatives is not None:
            review["false_negatives"] = false_negatives
        return review

    @staticmethod
    def _write_manifest(root, repositories):
        (root / "public_canary_manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "public_canary_manifest",
                    "limitations": ["Synthetic contract test evidence only."],
                    "repositories": repositories,
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _write_layer(root, layer, name, document):
        path = root / layer
        path.mkdir(exist_ok=True)
        (path / name).write_text(json.dumps(document), encoding="utf-8")

    @staticmethod
    def _write_corpus_manifest(path, case_id, expected):
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "gates": {"min_precision": 1, "min_recall": 1},
                    "cases": [
                        {
                            "id": case_id,
                            "files": [
                                {
                                    "source": "case.fixture",
                                    "target": "AGENTS.md",
                                }
                            ],
                            "expected": expected,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    unittest.main()
