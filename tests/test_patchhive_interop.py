import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = REPOSITORY_ROOT / "tools" / "generate_patchhive_fixture.py"
SPEC = importlib.util.spec_from_file_location(
    "generate_patchhive_fixture",
    GENERATOR_PATH,
)
GENERATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GENERATOR)


class PatchHiveInteropTests(unittest.TestCase):
    def test_committed_fixtures_match_the_portable_report_contract(self):
        fixture_directory = REPOSITORY_ROOT / "examples" / "patchhive"

        for case in ("findings", "clean-rerun"):
            with self.subTest(case=case):
                expected = GENERATOR.generate_fixture(case)
                fixture_path = fixture_directory / f"{case}.json"
                actual = fixture_path.read_text(encoding="utf-8")

                self.assertEqual(actual, expected)
                payload = json.loads(actual)
                self.assertNotIn("root", payload["summary"])
                self.assertEqual(
                    payload["summary"]["source_revision"],
                    GENERATOR.SOURCE_REVISIONS[case],
                )
                self.assertRegex(
                    hashlib.sha256(actual.encode("utf-8")).hexdigest(),
                    r"\A[0-9a-f]{64}\Z",
                )


if __name__ == "__main__":
    unittest.main()
