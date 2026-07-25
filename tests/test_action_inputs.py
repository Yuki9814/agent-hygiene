import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = REPOSITORY_ROOT / "tools" / "validate_action_inputs.py"
SPEC = importlib.util.spec_from_file_location("validate_action_inputs", VALIDATOR_PATH)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class ActionInputTests(unittest.TestCase):
    def test_valid_inputs_are_normalized_inside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            (workspace / "baseline.json").write_text("{}", encoding="utf-8")

            values = VALIDATOR.validate(
                workspace,
                {
                    "path": ".",
                    "min_score": "085",
                    "fail_on": "high",
                    "baseline": "baseline.json",
                    "sarif": "report.sarif",
                },
            )

            self.assertEqual(values["path"], str(workspace.resolve()))
            self.assertEqual(values["min_score"], "85")
            self.assertEqual(values["baseline"], str((workspace / "baseline.json").resolve()))
            self.assertEqual(values["sarif"], str((workspace / "report.sarif").resolve()))

    def test_score_and_severity_are_strictly_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            common = {
                "path": ".",
                "baseline": "",
                "sarif": "",
                "fail_on": "high",
                "min_score": "85; echo unsafe",
            }
            with self.assertRaisesRegex(VALIDATOR.InputError, "min-score"):
                VALIDATOR.validate(workspace, common)

            common["min_score"] = "85"
            common["fail_on"] = "HIGH"
            with self.assertRaisesRegex(VALIDATOR.InputError, "fail-on"):
                VALIDATOR.validate(workspace, common)

    def test_paths_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            values = {
                "path": str(workspace.parent),
                "min_score": "85",
                "fail_on": "high",
                "baseline": "",
                "sarif": "",
            }

            with self.assertRaisesRegex(VALIDATOR.InputError, "inside"):
                VALIDATOR.validate(workspace, values)

    @unittest.skipIf(os.name == "nt", "symlink behavior differs on Windows")
    def test_baseline_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            target = workspace / "real.json"
            target.write_text("{}", encoding="utf-8")
            (workspace / "baseline.json").symlink_to(target)
            values = {
                "path": ".",
                "min_score": "85",
                "fail_on": "high",
                "baseline": "baseline.json",
                "sarif": "",
            }

            with self.assertRaisesRegex(VALIDATOR.InputError, "regular file"):
                VALIDATOR.validate(workspace, values)

    def test_shell_syntax_in_input_is_data_and_is_not_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            output = workspace / "github-output"
            output.write_text("", encoding="utf-8")
            sentinel = workspace / "should-not-exist"
            env = dict(os.environ)
            env.update(
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "AGENT_HYGIENE_INPUT_PATH": f"$(touch {sentinel})",
                    "AGENT_HYGIENE_INPUT_MIN_SCORE": "85",
                    "AGENT_HYGIENE_INPUT_FAIL_ON": "high",
                    "AGENT_HYGIENE_INPUT_SARIF": "",
                    "AGENT_HYGIENE_INPUT_BASELINE": "",
                }
            )

            completed = subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), str(output)],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertFalse(sentinel.exists())

    def test_action_run_blocks_do_not_interpolate_inputs(self):
        action = (REPOSITORY_ROOT / "action.yml").read_text(encoding="utf-8")

        self.assertNotRegex(action, re.compile(r"run:.*\$\{\{\s*inputs\."))
        run_block = action.split("run: |", 1)[1].split("\nbranding:", 1)[0]
        self.assertNotIn("${{ inputs.", run_block)

    def test_repository_workflows_pin_actions_to_full_commits(self):
        workflows = REPOSITORY_ROOT / ".github" / "workflows"
        references = []
        for workflow in workflows.glob("*.yml"):
            workflow_text = workflow.read_text(encoding="utf-8")
            references.extend(
                (workflow.name, action, reference)
                for action, reference in re.findall(
                    r"uses:\s+([^@\s]+)@([^\s#]+)", workflow_text
                )
            )

        self.assertGreater(len(references), 0)
        for workflow, action, reference in references:
            if (
                workflow == "action-consumer-smoke.yml"
                and action == "Yuki9814/agent-hygiene"
            ):
                self.assertRegex(reference, r"\Av[0-9]+\.[0-9]+\.[0-9]+\Z")
                continue
            self.assertRegex(reference, r"\A[0-9a-f]{40}\Z")

    def test_release_workflow_ignores_floating_major_tag(self):
        release = (
            REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('- "v*.*.*"', release)
        self.assertNotIn('- "v*"\n', release)
        self.assertNotIn("gh release upload", release)
        self.assertNotIn("--clobber", release)
        self.assertIn("permissions:\n  contents: read", release)
        release_job = release.split("\n  github-release:", 1)[1]
        self.assertIn("needs: verify", release_job)
        self.assertIn("contents: write", release_job)
        self.assertNotIn("actions/checkout", release_job)
        self.assertNotIn("python ", release_job)


if __name__ == "__main__":
    unittest.main()
