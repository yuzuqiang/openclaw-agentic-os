from __future__ import annotations

import json
import unittest

from agentic_os.migrations import repository_root


class CIContractTests(unittest.TestCase):
    def test_agentic_os_ci_check_identity_and_required_commands_are_pinned(self) -> None:
        root = repository_root()
        contract = json.loads(
            (root / ".github/agentic-os-ci-contract.json").read_text(encoding="utf-8")
        )
        workflow = (root / ".github/workflows/agentic-os-ci.yml").read_text(
            encoding="utf-8"
        )

        required_check = contract["required_check"]
        self.assertEqual(required_check["workflow_name"], "agentic-os-ci")
        self.assertEqual(required_check["job_id"], "agentic-os-ci")
        self.assertEqual(required_check["job_name"], "agentic-os-ci")

        self.assertRegex(workflow, r"(?m)^name: agentic-os-ci$")
        self.assertRegex(workflow, r"(?m)^  pull_request:\s*$")
        self.assertRegex(workflow, r"(?m)^  push:\s*$")
        self.assertRegex(workflow, r"(?m)^      - main$")
        self.assertRegex(workflow, r"(?m)^  agentic-os-ci:\s*$")
        self.assertRegex(workflow, r"(?m)^    name: agentic-os-ci$")

        for step in contract["required_steps"]:
            with self.subTest(step=step["name"]):
                self.assertIn(f"- name: {step['name']}", workflow)
                self.assertIn(f"run: {step['command']}", workflow)

    def test_agentic_os_ci_contract_has_no_empty_required_identity(self) -> None:
        contract = json.loads(
            (
                repository_root() / ".github/agentic-os-ci-contract.json"
            ).read_text(encoding="utf-8")
        )
        required_check = contract["required_check"]
        for key in ("workflow_name", "job_id", "job_name"):
            with self.subTest(key=key):
                self.assertRegex(required_check[key], r"\S")

        commands = [step["command"] for step in contract["required_steps"]]
        self.assertEqual(len(commands), len(set(commands)))
        self.assertTrue(any("unittest discover -s tests" in command for command in commands))
        self.assertTrue(any("compileall" in command for command in commands))
        self.assertTrue(any("git diff --check" == command for command in commands))


if __name__ == "__main__":
    unittest.main()
