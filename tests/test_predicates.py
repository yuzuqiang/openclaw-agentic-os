from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from agentic_os.predicates import (
    INPROC_PREDICATE_BACKEND,
    PredicateContext,
    PredicateContractError,
    evaluate_predicate_document,
)


def document(predicate: dict[str, object]) -> dict[str, object]:
    return {"backend": INPROC_PREDICATE_BACKEND, "predicate": predicate}


class PredicateTests(unittest.TestCase):
    def test_boolean_composition_positive_control(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=Path(tmp))
            self.assertTrue(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "all",
                            "predicates": [
                                {"op": "literal", "value": True},
                                {
                                    "op": "not",
                                    "predicate": {"op": "literal", "value": False},
                                },
                                {
                                    "op": "any",
                                    "predicates": [
                                        {"op": "literal", "value": False},
                                        {"op": "literal", "value": True},
                                    ],
                                },
                            ],
                        }
                    ),
                    context,
                )
            )

    def test_repo_bounded_file_exists_and_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            context = PredicateContext(repo_root=root)

            self.assertTrue(
                evaluate_predicate_document(
                    document({"op": "file_exists", "path": "evidence.txt"}),
                    context,
                )
            )
            self.assertTrue(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "file_sha256",
                            "path": "evidence.txt",
                            "sha256": digest,
                        }
                    ),
                    context,
                )
            )
            self.assertFalse(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "file_sha256",
                            "path": "evidence.txt",
                            "sha256": "0" * 64,
                        }
                    ),
                    context,
                )
            )

    def test_json_and_command_evidence_are_caller_supplied(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(
                repo_root=Path(tmp),
                json_documents={"manifest": {"gate": {"status": "pass"}, "items": [7]}},
                command_results={
                    "unit": {"exit_code": 0, "stdout_sha256": "a" * 64}
                },
            )

            self.assertTrue(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "json_equals",
                            "document": "manifest",
                            "path": ["gate", "status"],
                            "value": "pass",
                        }
                    ),
                    context,
                )
            )
            self.assertTrue(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "json_equals",
                            "document": "manifest",
                            "path": ["items", 0],
                            "value": 7,
                        }
                    ),
                    context,
                )
            )
            self.assertTrue(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "command_result_equals",
                            "id": "unit",
                            "field": "exit_code",
                            "value": 0,
                        }
                    ),
                    context,
                )
            )
            self.assertFalse(
                evaluate_predicate_document(
                    document(
                        {
                            "op": "json_equals",
                            "document": "manifest",
                            "path": ["gate", "status"],
                            "value": "fail",
                        }
                    ),
                    context,
                )
            )

    def test_unsupported_backend_and_extra_keys_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=Path(tmp))
            for malformed_document in (None, ["backend", "predicate"]):
                with self.subTest(document=malformed_document), self.assertRaisesRegex(
                    PredicateContractError, "JSON object"
                ):
                    evaluate_predicate_document(malformed_document, context)  # type: ignore[arg-type]
            with self.assertRaisesRegex(PredicateContractError, "unsupported"):
                evaluate_predicate_document(
                    {"backend": "agentic_predicate_external_sandbox_v1", "predicate": {}},
                    context,
                )
            with self.assertRaisesRegex(PredicateContractError, "exactly"):
                evaluate_predicate_document(
                    {
                        "backend": INPROC_PREDICATE_BACKEND,
                        "predicate": {"op": "literal", "value": True},
                        "approval_id": "broad-approval",
                    },
                    context,
                )

    def test_malicious_or_sensitive_adapters_are_rejected(self) -> None:
        blocked = (
            {"op": "eval", "source": "True"},
            {"op": "exec", "source": "x=1"},
            {"op": "subprocess", "argv": ["true"]},
            {"op": "shell", "command": "true"},
            {"op": "network", "url": "https://example.invalid"},
            {"op": "env", "name": "HOME"},
            {"op": "write_file", "path": "out.txt", "content": "x"},
            {"op": "sql_query", "query": "select 1"},
            {"op": "time_window", "start": 1, "end": 2},
        )
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=Path(tmp))
            for predicate in blocked:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "unsupported"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_boolean_composition_validates_children_before_aggregating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=Path(tmp))
            cases = (
                {
                    "op": "any",
                    "predicates": [
                        {"op": "literal", "value": True},
                        {"op": "shell", "command": "true"},
                    ],
                },
                {
                    "op": "all",
                    "predicates": [
                        {"op": "literal", "value": False},
                        {"op": "network", "url": "https://example.invalid"},
                    ],
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "unsupported"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_path_traversal_absolute_and_symlink_escape_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            outside_file = Path(outside) / "secret.txt"
            outside_file.write_text("secret\n", encoding="utf-8")
            (root / "link").symlink_to(outside_file)
            context = PredicateContext(repo_root=root)

            for path in ("../secret.txt", str(outside_file), "link"):
                with self.subTest(path=path), self.assertRaisesRegex(
                    PredicateContractError, "repo"
                ):
                    evaluate_predicate_document(
                        document({"op": "file_exists", "path": path}),
                        context,
                    )

    def test_raw_state_file_paths_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state" / "agentic-os"
            state.mkdir(parents=True)
            raw_state = state / "control.db"
            raw_state.write_bytes(b"private sqlite bytes")
            digest = hashlib.sha256(raw_state.read_bytes()).hexdigest()
            context = PredicateContext(repo_root=root)

            cases = (
                {"op": "file_exists", "path": "state/agentic-os/control.db"},
                {
                    "op": "file_sha256",
                    "path": "state/agentic-os/control.db",
                    "sha256": digest,
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "private raw state"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_resolved_raw_state_symlink_paths_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state" / "agentic-os"
            state.mkdir(parents=True)
            raw_state = state / "control.db"
            raw_state.write_bytes(b"private sqlite bytes")
            digest = hashlib.sha256(raw_state.read_bytes()).hexdigest()
            link = root / "apparently-safe-evidence"
            link.symlink_to(raw_state)
            context = PredicateContext(repo_root=root)

            cases = (
                {"op": "file_exists", "path": "apparently-safe-evidence"},
                {
                    "op": "file_sha256",
                    "path": "apparently-safe-evidence",
                    "sha256": digest,
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "private raw state"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_credential_file_paths_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = root / ".env"
            env_file.write_text("TOKEN=secret\n", encoding="utf-8")
            ssh_dir = root / ".ssh"
            ssh_dir.mkdir()
            ssh_key = ssh_dir / "id_rsa"
            ssh_key.write_text("private key\n", encoding="utf-8")
            env_link = root / "public-evidence"
            env_link.symlink_to(env_file)
            digest = hashlib.sha256(env_file.read_bytes()).hexdigest()
            context = PredicateContext(repo_root=root)

            cases = (
                {"op": "file_exists", "path": ".env"},
                {
                    "op": "file_sha256",
                    "path": ".env",
                    "sha256": digest,
                },
                {"op": "file_exists", "path": ".ssh/id_rsa"},
                {"op": "file_exists", "path": "config/credentials.json"},
                {"op": "file_exists", "path": "public-evidence"},
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "private credentials"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_file_exists_stat_failures_are_contract_errors_even_when_negated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            locked_dir = root / "locked"
            locked_dir.mkdir()
            evidence = locked_dir / "evidence.txt"
            evidence.write_text("predicate evidence\n", encoding="utf-8")
            locked_dir.chmod(0)
            context = PredicateContext(repo_root=root)
            try:
                with self.assertRaises(PredicateContractError):
                    evaluate_predicate_document(
                        document(
                            {
                                "op": "not",
                                "predicate": {
                                    "op": "file_exists",
                                    "path": "locked/evidence.txt",
                                },
                            }
                        ),
                        context,
                    )
            finally:
                locked_dir.chmod(0o700)

    def test_file_sha256_read_failures_are_contract_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            target.chmod(0)
            context = PredicateContext(repo_root=root)
            try:
                with self.assertRaisesRegex(PredicateContractError, "cannot be read"):
                    evaluate_predicate_document(
                        document(
                            {
                                "op": "file_sha256",
                                "path": "evidence.txt",
                                "sha256": "0" * 64,
                            }
                        ),
                        context,
                    )
            finally:
                target.chmod(0o600)

    def test_missing_json_path_fails_closed_even_when_negated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(
                repo_root=Path(tmp),
                json_documents={"manifest": {"gate": {"status": "pass"}}},
            )
            with self.assertRaisesRegex(PredicateContractError, "path is missing"):
                evaluate_predicate_document(
                    document(
                        {
                            "op": "not",
                            "predicate": {
                                "op": "json_equals",
                                "document": "manifest",
                                "path": ["gate", "missing"],
                                "value": "pass",
                            },
                        }
                    ),
                    context,
                )

    def test_json_and_command_scalar_type_mismatches_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(
                repo_root=Path(tmp),
                json_documents={"manifest": {"exit_code": False}},
                command_results={"unit": {"exit_code": True}},
            )
            cases = (
                {
                    "op": "json_equals",
                    "document": "manifest",
                    "path": ["exit_code"],
                    "value": 0,
                },
                {
                    "op": "command_result_equals",
                    "id": "unit",
                    "field": "exit_code",
                    "value": 1,
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "type mismatch"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_missing_evidence_and_malformed_values_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=Path(tmp), json_documents={})
            cases = (
                {"op": "literal", "value": "true"},
                {"op": "all", "predicates": []},
                {
                    "op": "file_sha256",
                    "path": "missing",
                    "sha256": "not-a-sha",
                },
                {
                    "op": "json_equals",
                    "document": "missing",
                    "path": ["status"],
                    "value": "pass",
                },
                {
                    "op": "command_result_equals",
                    "id": "missing",
                    "field": "exit_code",
                    "value": 0,
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaises(
                    PredicateContractError
                ):
                    evaluate_predicate_document(document(predicate), context)


if __name__ == "__main__":
    unittest.main()
