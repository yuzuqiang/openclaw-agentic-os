from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agentic_os.predicates as predicates
from agentic_os.predicates import (
    INPROC_PREDICATE_BACKEND,
    MAX_FILE_EVIDENCE_BYTES,
    PredicateContext,
    PredicateContractError,
    evaluate_predicate_document,
)


def document(predicate: dict[str, object]) -> dict[str, object]:
    return {"backend": INPROC_PREDICATE_BACKEND, "predicate": predicate}


def make_repo_root(tmp: str) -> Path:
    root = Path(tmp)
    git_dir = root / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (git_dir / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n",
        encoding="utf-8",
    )
    (git_dir / "objects").mkdir()
    (git_dir / "refs").mkdir()
    return root


class PredicateTests(unittest.TestCase):
    def test_boolean_composition_positive_control(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=make_repo_root(tmp))
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
            root = make_repo_root(tmp)
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
                repo_root=make_repo_root(tmp),
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
            context = PredicateContext(repo_root=make_repo_root(tmp))
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
            context = PredicateContext(repo_root=make_repo_root(tmp))
            for predicate in blocked:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "unsupported"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_boolean_composition_validates_children_before_aggregating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=make_repo_root(tmp))
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
            root = make_repo_root(tmp)
            outside_file = Path(outside) / "secret.txt"
            outside_file.write_text("secret\n", encoding="utf-8")
            (root / "link").symlink_to(outside_file)
            context = PredicateContext(repo_root=root)

            for path in ("../secret.txt", str(outside_file), "link"):
                with self.subTest(path=path), self.assertRaisesRegex(
                    PredicateContractError, "repo|symlink evidence"
                ):
                    evaluate_predicate_document(
                        document({"op": "file_exists", "path": path}),
                        context,
                    )

    def test_raw_state_file_paths_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
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

    def test_raw_state_symlink_paths_are_rejected_before_target_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
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
                    PredicateContractError, "symlink evidence"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_file_predicates_reject_symlink_evidence_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            link = root / "evidence-link"
            link.symlink_to(target)
            broken = root / "broken-link"
            broken.symlink_to(root / "missing-target")
            context = PredicateContext(repo_root=root)

            cases = (
                {"op": "file_exists", "path": "evidence-link"},
                {
                    "op": "file_sha256",
                    "path": "evidence-link",
                    "sha256": digest,
                },
                {
                    "op": "not",
                    "predicate": {"op": "file_exists", "path": "broken-link"},
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "symlink evidence"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_credential_file_paths_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
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
                {"op": "file_exists", "path": "prod.env"},
                {"op": "file_exists", "path": "settings.env"},
                {"op": "file_exists", "path": "config/staging.env"},
                {"op": "file_exists", "path": ".env_backup"},
                {"op": "file_exists", "path": ".env-backup"},
                {"op": "file_exists", "path": ".env backup"},
                {"op": "file_exists", "path": ".ssh/id_rsa"},
                {"op": "file_exists", "path": "config/credentials.json"},
                {"op": "file_exists", "path": ".docker/config.json"},
                {"op": "file_exists", "path": ".kube/config"},
                {"op": "file_exists", "path": ".git/config"},
                {"op": "file_exists", "path": "private/customer.json"},
                {"op": "file_exists", "path": "artifacts/private-data.json"},
                {"op": "file_exists", "path": "config/passwords.txt"},
                {"op": "file_exists", "path": "api-key.json"},
                {"op": "file_exists", "path": ".npmrc.bak"},
                {"op": "file_exists", "path": "config/clientSecret.txt"},
                {"op": "file_exists", "path": "state/agentic-os/control.db_backup"},
                {"op": "file_exists", "path": "public-evidence"},
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError,
                    "private credentials or artifacts|private raw state|symlink evidence",
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_hard_linked_private_aliases_are_rejected_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            env_file = root / ".env"
            env_file.write_text("TOKEN=secret\n", encoding="utf-8")
            public_alias = root / "public-evidence"
            try:
                os.link(env_file, public_alias)
            except OSError as exc:
                self.skipTest(f"hard links are unavailable on this filesystem: {exc}")
            digest = hashlib.sha256(env_file.read_bytes()).hexdigest()
            context = PredicateContext(repo_root=root)

            cases = (
                {"op": "file_exists", "path": "public-evidence"},
                {
                    "op": "file_sha256",
                    "path": "public-evidence",
                    "sha256": digest,
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "hard-linked"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_file_exists_stat_failures_are_contract_errors_even_when_negated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            locked_dir = root / "locked"
            locked_dir.mkdir()
            evidence = locked_dir / "evidence.txt"
            evidence.write_text("predicate evidence\n", encoding="utf-8")
            context = PredicateContext(repo_root=root)

            original_stat = os.stat

            def stat_side_effect(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *args: object,
                **kwargs: object,
            ) -> object:
                if Path(path) == evidence:
                    raise PermissionError("permission denied")
                return original_stat(path, *args, **kwargs)

            with mock.patch("os.stat") as stat_mock:
                stat_mock.side_effect = stat_side_effect
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

    def test_file_exists_rejects_swapped_symlink_after_path_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            symlink = root / "swapped-evidence"
            symlink.symlink_to(target)
            context = PredicateContext(repo_root=root)
            original_stat = os.stat

            def stat_side_effect(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *args: object,
                **kwargs: object,
            ) -> object:
                if Path(path) == target and kwargs.get("follow_symlinks") is False:
                    return original_stat(symlink, *args, **kwargs)
                return original_stat(path, *args, **kwargs)

            with mock.patch("os.stat") as stat_mock:
                stat_mock.side_effect = stat_side_effect
                with self.assertRaisesRegex(PredicateContractError, "symlink evidence"):
                    evaluate_predicate_document(
                        document({"op": "file_exists", "path": "evidence.txt"}),
                        context,
                    )

    def test_file_sha256_read_failures_are_contract_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            context = PredicateContext(repo_root=root)

            original_open = os.open

            def open_side_effect(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if Path(path) == target or path == "evidence.txt":
                    raise PermissionError("permission denied")
                return original_open(path, flags, *args, **kwargs)

            with mock.patch("os.open", side_effect=open_side_effect):
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

    def test_file_sha256_revalidates_opened_file_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            replacement = root / "replacement.txt"
            replacement.write_text("different evidence\n", encoding="utf-8")
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            context = PredicateContext(repo_root=root)
            original_open = os.open

            def open_side_effect(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                *args: object,
                **kwargs: object,
            ) -> int:
                if Path(path) == target or path == "evidence.txt":
                    target.unlink()
                    replacement.rename(target)
                return original_open(path, flags, *args, **kwargs)

            with mock.patch("os.open", side_effect=open_side_effect):
                with self.assertRaisesRegex(PredicateContractError, "changed during read"):
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

    def test_file_sha256_rejects_swapped_symlink_after_path_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            parent = root / "safe"
            parent.mkdir()
            target = parent / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            replacement = parent / "replacement.txt"
            replacement.write_text("replacement evidence\n", encoding="utf-8")
            digest = hashlib.sha256(replacement.read_bytes()).hexdigest()
            context = PredicateContext(repo_root=root)

            original_reject = predicates._reject_symlink_evidence_path
            swapped = False

            def reject_then_swap(repo_root: Path, relative_path: Path) -> None:
                nonlocal swapped
                original_reject(repo_root, relative_path)
                if not swapped and relative_path == Path("safe/evidence.txt"):
                    target.unlink()
                    target.symlink_to(replacement)
                    swapped = True

            with mock.patch.object(
                predicates,
                "_reject_symlink_evidence_path",
                side_effect=reject_then_swap,
            ):
                with self.assertRaises(PredicateContractError):
                    evaluate_predicate_document(
                        document(
                            {
                                "op": "file_sha256",
                                "path": "safe/evidence.txt",
                                "sha256": digest,
                            }
                        ),
                        context,
                    )

    def test_file_predicates_recheck_parent_components_at_use(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            parent = root / "safe"
            parent.mkdir()
            target = parent / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            outside = root / "other"
            outside.mkdir()
            (outside / "evidence.txt").write_text("other evidence\n", encoding="utf-8")
            context = PredicateContext(repo_root=root)

            original_reject = predicates._reject_symlink_evidence_path
            swapped = False

            def reject_then_swap(repo_root: Path, relative_path: Path) -> None:
                nonlocal swapped
                original_reject(repo_root, relative_path)
                if not swapped and relative_path == Path("safe/evidence.txt"):
                    target.unlink()
                    parent.rmdir()
                    parent.symlink_to(outside, target_is_directory=True)
                    swapped = True

            with mock.patch.object(
                predicates,
                "_reject_symlink_evidence_path",
                side_effect=reject_then_swap,
            ):
                with self.assertRaises(PredicateContractError):
                    evaluate_predicate_document(
                        document({"op": "file_exists", "path": "safe/evidence.txt"}),
                        context,
                    )

    def test_file_sha256_rechecks_size_cap_while_streaming(self) -> None:
        class GrowingHandle:
            def __init__(self) -> None:
                self._chunks = [b"a" * MAX_FILE_EVIDENCE_BYTES, b"b"]

            def read(self, _size: int) -> bytes:
                if not self._chunks:
                    return b""
                return self._chunks.pop(0)

            def __enter__(self) -> "GrowingHandle":
                return self

            def __exit__(self, *_exc: object) -> None:
                return None

        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            target = root / "evidence.txt"
            target.write_text("predicate evidence\n", encoding="utf-8")
            checked_stat = os.stat(target, follow_symlinks=False)
            context = PredicateContext(repo_root=root)

            with (
                mock.patch(
                    "agentic_os.predicates._repo_path_stat",
                    return_value=checked_stat,
                ),
                mock.patch(
                    "agentic_os.predicates._open_parent_directory_nofollow",
                    return_value=(98, "evidence.txt"),
                ),
                mock.patch("os.open", return_value=99),
                mock.patch("os.fstat", return_value=checked_stat),
                mock.patch("os.fdopen", return_value=GrowingHandle()),
                mock.patch("os.close"),
            ):
                with self.assertRaisesRegex(PredicateContractError, "size limit"):
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

    def test_file_sha256_missing_or_non_regular_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            directory = root / "directory"
            directory.mkdir()
            context = PredicateContext(repo_root=root)
            predicates = (
                {
                    "op": "not",
                    "predicate": {
                        "op": "file_sha256",
                        "path": "missing.txt",
                        "sha256": "0" * 64,
                    },
                },
                {
                    "op": "file_sha256",
                    "path": "directory",
                    "sha256": "0" * 64,
                },
            )
            for predicate in predicates:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "regular file"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_file_sha256_streams_under_size_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            target = root / "large-evidence.bin"
            with target.open("wb") as handle:
                handle.seek(MAX_FILE_EVIDENCE_BYTES + 1)
                handle.write(b"\0")
            context = PredicateContext(repo_root=root)

            with self.assertRaisesRegex(PredicateContractError, "size limit"):
                evaluate_predicate_document(
                    document(
                        {
                            "op": "file_sha256",
                            "path": "large-evidence.bin",
                            "sha256": "0" * 64,
                        }
                    ),
                    context,
                )

    def test_repo_root_must_be_git_worktree_top_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(PredicateContractError, "Git worktree"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=Path(tmp)),
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            subdir = root / "subdir"
            subdir.mkdir()

            with self.assertRaisesRegex(PredicateContractError, "Git worktree"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=subdir),
                )

        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp)
            (fake_root / ".git").mkdir()
            with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=fake_root),
                )

        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp)
            git_dir = fake_root / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("not a valid head\n", encoding="utf-8")
            (git_dir / "config").write_text(
                "[core]\n\trepositoryformatversion = 0\n",
                encoding="utf-8",
            )
            (git_dir / "objects").mkdir()
            (git_dir / "refs").mkdir()
            with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=fake_root),
                )

        with tempfile.TemporaryDirectory() as tmp:
            fake_root = Path(tmp)
            git_dir = fake_root / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git_dir / "config").write_text(
                "[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
                encoding="utf-8",
            )
            (git_dir / "objects").mkdir()
            (git_dir / "refs").mkdir()
            with self.assertRaisesRegex(PredicateContractError, "Git worktree"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=fake_root),
                )

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            owner_dir = base / "owner"
            owner_dir.mkdir()
            owner_root = make_repo_root(str(owner_dir))
            borrowed_root = base / "borrowed"
            borrowed_root.mkdir()
            (borrowed_root / ".git").symlink_to(owner_root / ".git")
            with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=borrowed_root),
                )

        with tempfile.TemporaryDirectory() as tmp:
            fake_root = make_repo_root(tmp)
            (fake_root / ".git" / "HEAD").write_bytes(b"\xff\xfe\x00")
            with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=fake_root),
                )

    def test_sha1_detached_head_git_worktree_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            (root / ".git" / "HEAD").write_text("a" * 40 + "\n", encoding="utf-8")

            self.assertTrue(
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=root),
                )
            )

    def test_gitdir_file_must_bind_core_worktree_to_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            linked_root = base / "linked-root"
            linked_root.mkdir()
            borrowed_root = base / "borrowed-root"
            borrowed_root.mkdir()
            other_root = base / "other-root"
            other_root.mkdir()
            git_dir = base / "gitdir"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git_dir / "objects").mkdir()
            (git_dir / "refs").mkdir()

            def write_gitdir_config(worktree: Path) -> None:
                (git_dir / "config").write_text(
                    "[core]\n"
                    "\trepositoryformatversion = 0\n"
                    f"\tworktree = {worktree}\n",
                    encoding="utf-8",
                )

            write_gitdir_config(linked_root)
            (linked_root / ".git").write_text(f"gitdir: {git_dir}\n", encoding="utf-8")
            self.assertTrue(
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=linked_root),
                )
            )

            write_gitdir_config(other_root)
            (borrowed_root / ".git").write_text(f"gitdir: {git_dir}\n", encoding="utf-8")
            with self.assertRaisesRegex(PredicateContractError, "core.worktree"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=borrowed_root),
                )

    def test_directory_git_config_core_worktree_must_bind_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            other = root / "other-root"
            other.mkdir()
            (root / ".git" / "config").write_text(
                "[core]\n"
                "\trepositoryformatversion = 0\n"
                f"\tworktree = {other}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PredicateContractError, "core.worktree"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=root),
                )

    def test_git_metadata_rejects_symlinked_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for entry_name, target_content in (
                ("HEAD", "ref: refs/heads/main\n"),
                ("config", "[core]\n\trepositoryformatversion = 0\n"),
            ):
                with self.subTest(entry_name=entry_name):
                    root_dir = Path(tmp) / entry_name
                    root_dir.mkdir()
                    root = make_repo_root(str(root_dir))
                    target = root.parent / f"{entry_name}-target"
                    target.write_text(target_content, encoding="utf-8")
                    metadata_entry = root / ".git" / entry_name
                    metadata_entry.unlink()
                    metadata_entry.symlink_to(target)

                    with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                        evaluate_predicate_document(
                            document({"op": "literal", "value": True}),
                            PredicateContext(repo_root=root),
                        )

            for entry_name in ("objects", "refs"):
                with self.subTest(entry_name=entry_name):
                    root_dir = Path(tmp) / f"{entry_name}-dir"
                    root_dir.mkdir()
                    root = make_repo_root(str(root_dir))
                    target_dir = root.parent / f"{entry_name}-target"
                    target_dir.mkdir()
                    metadata_entry = root / ".git" / entry_name
                    metadata_entry.rmdir()
                    metadata_entry.symlink_to(target_dir, target_is_directory=True)

                    with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                        evaluate_predicate_document(
                            document({"op": "literal", "value": True}),
                            PredicateContext(repo_root=root),
                        )

    def test_git_metadata_repository_format_version_must_be_supported_integer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            for value in ("nope", "1"):
                with self.subTest(value=value):
                    (root / ".git" / "config").write_text(
                        f"[core]\n\trepositoryformatversion = {value}\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                        evaluate_predicate_document(
                            document({"op": "literal", "value": True}),
                            PredicateContext(repo_root=root),
                        )

    def test_linked_worktree_rejects_empty_commondir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            common_dir = base / "main" / ".git"
            common_dir.mkdir(parents=True)
            (common_dir / "config").write_text(
                "[core]\n\trepositoryformatversion = 0\n",
                encoding="utf-8",
            )
            (common_dir / "objects").mkdir()
            (common_dir / "refs").mkdir()

            linked_root = base / "linked-root"
            linked_root.mkdir()
            git_dir = common_dir / "worktrees" / "linked-root"
            git_dir.mkdir(parents=True)
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git_dir / "commondir").write_text("\n", encoding="utf-8")
            (git_dir / "gitdir").write_text(
                str(linked_root / ".git") + "\n",
                encoding="utf-8",
            )
            (linked_root / ".git").write_text(
                f"gitdir: {git_dir}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PredicateContractError, "Git metadata"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=linked_root),
                )

    def test_standard_linked_worktree_gitdir_file_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            common_dir = base / "main" / ".git"
            common_dir.mkdir(parents=True)
            (common_dir / "config").write_text(
                "[core]\n\trepositoryformatversion = 0\n",
                encoding="utf-8",
            )
            (common_dir / "objects").mkdir()
            (common_dir / "refs").mkdir()

            linked_root = base / "linked-root"
            linked_root.mkdir()
            git_dir = common_dir / "worktrees" / "linked-root"
            git_dir.mkdir(parents=True)
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git_dir / "commondir").write_text("../..\n", encoding="utf-8")
            (git_dir / "gitdir").write_text(
                str(linked_root / ".git") + "\n",
                encoding="utf-8",
            )
            (linked_root / ".git").write_text(
                f"gitdir: {git_dir}\n",
                encoding="utf-8",
            )

            self.assertTrue(
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=linked_root),
                )
            )

    def test_linked_worktree_gitdir_file_must_bind_repo_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            common_dir = base / "main" / ".git"
            common_dir.mkdir(parents=True)
            (common_dir / "config").write_text(
                "[core]\n\trepositoryformatversion = 0\n",
                encoding="utf-8",
            )
            (common_dir / "objects").mkdir()
            (common_dir / "refs").mkdir()

            linked_root = base / "linked-root"
            linked_root.mkdir()
            borrowed_root = base / "borrowed-root"
            borrowed_root.mkdir()
            git_dir = common_dir / "worktrees" / "linked-root"
            git_dir.mkdir(parents=True)
            (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (git_dir / "commondir").write_text("../..\n", encoding="utf-8")
            (git_dir / "gitdir").write_text(
                str(linked_root / ".git") + "\n",
                encoding="utf-8",
            )
            (borrowed_root / ".git").write_text(
                f"gitdir: {git_dir}\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PredicateContractError, "gitdir file"):
                evaluate_predicate_document(
                    document({"op": "literal", "value": True}),
                    PredicateContext(repo_root=borrowed_root),
                )

    def test_missing_json_path_fails_closed_even_when_negated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(
                repo_root=make_repo_root(tmp),
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
                repo_root=make_repo_root(tmp),
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

    def test_sensitive_json_and_command_evidence_names_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(
                repo_root=make_repo_root(tmp),
                json_documents={
                    "manifest": {
                        "password": "secret",
                        "nested": {"api_key": "secret"},
                        "camel": {"clientSecret": "secret"},
                    },
                    "secret-manifest": {"status": "pass"},
                },
                command_results={
                    "unit": {
                        "password": "secret",
                        "api_key": "secret",
                        "accessToken": "secret",
                    },
                    "secret-check": {"exit_code": 0},
                },
            )
            cases = (
                {
                    "op": "json_equals",
                    "document": "secret-manifest",
                    "path": ["status"],
                    "value": "pass",
                },
                {
                    "op": "json_equals",
                    "document": "manifest",
                    "path": ["password"],
                    "value": "secret",
                },
                {
                    "op": "json_equals",
                    "document": "manifest",
                    "path": ["nested", "api_key"],
                    "value": "secret",
                },
                {
                    "op": "json_equals",
                    "document": "manifest",
                    "path": ["camel", "clientSecret"],
                    "value": "secret",
                },
                {
                    "op": "command_result_equals",
                    "id": "secret-check",
                    "field": "exit_code",
                    "value": 0,
                },
                {
                    "op": "command_result_equals",
                    "id": "unit",
                    "field": "password",
                    "value": "secret",
                },
                {
                    "op": "command_result_equals",
                    "id": "unit",
                    "field": "api_key",
                    "value": "secret",
                },
                {
                    "op": "command_result_equals",
                    "id": "unit",
                    "field": "accessToken",
                    "value": "secret",
                },
            )
            for predicate in cases:
                with self.subTest(predicate=predicate), self.assertRaisesRegex(
                    PredicateContractError, "private credentials or artifacts"
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_malformed_evidence_maps_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_repo_root(tmp)
            cases = (
                (
                    PredicateContext(repo_root=root, json_documents=None),  # type: ignore[arg-type]
                    {
                        "op": "json_equals",
                        "document": "manifest",
                        "path": ["status"],
                        "value": "pass",
                    },
                    "JSON evidence map",
                ),
                (
                    PredicateContext(repo_root=root, command_results=None),  # type: ignore[arg-type]
                    {
                        "op": "command_result_equals",
                        "id": "unit",
                        "field": "exit_code",
                        "value": 0,
                    },
                    "command result evidence map",
                ),
            )
            for context, predicate, message in cases:
                with self.subTest(message=message), self.assertRaisesRegex(
                    PredicateContractError, message
                ):
                    evaluate_predicate_document(document(predicate), context)

    def test_missing_evidence_and_malformed_values_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            context = PredicateContext(repo_root=make_repo_root(tmp), json_documents={})
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
