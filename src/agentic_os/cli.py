"""Command-line probes for the P0 foundation."""

from __future__ import annotations

import argparse
from pathlib import Path

from .db_authority_canary import (
    db_authority_canary_artifact,
    rollback_db_authority_canary,
)
from .db_authority_controller import (
    proof_json,
    rollback_synthetic_db_authority_expansion,
    run_synthetic_db_authority_expansion,
)
from .migrations import apply_migrations, repository_root, verify_database
from .privacy import assert_paths_retrievable, assert_privacy_preflight
from .shadow import (
    audit_dual_write_shadow,
    audit_file_authority_shadow,
    backfill_file_authority_shadow,
    dual_write_shadow_artifact,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="agentic-os")
    commands = result.add_subparsers(dest="command", required=True)

    preflight = commands.add_parser("preflight", help="verify fail-closed privacy guards")
    preflight.add_argument("--repo-root", type=Path, default=repository_root())

    migrate = commands.add_parser("migrate", help="apply pinned schema migrations")
    target = migrate.add_mutually_exclusive_group(required=True)
    target.add_argument("--db", type=Path)
    target.add_argument(
        "--test-db",
        action="store_true",
        help="use ignored repo-local state/agentic-os/test-control.db",
    )
    migrate.add_argument("--repo-root", type=Path, default=repository_root())

    verify = commands.add_parser("verify", help="verify an existing migrated database")
    verify.add_argument("--db", type=Path, required=True)

    shadow_backfill = commands.add_parser(
        "shadow-backfill", help="backfill explicit artifacts as file-authority shadow"
    )
    shadow_backfill.add_argument("--db", type=Path, required=True)
    shadow_backfill.add_argument("--workflow", required=True)
    shadow_backfill.add_argument("--run-id", required=True)
    shadow_backfill.add_argument("--prepare-idempotency-key")
    shadow_backfill.add_argument("--artifact", type=Path, action="append", required=True)
    shadow_backfill.add_argument("--repo-root", type=Path, default=repository_root())

    shadow_audit = commands.add_parser(
        "shadow-audit", help="audit file-authority shadow projection parity"
    )
    shadow_audit.add_argument("--db", type=Path, required=True)
    shadow_audit.add_argument("--workflow", required=True)
    shadow_audit.add_argument("--run-id", required=True)
    shadow_audit.add_argument("--prepare-idempotency-key")
    shadow_audit.add_argument("--artifact", type=Path, action="append", required=True)
    shadow_audit.add_argument("--repo-root", type=Path, default=repository_root())

    dual_write = commands.add_parser(
        "dual-write-shadow", help="write a file artifact plus dual-write shadow evidence"
    )
    dual_write.add_argument("--db", type=Path, required=True)
    dual_write.add_argument("--workflow", required=True)
    dual_write.add_argument("--run-id", required=True)
    dual_write.add_argument("--prepare-idempotency-key")
    dual_write.add_argument("--risk-class", choices=("R1",), required=True)
    dual_write.add_argument("--risk-dominance", choices=("R1",), required=True)
    dual_write.add_argument("--artifact", type=Path, required=True)
    content = dual_write.add_mutually_exclusive_group(required=True)
    content.add_argument("--content")
    content.add_argument("--content-file", type=Path)
    dual_write.add_argument(
        "--new-workflow",
        action="store_true",
        help="assert this workflow has no prior file-authority run evidence",
    )
    dual_write.add_argument("--repo-root", type=Path, default=repository_root())

    dual_audit = commands.add_parser(
        "dual-write-shadow-audit", help="audit dual-write shadow parity"
    )
    dual_audit.add_argument("--db", type=Path, required=True)
    dual_audit.add_argument("--workflow", required=True)
    dual_audit.add_argument("--run-id", required=True)
    dual_audit.add_argument("--prepare-idempotency-key")
    dual_audit.add_argument("--artifact", type=Path, action="append", required=True)
    dual_audit.add_argument("--repo-root", type=Path, default=repository_root())

    canary = commands.add_parser(
        "db-authority-canary",
        help="write one synthetic local-only DB-authority canary artifact",
    )
    canary.add_argument("--db", type=Path, required=True)
    canary.add_argument("--workflow", required=True)
    canary.add_argument("--run-id", required=True)
    canary.add_argument("--prepare-idempotency-key")
    canary.add_argument("--cutover-approved-by", required=True)
    canary.add_argument("--cutover-evidence-hash", required=True)
    canary.add_argument("--rollback-deadline", required=True)
    canary.add_argument("--last-parity-audit-hash", required=True)
    canary.add_argument("--artifact", type=Path, required=True)
    canary_content = canary.add_mutually_exclusive_group(required=True)
    canary_content.add_argument("--content")
    canary_content.add_argument("--content-file", type=Path)
    canary.add_argument(
        "--crash-after-prepare",
        action="store_true",
        help="simulate the local post-DB/pre-artifact crash boundary",
    )
    canary.add_argument("--repo-root", type=Path, default=repository_root())

    canary_rollback = commands.add_parser(
        "db-authority-canary-rollback",
        help="rollback the synthetic canary and prove projection regeneration",
    )
    canary_rollback.add_argument("--db", type=Path, required=True)
    canary_rollback.add_argument("--workflow", required=True)
    canary_rollback.add_argument(
        "--artifact", type=Path, action="append", required=True
    )
    canary_rollback.add_argument(
        "--repo-root", type=Path, default=repository_root()
    )

    expansion = commands.add_parser(
        "db-authority-expansion",
        help="run the one allowed per-workflow synthetic DB-authority expansion",
    )
    expansion.add_argument("--db", type=Path, required=True)
    expansion.add_argument("--workflow", required=True)
    expansion.add_argument("--run-id", required=True)
    expansion.add_argument("--prepare-idempotency-key")
    expansion.add_argument("--risk-class", required=True)
    expansion.add_argument("--risk-dominance", required=True)
    expansion.add_argument("--cutover-approved-by", required=True)
    expansion.add_argument("--cutover-evidence-hash", required=True)
    expansion.add_argument("--rollback-deadline", required=True)
    expansion.add_argument("--last-parity-audit-hash", required=True)
    expansion.add_argument("--artifact", type=Path, required=True)
    expansion_content = expansion.add_mutually_exclusive_group(required=True)
    expansion_content.add_argument("--content")
    expansion_content.add_argument("--content-file", type=Path)
    expansion.add_argument(
        "--crash-after-prepare",
        action="store_true",
        help="simulate the local post-DB/pre-artifact crash boundary",
    )
    expansion.add_argument("--repo-root", type=Path, default=repository_root())

    expansion_rollback = commands.add_parser(
        "db-authority-expansion-rollback",
        help="rollback the per-workflow synthetic DB-authority expansion",
    )
    expansion_rollback.add_argument("--db", type=Path, required=True)
    expansion_rollback.add_argument("--workflow", required=True)
    expansion_rollback.add_argument(
        "--artifact", type=Path, action="append", required=True
    )
    expansion_rollback.add_argument(
        "--repo-root", type=Path, default=repository_root()
    )
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "preflight":
        checked = assert_privacy_preflight(args.repo_root)
        print(f"privacy preflight passed: {len(checked.ignored_paths)} paths")
        return 0
    if args.command == "migrate":
        database = (
            args.repo_root / "state/agentic-os/test-control.db"
            if args.test_db
            else args.db
        )
        applied = apply_migrations(database, repo_root=args.repo_root)
        print(f"migration verification passed: applied={list(applied)} db={database}")
        return 0
    if args.command == "verify":
        versions = verify_database(args.db)
        print(f"database verification passed: versions={list(versions)} db={args.db}")
        return 0
    if args.command == "shadow-backfill":
        result = backfill_file_authority_shadow(
            args.db,
            args.artifact,
            workflow=args.workflow,
            run_id=args.run_id,
            prepare_idempotency_key=args.prepare_idempotency_key,
            repo_root_path=args.repo_root,
        )
        print(
            "shadow backfill passed: "
            f"workflow={result.workflow} run_id={result.run_id} "
            f"projections={len(result.projections)}"
        )
        return 0
    if args.command == "dual-write-shadow":
        if args.content_file is not None:
            content_file = args.content_file.expanduser()
            assert_paths_retrievable((content_file, content_file.resolve()))
            content = content_file.read_bytes()
        else:
            content = args.content.encode("utf-8")
        result = dual_write_shadow_artifact(
            args.db,
            args.artifact,
            content,
            workflow=args.workflow,
            run_id=args.run_id,
            prepare_idempotency_key=args.prepare_idempotency_key,
            risk_class=args.risk_class,
            risk_dominance=args.risk_dominance,
            new_workflow=args.new_workflow,
            repo_root_path=args.repo_root,
        )
        print(
            "dual-write shadow "
            f"{result.status}: workflow={result.workflow} run_id={result.run_id} "
            f"path={result.projection.path} sha256={result.projection.sha256}"
        )
        return 0
    if args.command == "dual-write-shadow-audit":
        audit = audit_dual_write_shadow(
            args.db,
            args.artifact,
            workflow=args.workflow,
            run_id=args.run_id,
            prepare_idempotency_key=args.prepare_idempotency_key,
            repo_root_path=args.repo_root,
        )
    elif args.command == "db-authority-canary":
        if args.content_file is not None:
            content_file = args.content_file.expanduser()
            assert_paths_retrievable((content_file, content_file.resolve()))
            content = content_file.read_bytes()
        else:
            content = args.content.encode("utf-8")
        canary = db_authority_canary_artifact(
            args.db,
            args.artifact,
            content,
            workflow=args.workflow,
            run_id=args.run_id,
            cutover_approved_by=args.cutover_approved_by,
            cutover_evidence_hash=args.cutover_evidence_hash,
            rollback_deadline=args.rollback_deadline,
            last_parity_audit_hash=args.last_parity_audit_hash,
            prepare_idempotency_key=args.prepare_idempotency_key,
            repo_root_path=args.repo_root,
            crash_after_prepare=args.crash_after_prepare,
        )
        print(
            "db-authority canary "
            f"{canary.status}: workflow={canary.workflow} run_id={canary.run_id} "
            f"path={canary.projection.path} sha256={canary.projection.sha256}"
        )
        return 0
    elif args.command == "db-authority-canary-rollback":
        rollback = rollback_db_authority_canary(
            args.db,
            tuple(args.artifact),
            workflow=args.workflow,
            repo_root_path=args.repo_root,
        )
        print(
            "db-authority canary rollback "
            f"{rollback.status}: workflow={rollback.workflow} "
            f"projections={len(rollback.regenerated)}"
        )
        return 0
    elif args.command == "db-authority-expansion":
        if args.content_file is not None:
            content_file = args.content_file.expanduser()
            assert_paths_retrievable((content_file, content_file.resolve()))
            content = content_file.read_bytes()
        else:
            content = args.content.encode("utf-8")
        expansion = run_synthetic_db_authority_expansion(
            args.db,
            args.artifact,
            content,
            workflow=args.workflow,
            run_id=args.run_id,
            risk_class=args.risk_class,
            risk_dominance=args.risk_dominance,
            cutover_approved_by=args.cutover_approved_by,
            cutover_evidence_hash=args.cutover_evidence_hash,
            rollback_deadline=args.rollback_deadline,
            last_parity_audit_hash=args.last_parity_audit_hash,
            prepare_idempotency_key=args.prepare_idempotency_key,
            repo_root_path=args.repo_root,
            crash_after_prepare=args.crash_after_prepare,
        )
        print(
            "db-authority expansion "
            f"{expansion.canary.status}: workflow={expansion.workflow} "
            f"run_id={expansion.run_id} "
            f"path={expansion.canary.projection.path} "
            f"sha256={expansion.canary.projection.sha256} "
            f"proof={proof_json(expansion.proof)}"
        )
        return 0
    elif args.command == "db-authority-expansion-rollback":
        rollback = rollback_synthetic_db_authority_expansion(
            args.db,
            tuple(args.artifact),
            workflow=args.workflow,
            repo_root_path=args.repo_root,
        )
        print(
            "db-authority expansion rollback "
            f"{rollback.rollback.status}: workflow={rollback.workflow} "
            f"projections={len(rollback.rollback.regenerated)} "
            f"proof={proof_json(rollback.proof)}"
        )
        return 0
    else:
        audit = audit_file_authority_shadow(
            args.db,
            args.artifact,
            workflow=args.workflow,
            run_id=args.run_id,
            prepare_idempotency_key=args.prepare_idempotency_key,
            repo_root_path=args.repo_root,
        )
    print(
        "shadow audit "
        f"{audit.status}: workflow={audit.workflow} run_id={audit.run_id} "
        f"checked={audit.checked_count} issues={len(audit.issues)}"
    )
    for issue in audit.issues:
        print(f"{issue.reason}: {issue.path}")
    return 0 if audit.status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
