"""Command-line probes for the P0 foundation."""

from __future__ import annotations

import argparse
from pathlib import Path

from .migrations import apply_migrations, repository_root, verify_database
from .privacy import assert_privacy_preflight
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
    dual_write.add_argument("--artifact", type=Path, required=True)
    content = dual_write.add_mutually_exclusive_group(required=True)
    content.add_argument("--content")
    content.add_argument("--content-file", type=Path)
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
            content = args.content_file.read_bytes()
        else:
            content = args.content.encode("utf-8")
        result = dual_write_shadow_artifact(
            args.db,
            args.artifact,
            content,
            workflow=args.workflow,
            run_id=args.run_id,
            prepare_idempotency_key=args.prepare_idempotency_key,
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
