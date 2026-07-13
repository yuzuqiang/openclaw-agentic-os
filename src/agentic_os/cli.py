"""Command-line probes for the P0 foundation."""

from __future__ import annotations

import argparse
from pathlib import Path

from .migrations import apply_migrations, repository_root, verify_database
from .privacy import assert_privacy_preflight


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
    versions = verify_database(args.db)
    print(f"database verification passed: versions={list(versions)} db={args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

