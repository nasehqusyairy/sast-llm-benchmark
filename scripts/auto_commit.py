#!/usr/bin/env python3
"""Periodically commit all working-tree changes and push them to origin."""

import argparse
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def run_git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=check,
    )


def changed_paths(root: Path) -> list[str]:
    result = run_git(root, "status", "--short", "--untracked-files=all")
    return [line for line in result.stdout.splitlines() if line.strip()]


def make_commit_message(timestamp: str, changes: list[str]) -> str:
    summary = "\n".join(f"  {change}" for change in changes)
    return f"chore: automated sync {timestamp}\n\nDetected changes:\n{summary}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Commit working-tree changes and push to origin on a timer."
    )
    parser.add_argument(
        "--interval", type=float, default=5.0, metavar="MINUTES",
        help="check interval in minutes (default: 5)",
    )
    parser.add_argument(
        "--message", default=None,
        help="commit subject prefix (default: 'chore: automated sync')",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="show what would be committed without staging, committing, or pushing",
    )
    parser.add_argument(
        "--once", action="store_true", help="run one check and exit",
    )
    parser.add_argument(
        "--include-ignored", action="store_true",
        help="also stage ignored files (use with care)",
    )
    return parser


def sync_once(root: Path, args: argparse.Namespace) -> bool:
    changes = changed_paths(root)
    if not changes:
        print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] Tidak ada perubahan.", flush=True)
        return False

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"{args.message} {timestamp}" if args.message else f"chore: automated sync {timestamp}"
    print(f"[{timestamp}] Perubahan terdeteksi:\n" + "\n".join(f"  {line}" for line in changes), flush=True)
    if args.dry_run:
        print("Dry-run: tidak melakukan stage, commit, atau push.", flush=True)
        return False

    stage_args = ["add"]
    if args.include_ignored:
        stage_args.append("-f")
    stage_args.append("--all")
    run_git(root, *stage_args)

    # Build the message after staging so it describes the current detected diff.
    message = subject + "\n\nDetected changes:\n" + "\n".join(f"  {line}" for line in changes)
    commit = run_git(root, "commit", "-m", message, check=False)
    if commit.returncode:
        raise RuntimeError(commit.stderr.strip() or commit.stdout.strip() or "git commit failed")
    print(commit.stdout.strip(), flush=True)

    push = run_git(root, "push", "origin", "HEAD", check=False)
    if push.returncode:
        raise RuntimeError(push.stderr.strip() or push.stdout.strip() or "git push failed")
    print(push.stderr.strip() or push.stdout.strip() or "Push ke origin berhasil.", flush=True)
    return True


def main() -> int:
    args = build_parser().parse_args()
    if args.interval <= 0:
        build_parser().error("--interval harus lebih besar dari 0")
    try:
        root = Path(run_git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip())
    except subprocess.CalledProcessError:
        print("Error: jalankan dari dalam repository Git.", file=sys.stderr)
        return 2

    if run_git(root, "remote", "get-url", "origin", check=False).returncode:
        print("Error: remote 'origin' tidak ditemukan.", file=sys.stderr)
        return 2

    print(f"Auto-commit aktif di {root}; interval {args.interval:g} menit.", flush=True)
    try:
        while True:
            try:
                sync_once(root, args)
            except (subprocess.CalledProcessError, RuntimeError) as exc:
                print(f"Error saat sinkronisasi: {exc}", file=sys.stderr, flush=True)
            if args.once:
                return 0
            time.sleep(args.interval * 60)
    except KeyboardInterrupt:
        print("\nDihentikan.", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
