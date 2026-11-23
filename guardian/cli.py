"""
Guardian CLI – the main entry point.
Usage:
  guardian scan <url_or_path> [--no-ai] [--since <ref>] [--remediate] [--demo-cache]
  guardian verify <F-ID> --run out/<run-id>
  guardian diff <old-run> <new-run>
  guardian serve
"""
import argparse
import sys
import uuid
from datetime import datetime

from guardian.orchestrator import Orchestrator


def cmd_scan(args) -> None:
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    orch = Orchestrator(run_id=run_id, ai_enabled=not args.no_ai)
    orch.scan(
        target=args.target,
        since=args.since or "",
        remediate=args.remediate,
        demo_cache=args.demo_cache,
    )


def cmd_verify(args) -> None:
    print("'verify' command coming in a later gate.")


def cmd_diff(args) -> None:
    print("'diff' command coming in a later gate.")


def cmd_serve(args) -> None:
    print("'serve' command coming in Day 2.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="guardian",
        description="Software Supply Chain Guardian – security scanner",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Scan a GitHub URL or local folder")
    p_scan.add_argument("target", help="GitHub URL (https://github.com/...) or local path")
    p_scan.add_argument("--no-ai", action="store_true", help="Disable all LLM calls")
    p_scan.add_argument("--since", default="", help="Git ref for lockfile diff (e.g. HEAD~1)")
    p_scan.add_argument("--remediate", action="store_true", help="Run Remediator after scan")
    p_scan.add_argument("--demo-cache", action="store_true", help="Use pre-warmed caches")

    # ── verify ────────────────────────────────────────────────────────
    p_verify = sub.add_parser("verify", help="Re-derive a finding from raw evidence")
    p_verify.add_argument("finding_id", help="Finding ID, e.g. F-012")
    p_verify.add_argument("--run", required=True, help="Path to the run output dir")

    # ── diff ──────────────────────────────────────────────────────────
    p_diff = sub.add_parser("diff", help="Compare two scan runs")
    p_diff.add_argument("old_run", help="Path to old run dir")
    p_diff.add_argument("new_run", help="Path to new run dir")

    # ── serve ─────────────────────────────────────────────────────────
    p_serve = sub.add_parser("serve", help="Start local web UI")

    args = parser.parse_args()

    dispatch = {
        "scan": cmd_scan,
        "verify": cmd_verify,
        "diff": cmd_diff,
        "serve": cmd_serve,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
