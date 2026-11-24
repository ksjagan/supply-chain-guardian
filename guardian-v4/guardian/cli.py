"""CLI interface for Software Supply Chain Guardian (spec section 15)."""
import argparse
import sys
import time
from pathlib import Path

from guardian import baseline, changes, config, evalharness, packager, verifier
from guardian.graph import run_pipeline
from guardian.ledger import Ledger


def cmd_scan(args):
    source = args.source
    rd_name = config.new_run_id()
    rd = config.run_dir(rd_name)
    rd.mkdir(parents=True, exist_ok=True)

    run_config = {
        "run_id": rd_name,
        "source": source,
        "ai": not args.no_ai,
        "remediate": args.remediate,
        "offline": args.demo_cache,
        "since": args.since,
        "since_dir": args.since_dir,
        "cheap_model": config.model_cheap(),
        "big_model": config.model_big(),
        "created_ts": time.time(),
    }
    config.write_json(rd / "run.json", run_config)

    print(f"[*] Starting Guardian Scan...")
    print(f"    Run ID   : {rd_name}")
    print(f"    Source   : {source}")
    print(f"    AI Mode  : {'ON' if not args.no_ai else 'OFF'}")
    print(f"    Offline  : {args.demo_cache}")

    res = run_pipeline(rd_name)
    summary = config.read_json(rd / "run_summary.json", {})

    print(f"\n[+] Scan Complete! Status: {summary.get('status', 'COMPLETE')}")
    print(f"    Components : {summary.get('components_total', 0)} (Direct: {summary.get('components_direct', 0)})")
    print(f"    Vulns      : {summary.get('vulns_total', 0)} (Crit: {summary.get('vulns_critical', 0)}, High: {summary.get('vulns_high', 0)})")
    print(f"    New Risks  : {summary.get('new_risks', 0)}")
    print(f"    Report HTML: {rd / 'report.html'}")
    return 0


def cmd_diff(args):
    old_dir, new_dir = args.old, args.new
    print(f"[*] Comparing {old_dir} -> {new_dir}...")
    old_tree = baseline.read_tree(old_dir)
    new_tree = baseline.read_tree(new_dir)
    from guardian import mapper
    old_model = mapper.build_model(old_tree["npm_lock"])
    new_model = mapper.build_model(new_tree["npm_lock"])
    res = changes.compare(old_tree, new_tree, {"ref": "diff", "time": ""}, offline=True, new_model=new_model)

    print(f"\n[+] Diff Summary: Status: {res.get('status')}")
    items = res.get("items", [])
    if not items:
        print("    No changes detected.")
        return 0
    print(f"{'PACKAGE':<25} {'CHANGE TYPE':<20} {'OLD -> NEW':<25}")
    print("-" * 75)
    for it in items:
        trans = f"{it.get('old') or '-'} -> {it.get('new') or '-'}"
        print(f"{it.get('package', ''):<25} {it.get('change_type', ''):<20} {trans:<25}")
    return 0


def cmd_verify(args):
    fid = args.fid
    rd = Path(args.run)
    findings = config.read_json(rd / "findings.json", [])
    led = Ledger(rd / "ledger.json")
    target = next((f for f in findings if f["id"] == fid), None)
    if not target:
        print(f"[-] Finding {fid} not found in {rd / 'findings.json'}")
        return 1

    print(f"[*] Verifying Finding {fid}: {target['title']}")
    print(f"    Risk      : {target['risk']}")
    print(f"    Explanation: {target.get('explanation') or '(No AI explanation)'}")
    print(f"    Evidence  : {target.get('evidence_ids', [])}")

    if not target.get("explanation"):
        print("    Status: NO EXPLANATION TO VERIFY")
        return 0

    errs = verifier.verify_claim(target["explanation"], target.get("evidence_ids_used", []), led,
                                 context=target["title"] + " " + target.get("detail", ""))
    if errs:
        print(f"[-] VERIFICATION FAILED:")
        for e in errs:
            print(f"    - {e}")
        return 1
    print("[+] VERIFICATION PASSED: Every claim and number verified against ledger.")
    return 0


def cmd_resume(args):
    run_id = args.run_id
    print(f"[*] Resuming run {run_id} from checkpointer...")
    res = run_pipeline(run_id, resume=True)
    print(f"[+] Run {run_id} resumed. Final status: {res.get('status')}")
    return 0


def cmd_eval(args):
    print("[*] Running Guardian 6-Metric Evaluation Suite...")
    card = evalharness.run_eval()
    print("\n================== EVAL SCORECARD ==================")
    for k, v in card["metrics"].items():
        pass_str = "PASS" if v["pass"] else "FAIL"
        print(f"{k:<25} : {v['value']}{v['unit']} (Target: {v['target']}{v['unit']}) [{pass_str}]")
    print("====================================================")
    print(f"Overall Result: {'PASS' if card['all_pass'] else 'FAIL'}")
    return 0 if card["all_pass"] else 1


def cmd_selfcheck(args):
    print("[*] Running Guardian Fast Selfcheck (<60s)...")
    res = evalharness.selfcheck()
    print("\n---------------- SELFCHECK ----------------")
    print(f"Verifier (10 Deliberate Hallucinations) : {res['verifier']}")
    print(f"Injection Payloads Resistance          : {res['injections']}")
    print(f"Sentinel Canary Integrity Check        : {res['sentinel_canary']}")
    print("-------------------------------------------")
    print(f"Status: {'PASS' if res['all_pass'] else 'FAIL'}\n")
    return 0 if res["all_pass"] else 1


def cmd_package(args):
    print("[*] Generating Hackathon Submission Package...")
    out_dir = packager.package()
    print(f"[+] All submission deliverables successfully written to: {out_dir}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="guardian", description="Software Supply Chain Guardian CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan a GitHub repository or local directory")
    p_scan.add_argument("source", help="GitHub repo URL or local directory path")
    p_scan.add_argument("--no-ai", action="store_true", help="Run without AI (deterministic rules only)")
    p_scan.add_argument("--since", help="Git ref or 'last' to compare changes against")
    p_scan.add_argument("--since-dir", help="Directory of baseline version to compare against")
    p_scan.add_argument("--remediate", action="store_true", help="Generate remediation recommendations and validation")
    p_scan.add_argument("--demo-cache", action="store_true", help="Use offline demo fixture cache")

    # diff
    p_diff = sub.add_parser("diff", help="Diff two repository folders")
    p_diff.add_argument("old", help="Old folder path")
    p_diff.add_argument("new", help="New folder path")

    # verify
    p_verify = sub.add_parser("verify", help="Verify an AI finding explanation against the evidence ledger")
    p_verify.add_argument("fid", help="Finding ID (e.g. F-001)")
    p_verify.add_argument("--run", required=True, help="Path to run output directory (e.g. out/run-xxx)")

    # resume
    p_resume = sub.add_parser("resume", help="Resume an interrupted LangGraph run from checkpointer")
    p_resume.add_argument("run_id", help="The run ID to resume")

    # eval
    sub.add_parser("eval", help="Run 6-metric evaluation harness")

    # selfcheck
    sub.add_parser("selfcheck", help="Fast pre-demo integrity sanity check")

    # package
    sub.add_parser("package", help="Generate all deliverables into submission/")

    args = parser.parse_args()
    cmds = {
        "scan": cmd_scan,
        "diff": cmd_diff,
        "verify": cmd_verify,
        "resume": cmd_resume,
        "eval": cmd_eval,
        "selfcheck": cmd_selfcheck,
        "package": cmd_package,
    }
    sys.exit(cmds[args.command](args))


if __name__ == "__main__":
    main()
