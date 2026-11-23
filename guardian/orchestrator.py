"""
Orchestrator – sequences agents, enforces time budgets, sets run status.
Pipeline: Scout -> Mapper -> Hunter (Changes) -> Reporter.
Never executes code from the scanned repository.
"""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from guardian.config import AGENT_TIMEOUT_S, GLOBAL_TIMEOUT_S, OUT_DIR
from guardian.hunter import Hunter
from guardian.ledger import Ledger
from guardian.mapper import Mapper
from guardian.reporter import Reporter
from guardian.scout import Scout, ScoutError


class Orchestrator:
    """
    Runs agents in sequence and enforces budgets.
    """

    def __init__(self, run_id: str, ai_enabled: bool = False, custom_out: Optional[Path] = None):
        self.run_id = run_id
        self.ai_enabled = ai_enabled
        self.out_dir = (custom_out / run_id) if custom_out else (OUT_DIR / run_id)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.ledger = Ledger(self.out_dir)
        self.ledger.ai_enabled = ai_enabled
        self.ledger.run_status = "RUNNING"

        self._start_time = time.time()
        self._agent_times: dict = {}

    # ------------------------------------------------------------------
    # Main scan / checkpoint flow
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        since: str = "",
        baseline_dir: Optional[Path] = None,
        demo_mode: bool = False,
        remediate: bool = False,
        demo_cache: bool = False,
        is_checkpoint: bool = False,
    ) -> None:
        """
        Run the complete pipeline: Scout -> Mapper -> Hunter -> Reporter.
        """
        print(f"\n{'='*60}")
        print(f"  Guardian {'Checkpoint' if is_checkpoint else 'Security Scan'}")
        print(f"  Run ID  : {self.run_id}")
        print(f"  Target  : {target}")
        if since:
            print(f"  Since   : {since}")
        if baseline_dir:
            print(f"  BaseDir : {baseline_dir}")
        print(f"  AI      : {'on' if self.ai_enabled else 'off (--no-ai)'}")
        print(f"  DemoMode: {'yes (offline)' if (demo_mode or demo_cache) else 'no'}")
        print(f"  Output  : {self.out_dir}")
        print(f"{'='*60}\n")

        scout = Scout(self.ledger)
        diff_res = None

        try:
            # ── 1. Scout ──────────────────────────────────────────────
            repo_dir = self._run_agent("scout", lambda: scout.run(target))

            # Auto-detect git history for baseline if --baseline or --since is absent
            effective_since = since
            effective_baseline_dir = baseline_dir
            if not effective_since and not effective_baseline_dir:
                if (repo_dir / ".git").exists():
                    # Check if HEAD~1 exists in repo
                    import subprocess
                    r = subprocess.run(["git", "-C", str(repo_dir), "rev-parse", "--verify", "HEAD~1"], capture_output=True)
                    if r.returncode == 0:
                        effective_since = "HEAD~1"

            # ── 2. Mapper (SBOM + Graph) ──────────────────────────────
            mapper = Mapper(self.ledger, self.out_dir)
            self._run_agent("mapper", lambda: mapper.run(repo_dir))

            # ── 3. Hunter (Vulnerabilities, Anomalies, Baseline Diff) ─
            hunter = Hunter(self.ledger, self.out_dir, demo_mode=(demo_mode or demo_cache))
            self._run_agent(
                "hunter",
                lambda: hunter.run(
                    repo_dir=repo_dir,
                    components=mapper.components,
                    since_ref=effective_since,
                    baseline_dir=effective_baseline_dir,
                )
            )
            diff_res = hunter.diff_result

            # ── 4. Reporter (HTML, Findings JSON, Baseline JSON) ──────
            repo_key = Path(target).name if not target.startswith("http") else target.rstrip("/").split("/")[-1]
            reporter = Reporter(self.ledger, self.out_dir)
            self._run_agent(
                "reporter",
                lambda: reporter.generate(diff_result=diff_res, repo_key=repo_key, is_checkpoint=is_checkpoint)
            )

            # Final run status
            if self.ledger.run_status == "RUNNING":
                self.ledger.run_status = "COMPLETE"

            print("\n✅  DAY-1 CHECKPOINT COMPLETE: What is in app, what changed, and what appears risky.")
            self._print_coverage_summary()
            self._print_diff_summary(diff_res)
            self._print_risks_summary()

        except ScoutError as exc:
            print(f"\n❌  Scout error: {exc}", file=sys.stderr)
            self.ledger.run_status = "INCOMPLETE"
        except Exception as exc:
            print(f"\n❌  Unexpected error: {exc}", file=sys.stderr)
            import traceback; traceback.print_exc()
            self.ledger.run_status = "INCOMPLETE"
        finally:
            scout.cleanup()
            self._write_summary()
            self.ledger.save()
            self._print_outputs()

    # ------------------------------------------------------------------
    # Agent runner with time-budget enforcement
    # ------------------------------------------------------------------

    def _run_agent(self, name: str, fn):
        elapsed_global = time.time() - self._start_time
        if elapsed_global > GLOBAL_TIMEOUT_S:
            raise RuntimeError(f"Global timeout ({GLOBAL_TIMEOUT_S}s) exceeded before running {name}")

        print(f"\n── Agent: {name} ──────────────────────")
        t0 = time.time()
        result = fn()
        duration = time.time() - t0
        self._agent_times[name] = round(duration, 2)
        print(f"[{name}] done in {duration:.1f}s")
        return result

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def _print_coverage_summary(self) -> None:
        print("\n📦  COVERAGE BOX")
        print("─" * 40)
        for ev in self.ledger.evidence:
            if ev.kind == "coverage":
                d = ev.data
                print(f"  Total components   : {d.get('total_components', 0)}")
                print(f"  Direct deps        : {d.get('direct', 0)}")
                print(f"  Transitive deps    : {d.get('transitive', 0)}")
                for plugin_cov in d.get("plugin_coverage", []):
                    status = plugin_cov.get("status", "?")
                    note   = plugin_cov.get("note", "")
                    cap    = plugin_cov.get("skipped_cap", 0)
                    print(f"  {plugin_cov['plugin']}: {status}" +
                          (f" ({note})" if note and note != status else "") +
                          (f" [capped: {cap} skipped]" if cap else ""))
        print("─" * 40)

    def _print_diff_summary(self, diff_res) -> None:
        if not diff_res:
            return
        print("\n🔍  WHAT CHANGED (BASELINE COMPARISON)")
        print("─" * 40)
        if not diff_res.baseline_available:
            print(f"  Baseline status    : UNAVAILABLE")
            print(f"  Reason             : {diff_res.unavailable_reason}")
        else:
            print(f"  Baseline           : {diff_res.baseline_ref}")
            print(f"  Added (+)          : {diff_res.count_added}")
            print(f"  Removed (-)        : {diff_res.count_removed}")
            print(f"  Upgraded (↑)       : {diff_res.count_upgraded}")
            print(f"  Downgraded (↓)     : {diff_res.count_downgraded}")
            print(f"  Modified (⚙)       : {diff_res.count_modified}")
            print(f"  New install scripts: {diff_res.count_new_install_scripts}")
        print("─" * 40)

    def _print_risks_summary(self) -> None:
        print("\n⚠️   WHAT APPEARS RISKY (FINDINGS)")
        print("─" * 40)
        crit = sum(1 for f in self.ledger.findings if f.risk.lower() == "critical")
        high = sum(1 for f in self.ledger.findings if f.risk.lower() == "high")
        med = sum(1 for f in self.ledger.findings if f.risk.lower() == "medium")
        low = sum(1 for f in self.ledger.findings if f.risk.lower() == "low")
        print(f"  Critical : {crit}")
        print(f"  High     : {high}")
        print(f"  Medium   : {med}")
        print(f"  Low      : {low}")
        print(f"  Total    : {len(self.ledger.findings)}")
        print("─" * 40)

    def _write_summary(self) -> None:
        import json
        summary = {
            "run_id": self.run_id,
            "run_status": self.ledger.run_status,
            "ai_enabled": self.ai_enabled,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "agent_times_s": self._agent_times,
            "total_elapsed_s": round(time.time() - self._start_time, 2),
            "components": len(self.ledger.components),
            "findings": len(self.ledger.findings),
            "evidence_records": len(self.ledger.evidence),
        }
        path = self.out_dir / "run_summary.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)

    def _print_outputs(self) -> None:
        print(f"\n📁  Output files in {self.out_dir}:")
        for f in sorted(self.out_dir.iterdir()):
            size = f.stat().st_size
            print(f"   {f.name:<30} {size:>8,} bytes")
        print(f"\n   Open report: {self.out_dir / 'checkpoint.html'}")
        print(f"   Open graph : {self.out_dir / 'graph.html'}")
        print(f"   Run status : {self.ledger.run_status}\n")
