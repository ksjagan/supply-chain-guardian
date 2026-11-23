"""
Orchestrator – sequences agents, enforces time budgets, sets run status.
For Day 1 Checkpoint 1 we only run: Scout -> Mapper.
Later steps (Hunter, Reader, Analyst, etc.) will be added in subsequent gates.
"""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from guardian.config import AGENT_TIMEOUT_S, GLOBAL_TIMEOUT_S, OUT_DIR
from guardian.ledger import Ledger
from guardian.mapper import Mapper
from guardian.scout import Scout, ScoutError


class Orchestrator:
    """
    Runs agents in sequence (and later in parallel).
    Writes run_summary.json at the end.
    """

    def __init__(self, run_id: str, ai_enabled: bool = True):
        self.run_id = run_id
        self.ai_enabled = ai_enabled
        self.out_dir = OUT_DIR / run_id
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.ledger = Ledger(self.out_dir)
        self.ledger.ai_enabled = ai_enabled
        self.ledger.run_status = "RUNNING"

        self._start_time = time.time()
        self._agent_times: dict = {}

    # ------------------------------------------------------------------
    # Main scan flow
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        since: str = "",
        remediate: bool = False,
        demo_cache: bool = False,
    ) -> None:
        """
        Run the full pipeline (or as much as is implemented for the current gate).
        """
        print(f"\n{'='*60}")
        print(f"  Guardian Security Scan")
        print(f"  Run ID : {self.run_id}")
        print(f"  Target : {target}")
        print(f"  AI     : {'on' if self.ai_enabled else 'off (--no-ai)'}")
        print(f"  Output : {self.out_dir}")
        print(f"{'='*60}\n")

        scout = Scout(self.ledger)

        try:
            # ── 1. Scout ──────────────────────────────────────────────
            repo_dir = self._run_agent("scout", lambda: scout.run(target))

            # ── 2. Mapper (SBOM + Graph) ──────────────────────────────
            mapper = Mapper(self.ledger, self.out_dir)
            self._run_agent("mapper", lambda: mapper.run(repo_dir))

            # ── Checkpoint 1 complete ─────────────────────────────────
            self.ledger.run_status = "COMPLETE"
            print("\n✅  DAY-1 CHECKPOINT 1 COMPLETE")
            self._print_coverage_summary()

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
        print(f"\n   Open graph: {self.out_dir / 'graph.html'}")
        print(f"   Run status: {self.ledger.run_status}\n")
