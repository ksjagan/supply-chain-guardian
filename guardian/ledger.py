"""
The Evidence Ledger – the single shared blackboard.
Only code agents write evidence; LLM outputs are stored as 'claims', not evidence.
"""
import json
import threading
from pathlib import Path
from typing import List, Optional

from guardian.models import Evidence, Component, Edge, Finding


class Ledger:
    """
    Thread-safe in-memory ledger that also persists to ledger.json.
    Usage:
        ledger = Ledger(out_dir)
        e = ledger.add_evidence(kind="repo_snapshot", source="scout", component="", data={...})
        ledger.save()
    """

    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

        # counters
        self._ev_counter = 0
        self._finding_counter = 0

        # stores
        self.evidence: List[Evidence] = []
        self.components: List[Component] = []
        self.edges: List[Edge] = []
        self.findings: List[Finding] = []
        self.claims: List[dict] = []  # LLM outputs, never treated as facts

        # run-level metadata
        self.run_id: str = out_dir.name
        self.run_status: str = "RUNNING"  # COMPLETE | INCOMPLETE | UNTRUSTED
        self.ai_enabled: bool = True

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def add_evidence(
        self,
        kind: str,
        source: str,
        component: str,
        data: dict,
    ) -> Evidence:
        """Create and store one evidence record. Returns it."""
        with self._lock:
            self._ev_counter += 1
            eid = f"E-{self._ev_counter:03d}"
            ev = Evidence(id=eid, kind=kind, source=source, component=component, data=data)
            self.evidence.append(ev)
        return ev

    def get_evidence(self, eid: str) -> Optional[Evidence]:
        for ev in self.evidence:
            if ev.id == eid:
                return ev
        return None

    # ------------------------------------------------------------------
    # Components / Edges (convenience wrappers)
    # ------------------------------------------------------------------

    def add_component(self, component: Component) -> None:
        with self._lock:
            self.components.append(component)

    def add_edge(self, edge: Edge) -> None:
        with self._lock:
            self.edges.append(edge)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(self, **kwargs) -> Finding:
        with self._lock:
            self._finding_counter += 1
            fid = f"F-{self._finding_counter:03d}"
            f = Finding(id=fid, **kwargs)
            self.findings.append(f)
        return f

    # ------------------------------------------------------------------
    # Claims (LLM outputs)
    # ------------------------------------------------------------------

    def add_claim(self, agent: str, data: dict) -> None:
        with self._lock:
            self.claims.append({"agent": agent, "data": data})

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Write ledger.json to the run output directory."""
        payload = {
            "run_id": self.run_id,
            "run_status": self.run_status,
            "ai_enabled": self.ai_enabled,
            "evidence": [e.to_dict() for e in self.evidence],
            "components": [
                {k: v for k, v in vars(c).items()} for c in self.components
            ],
            "edges": [vars(e) for e in self.edges],
            "findings": [vars(f) for f in self.findings],
            "claims": self.claims,
        }
        path = self.out_dir / "ledger.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

    def load(self, path: Path) -> None:
        """Restore ledger from a saved file (for verify / diff commands)."""
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        # minimal restore – enough for verify
        self.run_id = payload.get("run_id", "")
        self.run_status = payload.get("run_status", "UNKNOWN")
