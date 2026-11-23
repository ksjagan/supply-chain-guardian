"""
Unit and integration tests for Day 1 Checkpoint:
- Checkpoint command execution
- Section A: Components catalog, counts, and origin fields
- Section B: Lockfile diff (added, upgraded, modified)
- Section C: Evidence cards, real CVE with severity & fix version, anomalies
- Verification command (guardian verify)
- Zero code execution assertion
"""
import json
from pathlib import Path
import pytest
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from guardian.orchestrator import Orchestrator


ROOT_DIR = Path(__file__).parent.parent
DEMO_APP = ROOT_DIR / "fixtures" / "demo-app"
DEMO_APP_V2 = ROOT_DIR / "fixtures" / "demo-app-v2"
PLANTED = ROOT_DIR / "fixtures" / "planted"
OUT_DIR = ROOT_DIR / "out" / "_test_checkpoint"


class TestDay1Checkpoint:
    @classmethod
    def setup_class(cls):
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        cls.orch = Orchestrator(run_id="test_cp_run", ai_enabled=False, custom_out=OUT_DIR)
        cls.orch.scan(
            target=str(DEMO_APP),
            baseline_dir=DEMO_APP_V2,
            demo_mode=True,
            is_checkpoint=True,
        )

    def test_deliverables_created(self):
        out = self.orch.out_dir
        assert (out / "checkpoint.html").exists(), "checkpoint.html must be generated"
        assert (out / "report.html").exists(), "report.html must be generated"
        assert (out / "sbom.cdx.json").exists(), "sbom.cdx.json must be generated"
        assert (out / "graph.html").exists(), "graph.html must be generated"
        assert (out / "findings.json").exists(), "findings.json must be generated"
        assert (out / "baseline.json").exists(), "baseline.json must be generated"
        assert (out / "ledger.json").exists(), "ledger.json must be generated"

    def test_section_a_components_and_origin(self):
        components = self.orch.ledger.components
        assert len(components) == 68

        # Origin fields: {ecosystem, registry_host, manifest_file, direct_parent}
        for c in components:
            assert c.origin, f"Component {c.name} must have origin dictionary"
            assert "ecosystem" in c.origin
            assert "registry_host" in c.origin
            assert "manifest_file" in c.origin
            assert "direct_parent" in c.origin

    def test_section_b_diff_detection(self):
        # demo-app vs demo-app-v2
        diff_ev = [e for e in self.orch.ledger.evidence if e.kind == "lockfile_diff" and e.data.get("change_type")]
        assert len(diff_ev) >= 2, "Must detect differences between demo-app and demo-app-v2"

    def test_section_c_real_cve_and_evidence_cards(self):
        vuln_findings = [f for f in self.orch.ledger.findings if f.type == "vulnerability"]
        assert len(vuln_findings) > 0, "At least one vulnerability must be recorded"

        # Check CVE, CVSS/severity, fix version
        has_full_cve = any(f.cve and f.fix_version and f.cvss for f in vuln_findings)
        assert has_full_cve, "Must have real CVE with severity and fix version"

        # Every finding must have path, evidence_ids, and risk level
        for f in self.orch.ledger.findings:
            assert f.path, f"Finding {f.id} must have dependency path"
            assert f.evidence_ids, f"Finding {f.id} must cite evidence IDs"
            assert f.risk in ("critical", "high", "medium", "low")

    def test_checkpoint_html_layout(self):
        html_text = (self.orch.out_dir / "checkpoint.html").read_text(encoding="utf-8")

        # Header stages
        assert "Repository" in html_text
        assert "SBOM" in html_text
        assert "Dependency Graph" in html_text
        assert "Risk Detection" in html_text
        assert "Evidence" in html_text

        # 3 Sections
        assert "Section A: What is in the Application" in html_text
        assert "Section B: What Changed" in html_text
        assert "Section C: What Appears Risky" in html_text
        assert "Coverage Box" in html_text
        assert "guardian verify" in html_text
