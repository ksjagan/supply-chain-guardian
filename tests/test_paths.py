"""
Tests for dependency path computation.
Run with: pytest tests/test_paths.py -v
"""
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardian.ledger import Ledger
from guardian.mapper import Mapper


DEMO_APP = Path(__file__).parent.parent / "fixtures" / "demo-app"
OUT_DIR  = Path(__file__).parent.parent / "out" / "_test_paths"


class TestDependencyPaths:
    def setup_method(self):
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(OUT_DIR)
        self.mapper = Mapper(self.ledger, OUT_DIR)

    def test_mapper_runs_without_error(self):
        self.mapper.run(DEMO_APP)

    def test_sbom_created(self):
        self.mapper.run(DEMO_APP)
        sbom_path = OUT_DIR / "sbom.cdx.json"
        assert sbom_path.exists(), "sbom.cdx.json should be created"

    def test_graph_html_created(self):
        self.mapper.run(DEMO_APP)
        graph_path = OUT_DIR / "graph.html"
        assert graph_path.exists(), "graph.html should be created"

    def test_all_components_have_path_evidence(self):
        self.mapper.run(DEMO_APP)
        path_ev = [e for e in self.ledger.evidence if e.kind == "dependency_path"]
        component_ev = [e for e in self.ledger.evidence if e.kind == "component"]
        # Every component should have a path record
        comp_names = {e.data["name"] for e in component_ev}
        path_names = {e.data["component"] for e in path_ev}
        assert comp_names == path_names, "Every component should have a path record"

    def test_root_to_lodash_path_exists(self):
        self.mapper.run(DEMO_APP)
        path_ev = [e for e in self.ledger.evidence
                   if e.kind == "dependency_path" and e.data["component"] == "lodash"]
        assert len(path_ev) > 0, "lodash should have a path"
        path = path_ev[0].data["path_readable"]
        assert "[root]" in path[0], f"Path should start from root: {path}"
        assert "lodash" in path[-1], f"Path should end at lodash: {path}"

    def test_coverage_evidence_exists(self):
        self.mapper.run(DEMO_APP)
        cov_ev = [e for e in self.ledger.evidence if e.kind == "coverage"]
        assert len(cov_ev) > 0, "Coverage evidence should be recorded"
        assert cov_ev[0].data["total_components"] > 0

    def test_ledger_saved(self):
        self.mapper.run(DEMO_APP)
        assert (OUT_DIR / "ledger.json").exists(), "ledger.json should be saved"
