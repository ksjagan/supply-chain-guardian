"""
Tests for the npm ecosystem plugin.
Run with: pytest tests/test_npm.py -v
"""
import json
from pathlib import Path
import pytest
import sys, os
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardian.ecosystems.npm import NpmPlugin


DEMO_APP = Path(__file__).parent.parent / "fixtures" / "demo-app"


class TestNpmPlugin:
    plugin = NpmPlugin()

    def test_parse_demo_app_returns_components(self):
        comps, edges, note = self.plugin.parse(DEMO_APP)
        assert len(comps) > 0, "Should find components"
        assert note == "full", f"Expected 'full' coverage, got: {note}"

    def test_direct_deps_are_flagged(self):
        comps, edges, note = self.plugin.parse(DEMO_APP)
        direct_names = {c.name for c in comps if c.is_direct}
        # express and lodash are declared in package.json
        assert "express" in direct_names, "express should be a direct dep"
        assert "lodash" in direct_names, "lodash should be a direct dep"

    def test_dev_deps_are_flagged(self):
        comps, edges, note = self.plugin.parse(DEMO_APP)
        dev_names = {c.name for c in comps if c.is_dev}
        assert "jest" in dev_names, "jest should be flagged as dev-only"
        assert "eslint" in dev_names, "eslint should be flagged as dev-only"

    def test_purls_are_correct(self):
        comps, edges, note = self.plugin.parse(DEMO_APP)
        for comp in comps:
            assert comp.purl.startswith("pkg:npm/"), f"Bad purl: {comp.purl}"
            assert comp.version in comp.purl, f"Version missing from purl: {comp.purl}"

    def test_edges_exist(self):
        comps, edges, note = self.plugin.parse(DEMO_APP)
        assert len(edges) > 0, "Should have dependency edges"

    def test_express_has_transitive_deps(self):
        comps, edges, note = self.plugin.parse(DEMO_APP)
        # Find express's bom_ref
        express = next((c for c in comps if c.name == "express"), None)
        assert express is not None, "express should be found"
        # Find children of express
        children = [e.child for e in edges if e.parent == express.bom_ref]
        assert len(children) > 0, "express should have transitive dependencies"

    def test_name_from_key(self):
        assert NpmPlugin._name_from_key("node_modules/lodash") == "lodash"
        assert NpmPlugin._name_from_key("node_modules/@scope/pkg") == "@scope/pkg"
        assert NpmPlugin._name_from_key("node_modules/a/node_modules/b") == "b"

    def test_no_package_lock_falls_back_to_package_json(self, tmp_path):
        """When only package.json exists, we get partial coverage."""
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "^4.17.21"},
            "devDependencies": {"jest": "^29.0.0"}
        }))
        comps, edges, note = self.plugin.parse(tmp_path)
        assert len(comps) == 2
        assert "partial" in note

    def test_missing_all_manifests(self, tmp_path):
        """Empty directory = skipped."""
        comps, edges, note = self.plugin.parse(tmp_path)
        assert len(comps) == 0
        assert "skipped" in note
