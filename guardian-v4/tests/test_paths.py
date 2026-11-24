"""Tests for dependency graph paths and Mapper annotations."""
from guardian import mapper
from guardian.ecosystems import npm

SAMPLE_LOCK = """{
  "name": "test-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "test-app",
      "dependencies": {"express": "4.17.1"}
    },
    "node_modules/express": {
      "version": "4.17.1",
      "dependencies": {"qs": "6.5.2"}
    },
    "node_modules/qs": {
      "version": "6.5.2"
    }
  }
}"""


def test_mapper_path_resolution():
    model = mapper.build_model({"package-lock.json": SAMPLE_LOCK})
    comps = model["components"]

    assert "express@4.17.1" in comps
    assert "qs@6.5.2" in comps

    # Direct vs Transitive
    assert comps["express@4.17.1"]["direct"] is True
    assert comps["qs@6.5.2"]["direct"] is False

    # Shortest Path
    assert comps["express@4.17.1"]["path"] == ["(app)", "express@4.17.1"]
    assert comps["qs@6.5.2"]["path"] == ["(app)", "express@4.17.1", "qs@6.5.2"]
    assert comps["qs@6.5.2"]["origin_direct"] == "express@4.17.1"
