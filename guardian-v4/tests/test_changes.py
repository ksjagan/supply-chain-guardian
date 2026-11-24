"""Tests for supply chain change detection (changes.py)."""
from guardian import changes, mapper

BASE_LOCK = """{
  \"name\": \"app\",
  \"version\": \"1.0.0\",
  \"lockfileVersion\": 2,
  \"packages\": {
    \"\": {\"dependencies\": {\"lodash\": \"3.10.1\"}},
    \"node_modules/lodash\": {
      \"version\": \"3.10.1\",
      \"resolved\": \"https://registry.npmjs.org/lodash/-/lodash-3.10.1.tgz\",
      \"integrity\": \"sha512-hash1==\"
    }
  }
}"""

NEW_LOCK = """{
  \"name\": \"app\",
  \"version\": \"1.1.0\",
  \"lockfileVersion\": 2,
  \"packages\": {
    \"\": {\"dependencies\": {\"lodash\": \"4.17.15\", \"recats\": \"1.0.0\"}},
    \"node_modules/lodash\": {
      \"version\": \"4.17.15\",
      \"resolved\": \"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz\",
      \"integrity\": \"sha512-hash2==\"
    },
    \"node_modules/recats\": {
      \"version\": \"1.0.0\",
      \"resolved\": \"https://registry.npmjs.org/recats/-/recats-1.0.0.tgz\",
      \"integrity\": \"sha512-hash3==\",
      \"hasInstallScript\": true
    }
  }
}"""


def test_diff_components():
    old_m = mapper.build_model({"package-lock.json": BASE_LOCK})
    new_m = mapper.build_model({"package-lock.json": NEW_LOCK})

    items, evs = changes.diff_components(old_m, new_m)
    by_pkg = {i["package"]: i for i in items}

    assert "recats" in by_pkg
    assert by_pkg["recats"]["change_type"] == "added"

    assert "lodash" in by_pkg
    assert by_pkg["lodash"]["change_type"] == "upgraded"
    assert by_pkg["lodash"]["old"] == "3.10.1"
    assert by_pkg["lodash"]["new"] == "4.17.15"
    assert by_pkg["lodash"]["flags"].get("major_jump") is True
