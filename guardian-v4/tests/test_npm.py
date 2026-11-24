"""Tests for npm ecosystem parser (ecosystems/npm.py)."""
from guardian.ecosystems import npm

VALID_LOCK_V2 = """{
  "name": "sample-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "packages": {
    "": {
      "name": "sample-app",
      "version": "1.0.0",
      "dependencies": {"express": "^4.17.1"}
    },
    "node_modules/express": {
      "version": "4.17.1",
      "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
      "integrity": "sha512-test==",
      "dependencies": {"qs": "6.5.2"}
    },
    "node_modules/express/node_modules/qs": {
      "version": "6.5.2",
      "resolved": "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz",
      "integrity": "sha512-qstest=="
    }
  }
}"""


def test_parse_valid_lockfile():
    res = npm.parse_lock(VALID_LOCK_V2)
    assert res["ok"] is True
    assert "express@4.17.1" in res["components"]
    assert "qs@6.5.2" in res["components"]
    assert ("(app)", "express@4.17.1") in res["edges"]
    assert ("express@4.17.1", "qs@6.5.2") in res["edges"]


def test_parse_invalid_json():
    res = npm.parse_lock("not a json")
    assert res["ok"] is False
    assert "not valid JSON" in res["error"]


def test_parse_unsupported_version():
    bad_v = '{"name": "app", "lockfileVersion": 1, "packages": {}}'
    res = npm.parse_lock(bad_v)
    assert res["ok"] is False
    assert "unsupported lockfile" in res["error"]


def test_purl_escaping():
    assert npm.purl("qs", "6.5.2") == "pkg:npm/qs@6.5.2"
    assert npm.purl("@types/node", "18.0.0") == "pkg:npm/%40types/node@18.0.0"
