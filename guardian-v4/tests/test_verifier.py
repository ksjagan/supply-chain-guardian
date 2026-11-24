"""Tests for plain code Verifier (zero hallucination enforcement)."""
from guardian import verifier
from guardian.ledger import Ledger
from pathlib import Path


def test_verifier_accepts_valid_claim(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    eid = led.add("vuln", "osv", {"name": "qs", "version": "6.5.2",
                                  "cves": ["CVE-2017-1000048"], "fixed": ["6.5.3"],
                                  "cvss_est": 8.0})

    text = "Upgrading qs from 6.5.2 to 6.5.3 resolves CVE-2017-1000048 cited in [E-001]."
    errs = verifier.verify_claim(text, [eid], led)
    assert errs == [], f"Expected clean pass, got: {errs}"


def test_verifier_rejects_hallucinated_version(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    eid = led.add("vuln", "osv", {"name": "qs", "version": "6.5.2",
                                  "cves": ["CVE-2017-1000048"], "fixed": ["6.5.3"]})

    # 9.9.9 does not exist in evidence
    text = "Upgrading qs to 9.9.9 resolves the issue in [E-001]."
    errs = verifier.verify_claim(text, [eid], led)
    assert any("does not support the number/version 9.9.9" in e for e in errs)


def test_verifier_rejects_fake_cve(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    eid = led.add("vuln", "osv", {"name": "qs", "version": "6.5.2",
                                  "cves": ["CVE-2017-1000048"]})

    # CVE-2099-9999 is fabricated
    text = "Resolves critical issue CVE-2099-9999 as seen in [E-001]."
    errs = verifier.verify_claim(text, [eid], led)
    assert any("CVE-2099-9999 is not in the cited evidence" in e for e in errs)


def test_verifier_rejects_missing_citation(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    led.add("vuln", "osv", {"name": "qs", "version": "6.5.2"})

    text = "A finding without any cited evidence brackets."
    errs = verifier.verify_claim(text, [], led)
    assert "no evidence IDs cited" in errs


def test_verifier_rejects_unoffered_option(tmp_path):
    led = Ledger(tmp_path / "ledger.json")
    eid = led.add("vuln", "osv", {"name": "qs", "version": "6.5.2"})

    text = "We should apply [O-99] as seen in [E-001]."
    errs = verifier.verify_claim(text, [eid, "O-99"], led, option_ids=["O-1"])
    assert any("O-99 is not an offered option" in e for e in errs)
