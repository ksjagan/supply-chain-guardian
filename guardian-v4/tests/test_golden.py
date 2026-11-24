"""Tests for Golden end-to-end scan on fixtures/demo-app with mocked LLM."""
from pathlib import Path
from guardian import config, evalharness, pipeline
from guardian.llm import client


def mock_llm_backend(model, system, user):
    """Deterministic mock LLM returns schema-valid explanations citing real ledger IDs."""
    if "You are a text classifier" in system:
        return '{"items":[{"id":"E-001","runs_network_command":false,"downloads_and_executes":false,"reads_env_or_credentials":false,"obfuscated":false,"mentions_instructions_to_ai":false,"benign_build_step":true}]}'
    elif "You help a beginner understand" in system:
        return '{"findings":[{"id":"F-001","priority_rank":1,"explanation":"Vulnerability in component identified in [E-001].","evidence_ids_used":["E-001"]}]}'
    elif "You are a sceptical security reviewer" in system:
        return '{"opinions":[{"id":"F-001","risk_opinion":"high","evidence_ids_used":["E-001"]}]}'
    elif "You choose ONE fix option" in system:
        return '{"choices":[{"finding_id":"F-001","option_id":"O-1","explanation":"Upgrade component using [O-1] as cited in [E-001].","evidence_ids_used":["E-001"]}]}'
    return "{}"


def test_golden_pipeline_run(tmp_path):
    client.set_backend(mock_llm_backend)

    res = pipeline.analyze_tree(tmp_path, config.FIXTURES / "demo-app", offline=True)
    findings = res["findings"]
    led = res["ledger"]

    assert len(findings) > 0
    # Every finding has evidence IDs and valid paths
    for f in findings:
        assert len(f["evidence_ids"]) > 0
        for eid in f["evidence_ids"]:
            assert led.exists(eid), f"Evidence {eid} missing from ledger"

    # Sentinel canary passes
    canary = res["parts"]["canary"]
    assert canary["ok"] is True

    # Parity: second run gives identical results
    res2 = pipeline.analyze_tree(tmp_path / "run2", config.FIXTURES / "demo-app", offline=True)
    assert [f["id"] for f in findings] == [f["id"] for f in res2["findings"]]
    assert [f["risk"] for f in findings] == [f["risk"] for f in res2["findings"]]

    client.set_backend(None)
