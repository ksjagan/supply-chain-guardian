# Software Supply Chain Guardian 🛡️

**LangGraph multi-agent, evidence-first, Streamlit UI for software supply chain security.**

> "LLMs are untrusted interns inside a deterministic system. Code collects facts into an Evidence Ledger. AI may only classify, rank and explain by citing ledger IDs. Plain code verifies every claim. If AI is off, wrong or attacked, the product still works and never lies."

---

## ⚡ Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
cp .env.example .env
```

### 2. Launch Streamlit UI
```bash
streamlit run guardian/app.py
```
Open your browser at `http://localhost:8501`.

### 3. CLI Commands
```bash
# Scan a local folder or public GitHub URL
python -m guardian.cli scan fixtures/demo-app --demo-cache
python -m guardian.cli scan https://github.com/lodash/lodash --no-ai

# Scan with baseline changes comparison
python -m guardian.cli scan fixtures/attack-demo --since HEAD~1 --demo-cache

# Fast pre-demo selfcheck (<60s)
python -m guardian.cli selfcheck

# Full 6-metric evaluation suite
python -m guardian.cli eval

# Verify an AI explanation against the Evidence Ledger
python -m guardian.cli verify F-001 --run out/<run-id>

# Generate submission package
python -m guardian.cli package
```

---

## 🏛️ Architecture & Competitive Edge

1. **Evidence Ledger (`E-001...`) + Code Verifier**: Single source of truth. LLMs never write evidence; plain Python checks every version number, CVE, and package name.
2. **Quarantined Reader**: Untrusted scripts and READMEs are isolated to an LLM that outputs strict booleans only. Prompt injection payloads cannot manipulate risk downward.
3. **LangGraph Multi-Agent Orchestration**: Parallel Hunter fan-out, automated 2-round repair loop between Analyst and Verifier, human approval checkpoints via `interrupt()`, and SQLite checkpointer for resuming runs.
4. **Sentinel Canary**: Planted test vulnerability and typosquat pass through the same code path on every run. Silent feed failure marks the run `UNTRUSTED`.
5. **Separation of Verified Facts vs AI Claims**: UI displays verified evidence in green success cards and AI explanations in blue cards with verified tags.
6. **17 Safety Guardrails**: Zero hallucination design, sandbox execution, HTML autoescaping, and mandatory human approval before applying patches.

---

## 📂 Output Artifacts (per run in `out/<run-id>/`)
- `report.html`: Standalone offline HTML report with embedded styles.
- `findings.json`: Ranked findings with 0-100 priority score breakdown.
- `ledger.json`: Append-only Evidence Ledger facts (`E-001...`).
- `sbom.cdx.json`: CycloneDX 1.5 Software Bill of Materials.
- `graph.json`: Directed dependency graph with BFS shortest paths.
- `run_summary.json`: High-level metrics, vulnerability counts, and execution cost.
- `trace.jsonl`: Detailed latency, token usage, and cost spans per agent.
- `remediation.patch`: Validated git patch for approved remediations.
