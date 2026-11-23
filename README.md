# Guardian – Software Supply Chain Security Scanner

> **Day 1 Checkpoint 1** ✅ — dependency graph, SBOM, and coverage box working.

---

## Quick Start (5 minutes)

### 1. Install dependencies

```powershell
pip install networkx pyvis jinja2 requests pytest
```

### 2. Scan a **local folder** (the included demo app)

```powershell
cd c:\Desktop\files\boschai
python -m guardian.cli scan fixtures/demo-app --no-ai
```

### 3. Scan **any public GitHub repo**

```powershell
python -m guardian.cli scan https://github.com/OWASP/NodeGoat --no-ai
```

> Opens a browser-only clone (no code is ever executed). Works in ~10 seconds.

### 4. Open the dependency graph

After the scan finishes you'll see a line like:
```
Open graph: out\20261123_152015_56d4d5\graph.html
```
Double-click that file in Explorer (or open it in Chrome/Edge).

---

## What the tool does right now (Checkpoint 1)

| Step | Agent | Output |
|---|---|---|
| Validate URL / clone repo | Scout | `ledger.json` entries for snapshot + files |
| Parse `package-lock.json` | NpmPlugin | Components, edges, direct vs transitive flags |
| Build CycloneDX SBOM | Mapper | `sbom.cdx.json` |
| Build dependency graph | Mapper | `graph.json` + interactive `graph.html` |
| Compute root→package paths | Mapper | Evidence records per component |
| Coverage box | Mapper | Printed to terminal + stored in ledger |

---

## Output files explained

After each scan you get a folder like `out/20261123_152015_56d4d5/`:

| File | What it is |
|---|---|
| `graph.html` | **Open this in a browser** – interactive dependency graph. Zoom, drag, hover for details. |
| `graph.json` | Raw node/edge list (JSON) – for programmatic use |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM – import into any SBOM tool or Dependency-Track |
| `ledger.json` | The Evidence Ledger – every fact the tool collected, with IDs (E-001 …) |
| `run_summary.json` | Machine-readable run metadata: status, timing, component count |

---

## Graph colour legend

| Colour | Meaning |
|---|---|
| 🔴 Red | Root application |
| 🔵 Dark blue | Direct dependency (declared in package.json) |
| 🌑 Dark grey | Transitive dependency |
| 🟣 Purple | Dev-only package |
| 🟠 Orange | Package with an **install script** (runs code on `npm install`) |

---

## Project structure

```
guardian/
  cli.py          ← Entry point: `python -m guardian.cli scan ...`
  orchestrator.py ← Sequences agents, enforces time limits
  scout.py        ← Validates input, clones repo, finds manifests
  mapper.py       ← Parses lockfiles, builds graph, writes SBOM
  ledger.py       ← Shared evidence store (the "blackboard")
  models.py       ← Data classes: Evidence, Component, Edge, Finding
  config.py       ← All tunable settings in one place
  ecosystems/
    npm.py        ← npm package-lock.json v2/v3 parser

fixtures/
  demo-app/       ← Local test app with package-lock.json

tests/
  test_npm.py     ← 9 npm parser tests
  test_paths.py   ← 7 graph/SBOM tests

out/              ← Created at runtime; one sub-folder per scan run
```

---

## Run the tests

```powershell
cd c:\Desktop\files\boschai
python -m pytest tests/ -v
```

Expected: **16 passed**.

---

## Coming next (remaining Day 1 gates)

- **Gate 4** – OSV vulnerability lookup (CVE, severity, fix version in ledger)
- **Gate 5** – Typosquatting, install-script, Dockerfile/workflow checks, Sentinel
- **Gate 6** – HTML evidence-card report
- **Gate 7** – README polish, Analyst + Verifier (if ahead of schedule)

---

## AI features (Day 2)

Set your Anthropic key to unlock LLM analysis:

```powershell
copy .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

Then drop `--no-ai` from the scan command.
The tool is fully functional without AI — `--no-ai` gives you everything above at zero cost.
