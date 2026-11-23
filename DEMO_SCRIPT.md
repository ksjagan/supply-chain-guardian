# Software Supply Chain Guardian – 3-Minute Live Demo Script (Day 1)

> **Checkpoint Theme:** "Show us what is in the application, what changed, and what appears risky."  
> **Rule:** Deterministic code only. No LLM required. Zero code execution from scanned repos.

---

## ⏱️ Minute 0:00 – 0:30: Step 1 — One Command Run

Run the Day 1 Checkpoint scanner on the demo application against baseline `demo-app-v2`:

```powershell
python -m guardian.cli checkpoint fixtures/demo-app --baseline fixtures/demo-app-v2 --demo
```

*(For live internet scan, run on any GitHub repository URL)*:
```powershell
python -m guardian.cli checkpoint https://github.com/OWASP/NodeGoat --no-ai
```

**What to point out:**
- Runs in **under 3 seconds**.
- Executes four deterministic code agents: **Scout &rarr; Mapper &rarr; Hunter &rarr; Reporter**.
- Outputs: `checkpoint.html`, `graph.html`, `sbom.cdx.json`, `findings.json`, `ledger.json`.

---

## ⏱️ Minute 0:30 – 1:00: Step 2 — Header Strip & Coverage Box

Open the generated `checkpoint.html` in your browser:
*(Path printed in terminal, e.g. `out/checkpoint_<id>/checkpoint.html`)*

**What to point out:**
1. **Pipeline Stage Chips:**
   `Repository -> SBOM -> Dependency Graph -> Risk Detection -> Evidence` with status checkmarks and component counts.
2. **Run Status:** `COMPLETE` with OSV snapshot timestamp.
3. **Coverage Box:**
   Shows honest inventory counts:
   - `Detected: 68`
   - `Fully Analysed: 68`
   - `Partial: 0`
   - `Skipped: 0`

---

## ⏱️ Minute 1:00 – 1:30: Step 3 — Section A: "What is in the Application"

Scroll to **Section A: What is in the Application**.

**What to point out:**
1. **Component Counts:**
   - Total Components: **68**
   - Direct: **6** (declared in `package.json`)
   - Transitive: **62**
   - Dev-Only: **2** (`jest`, `eslint`)
2. **Origin & Catalogs Table:**
   - Every component shows its origin: `{ecosystem, registry_host, manifest_file, direct_parent}`.
   - Type in the search box (e.g. `debug` or `lodash`) to show instant client-side filtering.
3. **Interactive Graph:**
   - Click the blue **"View Dependency Graph"** button &rarr; opens `graph.html`.
   - Show hierarchical layout (root at top, direct deps, transitives below).
   - Click "Show direct deps only" to cut noise.

---

## ⏱️ Minute 1:30 – 2:00: Step 4 — Section B: "What Changed"

Scroll to **Section B: What Changed**.

**What to point out:**
1. **Summary Strip:**
   Shows changes between current version and baseline (`fixtures/demo-app-v2` or `HEAD~1`):
   - `+0 added`, `-1 removed`, `1 downgraded`
2. **Deterministic Diff Engine:**
   - Compares package sets by `name@version`, `integrity` hash, and `resolved_url`.
   - Never checks out files or executes code.
3. **New Risks Box:**
   - Highlights any newly introduced vulnerabilities or tampered hashes before developers deploy.

---

## ⏱️ Minute 2:00 – 2:30: Step 5 — Section C: "What Appears Risky" & Verification

Scroll to **Section C: What Appears Risky**.

**What to point out:**
1. **Evidence Cards:**
   - Show real CVEs with severity badges (e.g. `CVE-2017-16137`, `CVSS 7.5`, `HIGH`).
   - Fix version clearly shown (e.g. `Fix: 3.1.0`).
   - **Dependency Path:** `[root] -> express@4.18.2 -> debug@2.6.9`.
   - **Direct Dependency to Upgrade:** Points directly to `express@4.18.2`.
   - Expandable **Raw Evidence Data** showing the cryptographic SHA-256 hash.
2. **Deterministic Verification:**
   Copy the command from any card and run it in terminal:
   ```powershell
   python -m guardian.cli verify F-001 --run out/selfcheck_demo
   ```
   Show how plain code re-derives the finding directly from the Evidence Ledger.

---

## ⏱️ Minute 2:30 – 3:00: Step 6 — Network Failure Transparency & Self-Check

Show what happens when the network fails or vulnerability data is blocked.

Run with an unreachable network target:
```powershell
python -m guardian.cli checkpoint fixtures/demo-app --no-ai
```

**What to point out:**
- The system **never lies** and never claims "no vulnerabilities found" when the network is down.
- Status switches honestly to **`INCOMPLETE`**.
- Section C displays: **"Vulnerability data unavailable: Network connection failed."**

Run the automated Step 5 test suite to prove full compliance:
```powershell
python -m guardian.cli selfcheck
```
- Passes all **12 Checkpoint criteria** in under 3 seconds!
