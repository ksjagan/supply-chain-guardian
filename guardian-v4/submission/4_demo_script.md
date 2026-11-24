# Guardian 3-Minute Hackathon Demo Script

## Milestone 1: Day 1 Checkpoint - Discovery & Graph
1. Launch UI: `streamlit run guardian/app.py`
2. Select **Demo App** and click **Start Guardian Scan**.
3. Point out live agent status bar in `st.status`.
4. Go to **Inventory & Graph**:
   - Highlight the interactive Pyvis graph with nodes colored by risk.
   - Select `qs@6.5.2`: explain the shortest path `demo-app -> express -> qs`.
5. Go to **What Changed**:
   - Run comparison against `fixtures/attack-demo` (`--since HEAD~1`).
   - Point out the red box: "New risks introduced by this change" (typosquat, major jump, changed integrity).

## Milestone 2: Day 2 12:00 PM - Risk Prioritisation & Approval
1. Go to **Findings**:
   - Show how findings are ranked by transparent 0-100 score.
   - Expand `F-001`: show verified evidence in green vs AI explanation in blue.
   - Show Skeptic second opinion.
2. Go to **Remediation**:
   - Review options `O-1` (upgrade), `O-2` (override), `O-3` (remove), `O-4` (escalate).
   - Point out the AI-chosen recommendation with trade-off explanation.
   - Click **Approve Fix**.

## Milestone 3: Day 2 3:00 PM - Validate and Rescan
1. Click **Validate and Rescan**.
2. Show before/after metric cards:
   - Fixed vulnerabilities.
   - Still open issues.
   - Component count change.
3. Show unified git diff (`remediation.patch`).
4. Download the standalone offline `report.html`.

## Milestone 4: Trust & Quality
1. Go to **Trust & Quality**:
   - Review the 17-point Guardrails table.
   - Review the 6-metric Eval scorecard (100% recall, 0% hallucinations).
   - Show Agent runtime trace & token cost table.
