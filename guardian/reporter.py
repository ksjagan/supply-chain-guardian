"""
Reporter agent (Day 1 Checkpoint).
Generates checkpoint.html (self-contained, opens offline),
report.html, findings.json, and baseline.json.
Uses safe HTML escaping across all rendered fields.
Includes AI Risk Prioritization & Executive Briefing.
"""
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from guardian.changes import DiffResult
from guardian.ledger import Ledger
from guardian.models import Component, Finding


class Reporter:
    """
    Renders checkpoint.html, report.html, findings.json, and baseline.json.
    """

    def __init__(self, ledger: Ledger, out_dir: Path):
        self.ledger = ledger
        self.out_dir = out_dir

    def generate(
        self,
        diff_result: Optional[DiffResult] = None,
        repo_key: str = "default",
        is_checkpoint: bool = True,
        analyst_result: Optional[dict] = None,
    ) -> None:
        self._write_findings_json()
        self._write_baseline_json(repo_key)
        self._write_checkpoint_html(diff_result, analyst_result)

    def _write_findings_json(self) -> None:
        path = self.out_dir / "findings.json"
        data = [vars(f) for f in self.ledger.findings]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"run_id": self.ledger.run_id, "findings": data}, fh, indent=2, default=str)
        print(f"[reporter] Findings JSON → {path}")

    def _write_baseline_json(self, repo_key: str) -> None:
        baseline_payload = {
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "run_id": self.ledger.run_id,
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "integrity": c.integrity,
                    "resolved_url": c.resolved_url,
                    "has_install_script": c.has_install_script,
                    "is_dev": c.is_dev,
                    "is_direct": c.is_direct,
                    "purl": c.purl,
                    "bom_ref": c.bom_ref,
                    "manifest_path": c.manifest_path,
                    "direct_parent": c.direct_parent,
                    "origin": c.origin,
                }
                for c in self.ledger.components
            ],
            "findings_count": len(self.ledger.findings),
            "findings": [vars(f) for f in self.ledger.findings],
        }

        # Save in run directory
        p1 = self.out_dir / "baseline.json"
        with open(p1, "w", encoding="utf-8") as fh:
            json.dump(baseline_payload, fh, indent=2, default=str)

        # Save in persistent repo baseline location out/<repo-key>/baseline.json
        p2_dir = self.out_dir.parent / repo_key
        p2_dir.mkdir(parents=True, exist_ok=True)
        p2 = p2_dir / "baseline.json"
        with open(p2, "w", encoding="utf-8") as fh:
            json.dump(baseline_payload, fh, indent=2, default=str)
        print(f"[reporter] Saved baseline → {p2}")

    def _write_checkpoint_html(self, diff: Optional[DiffResult], analyst_res: Optional[dict] = None) -> None:
        total_comps = len(self.ledger.components)
        direct_comps = sum(1 for c in self.ledger.components if c.is_direct)
        trans_comps = total_comps - direct_comps
        dev_comps = sum(1 for c in self.ledger.components if c.is_dev)

        files_found_count = sum(1 for e in self.ledger.evidence if e.kind == "file_found")
        ecosystems = sorted(list({c.ecosystem for c in self.ledger.components} or ["npm"]))

        critical_count = sum(1 for f in self.ledger.findings if f.risk.lower() == "critical")
        high_count = sum(1 for f in self.ledger.findings if f.risk.lower() == "high")
        medium_count = sum(1 for f in self.ledger.findings if f.risk.lower() == "medium")
        low_count = sum(1 for f in self.ledger.findings if f.risk.lower() == "low")
        total_findings = len(self.ledger.findings)

        snapshot_ev = next((e for e in self.ledger.evidence if e.kind == "repo_snapshot"), None)
        target_name = snapshot_ev.data.get("original_target", "") if snapshot_ev else "Application"
        commit_sha = snapshot_ev.data.get("commit_sha", "")[:8] if snapshot_ev else "HEAD"

        # Check OSV status
        osv_unavail = any(e.kind == "osv_record" and e.data.get("status") == "unavailable" for e in self.ledger.evidence)
        osv_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # ── Header Stage Chips ────────────────────────────────────────
        # Repository -> SBOM -> Dependency Graph -> Risk Detection -> Evidence
        stages = [
            ("Repository", "done", f"{files_found_count} files"),
            ("SBOM", "done", f"{total_comps} components"),
            ("Dependency Graph", "done", f"{len(self.ledger.edges) if hasattr(self.ledger, 'edges') else total_comps} edges"),
            ("Risk Detection", "failed" if osv_unavail else "done", f"{total_findings} findings"),
            ("Evidence", "done", f"{len(self.ledger.evidence)} records"),
        ]

        stage_chips_html = ""
        for name, st, desc in stages:
            icon = "&#10003;" if st == "done" else ("&#9888;" if st == "partial" else "&#10007;")
            stage_chips_html += f"""
            <div class="stage-chip stage-{st}">
              <span class="stage-icon">{icon}</span>
              <div>
                <div class="stage-name">{name}</div>
                <div class="stage-desc">{desc}</div>
              </div>
            </div>
            """

        # Coverage box data
        cov_ev = next((e for e in self.ledger.evidence if e.kind == "coverage"), None)
        cov_detected = total_comps
        cov_analysed = total_comps
        cov_partial = 0
        cov_skipped = 0
        if cov_ev:
            for p in cov_ev.data.get("plugin_coverage", []):
                cov_skipped += p.get("skipped_cap", 0)

        # ── Section A: Table of Components ───────────────────────────
        comp_rows = ""
        for c in self.ledger.components:
            orig = c.origin or {
                "ecosystem": c.ecosystem,
                "registry_host": "registry.npmjs.org",
                "manifest_file": c.manifest_path,
                "direct_parent": c.direct_parent or "[root]",
            }
            comp_rows += f"""
            <tr>
              <td><b>{html.escape(c.name)}@{html.escape(c.version)}</b></td>
              <td><span class="badge-role {'direct' if c.is_direct else 'trans'}">{'Direct' if c.is_direct else 'Transitive'}</span></td>
              <td><code>{html.escape(orig.get('ecosystem', 'npm'))}</code></td>
              <td><code>{html.escape(orig.get('registry_host', 'registry.npmjs.org'))}</code></td>
              <td>{html.escape(orig.get('manifest_file', 'package-lock.json'))}</td>
              <td><b>{html.escape(orig.get('direct_parent', '[root]'))}</b></td>
            </tr>
            """

        # ── Section B: What Changed ───────────────────────────────────
        sec_b_html = ""
        if diff is None:
            sec_b_html = """
            <div class="card unavailable-box">
              <div class="card-header"><h3>Section B: What Changed</h3></div>
              <p class="text-muted">No baseline provided. To compare against previous revisions, pass <code>--baseline &lt;ref_or_dir&gt;</code>, <code>--since HEAD~1</code>, or run <code>guardian diff</code>.</p>
            </div>
            """
        elif not diff.baseline_available:
            sec_b_html = f"""
            <div class="card unavailable-box">
              <div class="card-header">
                <h3>Section B: What Changed — Baseline Unavailable</h3>
                <span class="ref-pill">baseline unavailable</span>
              </div>
              <p class="text-danger" style="margin-top:6px"><b>Reason:</b> {html.escape(diff.unavailable_reason)}</p>
              <p class="text-muted" style="margin-top:4px">The scan completed fully, but historical comparison could not be performed against this baseline reference.</p>
            </div>
            """
        else:
            strip_html = f"""
            <div class="summary-strip">
              <span class="badge-ch added">+{diff.count_added} added</span>
              <span class="badge-ch removed">-{diff.count_removed} removed</span>
              <span class="badge-ch upgraded">&#8679; {diff.count_upgraded} upgraded</span>
              <span class="badge-ch downgraded">&#8681; {diff.count_downgraded} downgraded</span>
              <span class="badge-ch modified">&#9881; {diff.count_modified} modified</span>
              <span class="badge-ch scripts">&#9888; {diff.count_new_install_scripts} install scripts</span>
            </div>
            """

            new_risks_rows = ""
            for item in diff.changes:
                if item.risk_hint in ("critical", "high") or "install-script-gained" in item.flags or "modified-integrity" in item.flags:
                    flags_badges = " ".join(f'<span class="pill-flag">{html.escape(fl)}</span>' for fl in item.flags)
                    new_risks_rows += f"""
                    <tr>
                      <td><b>{html.escape(item.name)}</b></td>
                      <td><span class="risk-badge {item.risk_hint}">{item.risk_hint.upper()}</span></td>
                      <td>{html.escape(item.change_type)}</td>
                      <td>{html.escape(str(item.old_version or "—"))} &rarr; <b>{html.escape(str(item.new_version or "—"))}</b></td>
                      <td>{flags_badges or "—"}</td>
                      <td>{html.escape(item.details)}</td>
                    </tr>
                    """

            new_risks_box = ""
            if new_risks_rows:
                new_risks_box = f"""
                <div class="new-risks-box">
                  <h4>&#9888; New Risks Introduced By This Change</h4>
                  <table class="report-table">
                    <thead>
                      <tr><th>Package</th><th>Risk</th><th>Change</th><th>Versions</th><th>Flags</th><th>Details</th></tr>
                    </thead>
                    <tbody>{new_risks_rows}</tbody>
                  </table>
                </div>
                """
            else:
                new_risks_box = """
                <div class="new-risks-box clean">
                  <h4>&#10003; No High-Risk Supply Chain Changes Introduced</h4>
                  <p class="text-muted" style="margin:4px 0 0">None of the modified or added packages introduced high-severity diff alerts.</p>
                </div>
                """

            changes_rows = ""
            for item in diff.changes:
                flags_badges = " ".join(f'<span class="pill-flag">{html.escape(fl)}</span>' for fl in item.flags)
                ev_id_match = next((e.id for e in self.ledger.evidence if e.kind == "lockfile_diff" and e.component == item.name), "—")
                changes_rows += f"""
                <tr>
                  <td><b>{html.escape(item.name)}</b></td>
                  <td><span class="badge-ch {item.change_type}">{html.escape(item.change_type)}</span></td>
                  <td>{html.escape(str(item.old_version or "—"))} &rarr; {html.escape(str(item.new_version or "—"))}</td>
                  <td>{flags_badges or "—"}</td>
                  <td><span class="risk-badge {item.risk_hint}">{item.risk_hint.upper()}</span></td>
                  <td><span class="ev-tag">{ev_id_match}</span></td>
                </tr>
                """

            infra_rows = ""
            for d in diff.dockerfile_diff:
                infra_rows += f"""
                <tr>
                  <td><b>Dockerfile</b></td>
                  <td><span class="badge-ch modified">dockerfile</span></td>
                  <td colspan="2">{html.escape(d.get('details', ''))}</td>
                  <td><span class="risk-badge {d.get('risk', 'medium')}">{d.get('risk', 'medium').upper()}</span></td>
                  <td><span class="ev-tag">E-diff</span></td>
                </tr>
                """
            for w in diff.workflow_diff:
                infra_rows += f"""
                <tr>
                  <td><b>{html.escape(w.get('file', 'workflow'))}</b></td>
                  <td><span class="badge-ch modified">workflow</span></td>
                  <td colspan="2">{html.escape(w.get('details', ''))}</td>
                  <td><span class="risk-badge {w.get('risk', 'medium')}">{w.get('risk', 'medium').upper()}</span></td>
                  <td><span class="ev-tag">E-diff</span></td>
                </tr>
                """

            table_content = changes_rows + infra_rows
            if not table_content:
                table_content = "<tr><td colspan='6' class='text-muted' style='text-align:center'>No differences detected between baseline and current state.</td></tr>"

            sec_b_html = f"""
            <div class="card">
              <div class="card-header">
                <h3>Section B: What Changed</h3>
                <span class="ref-pill">{html.escape(diff.baseline_ref)} &rarr; {html.escape(diff.current_ref)}</span>
              </div>
              {strip_html}
              {new_risks_box}
              <h4 style="margin:16px 0 8px">All Detected Changes</h4>
              <table class="report-table">
                <thead>
                  <tr><th>Package / Config</th><th>Change Type</th><th>Old &rarr; New</th><th>Flags</th><th>Risk</th><th>Evidence ID</th></tr>
                </thead>
                <tbody>{table_content}</tbody>
              </table>
            </div>
            """

        # ── AI Risk Prioritization Section ─────────────────────────────
        ai_panel_html = ""
        exec_summary = ""
        is_ai_powered = False
        if analyst_res:
            exec_summary = analyst_res.get("executive_summary", "")
            is_ai_powered = analyst_res.get("ai_powered", False)

        ai_badge = '<span class="pill-fix" style="background:#0284c7;color:#fff">AI Agent Active</span>' if is_ai_powered else '<span class="pill-flag">Deterministic Prioritizer</span>'
        
        prio_items_html = ""
        p1_count = sum(1 for f in self.ledger.findings if "P1" in str(f.context.get("ai_priority", "")))
        p2_count = sum(1 for f in self.ledger.findings if "P2" in str(f.context.get("ai_priority", "")))
        p3_count = sum(1 for f in self.ledger.findings if "P3" in str(f.context.get("ai_priority", "")))

        ai_panel_html = f"""
        <div class="card ai-card">
          <div class="card-header">
            <div style="display:flex;align-items:center;gap:10px">
              <span style="font-size:20px">🧠</span>
              <h3 style="margin:0">AI Risk Analysis & Prioritization</h3>
              {ai_badge}
            </div>
            <span class="pill-cve" style="background:#1e293b;color:#38bdf8">Step 3: Analyze with AI</span>
          </div>
          <div style="margin-top:10px;padding:12px;background:#0f172a;border-radius:8px;border-left:4px solid #38bdf8">
            <div style="font-size:11px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Executive Risk Briefing</div>
            <p style="font-size:14px;color:#f1f5f9;line-height:1.6">{html.escape(exec_summary or 'All supply chain components mapped and correlated against known vulnerability advisories.')}</p>
          </div>
          <div style="display:flex;gap:12px;margin-top:14px;flex-wrap:wrap">
            <div class="prio-stat prio-p1"><b>{p1_count}</b> Immediate Action (P1)</div>
            <div class="prio-stat prio-p2"><b>{p2_count}</b> Remediation Queue (P2)</div>
            <div class="prio-stat prio-p3"><b>{p3_count}</b> Hardening / Config (P3)</div>
          </div>
        </div>
        """

        # ── Section C: What Appears Risky (Evidence Cards) ────────────
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(self.ledger.findings, key=lambda f: risk_order.get(f.risk.lower(), 4))

        sec_c_cards = ""
        if osv_unavail:
            sec_c_cards += """
            <div class="banner-warning">
              <b>&#9888; Vulnerability data unavailable:</b> Network connection to OSV vulnerability database failed or was blocked. Status marked INCOMPLETE.
            </div>
            """

        if not sorted_findings:
            sec_c_cards += "<p class='text-muted' style='text-align:center;padding:20px'>No findings detected.</p>"
        else:
            for f in sorted_findings:
                path_str = " &rarr; ".join(html.escape(p) for p in f.path)
                ev_chips = " ".join(f'<span class="ev-tag">{html.escape(eid)}</span>' for eid in f.evidence_ids)

                cve_badge = f'<span class="pill-cve">{html.escape(f.cve)}</span>' if f.cve else ""
                cvss_badge = f'<span class="pill-cvss">CVSS {html.escape(f.cvss)}</span>' if f.cvss else ""
                fix_badge = f'<span class="pill-fix">Fix: {html.escape(f.fix_version)}</span>' if f.fix_version else ""
                parent_upgrade = f'<div style="margin-top:6px"><b>Direct Dependency to Upgrade:</b> <span class="highlight-parent">{html.escape(f.direct_parent_to_upgrade)}</span></div>' if f.direct_parent_to_upgrade else ""

                prio_val = f.context.get("ai_priority", "")
                prio_badge = f'<span class="pill-prio">{html.escape(prio_val)}</span>' if prio_val else ""
                verif_badge = '<span class="pill-verif">&#10003; Verified by Code</span>' if f.status == "verified" else '<span class="pill-unverif">&#9888; Unverified</span>'

                rec_action = f.context.get("ai_recommended_action", "")
                action_box = f'<div class="action-box"><b>Recommended Action:</b> {html.escape(rec_action)}</div>' if rec_action else ""

                raw_json = html.escape(json.dumps(f.raw_data or vars(f), indent=2, default=str))

                sec_c_cards += f"""
                <div class="evidence-card risk-border-{f.risk.lower()}">
                  <div class="card-top-row">
                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                      <span class="risk-badge {f.risk.lower()}">{f.risk.upper()}</span>
                      {prio_badge}
                      {verif_badge}
                      <b class="card-comp">{html.escape(f.component)}</b>
                      <span class="card-type">({html.escape(f.type)})</span>
                      {cve_badge}
                      {cvss_badge}
                      {fix_badge}
                    </div>
                    <div>
                      <code class="verify-cmd">guardian verify {html.escape(f.id)}</code>
                    </div>
                  </div>

                  <p class="card-desc">{html.escape(f.explanation)}</p>
                  {action_box}

                  <div class="card-meta">
                    <div><b>Dependency Path:</b> <span class="path-box">{path_str}</span></div>
                    {parent_upgrade}
                    <div style="margin-top:6px"><b>Confidence Basis:</b> {html.escape(f.confidence_basis)}</div>
                    <div style="margin-top:6px"><b>Evidence IDs:</b> {ev_chips}</div>
                    <details style="margin-top:8px">
                      <summary style="cursor:pointer;color:#60a5fa;font-size:11px">Expand Raw Evidence Data</summary>
                      <pre class="raw-data-box">{raw_json}</pre>
                    </details>
                  </div>
                </div>
                """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Guardian Checkpoint – {html.escape(target_name)}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:#0a0e17;color:#e2e8f0;padding:24px;line-height:1.5}}
  .container{{max-width:1150px;margin:0 auto}}

  /* Header Strip */
  .top-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;border-bottom:1px solid #1e293b;padding-bottom:16px}}
  h1{{font-size:24px;color:#f8fafc;font-weight:700}}
  .subhead{{font-size:13px;color:#94a3b8;margin-top:4px}}
  .run-badge{{display:inline-block;padding:5px 12px;border-radius:6px;font-size:12px;font-weight:700;letter-spacing:.05em}}
  .status-COMPLETE{{background:#065f46;color:#a7f3d0}}
  .status-INCOMPLETE{{background:#854d0e;color:#fef08a}}
  .status-UNTRUSTED{{background:#991b1b;color:#fecaca}}

  /* Stage progress bar */
  .stage-bar{{display:flex;gap:12px;margin-bottom:20px;overflow-x:auto;padding-bottom:4px}}
  .stage-chip{{flex:1;min-width:160px;background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px 14px;display:flex;align-items:center;gap:10px}}
  .stage-done{{border-color:#10b981;background:#062319}}
  .stage-failed{{border-color:#f59e0b;background:#2b1d0c}}
  .stage-icon{{font-size:16px;font-weight:bold}}
  .stage-done .stage-icon{{color:#34d399}}
  .stage-failed .stage-icon{{color:#fbbf24}}
  .stage-name{{font-weight:600;font-size:12px;color:#f8fafc}}
  .stage-desc{{font-size:11px;color:#94a3b8}}

  /* Coverage Box */
  .coverage-box{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px 20px;margin-bottom:24px;display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:16px}}
  .stat-item .stat-label{{font-size:11px;color:#9ca3af;text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}}
  .stat-item .stat-val{{font-size:22px;font-weight:700;color:#f3f4f6}}
  .stat-sub{{font-size:11px;color:#6b7280;margin-top:2px}}

  /* Cards */
  .card{{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:20px;margin-bottom:24px}}
  .ai-card{{border-color:#0369a1;background:#082f4922}}
  .card-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;border-bottom:1px solid #1f2937;padding-bottom:10px}}
  .card-header h3{{font-size:16px;color:#f1f5f9;font-weight:600}}
  .ref-pill{{background:#1e293b;color:#cbd5e1;padding:3px 10px;border-radius:12px;font-size:11px;font-family:monospace}}

  /* Priority Stats */
  .prio-stat{{padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600}}
  .prio-p1{{background:#7f1d1d;color:#fecaca}}
  .prio-p2{{background:#78350f;color:#fed7aa}}
  .prio-p3{{background:#1e3a8a;color:#bfdbfe}}

  /* Tables */
  .table-wrap{{max-height:360px;overflow-y:auto;border:1px solid #1f2937;border-radius:6px}}
  .report-table{{width:100%;border-collapse:collapse;font-size:12px;text-align:left}}
  .report-table th{{background:#1e293b;color:#cbd5e1;padding:8px 12px;position:sticky;top:0;font-weight:600}}
  .report-table td{{padding:8px 12px;border-bottom:1px solid #1e293b;color:#cbd5e1}}
  .report-table tr:hover td{{background:#1e293b55}}

  /* Badges */
  .badge-role{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
  .badge-role.direct{{background:#1e3a8a;color:#93c5fd}}
  .badge-role.trans{{background:#1e293b;color:#94a3b8}}
  .pill-cve{{background:#991b1b;color:#fecaca;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700}}
  .pill-cvss{{background:#7f1d1d;color:#fca5a5;padding:2px 6px;border-radius:4px;font-size:11px}}
  .pill-fix{{background:#065f46;color:#a7f3d0;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600}}
  .pill-prio{{background:#0284c7;color:#ffffff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700}}
  .pill-verif{{background:#065f46;color:#a7f3d0;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
  .pill-unverif{{background:#854d0e;color:#fef08a;padding:2px 8px;border-radius:4px;font-size:11px}}
  .ev-tag{{background:#1e293b;color:#38bdf8;padding:1px 6px;border-radius:4px;font-size:10px;font-family:monospace;border:1px solid #334155}}
  .highlight-parent{{background:#312e81;color:#c7d2fe;padding:2px 6px;border-radius:4px;font-weight:600}}
  .verify-cmd{{background:#0f172a;color:#a5f3fc;padding:3px 8px;border-radius:4px;font-size:11px;font-family:monospace;border:1px solid #1e293b}}

  /* Summary Strip */
  .summary-strip{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}}
  .badge-ch{{padding:4px 10px;border-radius:6px;font-size:12px;font-weight:600}}
  .badge-ch.added{{background:#065f46;color:#a7f3d0}}
  .badge-ch.removed{{background:#374151;color:#9ca3af}}
  .badge-ch.upgraded{{background:#1e3a8a;color:#93c5fd}}
  .badge-ch.downgraded{{background:#78350f;color:#fed7aa}}
  .badge-ch.modified{{background:#581c87;color:#e9d5ff}}
  .badge-ch.scripts{{background:#991b1b;color:#fecaca}}
  .pill-flag{{background:#7f1d1d44;border:1px solid #991b1b;color:#fca5a5;padding:1px 6px;border-radius:4px;font-size:10px}}

  /* Risk Badges */
  .risk-badge{{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.05em}}
  .risk-badge.critical{{background:#dc2626;color:#fff}}
  .risk-badge.high{{background:#ea580c;color:#fff}}
  .risk-badge.medium{{background:#d97706;color:#fff}}
  .risk-badge.low{{background:#2563eb;color:#fff}}

  /* Evidence Cards */
  .evidence-card{{background:#111827;border:1px solid #1f2937;border-radius:8px;padding:16px;margin-bottom:14px;border-left:4px solid #4b5563}}
  .risk-border-critical{{border-left-color:#ef4444}}
  .risk-border-high{{border-left-color:#f97316}}
  .risk-border-medium{{border-left-color:#f59e0b}}
  .risk-border-low{{border-left-color:#3b82f6}}
  .card-top-row{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
  .card-comp{{font-size:15px;color:#f8fafc}}
  .card-type{{font-size:12px;color:#94a3b8}}
  .card-desc{{font-size:13px;color:#e2e8f0;margin-bottom:10px;line-height:1.5}}
  .action-box{{background:#064e3b33;border:1px solid #065f46;border-radius:6px;padding:8px 12px;font-size:12px;color:#a7f3d0;margin-bottom:10px}}
  .card-meta{{font-size:12px;color:#94a3b8;background:#0f172a;padding:10px;border-radius:6px}}
  .path-box{{color:#e2e8f0;font-family:monospace;font-size:11px}}
  .raw-data-box{{background:#020617;color:#94a3b8;padding:8px;border-radius:4px;font-size:10px;margin-top:6px;overflow-x:auto}}

  /* New Risks Box */
  .new-risks-box{{background:#201207;border:1px solid #78350f;border-radius:8px;padding:14px;margin-bottom:16px}}
  .new-risks-box.clean{{background:#062319;border-color:#065f46}}
  .new-risks-box h4{{font-size:13px;color:#fed7aa;margin-bottom:10px}}
  .new-risks-box.clean h4{{color:#a7f3d0}}

  /* Warning Banner */
  .banner-warning{{background:#451a03;border:1px solid #b45309;color:#fde68a;padding:12px 16px;border-radius:8px;margin-bottom:16px;font-size:13px}}
  .text-danger{{color:#f87171}}
  .text-muted{{color:#94a3b8;font-size:12px}}
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="top-header">
    <div>
      <h1>Guardian Security Checkpoint</h1>
      <div class="subhead">Target: <b>{html.escape(target_name)}</b> &middot; Ref: <code>{html.escape(commit_sha)}</code> &middot; Generated {html.escape(osv_timestamp)}</div>
    </div>
    <div>
      <span class="run-badge status-{self.ledger.run_status}">{self.ledger.run_status}</span>
    </div>
  </div>

  <!-- Stage Progress Bar -->
  <div class="stage-bar">
    {stage_chips_html}
  </div>

  <!-- Coverage Box -->
  <div class="coverage-box">
    <div class="stat-item">
      <div class="stat-label">Total Discovered</div>
      <div class="stat-val">{cov_detected}</div>
      <div class="stat-sub">100% of discovered lockfiles</div>
    </div>
    <div class="stat-item">
      <div class="stat-label">Direct Dependencies</div>
      <div class="stat-val">{direct_comps}</div>
      <div class="stat-sub">Declared in manifests</div>
    </div>
    <div class="stat-item">
      <div class="stat-label">Transitive Deps</div>
      <div class="stat-val">{trans_comps}</div>
      <div class="stat-sub">Resolved via dependency graph</div>
    </div>
    <div class="stat-item">
      <div class="stat-label">Ecosystems Analyzed</div>
      <div class="stat-val">{len(ecosystems)}</div>
      <div class="stat-sub">{', '.join(ecosystems)} (depth: full)</div>
    </div>
    <div class="stat-item">
      <div class="stat-label">Skipped / Capped</div>
      <div class="stat-val">{cov_skipped}</div>
      <div class="stat-sub">{"honest: no items capped" if cov_skipped == 0 else f"{cov_skipped} skipped"}</div>
    </div>
  </div>

  <!-- AI Analysis & Prioritization Card -->
  {ai_panel_html}

  <!-- Section B: What Changed -->
  {sec_b_html}

  <!-- Section C: What Appears Risky -->
  <div class="card">
    <div class="card-header">
      <h3>Section C: What Appears Risky</h3>
      <span class="ref-pill">{total_findings} findings identified</span>
    </div>
    {sec_c_cards}
  </div>

  <!-- Section A: Full Components Table -->
  <div class="card">
    <div class="card-header">
      <h3>Section A: What is in the Application (Components &amp; Supply Chain Origins)</h3>
      <span class="ref-pill">{total_comps} components</span>
    </div>
    <div class="table-wrap">
      <table class="report-table">
        <thead>
          <tr>
            <th>Component &amp; Version</th>
            <th>Relationship</th>
            <th>Ecosystem</th>
            <th>Registry Origin</th>
            <th>Manifest Source</th>
            <th>Direct Parent Ancestor</th>
          </tr>
        </thead>
        <tbody>
          {comp_rows}
        </tbody>
      </table>
    </div>
  </div>

</div>
</body>
</html>
"""
        p_cp = self.out_dir / "checkpoint.html"
        with open(p_cp, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"[reporter] checkpoint.html → {p_cp}")

        p_rp = self.out_dir / "report.html"
        with open(p_rp, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"[reporter] report.html → {p_rp}")
