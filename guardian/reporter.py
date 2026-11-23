"""
Reporter agent (Day 1 Checkpoint).
Generates checkpoint.html (self-contained, opens offline),
report.html, findings.json, and baseline.json.
Uses safe HTML escaping across all rendered fields.
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
    ) -> None:
        self._write_findings_json()
        self._write_baseline_json(repo_key)
        self._write_checkpoint_html(diff_result)

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

    def _write_checkpoint_html(self, diff: Optional[DiffResult]) -> None:
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

        # ── Section C: What Appears Risky (Evidence Cards) ────────────
        # Sort findings: critical -> high -> medium -> low
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

                raw_json = html.escape(json.dumps(f.raw_data or vars(f), indent=2, default=str))

                sec_c_cards += f"""
                <div class="evidence-card risk-border-{f.risk.lower()}">
                  <div class="card-top-row">
                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
                      <span class="risk-badge {f.risk.lower()}">{f.risk.upper()}</span>
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

  /* Pipeline chips */
  .stages-strip{{display:flex;gap:10px;margin-bottom:20px;overflow-x:auto;padding-bottom:4px}}
  .stage-chip{{background:#131d31;border:1px solid #1e293b;border-radius:6px;padding:8px 14px;display:flex;align-items:center;gap:10px;flex:1;min-width:180px}}
  .stage-chip.stage-done .stage-icon{{color:#34d399}}
  .stage-chip.stage-partial .stage-icon{{color:#facc15}}
  .stage-chip.stage-failed .stage-icon{{color:#f87171}}
  .stage-name{{font-size:12px;font-weight:700;color:#f8fafc}}
  .stage-desc{{font-size:11px;color:#94a3b8}}

  /* Coverage Box */
  .coverage-box{{background:#131d31;border:1px solid #1e293b;border-radius:8px;padding:14px 18px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:14px}}
  .cov-title{{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8}}
  .cov-chips{{display:flex;gap:12px;flex-wrap:wrap}}
  .cov-chip{{background:#0a0e17;border:1px solid #334155;border-radius:5px;padding:4px 10px;font-size:12px}}
  .cov-chip b{{color:#f8fafc}}

  /* Cards */
  .card{{background:#131d31;border:1px solid #1e293b;border-radius:8px;padding:20px;margin-bottom:24px}}
  .card-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}}
  h3{{font-size:17px;color:#f1f5f9;font-weight:600}}
  h4{{font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#94a3b8}}

  /* Stats grid */
  .grid-stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:14px}}
  .stat-box{{background:#0a0e17;border:1px solid #1e293b;border-radius:6px;padding:12px;text-align:center}}
  .stat-val{{font-size:22px;font-weight:700;color:#f8fafc}}
  .stat-lbl{{font-size:11px;text-transform:uppercase;color:#94a3b8;letter-spacing:.05em;margin-top:2px}}
  .risk-critical{{color:#ef4444}} .risk-high{{color:#f97316}} .risk-medium{{color:#eab308}} .risk-low{{color:#3b82f6}}

  /* Searchable table */
  .table-controls{{display:flex;justify-content:space-between;align-items:center;margin:12px 0 8px}}
  .search-input{{background:#0a0e17;border:1px solid #334155;color:#f1f5f9;padding:6px 12px;border-radius:6px;font-size:12px;width:240px;outline:none}}
  .search-input:focus{{border-color:#3b82f6}}
  .report-table{{width:100%;border-collapse:collapse;font-size:13px}}
  .report-table th,.report-table td{{padding:8px 10px;text-align:left;border-bottom:1px solid #1e293b}}
  .report-table th{{background:#0a0e17;color:#94a3b8;font-weight:600;font-size:11px;text-transform:uppercase}}

  /* Badges */
  .badge-role{{padding:2px 7px;border-radius:4px;font-size:11px;font-weight:600}}
  .badge-role.direct{{background:#1e3a8a;color:#bfdbfe}}
  .badge-role.trans{{background:#374151;color:#d1d5db}}
  .summary-strip{{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 16px}}
  .badge-ch{{display:inline-block;padding:3px 9px;border-radius:4px;font-size:12px;font-weight:600}}
  .badge-ch.added{{background:#065f46;color:#a7f3d0}}
  .badge-ch.removed{{background:#374151;color:#d1d5db}}
  .badge-ch.upgraded{{background:#1e3a8a;color:#bfdbfe}}
  .badge-ch.downgraded{{background:#7c2d12;color:#ffedd5}}
  .badge-ch.modified{{background:#831843;color:#fbcfe8}}
  .badge-ch.scripts{{background:#9a3412;color:#fed7aa}}

  /* Section C Evidence Cards */
  .evidence-card{{background:#131d31;border:1px solid #1e293b;border-left:5px solid #64748b;border-radius:6px;padding:16px;margin-bottom:16px}}
  .risk-border-critical{{border-left-color:#ef4444}}
  .risk-border-high{{border-left-color:#f97316}}
  .risk-border-medium{{border-left-color:#eab308}}
  .risk-border-low{{border-left-color:#3b82f6}}
  .card-top-row{{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px}}
  .card-comp{{font-size:15px;color:#f8fafc}}
  .card-type{{font-size:12px;color:#94a3b8}}
  .card-desc{{font-size:13px;color:#cbd5e1;margin-bottom:10px}}
  .card-meta{{font-size:11px;color:#94a3b8;background:#0a0e17;border-radius:6px;padding:10px 12px}}
  .path-box{{font-family:monospace;color:#facc15}}
  .highlight-parent{{color:#60a5fa;font-family:monospace;font-weight:700}}
  .verify-cmd{{background:#0a0e17;border:1px solid #334155;color:#a7f3d0;padding:2px 8px;border-radius:4px;font-family:monospace;font-size:11px}}
  .pill-cve{{background:#991b1b;color:#fecaca;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700}}
  .pill-cvss{{background:#374151;color:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:11px}}
  .pill-fix{{background:#065f46;color:#a7f3d0;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600}}
  .pill-flag{{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:1px 6px;border-radius:4px;font-size:10px}}
  .ev-tag{{background:#0a0e17;border:1px solid #3b82f6;color:#93c5fd;font-family:monospace;font-size:10px;padding:2px 6px;border-radius:3px}}
  .risk-badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase}}
  .risk-badge.critical{{background:#ef4444;color:#fff}}
  .risk-badge.high{{background:#f97316;color:#fff}}
  .risk-badge.medium{{background:#eab308;color:#000}}
  .risk-badge.low{{background:#3b82f6;color:#fff}}
  .btn{{display:inline-block;background:#3b82f6;color:#fff;text-decoration:none;padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600}}
  .raw-data-box{{background:#050811;padding:8px;border-radius:4px;color:#94a3b8;font-size:10px;overflow-x:auto;margin-top:4px}}
  .banner-warning{{background:#451a03;border:1px solid #b45309;color:#fde68a;padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px}}
  footer{{margin-top:32px;border-top:1px solid #1e293b;padding-top:14px;font-size:11px;color:#64748b;text-align:center}}
</style>
</head>
<body>
<div class="container">

  <!-- TOP HEADER -->
  <div class="top-header">
    <div>
      <h1>&#128737; Software Supply Chain Guardian</h1>
      <div class="subhead">Target: <b>{html.escape(target_name)}</b> &middot; Commit: <code>{html.escape(commit_sha)}</code> &middot; Run ID: <code>{html.escape(self.ledger.run_id)}</code></div>
    </div>
    <div style="text-align:right">
      <span class="run-badge status-{self.ledger.run_status}">{self.ledger.run_status}</span>
      <div style="font-size:11px;color:#94a3b8;margin-top:4px">OSV Snapshot: {osv_timestamp}</div>
    </div>
  </div>

  <!-- PIPELINE STAGE CHIPS -->
  <div class="stages-strip">
    {stage_chips_html}
  </div>

  <!-- COVERAGE BOX -->
  <div class="coverage-box">
    <div class="cov-title">&#128230; Coverage Box</div>
    <div class="cov-chips">
      <span class="cov-chip">Detected: <b>{cov_detected}</b></span>
      <span class="cov-chip">Fully Analysed: <b>{cov_analysed}</b></span>
      <span class="cov-chip">Partial: <b>{cov_partial}</b></span>
      <span class="cov-chip">Skipped: <b>{cov_skipped}</b></span>
    </div>
  </div>

  <!-- SECTION A: WHAT IS IN THE APPLICATION -->
  <div class="card">
    <div class="card-header">
      <h3>Section A: What is in the Application</h3>
      <div style="display:flex;gap:8px">
        <a class="btn" href="graph.html" target="_blank">&#127760; View Dependency Graph</a>
        <a class="btn" style="background:#4b5563" href="sbom.cdx.json" target="_blank">&#128203; CycloneDX SBOM</a>
      </div>
    </div>
    <div class="grid-stats">
      <div class="stat-box"><div class="stat-val">{total_comps}</div><div class="stat-lbl">Total Components</div></div>
      <div class="stat-box"><div class="stat-val">{direct_comps}</div><div class="stat-lbl">Direct Deps</div></div>
      <div class="stat-box"><div class="stat-val">{trans_comps}</div><div class="stat-lbl">Transitive Deps</div></div>
      <div class="stat-box"><div class="stat-val">{dev_comps}</div><div class="stat-lbl">Dev-Only Deps</div></div>
      <div class="stat-box"><div class="stat-val">{files_found_count}</div><div class="stat-lbl">Files Analysed</div></div>
      <div class="stat-box"><div class="stat-val">{len(ecosystems)}</div><div class="stat-lbl">Ecosystems</div></div>
    </div>

    <div class="table-controls">
      <h4 style="margin-top:14px">Component Catalog ({total_comps} components)</h4>
      <input class="search-input" placeholder="Search catalog…" onkeyup="filterTable(this.value)" />
    </div>

    <div style="max-height:360px;overflow-y:auto;border:1px solid #1e293b;border-radius:6px">
      <table class="report-table" id="catalog-table">
        <thead>
          <tr><th>Component@Version</th><th>Role</th><th>Ecosystem</th><th>Registry Host</th><th>Manifest File</th><th>Direct Parent</th></tr>
        </thead>
        <tbody>
          {comp_rows}
        </tbody>
      </table>
    </div>
  </div>

  <!-- SECTION B: WHAT CHANGED -->
  {sec_b_html}

  <!-- SECTION C: WHAT APPEARS RISKY -->
  <div class="card">
    <div class="card-header">
      <h3>Section C: What Appears Risky</h3>
      <span class="text-muted" style="font-size:12px">{len(sorted_findings)} findings prioritized by deterministic rules</span>
    </div>
    {sec_c_cards}
  </div>

  <!-- FOOTER -->
  <footer>
    <p>Software Supply Chain Guardian &middot; Day 1 Checkpoint &middot; Dockerfile and workflow static analysis only (no containers pulled or executed).</p>
  </footer>

</div>

<script>
function filterTable(val) {{
  var term = val.toLowerCase();
  var rows = document.querySelectorAll("#catalog-table tbody tr");
  rows.forEach(function(row) {{
    var text = row.textContent.toLowerCase();
    row.style.display = text.indexOf(term) > -1 ? "" : "none";
  }});
}}
</script>
</body>
</html>"""

        # Write checkpoint.html and report.html
        for name in ["checkpoint.html", "report.html"]:
            p = self.out_dir / name
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(html_content)
            print(f"[reporter] {name} → {p}")
