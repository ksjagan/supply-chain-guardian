"""Reporter: compile run outputs into JSON artifacts and standalone offline report.html (Jinja2 autoescape ON)."""
import time
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from guardian import config


def generate_all(rd):
    rd = Path(rd)
    run = config.load_run(rd)
    findings = config.read_json(rd / "findings.json", [])
    model = config.read_json(rd / "model.json", {"components": {}})
    scout = config.read_json(rd / "scout.json", {})
    coverage = config.read_json(rd / "coverage.json", {})
    validation = config.read_json(rd / "validation.json")
    changes = config.read_json(rd / "parts" / "changes.json", {})
    osv = config.read_json(rd / "parts" / "osv.json", {})
    kev = config.read_json(rd / "parts" / "kev.json", {})
    canary = config.read_json(rd / "parts" / "canary.json", {})

    from guardian.tracing import read_trace
    trace = read_trace(rd)

    comps = model.get("components", {})
    comp_total = len(comps)
    comp_direct = sum(1 for c in comps.values() if c.get("direct"))
    comp_transitive = comp_total - comp_direct

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        r = f.get("risk", "low")
        if r in sev_counts:
            sev_counts[r] += 1

    new_risks = sum(1 for f in findings if (f.get("flags") or {}).get("introduced"))

    summary = {
        "run_id": run.get("run_id", rd.name),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "COMPLETE",
        "source": run.get("source", ""),
        "components_total": comp_total,
        "components_direct": comp_direct,
        "components_transitive": comp_transitive,
        "vulns_total": sum(sev_counts.values()),
        "vulns_critical": sev_counts["critical"],
        "vulns_high": sev_counts["high"],
        "vulns_medium": sev_counts["medium"],
        "vulns_low": sev_counts["low"],
        "new_risks": new_risks,
        "changes_count": len(changes.get("items", [])),
        "total_duration": round(sum(s.get("duration", 0) for s in trace), 2),
        "total_tokens": sum(s.get("tokens", 0) for s in trace),
        "total_cost": round(sum(s.get("cost", 0) for s in trace), 5),
    }

    # Determine status
    if scout.get("error") or (osv and not osv.get("ok")):
        summary["status"] = "INCOMPLETE"
    elif canary and not canary.get("ok"):
        summary["status"] = "UNTRUSTED"

    config.write_json(rd / "run_summary.json", summary)

    # Render Jinja2 template
    tmpl_dir = config.PKG / "templates"
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        autoescape=select_autoescape(["html", "xml", "j2"])
    )
    tmpl = env.get_template("report_standalone.html.j2")
    html_out = tmpl.render(
        run=run,
        status=summary["status"],
        summary=summary,
        findings=findings,
        changes=changes,
        validation=validation,
        trace=trace,
        snapshots={
            "osv": osv.get("snapshot"),
            "kev": kev.get("snapshot"),
        }
    )
    (rd / "report.html").write_text(html_out, encoding="utf-8")
    return {"summary": summary, "report_html": str(rd / "report.html")}
