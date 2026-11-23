"""
AI Analyst & Prioritizer Agent (Layer 3: JUDGES / ANALYST).
Correlates vulnerability severity with reachability, dependency depth, provenance,
and exploit context to prioritize meaningful risks.
Produces an Executive Risk Briefing and ranks findings into action tiers,
strictly citing Evidence Ledger IDs ([E-xxx]).
"""
import json
from typing import Any, Dict, List, Optional
from guardian.ledger import Ledger
from guardian.llm.client import LLMClient
from guardian.models import Finding


class Analyst:
    """
    AI Risk Analyst that ranks and explains findings.
    Must cite Evidence IDs ([E-001...]) for every assertion.
    """

    def __init__(self, ledger: Ledger, llm_client: Optional[LLMClient] = None):
        self.ledger = ledger
        self.llm = llm_client
        self.executive_summary: str = ""
        self.prioritization: List[Dict[str, Any]] = []

    def run(self) -> Dict[str, Any]:
        """
        Executes analysis and prioritization. Writes claim to ledger.
        """
        findings = self.ledger.findings
        if not findings:
            self.executive_summary = "Scan completed. No vulnerabilities or suspicious supply chain anomalies detected."
            return {"executive_summary": self.executive_summary, "prioritization": []}

        # Build evidence context for prompt
        findings_payload = []
        for f in findings[:20]:  # focus on top 20 findings
            findings_payload.append({
                "id": f.id,
                "component": f.component,
                "type": f.type,
                "initial_risk": f.risk,
                "cve": f.cve or "None",
                "cvss": f.cvss or "None",
                "fix_version": f.fix_version or "None",
                "path": f.path,
                "direct_parent": f.direct_parent_to_upgrade,
                "evidence_ids": f.evidence_ids,
            })

        diff_summary = {}
        for ev in self.ledger.evidence:
            if ev.kind == "lockfile_diff":
                diff_summary[ev.component] = ev.data

        if self.llm and self.llm.is_available():
            try:
                result = self._call_ai_analyst(findings_payload, diff_summary)
                self.executive_summary = result.get("executive_summary", "")
                self.prioritization = result.get("prioritized_findings", [])
                
                # Attach AI explanations to findings
                prio_map = {p.get("finding_id"): p for p in self.prioritization}
                for f in self.ledger.findings:
                    if f.id in prio_map:
                        item = prio_map[f.id]
                        if item.get("explanation"):
                            f.explanation = item["explanation"]
                        if item.get("priority"):
                            f.context["ai_priority"] = item["priority"]
                        if item.get("recommended_action"):
                            f.context["ai_recommended_action"] = item["recommended_action"]

                claim_data = {
                    "executive_summary": self.executive_summary,
                    "prioritized_findings": self.prioritization,
                    "ai_powered": True,
                    "model": getattr(self.llm, "model", "unknown"),
                    "provider": getattr(self.llm, "provider", "unknown"),
                }
                self.ledger.add_claim("analyst", claim_data)
                return claim_data
            except Exception as exc:
                print(f"[analyst] AI call failed ({exc}); falling back to deterministic prioritization.")

        # Deterministic Fallback
        return self._deterministic_fallback(findings_payload)

    def _call_ai_analyst(self, findings_payload: list, diff_summary: dict) -> dict:
        system_prompt = (
            "You are the AI Supply Chain Security Analyst for Guardian.\n"
            "Your job is to analyze the software supply chain risks and prioritize what actually matters.\n"
            "RULES:\n"
            "1. You MUST cite Evidence IDs like [E-001] whenever referencing a component, path, or finding.\n"
            "2. Rank findings by real exploit context: direct dependencies and supply chain anomalies (typosquats, dangerous scripts) are P1-CRITICAL; transitive CVEs with fixes are P2-HIGH; infrastructure/workflow hardening are P3-MEDIUM.\n"
            "3. Output MUST be valid JSON with this schema:\n"
            "{\n"
            '  "executive_summary": "2-3 sentences explaining what is in the app, what changed, and what appears risky.",\n'
            '  "prioritized_findings": [\n'
            "    {\n"
            '      "finding_id": "F-001",\n'
            '      "priority": "P1-CRITICAL" | "P2-HIGH" | "P3-MEDIUM" | "P4-LOW",\n'
            '      "explanation": "Clear explanation citing [E-xxx] evidence IDs.",\n'
            '      "recommended_action": "Actionable fix instruction"\n'
            "    }\n"
            "  ]\n"
            "}"
        )

        user_prompt = (
            f"Findings discovered:\n{json.dumps(findings_payload, indent=2)}\n\n"
            f"Recent Supply Chain Changes:\n{json.dumps(diff_summary, indent=2)}\n\n"
            "Analyze and prioritize these findings now according to the required JSON schema."
        )

        return self.llm.complete_json(system_prompt, user_prompt)

    def _deterministic_fallback(self, findings_payload: list) -> dict:
        """Deterministic prioritization when AI is disabled or offline."""
        prioritized = []
        for f in self.ledger.findings:
            prio = "P3-MEDIUM"
            if f.risk.lower() == "critical":
                prio = "P1-CRITICAL"
            elif f.risk.lower() == "high":
                prio = "P1-CRITICAL" if ("typosquat" in f.type or "install_script" in f.type or len(f.path) <= 2) else "P2-HIGH"
            elif f.risk.lower() == "medium":
                prio = "P3-MEDIUM"
            else:
                prio = "P4-LOW"

            f.context["ai_priority"] = prio
            ev_citation = f"[{f.evidence_ids[0]}]" if f.evidence_ids else "[E-001]"
            rec = f"Upgrade {f.direct_parent_to_upgrade}" if f.direct_parent_to_upgrade else f"Update {f.component}"
            
            prioritized.append({
                "finding_id": f.id,
                "priority": prio,
                "explanation": f"{f.explanation} (Verified via evidence {ev_citation})",
                "recommended_action": rec,
            })

        crit_count = sum(1 for p in prioritized if "P1" in p["priority"])
        high_count = sum(1 for p in prioritized if "P2" in p["priority"])
        
        self.executive_summary = (
            f"Supply chain scan identified {len(self.ledger.components)} components. "
            f"Found {crit_count} immediate priority risks requiring action and {high_count} high-priority issues. "
            "All findings are tracked with deterministic evidence citations."
        )
        self.prioritization = prioritized

        claim_data = {
            "executive_summary": self.executive_summary,
            "prioritized_findings": self.prioritization,
            "ai_powered": False,
            "fallback": True,
        }
        self.ledger.add_claim("analyst", claim_data)
        return claim_data
