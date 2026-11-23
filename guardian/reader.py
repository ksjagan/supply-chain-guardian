"""
Quarantined Reader Agent.
Safely inspects untrusted strings (install scripts, custom Docker RUN instructions, CI/CD run steps)
under quarantine without executing any code.
Uses LLM structured boolean schema analysis, falling back to deterministic AST/regex heuristics.
"""
from typing import Dict, List, Optional
from guardian.ledger import Ledger
from guardian.llm.client import LLMClient


class Reader:
    """
    Quarantined inspector for untrusted code/script blocks.
    Never executes code from the target.
    """

    def __init__(self, ledger: Ledger, llm_client: Optional[LLMClient] = None):
        self.ledger = ledger
        self.llm = llm_client

    def run(self) -> None:
        """
        Scans evidence for install scripts and suspicious strings, runs quarantined analysis,
        and writes claims to the ledger.
        """
        # Collect scripts from evidence
        targets: List[Dict[str, str]] = []
        for ev in self.ledger.evidence:
            if ev.kind == "install_script":
                targets.append({
                    "type": "install_script",
                    "component": ev.component,
                    "evidence_id": ev.id,
                    "content": ev.data.get("script", ""),
                })
            elif ev.kind == "dockerfile_finding" and "curl" in ev.data.get("line", "").lower():
                targets.append({
                    "type": "dockerfile_run",
                    "component": "Dockerfile",
                    "evidence_id": ev.id,
                    "content": ev.data.get("line", ""),
                })

        for item in targets[:15]:  # limit to budget cap
            analysis = self._analyze_content(item["content"], item["type"])
            self.ledger.add_claim("reader", {
                "evidence_id": item["evidence_id"],
                "component": item["component"],
                "target_type": item["type"],
                "analysis": analysis,
            })

    def _analyze_content(self, text: str, target_type: str) -> dict:
        if self.llm and self.llm.is_available():
            try:
                system_prompt = (
                    "You are a sandboxed security code reader. Analyze this snippet under quarantine.\n"
                    "Output JSON matching this schema:\n"
                    "{\n"
                    '  "runs_network_command": true/false,\n'
                    '  "downloads_and_executes": true/false,\n'
                    '  "reads_env_or_credentials": true/false,\n'
                    '  "obfuscated": true/false,\n'
                    '  "risk_level": "critical"|"high"|"medium"|"low",\n'
                    '  "summary": "1-line explanation"\n'
                    "}"
                )
                user_prompt = f"Snippet ({target_type}):\n```\n{text[:1000]}\n```"
                return self.llm.complete_json(system_prompt, user_prompt)
            except Exception as e:
                pass  # fallback to deterministic

        # Deterministic fallback heuristics
        lower = text.lower()
        runs_net = any(k in lower for k in ["curl", "wget", "http://", "https://", "fetch", "axios"])
        dl_exec = any(k in lower for k in ["curl | sh", "curl|sh", "wget -q -o- | sh", "| bash", "eval("])
        reads_cred = any(k in lower for k in ["process.env", "env[", "$token", "$secret", "id_rsa", ".aws"])
        obf = any(k in lower for k in ["fromcharcode", "base64", "hex", "\\x", "eval(unescape"])

        risk = "low"
        if dl_exec or obf:
            risk = "critical"
        elif runs_net or reads_cred:
            risk = "high"

        return {
            "runs_network_command": runs_net,
            "downloads_and_executes": dl_exec,
            "reads_env_or_credentials": reads_cred,
            "obfuscated": obf,
            "risk_level": risk,
            "summary": "Heuristic analysis: detected risky pattern in untrusted script" if risk != "low" else "Standard build/install script execution",
            "fallback": True,
        }
