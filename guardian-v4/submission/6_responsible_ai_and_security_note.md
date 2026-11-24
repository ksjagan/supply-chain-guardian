# Responsible AI & Security Note

## Core Thesis
"LLMs are untrusted interns inside a deterministic system. Plain code collects facts into an Evidence Ledger. AI may only classify, rank and explain by citing ledger IDs. Plain code verifies every claim. If AI is off, wrong or attacked, the product still works and never lies."

## 17 Safety Guardrails
1. **ID-Only Citation**: LLMs cite IDs, never assert unbacked facts.
2. **Schema-Locked JSON**: Strict regex-enforced schemas on all outputs.
3. **Plain Code Verifier**: Verifies all versions, CVEs, and IDs against the ledger.
4. **Abstain by Default**: Low-confidence or unverified claims fall back to facts.
5. **Narrow Tasks Only**: AI answers structured questions, never open "is this safe?".
6. **Dual-LLM Quarantine**: Quarantined Reader sees untrusted text; Analyst sees only sanitised metadata.
7. **Name Whitelisting**: Strict `[a-z0-9@/._:-]` sanitisation before prompts.
8. **No Secrets in Prompts**: Credential and environment variables redacted.
9. **No Tools / Shell for LLMs**: Models operate in a zero-privilege jail.
10. **Sandbox Execution**: Repository code is NEVER executed; git limits enforced.
11. **Remediation on Temp Copy**: Fixes tested in temporary directory only.
12. **Strict HTML Escaping**: Jinja2 autoescape ON; no `unsafe_allow_html` for untrusted text.
13. **Timestamp Snapshots**: Data sources stamped with exact refresh timestamps.
14. **Sentinel Canary**: Planted canary detected on every run to verify integrity.
15. **Zero Hallucination Golden Tests**: Automated eval proves 0% hallucination rate.
16. **Mandatory Human Approval**: No patch or code modification without human click.
17. **Budgets & Circuit Breakers**: 120s per node, 600s total, 40k tokens maximum.
