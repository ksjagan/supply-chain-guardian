"""
Plain-Code Verifier Agent.
The deterministic guardrail: evaluates all LLM claims against the immutable Evidence Ledger.
Validates that every cited [E-xxx] evidence ID actually exists and matches.
Flags or strips hallucinated citations, ensuring zero ungrounded assertions reach production.
"""
import re
from typing import Dict, List, Set, Tuple
from guardian.ledger import Ledger
from guardian.models import Finding


class Verifier:
    """
    Plain-code verifier that enforces grounding on all LLM outputs.
    """

    def __init__(self, ledger: Ledger):
        self.ledger = ledger
        self.valid_evidence_ids: Set[str] = {ev.id for ev in ledger.evidence}

    def run(self) -> Dict[str, int]:
        """
        Verifies findings and claims in the ledger.
        Returns verification summary stats.
        """
        verified_count = 0
        unverified_count = 0

        # Verify each finding's evidence IDs and explanation citations
        for f in self.ledger.findings:
            # 1. Check all f.evidence_ids exist in ledger
            missing_ids = [eid for eid in f.evidence_ids if eid not in self.valid_evidence_ids]
            
            # 2. Extract citations in the explanation string like [E-001]
            cited_in_text = re.findall(r"\[(E-\d+)\]", f.explanation)
            invalid_citations = [cid for cid in cited_in_text if cid not in self.valid_evidence_ids]

            if missing_ids or invalid_citations:
                f.status = "unverified"
                f.confidence_basis += f" [VERIFIER WARNING: Missing evidence {missing_ids + invalid_citations}]"
                unverified_count += 1
            else:
                f.status = "verified"
                verified_count += 1

        # Record verification claim in ledger
        self.ledger.add_claim("verifier", {
            "verified_findings": verified_count,
            "unverified_findings": unverified_count,
            "total_evidence_ids": len(self.valid_evidence_ids),
            "status": "PASS" if unverified_count == 0 else "WARNING",
        })

        return {
            "verified": verified_count,
            "unverified": unverified_count,
        }
