"""SentraX AI — Remediation Agent.

Reference: Docs/Agents.md Section 4.
Job: For every confirmed finding, generate a concrete fix suggestion (original snippet,
fixed snippet, and clear one-sentence explanation).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from pydantic import ValidationError

from sentrax.utils.llm_client import LLMCallError, LLMClient
from sentrax.utils.schema import RemediationFix

SYSTEM_PROMPT = """You are the Remediation Agent in SentraX AI, an autonomous security testing system.

Your job is to generate a concrete, developer-friendly fix recommendation for a confirmed security finding.

Input:
A confirmed vulnerability finding object containing finding_id, vuln_type, target, mode (dast or sast), and evidence.

Rules:
1. original_snippet:
   - For SAST mode: The exact vulnerable line or snippet from the finding.
   - For DAST mode: A representative snippet of the vulnerable implementation or request pattern.
2. fixed_snippet:
   - For SAST mode: The exact corrected code line(s) implementing secure coding best practices (e.g. parameterized query, textContent, authorization check).
   - For DAST mode: A standard, clean, idiomatic secure code implementation for that endpoint and vuln type.
3. explanation:
   - Exactly 1 or 2 concise sentences explaining why the fix works and prevents the exploit. Keep it concrete and technical, not a lecture.
4. Output Format:
   - Return ONLY a valid JSON object matching this exact schema:
     {
       "finding_id": "<same finding_id as input>",
       "original_snippet": "<vulnerable code/request pattern>",
       "fixed_snippet": "<corrected code pattern>",
       "explanation": "<concise explanation>"
     }
"""

FALLBACK_TEMPLATES = {
    "sqli": {
        "original_snippet": "\"SELECT * FROM users WHERE email='\" + email + \"'\"",
        "fixed_snippet": "db.query(\"SELECT * FROM users WHERE email = ?\", [email])",
        "explanation": "Use parameterized queries or prepared statements so user input is never interpreted as SQL syntax.",
    },
    "xss": {
        "original_snippet": "element.innerHTML = userInput;",
        "fixed_snippet": "element.textContent = userInput; // or use DOMPurify.sanitize(userInput)",
        "explanation": "Safely encode or treat user input as text content rather than executable HTML/JavaScript.",
    },
    "idor": {
        "original_snippet": "const order = await Order.findById(req.params.id);",
        "fixed_snippet": "const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });",
        "explanation": "Enforce object-level access control by verifying that the authenticated user owns the requested resource.",
    },
    "broken_auth": {
        "original_snippet": "app.post('/api/login', authHandler);",
        "fixed_snippet": "app.post('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 5 }), authHandler);",
        "explanation": "Implement strict IP/account rate limiting or account lockout thresholds to prevent brute-force attacks.",
    },
}


class RemediationAgent:
    """LLM-driven agent that generates fix recommendations for confirmed vulnerabilities."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self._llm_client = llm_client

    @property
    def llm_client(self) -> Optional[LLMClient]:
        """Get or lazily instantiate the LLMClient."""
        if self._llm_client is None:
            try:
                self._llm_client = LLMClient()
            except Exception:
                pass
        return self._llm_client

    @llm_client.setter
    def llm_client(self, client: Optional[LLMClient]) -> None:
        self._llm_client = client

    def remediate_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a remediation suggestion for a single confirmed finding."""
        finding_id = finding.get("finding_id", "f_unknown")
        vuln_type = finding.get("vuln_type", "sqli").lower()
        mode = finding.get("mode", "dast").lower()

        user_prompt = (
            f"Generate a fix for this confirmed {vuln_type.upper()} finding ({mode.upper()} mode):\n"
            f"{json.dumps(finding, indent=2)}"
        )

        client = self.llm_client
        if client is not None:
            try:
                raw_response = client.complete_json(SYSTEM_PROMPT, user_prompt)
                # Ensure finding_id matches
                raw_response["finding_id"] = finding_id
                validated = RemediationFix(**raw_response)
                return validated.model_dump()
            except Exception:
                pass

        # Safe deterministic fallback if LLM call fails, is unavailable, or returns bad data
        template = FALLBACK_TEMPLATES.get(
            vuln_type,
            {
                "original_snippet": f"Vulnerable handler on {finding.get('target', 'endpoint')}",
                "fixed_snippet": "Apply input validation, authentication, and authorization controls.",
                "explanation": "Sanitize user input and enforce least-privilege access controls.",
            },
        )
        return RemediationFix(
            finding_id=finding_id,
            original_snippet=template["original_snippet"],
            fixed_snippet=template["fixed_snippet"],
            explanation=template["explanation"],
        ).model_dump()

    def run(
        self, findings: Union[List[Dict[str, Any]], Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Remediate a list of confirmed findings (or a single finding).

        Args:
            findings: Single finding dict or list of finding dicts.

        Returns:
            List of RemediationFix dicts.
        """
        if isinstance(findings, dict):
            findings = [findings]

        results: List[Dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            # Only remediate confirmed findings
            if finding.get("confirmed", True) is False:
                continue
            fix = self.remediate_finding(finding)
            results.append(fix)

        return results
