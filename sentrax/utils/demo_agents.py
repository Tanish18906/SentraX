"""SentraX AI — Demo-mode Strategist/Remediation stand-ins.

Reference: Docs/CLI.md Section 7 (demo-day safety net).
For `sentrax --demo`: removes dependency on live LLM latency/availability for
the two LLM-driven agents, while Recon, Exploit, and Reporter stay fully real
— every HTTP request and every "confirmed" verdict is still executed live
against the actual local target, never faked. Only the *narration* (which
vuln types are worth trying, and the suggested-fix wording) is pre-verified
and cached, per the explicit constraint in CLI.md section 7 that the Exploit
Agent's confirmations must always come from live, freshly-executed requests.
"""

from __future__ import annotations

from typing import Any, Dict, List

from sentrax.agents.remediation import RemediationAgent
from sentrax.utils.schema import StrategistResult, StrategistTask

# Ground truth endpoints from Docs/custom-target.md — the same 4 planted bugs
# a real Strategist call against VulnMart would plausibly identify.
_DEMO_URL_TASKS = [
    {
        "id": "task_1",
        "target": "/api/login",
        "vuln_type": "sqli",
        "reasoning": "Login form at /api/login takes raw email/password — classic SQLi injection point.",
    },
    {
        "id": "task_2",
        "target": "/api/login",
        "vuln_type": "broken_auth",
        "reasoning": "No rate-limiting observed on repeated failed login attempts against /api/login.",
    },
    {
        "id": "task_3",
        "target": "/api/reviews",
        "vuln_type": "xss",
        "reasoning": "Review 'comment' field is rendered back on /reviews — candidate stored-XSS sink.",
    },
    {
        "id": "task_4",
        "target": "/api/order/2",
        "vuln_type": "idor",
        "reasoning": "Numeric order ID in the URL; Bob's order may be reachable while authenticated as Alice.",
    },
]

# Only patterns that map cleanly onto one of the 4 supported vuln types get a
# task — matches StrategistAgent's own hallucination-filtering behavior of
# silently dropping anything it can't ground a real task in.
_SAST_PATTERN_TO_VULN_TYPE = {
    "sqli_concat": "sqli",
    "xss_innerhtml": "xss",
    "idor_missing_authz": "idor",
}


class DemoStrategistAgent:
    """Cached stand-in for StrategistAgent — same `.run()` contract, no LLM call."""

    def run(self, recon_output: Dict[str, Any]) -> Dict[str, Any]:
        mode = recon_output.get("mode")
        if mode not in ("url", "folder"):
            raise ValueError(f"Unsupported recon output mode: {mode!r}")

        if mode == "url":
            raw_tasks = _DEMO_URL_TASKS
        else:
            raw_tasks: List[Dict[str, Any]] = []
            for idx, raw in enumerate(recon_output.get("findings_raw", []), start=1):
                vuln_type = _SAST_PATTERN_TO_VULN_TYPE.get(raw["pattern"])
                if vuln_type is None:
                    continue
                raw_tasks.append(
                    {
                        "id": f"task_{idx}",
                        "target": f"{raw['file']}:{raw['line']}",
                        "vuln_type": vuln_type,
                        "reasoning": f"{raw['file']}:{raw['line']} matched {raw['pattern']} during recon.",
                    }
                )

        tasks = [StrategistTask(**t) for t in raw_tasks]
        return StrategistResult(tasks=tasks).model_dump()


class DemoRemediationAgent(RemediationAgent):
    """RemediationAgent forced onto its deterministic fallback templates — never calls a real LLM."""

    @property
    def llm_client(self):
        return None

    @llm_client.setter
    def llm_client(self, value):
        pass
