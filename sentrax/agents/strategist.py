"""SentraX AI — Strategist Agent.

Reference: Docs/Agents.md Section 2.
Job: given Recon's attack-surface JSON (url or folder mode), use LLM
reasoning to decide which vulnerability types are plausible where, and why.
This is the only genuine LLM-reasoning showcase in the pipeline — it must
never be used to decide whether an exploit worked, only what's worth trying.
That confirmation step is Exploit Agent's job, and it's deterministic.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from sentrax.utils.llm_client import LLMCallError, LLMClient
from sentrax.utils.schema import StrategistResult, StrategistTask

SUPPORTED_VULN_TYPES = ("sqli", "xss", "idor", "broken_auth")

SYSTEM_PROMPT = f"""You are the Strategist agent inside SentraX, an autonomous security-testing pipeline.

You are given the attack surface mapped by a Recon agent (either a crawled website or a scanned source-code folder) as JSON. Your job is to decide which specific vulnerability types are plausible at which specific locations, and briefly explain why.

Rules:
- You may ONLY use these vulnerability types: {", ".join(SUPPORTED_VULN_TYPES)}. Never invent a new vuln_type. If nothing plausible maps to one of these types for a given location, do not create a task for it.
- Show actual judgment, not brute-force coverage. Do not list every vuln type against every endpoint. For example: a login form taking email/password is a sqli and broken_auth candidate; a URL or endpoint containing a numeric ID is an idor candidate; a free-text field that gets rendered back (review, comment, search) is an xss candidate.
- Every "reasoning" string must reference something concrete from the input (a specific field name, form action, endpoint path, or code snippet/pattern) — not generic filler like "this could be vulnerable."
- For folder-mode input, each item in findings_raw is already a raw pattern match — decide whether it's worth a task, and ground your reasoning in its file/line/snippet.
- Respond with ONLY a JSON object of this exact shape, no prose outside it:
{{"tasks": [{{"id": "task_1", "target": "<endpoint or file:line>", "vuln_type": "<one of the supported types>", "reasoning": "<grounded, specific reasoning>"}}]}}
"""


class StrategistAgent:
    """LLM-driven prioritization: decides what's worth testing and why."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm_client = llm_client or LLMClient()

    def run(self, recon_output: Dict[str, Any]) -> Dict[str, Any]:
        """Take Recon Agent's JSON output (url or folder mode) and return a StrategistResult dict."""
        mode = recon_output.get("mode")
        if mode not in ("url", "folder"):
            raise ValueError(f"Unsupported recon output mode: {mode!r}")

        user_prompt = self._build_user_prompt(recon_output)
        raw = self.llm_client.complete_json(SYSTEM_PROMPT, user_prompt)
        tasks = self._extract_valid_tasks(raw)
        result = StrategistResult(tasks=tasks)
        return result.model_dump()

    @staticmethod
    def _build_user_prompt(recon_output: Dict[str, Any]) -> str:
        mode = recon_output["mode"]
        return f"Recon Agent output (mode={mode}):\n{json.dumps(recon_output, indent=2)}"

    @staticmethod
    def _extract_valid_tasks(raw: Dict[str, Any]) -> List[StrategistTask]:
        """Parse the LLM's raw JSON into StrategistTask objects, dropping anything malformed.

        The prompt already constrains vuln_type to the 4 supported types, but
        an LLM can still hallucinate outside that constraint — silently
        dropping a bad task here (rather than failing the whole scan) is the
        code-level backstop the prompt-level constraint alone can't guarantee.
        """
        raw_tasks = raw.get("tasks", [])
        if not isinstance(raw_tasks, list):
            raise LLMCallError("Strategist LLM response 'tasks' was not a list.")

        tasks: List[StrategistTask] = []
        for idx, raw_task in enumerate(raw_tasks, start=1):
            if not isinstance(raw_task, dict):
                continue
            if raw_task.get("vuln_type") not in SUPPORTED_VULN_TYPES:
                continue
            raw_task.setdefault("id", f"task_{idx}")
            try:
                tasks.append(StrategistTask(**raw_task))
            except ValidationError:
                continue
        return tasks
