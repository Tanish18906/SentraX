"""SentraX AI Pipeline Orchestrator.

Reference: Docs/architecture.md Section 2 (the 5-agent pipeline), Docs/Agents.md.
Wires the 5 agents in strict sequence — Recon -> Strategist -> Exploit ->
Remediation -> Reporter — feeding each agent's real output into the next.
No agent logic lives here; this file only chains the existing agents and
gives the CLI (Phase 8) a hook to observe each stage as it happens.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from sentrax.agents.exploit import ExploitAgent
from sentrax.agents.recon import ReconAgent, TargetUnreachableError
from sentrax.agents.remediation import RemediationAgent
from sentrax.agents.reporter import ReporterAgent
from sentrax.agents.strategist import StrategistAgent

OnEvent = Callable[[Dict[str, Any]], None]


class PipelineOrchestrator:
    """Runs Recon -> Strategist -> Exploit -> Remediation -> Reporter in sequence."""

    def __init__(
        self,
        recon_agent: Optional[ReconAgent] = None,
        strategist_agent: Optional[StrategistAgent] = None,
        exploit_agent: Optional[ExploitAgent] = None,
        remediation_agent: Optional[RemediationAgent] = None,
        reporter_agent: Optional[ReporterAgent] = None,
    ):
        # Recon/Exploit/Reporter are deterministic and have no external
        # dependency, so they're safe to construct eagerly. StrategistAgent's
        # default constructor builds a real LLMClient immediately and raises
        # if no API key is configured — deferred to a lazy property so that
        # building an orchestrator never fails just because no .env is set up,
        # and the failure only surfaces when the Strategist stage actually runs.
        self.recon_agent = recon_agent or ReconAgent()
        self._strategist_agent = strategist_agent
        self.exploit_agent = exploit_agent or ExploitAgent()
        self.remediation_agent = remediation_agent or RemediationAgent()
        self.reporter_agent = reporter_agent or ReporterAgent()

    @property
    def strategist_agent(self) -> StrategistAgent:
        if self._strategist_agent is None:
            self._strategist_agent = StrategistAgent()
        return self._strategist_agent

    def run(
        self,
        target: str,
        mode: str,
        display: bool = False,
        on_event: Optional[OnEvent] = None,
    ) -> Dict[str, Any]:
        """Run the full pipeline against `target` and return a FinalScanReport dict.

        Args:
            target: URL (mode="url") or folder path (mode="folder").
            mode: "url" for DAST, "folder" for SAST — same vocabulary Recon uses.
            display: forwarded to Reporter — render the rich terminal report or not.
            on_event: optional callback fired with a dict describing pipeline
                progress (`{"stage": ..., "type": "start"|"item"|"done"|"error", ...}`),
                so the CLI can stream per-agent activity live (Docs/CLI.md section 5)
                without this orchestrator knowing anything about terminal rendering.
        """
        if mode not in ("url", "folder"):
            raise ValueError(f"Unsupported orchestrator mode: {mode!r}. Must be 'url' or 'folder'.")

        exploit_mode = "dast" if mode == "url" else "sast"

        def emit(event: Dict[str, Any]) -> None:
            if on_event is not None:
                on_event(event)

        # 1. Recon
        emit({"stage": "recon", "type": "start", "target": target, "mode": mode})
        try:
            recon_output = self.recon_agent.run(target, mode=mode)
        except (TargetUnreachableError, FileNotFoundError) as e:
            emit({"stage": "recon", "type": "error", "error": str(e)})
            raise
        if mode == "url":
            recon_summary = {
                "pages": len(recon_output.get("pages", [])),
                "forms": sum(len(p.get("forms", [])) for p in recon_output.get("pages", [])),
                "endpoints": len({ep for p in recon_output.get("pages", []) for ep in p.get("endpoints_observed", [])}),
            }
        else:
            recon_summary = {"findings_raw": len(recon_output.get("findings_raw", []))}
        emit({"stage": "recon", "type": "done", **recon_summary})

        # 2. Strategist
        emit({"stage": "strategist", "type": "start"})
        strategist_output = self.strategist_agent.run(recon_output)
        tasks: List[Dict[str, Any]] = strategist_output["tasks"]
        for task in tasks:
            emit({"stage": "strategist", "type": "item", "task": task})
        emit({"stage": "strategist", "type": "done", "task_count": len(tasks)})

        # 3. Exploit — deterministic confirmation, the trust boundary of the pipeline
        emit({"stage": "exploit", "type": "start", "task_count": len(tasks)})
        findings: List[Dict[str, Any]] = self.exploit_agent.run(tasks, recon_output, mode=exploit_mode)
        for finding in findings:
            emit({"stage": "exploit", "type": "item", "finding": finding})
        emit(
            {
                "stage": "exploit",
                "type": "done",
                "confirmed_count": sum(1 for f in findings if f.get("confirmed")),
                "ruled_out_count": sum(1 for f in findings if not f.get("confirmed")),
            }
        )

        # 4. Remediation — RemediationAgent already filters to confirmed=True findings
        emit({"stage": "remediation", "type": "start"})
        remediations: List[Dict[str, Any]] = self.remediation_agent.run(findings)
        for fix in remediations:
            emit({"stage": "remediation", "type": "item", "fix": fix})
        emit({"stage": "remediation", "type": "done", "fix_count": len(remediations)})

        # 5. Reporter
        emit({"stage": "reporter", "type": "start"})
        report = self.reporter_agent.run(
            target=target,
            mode=exploit_mode,
            findings=findings,
            remediations=remediations,
            display=display,
        )
        emit({"stage": "reporter", "type": "done", "report_path": report.get("markdown_path")})

        return report
