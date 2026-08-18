"""SentraX AI — Reporter Agent.

Reference: Docs/Agents.md Section 5 & Docs/architecture.md.
Job: Pure formatting. Compiles confirmed findings + remediations into a rich terminal
display and a saved, deliverable Markdown report in reports/.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentrax.utils.schema import (
    ConfirmedFinding,
    EnrichedFinding,
    FinalScanReport,
    FindingEvidence,
    RemediationFix,
    ScanReportSummary,
)

VULN_TYPE_NAMES = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "broken_auth": "Broken Authentication",
}

SEVERITY_STYLES = {
    "critical": "bold red on black",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold cyan",
}


class ReporterAgent:
    """Formats and exports security scan reports for terminal and disk deliverable."""

    def __init__(
        self,
        console: Optional[Console] = None,
        reports_dir: Union[str, Path] = "reports",
    ):
        self.console = console or Console()
        self.reports_dir = Path(reports_dir)

    def compile_report(
        self,
        target: str,
        mode: str,
        findings: List[Dict[str, Any]],
        remediations: Optional[List[Dict[str, Any]]] = None,
        timestamp: Optional[str] = None,
    ) -> FinalScanReport:
        """Compile raw findings and remediation fixes into a structured FinalScanReport."""
        ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Map remediations by finding_id
        remediation_map: Dict[str, RemediationFix] = {}
        if remediations:
            for r in remediations:
                if isinstance(r, dict) and "finding_id" in r:
                    try:
                        remediation_map[r["finding_id"]] = RemediationFix(**r)
                    except Exception:
                        pass

        # Build list of enriched findings (only include confirmed vulnerabilities)
        enriched: List[EnrichedFinding] = []
        high_cnt = 0
        med_cnt = 0
        low_cnt = 0

        for f in findings:
            if not isinstance(f, dict):
                continue
            if not f.get("confirmed", True):
                continue

            try:
                finding_obj = ConfirmedFinding(**f)
            except Exception:
                # Fallback construction if fields need loose mapping
                finding_obj = ConfirmedFinding(
                    finding_id=f.get("finding_id", "f_unknown"),
                    vuln_type=f.get("vuln_type", "sqli"),
                    target=f.get("target", target),
                    mode=f.get("mode", mode.lower()),
                    confirmed=True,
                    evidence=FindingEvidence(
                        request_sent=f.get("evidence", {}).get("request_sent", ""),
                        response_snippet=f.get("evidence", {}).get("response_snippet", ""),
                        why_confirmed=f.get("evidence", {}).get("why_confirmed", ""),
                    ),
                    severity=f.get("severity", "high"),
                )

            sev = finding_obj.severity.lower()
            if sev in ("high", "critical"):
                high_cnt += 1
            elif sev == "medium":
                med_cnt += 1
            else:
                low_cnt += 1

            rem_obj = remediation_map.get(finding_obj.finding_id)
            enriched.append(EnrichedFinding(finding=finding_obj, remediation=rem_obj))

        summary = ScanReportSummary(
            total_findings=len(enriched),
            high_count=high_cnt,
            medium_count=med_cnt,
            low_count=low_cnt,
        )

        return FinalScanReport(
            target=target,
            mode="dast" if mode.lower() in ("url", "dast") else "sast",
            timestamp=ts,
            summary=summary,
            findings=enriched,
        )

    def generate_markdown(self, report: FinalScanReport) -> str:
        """Generate formatted GitHub-Flavored Markdown report content."""
        mode_label = "DAST (Live URL Attack)" if report.mode == "dast" else "SAST (Source Code Scan)"

        lines = [
            "# SentraX Security Scan Report",
            "",
            f"**Target:** `{report.target}`  ",
            f"**Mode:** `{mode_label}`  ",
            f"**Scan Date:** `{report.timestamp}`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"SentraX completed an automated multi-agent security assessment. A total of **{report.summary.total_findings} vulnerabilities** were confirmed with deterministic evidence.",
            "",
            f"- **High / Critical Severity:** {report.summary.high_count}",
            f"- **Medium Severity:** {report.summary.medium_count}",
            f"- **Low Severity:** {report.summary.low_count}",
            "",
        ]

        if not report.findings:
            lines.extend([
                "> [!NOTE]",
                "> No vulnerabilities were confirmed for this target during the scan.",
                "",
            ])
            return "\n".join(lines)

        lines.extend([
            "| # | Finding ID | Vulnerability Type | Target | Mode | Severity |",
            "|---|---|---|---|---|---|",
        ])

        for idx, item in enumerate(report.findings, start=1):
            f = item.finding
            v_name = VULN_TYPE_NAMES.get(f.vuln_type, f.vuln_type.upper())
            lines.append(
                f"| {idx} | `{f.finding_id}` | {v_name} | `{f.target}` | {f.mode.upper()} | **{f.severity.upper()}** |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 2. Detailed Findings & Remediation",
            "",
        ])

        for idx, item in enumerate(report.findings, start=1):
            f = item.finding
            rem = item.remediation
            v_name = VULN_TYPE_NAMES.get(f.vuln_type, f.vuln_type.upper())

            lines.extend([
                f"### {idx}. {v_name} — `{f.target}` [{f.severity.upper()}]",
                "",
                f"- **Finding ID:** `{f.finding_id}`",
                f"- **Vulnerability Class:** {v_name} (`{f.vuln_type}`)",
                f"- **Target Location:** `{f.target}`",
                f"- **Mode:** `{f.mode.upper()}`",
                f"- **Severity:** **{f.severity.upper()}**",
                "",
                "#### Deterministic Proof / Evidence",
                f"- **Action / Request Sent:**",
                "  ```http",
                f"  {f.evidence.request_sent}",
                "  ```",
                f"- **Response Snippet:**",
                "  ```http",
                f"  {f.evidence.response_snippet}",
                "  ```",
                f"- **Confirmation Rationale:**",
                f"  > {f.evidence.why_confirmed}",
                "",
            ])

            if rem:
                code_lang = "javascript" if ("js" in f.target or "json" in f.target or "{" in rem.fixed_snippet) else "python"
                lines.extend([
                    "#### Suggested Remediation",
                    "- **Vulnerable Pattern:**",
                    f"  ```{code_lang}",
                    f"  {rem.original_snippet}",
                    "  ```",
                    "- **Recommended Secure Fix:**",
                    f"  ```{code_lang}",
                    f"  {rem.fixed_snippet}",
                    "  ```",
                    f"- **Explanation:** {rem.explanation}",
                    "",
                ])
            else:
                lines.extend([
                    "#### Suggested Remediation",
                    f"- Apply standard defense for `{f.vuln_type}` (input sanitization, parameterization, and least-privilege access control).",
                    "",
                ])

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def save_markdown_report(
        self, report: FinalScanReport, custom_filename: Optional[str] = None
    ) -> Path:
        """Write the Markdown report to disk in reports_dir."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        if custom_filename:
            file_name = custom_filename
        else:
            safe_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S")
            file_name = f"scan_{safe_ts}.md"

        file_path = self.reports_dir / file_name
        md_content = self.generate_markdown(report)
        file_path.write_text(md_content, encoding="utf-8")
        report.markdown_path = str(file_path)
        return file_path

    def render_terminal(self, report: FinalScanReport) -> None:
        """Render beautiful, structured rich output to the terminal."""
        self.console.print()

        # Header summary panel
        summary_text = (
            f"[bold white]Target:[/bold white] {report.target}  |  "
            f"[bold white]Mode:[/bold white] {report.mode.upper()}  |  "
            f"[bold white]Date:[/bold white] {report.timestamp}\n"
            f"[bold white]Results:[/bold white] [bold]{report.summary.total_findings} Confirmed Vulnerabilities[/bold] "
            f"([bold red]{report.summary.high_count} High[/bold red], "
            f"[bold yellow]{report.summary.medium_count} Medium[/bold yellow], "
            f"[bold cyan]{report.summary.low_count} Low[/bold cyan])"
        )
        self.console.print(
            Panel(
                summary_text,
                title="[bold red]🛡️  SentraX Security Scan Summary[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        self.console.print()

        if not report.findings:
            self.console.print(
                Panel(
                    "[bold green]✓ No vulnerabilities confirmed on target attack surface.[/bold green]",
                    border_style="green",
                )
            )
            return

        # Render each finding in dedicated structured panel
        for idx, item in enumerate(report.findings, start=1):
            f = item.finding
            rem = item.remediation
            v_name = VULN_TYPE_NAMES.get(f.vuln_type, f.vuln_type.upper())
            sev_style = SEVERITY_STYLES.get(f.severity.lower(), "bold white")

            finding_content = Text()
            finding_content.append(f"Target: ", style="bold")
            finding_content.append(f"{f.target}\n", style="white")

            finding_content.append(f"\n[ Evidence ]\n", style="bold cyan")
            finding_content.append(f"• Action: {f.evidence.request_sent}\n", style="white")
            finding_content.append(f"• Output: {f.evidence.response_snippet}\n", style="dim")
            finding_content.append(f"• Proof:  {f.evidence.why_confirmed}\n", style="bold green")

            if rem:
                finding_content.append(f"\n[ Suggested Fix ]\n", style="bold magenta")
                finding_content.append(f"• Vulnerable: {rem.original_snippet}\n", style="red")
                finding_content.append(f"• Fixed:      {rem.fixed_snippet}\n", style="green")
                finding_content.append(f"• Explanation: {rem.explanation}\n", style="italic white")

            panel_title = f"[bold]#{idx}. {v_name}[/bold] — [{sev_style}][{f.severity.upper()}][/{sev_style}]"
            self.console.print(
                Panel(
                    finding_content,
                    title=panel_title,
                    border_style="yellow" if f.severity.lower() == "medium" else "red",
                    padding=(1, 2),
                )
            )

        if report.markdown_path:
            self.console.print(
                f"[bold green][REPORTER][/bold green] Scan report saved to [bold cyan]{report.markdown_path}[/bold cyan]\n"
            )

    def run(
        self,
        target: str,
        mode: str,
        findings: List[Dict[str, Any]],
        remediations: Optional[List[Dict[str, Any]]] = None,
        display: bool = True,
    ) -> Dict[str, Any]:
        """Execute complete reporting workflow: compile, save markdown, and render terminal."""
        report = self.compile_report(target, mode, findings, remediations)
        file_path = self.save_markdown_report(report)

        if display:
            self.render_terminal(report)

        return report.model_dump()
