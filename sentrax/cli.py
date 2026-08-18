"""SentraX AI — Interactive CLI Shell.

Reference: Docs/CLI.md
"""

from __future__ import annotations

import sys
from typing import Any, Dict, List, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.table import Table

from sentrax.agents.recon import TargetUnreachableError
from sentrax.agents.reporter import VULN_TYPE_NAMES
from sentrax.orchestrator import PipelineOrchestrator
from sentrax.utils.llm_client import LLMCallError
from sentrax.utils.schema import FinalScanReport

STAGE_META = {
    "recon": ("cyan", "RECON"),
    "strategist": ("yellow", "STRATEGIST"),
    "exploit": ("red", "EXPLOIT"),
    "remediation": ("magenta", "REMEDIATION"),
    "reporter": ("green", "REPORTER"),
}

BANNER_ART = r""" ____             _              __  __
/ ___|  ___ _ __ | |_ _ __ __ _ \ \/ /
\___ \ / _ \ '_ \| __| '__/ _` | \  / 
 ___) |  __/ | | | |_| | | (_| | /  \ 
|____/ \___|_| |_|\__|_|  \__,_|/_/\_\ """

TAGLINE = "SentraX AI — autonomous security testing, explained."
HINT = "Type [bold red]/help[/bold red] for commands."

COMMANDS_META = {
    "/scan": "DAST mode: attack live web application or API",
    "/scan-code": "SAST mode: scan local source code for vulnerabilities",
    "/report": "Re-display the most recent scan report",
    "/status": "Show current pipeline and scan status",
    "/help": "Display list of available commands",
    "/clear": "Clear terminal and re-display banner",
    "/exit": "Exit SentraX interactive session",
    "/quit": "Exit SentraX interactive session",
}

PROMPT_STYLE = Style.from_dict(
    {
        "prompt": "#ef4444 bold",
        "prompt-arrow": "#ef4444 bold",
        "completion-menu.completion": "bg:#1e293b #e2e8f0",
        "completion-menu.completion.current": "bg:#dc2626 #ffffff bold",
        "completion-menu.meta.completion": "bg:#0f172a #94a3b8",
        "completion-menu.meta.completion.current": "bg:#991b1b #fecaca bold",
        "scrollbar.background": "bg:#0f172a",
        "scrollbar.button": "bg:#334155",
    }
)


def get_command_completer() -> WordCompleter:
    """Create command autocompleter for prompt_toolkit dropdown."""
    return WordCompleter(
        words=list(COMMANDS_META.keys()),
        meta_dict=COMMANDS_META,
        ignore_case=True,
        sentence=True,
        match_middle=False,
    )


class SentraXCLI:
    """Interactive command-line shell for SentraX AI."""

    def __init__(
        self,
        console: Optional[Console] = None,
        orchestrator: Optional[PipelineOrchestrator] = None,
        demo_mode: bool = False,
    ):
        self.console: Console = console or Console()
        self.demo_mode = demo_mode
        if orchestrator is not None:
            self.orchestrator: PipelineOrchestrator = orchestrator
        elif demo_mode:
            from sentrax.utils.demo_agents import DemoRemediationAgent, DemoStrategistAgent

            self.orchestrator = PipelineOrchestrator(
                strategist_agent=DemoStrategistAgent(),
                remediation_agent=DemoRemediationAgent(),
            )
        else:
            self.orchestrator = PipelineOrchestrator()
        self.last_report: Optional[Dict[str, Any]] = None
        self.is_running: bool = False
        self._prompt_session: Optional[PromptSession] = None

    @property
    def prompt_session(self) -> PromptSession:
        """Lazy-initialize prompt_toolkit PromptSession."""
        if self._prompt_session is None:
            self._prompt_session = PromptSession(
                completer=get_command_completer(),
                complete_while_typing=True,
                style=PROMPT_STYLE,
            )
        return self._prompt_session

    def display_banner(self) -> None:
        """Display the SentraX ASCII banner and initial prompt information."""
        self.console.print(f"[bold red]{BANNER_ART}[/bold red]\n")
        self.console.print(f"[bold white]{TAGLINE}[/bold white]")
        self.console.print(f"{HINT}\n")
        if self.demo_mode:
            self.console.print(
                "[bold yellow][DEMO MODE][/bold yellow] Strategist/Remediation reasoning is "
                "cached — Recon, Exploit, and Reporter still run fully live against the real target.\n"
            )

    def display_help(self) -> None:
        """Display table of available commands."""
        table = Table(title="SentraX Commands", show_header=True, header_style="bold red")
        table.add_column("Command", style="bold red", no_wrap=True)
        table.add_column("Description", style="white")

        table.add_row("/scan <url>", "Run DAST security scan against a live web target (e.g. http://localhost:4000)")
        table.add_row("/scan-code <folder>", "Run SAST security scan against a local source code directory")
        table.add_row("/report", "Re-display the most recent scan report")
        table.add_row("/status", "Show current pipeline status")
        table.add_row("/clear", "Clear the terminal screen and redisplay banner")
        table.add_row("/help", "Show this help message")
        table.add_row("/exit, /quit", "Exit SentraX interactive session")

        self.console.print(table)
        self.console.print()

    def handle_command(self, raw_input: str) -> bool:
        """Process a single input line from the user.

        Returns:
            bool: True to keep prompt loop running, False to terminate session.
        """
        line = raw_input.strip()
        if not line:
            return True

        if not line.startswith("/"):
            self.console.print("[red]Not a recognized input — try /help[/red]")
            return True

        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("/exit", "/quit"):
            self.console.print("[bold yellow]Exiting SentraX AI. Goodbye![/bold yellow]")
            return False

        elif cmd == "/clear":
            self.console.clear()
            self.display_banner()
            return True

        elif cmd == "/help":
            self.display_help()
            return True

        elif cmd == "/status":
            if self.is_running:
                self.console.print("[yellow]Status:[/yellow] Scan is currently running...")
            elif self.last_report:
                self.console.print("[green]Status:[/green] Idle. Previous scan report is ready (view with /report).")
            else:
                self.console.print("[blue]Status:[/blue] Idle (no scans executed yet).")
            return True

        elif cmd == "/report":
            if self.last_report:
                self.orchestrator.reporter_agent.render_terminal(FinalScanReport(**self.last_report))
            else:
                self.console.print("[yellow]No scan report available yet. Run /scan or /scan-code first.[/yellow]")
            return True

        elif cmd == "/scan":
            if not args:
                self.console.print("[red]Usage: /scan <url>[/red]")
                self.console.print("[dim]Example: /scan http://localhost:4000[/dim]")
                return True
            self._run_scan(args, mode="url")
            return True

        elif cmd == "/scan-code":
            if not args:
                self.console.print("[red]Usage: /scan-code <folder>[/red]")
                self.console.print("[dim]Example: /scan-code ./routes[/dim]")
                return True
            self._run_scan(args, mode="folder")
            return True

        else:
            self.console.print(f"[red]Unknown command: {cmd} — try /help[/red]")
            return True

    @staticmethod
    def _label(stage: str) -> str:
        color, name = STAGE_META[stage]
        return f"[{color}][{name}][/{color}]"

    def _handle_pipeline_event(self, event: Dict[str, Any], status, finding_vuln_types: Dict[str, str]) -> None:
        """Render one orchestrator progress event as a styled, labeled line (CLI.md section 5)."""
        stage = event["stage"]
        etype = event["type"]
        label = self._label(stage)

        if stage == "recon":
            if etype == "start":
                desc = (
                    f"Mapping attack surface at {event['target']}..."
                    if event["mode"] == "url"
                    else f"Scanning source folder {event['target']}..."
                )
                status.update(f"{label} {desc}")
                self.console.print(f"{label} {desc}")
            elif etype == "done":
                if "pages" in event:
                    self.console.print(
                        f"{label} Found {event['pages']} pages, {event['forms']} forms, "
                        f"{event['endpoints']} API endpoints.\n"
                    )
                else:
                    self.console.print(f"{label} Found {event['findings_raw']} candidate pattern matches.\n")

        elif stage == "strategist":
            if etype == "start":
                status.update(f"{label} Analyzing attack surface...")
                self.console.print(f"{label} Analyzing attack surface...")
            elif etype == "item":
                task = event["task"]
                vuln_name = VULN_TYPE_NAMES.get(task["vuln_type"], task["vuln_type"])
                self.console.print(f"{label} → {task['target']}: testing for {vuln_name} ({task['reasoning']})")
            elif etype == "done":
                self.console.print()

        elif stage == "exploit":
            if etype == "start":
                status.update(f"{label} Attempting confirmations...")
            elif etype == "item":
                finding = event["finding"]
                finding_vuln_types[finding["finding_id"]] = finding["vuln_type"]
                vuln_name = VULN_TYPE_NAMES.get(finding["vuln_type"], finding["vuln_type"])
                self.console.print(f"{label} Attempting {vuln_name} on {finding['target']}...")
                if finding["confirmed"]:
                    self.console.print(
                        f"{label} [bold green]✓ CONFIRMED[/bold green] — {finding['evidence']['why_confirmed']}"
                    )
                else:
                    self.console.print(
                        f"{label} [bold yellow]✗ Ruled out[/bold yellow] — {finding['evidence']['why_confirmed']}"
                    )
            elif etype == "done":
                self.console.print()

        elif stage == "remediation":
            if etype == "start":
                status.update(f"{label} Generating fixes...")
            elif etype == "item":
                fix = event["fix"]
                vuln_name = VULN_TYPE_NAMES.get(finding_vuln_types.get(fix["finding_id"], ""), "confirmed")
                self.console.print(f"{label} Generating fix for {vuln_name} finding...")
            elif etype == "done":
                self.console.print()

        elif stage == "reporter":
            if etype == "start":
                status.update(f"{label} Compiling final report...")
                self.console.print(f"{label} Compiling final report...")
            elif etype == "done":
                self.console.print(f"{label} Report saved to {event['report_path']}\n")

    def _run_scan(self, target: str, mode: str) -> None:
        """Run the full pipeline for /scan or /scan-code, streaming live agent activity.

        Errors named in CLI.md section 6 (unreachable target, bad folder, LLM
        failure) get a specific, clear message rather than a raw traceback.
        Anything else falls through to run()'s outer generic-error handler.
        Ctrl+C is deliberately not caught here — it propagates to run()'s
        existing KeyboardInterrupt handler, which prints "Scan interrupted."
        and returns to the prompt without killing the session.
        """
        mode_label = "DAST" if mode == "url" else "SAST"
        self.console.print(f"\n[bold white]Starting {mode_label} scan on[/bold white] [bold]{target}[/bold]\n")
        self.is_running = True
        finding_vuln_types: Dict[str, str] = {}

        try:
            with self.console.status("[bold white]Initializing pipeline...[/bold white]", spinner="dots") as status:

                def on_event(event: Dict[str, Any]) -> None:
                    self._handle_pipeline_event(event, status, finding_vuln_types)

                report = self.orchestrator.run(target, mode=mode, display=False, on_event=on_event)

            self.last_report = report
            self.console.print()
            self.orchestrator.reporter_agent.render_terminal(FinalScanReport(**report))

        except TargetUnreachableError as e:
            self.console.print(f"[bold red]{e}[/bold red]")
        except FileNotFoundError as e:
            self.console.print(f"[bold red]{e}[/bold red]")
        except LLMCallError as e:
            self.console.print(
                f"{self._label('strategist')} [bold red]{e} — could not generate a test plan for this scan.[/bold red]"
            )
        finally:
            self.is_running = False

    def _read_input(self) -> str:
        """Read a line of user input with dropdown autocompletion if interactive."""
        if sys.stdin.isatty():
            return self.prompt_session.prompt(
                HTML("<prompt>sentrax</prompt> <prompt-arrow>▸</prompt-arrow> ")
            )
        # Fallback for piped input / non-interactive testing
        self.console.print("[bold red]sentrax[/bold red] [bold red]▸[/bold red] ", end="")
        return input()

    def run(self) -> int:
        """Run the interactive prompt loop until user exits."""
        self.display_banner()

        while True:
            try:
                try:
                    user_input = self._read_input()
                except KeyboardInterrupt:
                    self.console.print("\n[yellow]Scan interrupted.[/yellow]")
                    continue
                except EOFError:
                    self.console.print("\n[bold yellow]Exiting SentraX AI. Goodbye![/bold yellow]")
                    break

                keep_running = self.handle_command(user_input)
                if not keep_running:
                    break

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Scan interrupted.[/yellow]")
                continue
            except Exception as e:
                self.console.print(f"[red]An unexpected error occurred: {e}[/red]")

        return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Console script entry point.

    `--demo` (Docs/CLI.md section 7) is the only recognized flag — launch
    still takes no required arguments (CLI.md section 1); everything else
    is typed into the running session.
    """
    args = sys.argv[1:] if argv is None else argv
    demo_mode = "--demo" in args
    cli = SentraXCLI(demo_mode=demo_mode)
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
