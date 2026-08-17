"""SentraX AI — Interactive CLI Shell.

Reference: Docs/CLI.md
"""

from __future__ import annotations

import sys
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.table import Table

BANNER_ART = r""" ____             _              __  __
/ ___|  ___ _ __ | |_ _ __ __ _ \ \/ /
\___ \ / _ \ '_ \| __| '__/ _` | \  / 
 ___) |  __/ | | | |_| | | (_| | /  \ 
|____/ \___|_| |_|\__|_|  \__,_|/_/\_\ """

TAGLINE = "SentraX AI — autonomous security testing, explained."
HINT = "Type [bold cyan]/help[/bold cyan] for commands."

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
        "prompt": "#06b6d4 bold",
        "prompt-arrow": "#f8fafc bold",
        "completion-menu.completion": "bg:#1e293b #e2e8f0",
        "completion-menu.completion.current": "bg:#0284c7 #ffffff bold",
        "completion-menu.meta.completion": "bg:#0f172a #94a3b8",
        "completion-menu.meta.completion.current": "bg:#0369a1 #f1f5f9 bold",
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

    def __init__(self, console: Optional[Console] = None):
        self.console: Console = console or Console()
        self.last_report: Optional[str] = None
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
        self.console.print(f"[bold cyan]{BANNER_ART}[/bold cyan]\n")
        self.console.print(f"[bold white]{TAGLINE}[/bold white]")
        self.console.print(f"{HINT}\n")

    def display_help(self) -> None:
        """Display table of available commands."""
        table = Table(title="SentraX Commands", show_header=True, header_style="bold cyan")
        table.add_column("Command", style="bold green", no_wrap=True)
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
                self.console.print(self.last_report)
            else:
                self.console.print("[yellow]No scan report available yet. Run /scan or /scan-code first.[/yellow]")
            return True

        elif cmd == "/scan":
            if not args:
                self.console.print("[red]Usage: /scan <url>[/red]")
                self.console.print("[dim]Example: /scan http://localhost:4000[/dim]")
                return True
            # Placeholder for Phase 1 - real agent execution will be wired in Phase 8
            self.console.print(f"[cyan][*][/cyan] Would run DAST scan on target: [bold]{args}[/bold] (agent pipeline placeholder)")
            return True

        elif cmd == "/scan-code":
            if not args:
                self.console.print("[red]Usage: /scan-code <folder>[/red]")
                self.console.print("[dim]Example: /scan-code ./routes[/dim]")
                return True
            # Placeholder for Phase 1 - real agent execution will be wired in Phase 8
            self.console.print(f"[cyan][*][/cyan] Would run SAST code scan on folder: [bold]{args}[/bold] (agent pipeline placeholder)")
            return True

        else:
            self.console.print(f"[red]Unknown command: {cmd} — try /help[/red]")
            return True

    def _read_input(self) -> str:
        """Read a line of user input with dropdown autocompletion if interactive."""
        if sys.stdin.isatty():
            return self.prompt_session.prompt(
                HTML("<prompt>sentrax</prompt> <prompt-arrow>▸</prompt-arrow> ")
            )
        # Fallback for piped input / non-interactive testing
        self.console.print("[bold cyan]sentrax[/bold cyan] [bold white]▸[/bold white] ", end="")
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


def main() -> int:
    """Console script entry point."""
    cli = SentraXCLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
