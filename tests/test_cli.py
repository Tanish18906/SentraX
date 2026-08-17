"""Tests for SentraX CLI shell (Phase 1)."""

import io
from unittest.mock import patch
from rich.console import Console

from sentrax.cli import SentraXCLI, main


def test_cli_banner_and_help():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console)

    cli.display_banner()
    cli.display_help()

    output = output_io.getvalue()
    assert "SentraX AI — autonomous security testing, explained." in output
    assert "/scan <url>" in output
    assert "/scan-code <folder>" in output
    assert "/help" in output


def test_cli_handle_commands():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console)

    # Empty string
    assert cli.handle_command("") is True

    # Non-slash input
    assert cli.handle_command("hello world") is True
    assert "Not a recognized input" in output_io.getvalue()

    # Unknown slash command
    assert cli.handle_command("/foobar") is True
    assert "Unknown command: /foobar" in output_io.getvalue()

    # /help
    assert cli.handle_command("/help") is True
    assert "SentraX Commands" in output_io.getvalue()

    # /status
    assert cli.handle_command("/status") is True
    assert "Status:" in output_io.getvalue()

    # /report (no scan yet)
    assert cli.handle_command("/report") is True
    assert "No scan report available yet" in output_io.getvalue()

    # /scan with no args
    assert cli.handle_command("/scan") is True
    assert "Usage: /scan <url>" in output_io.getvalue()

    # /scan with url
    assert cli.handle_command("/scan http://localhost:4000") is True
    assert "Would run DAST scan on target: http://localhost:4000" in output_io.getvalue()

    # /scan-code with no args
    assert cli.handle_command("/scan-code") is True
    assert "Usage: /scan-code <folder>" in output_io.getvalue()

    # /scan-code with folder
    assert cli.handle_command("/scan-code ./src") is True
    assert "Would run SAST code scan on folder: ./src" in output_io.getvalue()

    # /clear
    assert cli.handle_command("/clear") is True

    # /exit and /quit
    assert cli.handle_command("/exit") is False
    assert "Exiting SentraX AI. Goodbye!" in output_io.getvalue()
    assert cli.handle_command("/quit") is False


def test_cli_run_loop_exit():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console)

    with patch("builtins.input", side_effect=["/help", "/scan http://localhost:4000", "/exit"]):
        ret = cli.run()
        assert ret == 0


def test_cli_run_loop_eof():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console)

    with patch("builtins.input", side_effect=EOFError):
        ret = cli.run()
        assert ret == 0


def test_cli_run_loop_keyboard_interrupt():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console)

    with patch("builtins.input", side_effect=[KeyboardInterrupt, "/exit"]):
        ret = cli.run()
        assert ret == 0
        assert "Scan interrupted." in output_io.getvalue()


def test_command_completer():
    from prompt_toolkit.completion import CompleteEvent
    from prompt_toolkit.document import Document
    from sentrax.cli import get_command_completer

    completer = get_command_completer()

    # When typing '/'
    doc_slash = Document("/")
    completions = [c.text for c in completer.get_completions(doc_slash, CompleteEvent())]
    assert "/scan" in completions
    assert "/scan-code" in completions
    assert "/help" in completions
    assert "/exit" in completions

    # When typing '/s'
    doc_s = Document("/s")
    completions_s = [c.text for c in completer.get_completions(doc_s, CompleteEvent())]
    assert "/scan" in completions_s
    assert "/scan-code" in completions_s
    assert "/help" not in completions_s


def test_main_entry_point():
    with patch("builtins.input", side_effect=["/exit"]):
        ret = main()
        assert ret == 0

