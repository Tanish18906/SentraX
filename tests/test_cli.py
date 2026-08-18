"""Tests for SentraX CLI shell (Phase 1 shell + Phase 8 pipeline integration)."""

import io
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from sentrax.agents.recon import TargetUnreachableError
from sentrax.cli import SentraXCLI, main
from sentrax.utils.llm_client import LLMCallError

SAMPLE_REPORT = {
    "target": "http://localhost:4000",
    "mode": "dast",
    "timestamp": "2026-08-18 00:00:00 UTC",
    "summary": {"total_findings": 1, "high_count": 1, "medium_count": 0, "low_count": 0},
    "findings": [
        {
            "finding": {
                "finding_id": "f1",
                "vuln_type": "sqli",
                "target": "/api/login",
                "mode": "dast",
                "confirmed": True,
                "evidence": {
                    "request_sent": "POST /api/login with email=\"' OR 1=1--\"",
                    "response_snippet": '{"success": true}',
                    "why_confirmed": "Login succeeded with an injected payload.",
                },
                "severity": "high",
            },
            "remediation": {
                "finding_id": "f1",
                "original_snippet": "raw concat",
                "fixed_snippet": "parameterized query",
                "explanation": "Use parameterized queries.",
            },
        }
    ],
    "markdown_path": "reports/scan_test.md",
}


def _mock_orchestrator(report=None, side_effect=None):
    """Build a mock PipelineOrchestrator whose .run() fires realistic on_event
    callbacks (mirroring what the real orchestrator emits) before returning."""
    orchestrator = MagicMock()
    orchestrator.reporter_agent = MagicMock()

    def fake_run(target, mode, display=False, on_event=None):
        if side_effect is not None:
            raise side_effect
        if on_event:
            on_event({"stage": "recon", "type": "start", "target": target, "mode": mode})
            if mode == "url":
                on_event({"stage": "recon", "type": "done", "pages": 2, "forms": 1, "endpoints": 3})
            else:
                on_event({"stage": "recon", "type": "done", "findings_raw": 1})
            on_event({"stage": "strategist", "type": "start"})
            on_event(
                {
                    "stage": "strategist",
                    "type": "item",
                    "task": {
                        "id": "task_1",
                        "target": "/api/login",
                        "vuln_type": "sqli",
                        "reasoning": "Login form takes raw credentials.",
                    },
                }
            )
            on_event({"stage": "strategist", "type": "done", "task_count": 1})
            on_event({"stage": "exploit", "type": "start", "task_count": 1})
            on_event({"stage": "exploit", "type": "item", "finding": SAMPLE_REPORT["findings"][0]["finding"]})
            on_event({"stage": "exploit", "type": "done", "confirmed_count": 1, "ruled_out_count": 0})
            on_event({"stage": "remediation", "type": "start"})
            on_event({"stage": "remediation", "type": "item", "fix": SAMPLE_REPORT["findings"][0]["remediation"]})
            on_event({"stage": "remediation", "type": "done", "fix_count": 1})
            on_event({"stage": "reporter", "type": "start"})
            on_event({"stage": "reporter", "type": "done", "report_path": "reports/scan_test.md"})
        return report if report is not None else SAMPLE_REPORT

    orchestrator.run.side_effect = fake_run
    return orchestrator


def _cli_with_mock(orchestrator=None):
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console, orchestrator=orchestrator or _mock_orchestrator())
    return cli, output_io


def test_cli_banner_and_help():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console, orchestrator=_mock_orchestrator())

    cli.display_banner()
    cli.display_help()

    output = output_io.getvalue()
    assert "SentraX AI — autonomous security testing, explained." in output
    assert "/scan <url>" in output
    assert "/scan-code <folder>" in output
    assert "/help" in output


def test_cli_handle_commands_no_scan_yet():
    cli, output_io = _cli_with_mock()

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

    # /scan-code with no args
    assert cli.handle_command("/scan-code") is True
    assert "Usage: /scan-code <folder>" in output_io.getvalue()

    # /clear
    assert cli.handle_command("/clear") is True

    # /exit and /quit
    assert cli.handle_command("/exit") is False
    assert "Exiting SentraX AI. Goodbye!" in output_io.getvalue()
    assert cli.handle_command("/quit") is False


def test_cli_scan_runs_real_pipeline_and_streams_events():
    mock_orch = _mock_orchestrator()
    cli, output_io = _cli_with_mock(mock_orch)

    assert cli.handle_command("/scan http://localhost:4000") is True

    output = output_io.getvalue()
    mock_orch.run.assert_called_once()
    call_kwargs = mock_orch.run.call_args
    assert call_kwargs.args[0] == "http://localhost:4000" or call_kwargs.kwargs.get("target") == "http://localhost:4000"

    # Per-agent streaming lines (CLI.md section 5)
    assert "[RECON]" in output
    assert "Found 2 pages, 1 forms, 3 API endpoints." in output
    assert "[STRATEGIST]" in output
    assert "→ /api/login: testing for" in output
    assert "[EXPLOIT]" in output
    assert "✓ CONFIRMED" in output
    assert "[REMEDIATION]" in output
    assert "Generating fix for" in output
    assert "[REPORTER]" in output
    assert "Report saved to reports/scan_test.md" in output

    # Final report stored for /report, and is_running reset
    assert cli.last_report == SAMPLE_REPORT
    assert cli.is_running is False
    mock_orch.reporter_agent.render_terminal.assert_called_once()


def test_cli_scan_shows_ruled_out_findings():
    ruled_out_finding = dict(SAMPLE_REPORT["findings"][0]["finding"])
    ruled_out_finding = {**ruled_out_finding, "confirmed": False}

    def fake_run(target, mode, display=False, on_event=None):
        on_event({"stage": "recon", "type": "start", "target": target, "mode": mode})
        on_event({"stage": "recon", "type": "done", "pages": 1, "forms": 0, "endpoints": 1})
        on_event({"stage": "strategist", "type": "start"})
        on_event({"stage": "strategist", "type": "done", "task_count": 0})
        on_event({"stage": "exploit", "type": "start", "task_count": 1})
        on_event({"stage": "exploit", "type": "item", "finding": ruled_out_finding})
        on_event({"stage": "exploit", "type": "done", "confirmed_count": 0, "ruled_out_count": 1})
        on_event({"stage": "remediation", "type": "start"})
        on_event({"stage": "remediation", "type": "done", "fix_count": 0})
        on_event({"stage": "reporter", "type": "start"})
        on_event({"stage": "reporter", "type": "done", "report_path": "reports/scan_test.md"})
        return {**SAMPLE_REPORT, "findings": []}

    mock_orch = MagicMock()
    mock_orch.reporter_agent = MagicMock()
    mock_orch.run.side_effect = fake_run
    cli, output_io = _cli_with_mock(mock_orch)

    cli.handle_command("/scan http://localhost:4000")
    assert "✗ Ruled out" in output_io.getvalue()


def test_cli_scan_target_unreachable_shows_clear_message():
    mock_orch = _mock_orchestrator(side_effect=TargetUnreachableError("Could not reach http://localhost:9999"))
    cli, output_io = _cli_with_mock(mock_orch)

    cli.handle_command("/scan http://localhost:9999")

    output = output_io.getvalue()
    assert "Could not reach http://localhost:9999" in output
    assert "Traceback" not in output
    assert cli.is_running is False


def test_cli_scan_code_folder_not_found_shows_clear_message():
    mock_orch = _mock_orchestrator(side_effect=FileNotFoundError("Folder not found: ./nope"))
    cli, output_io = _cli_with_mock(mock_orch)

    cli.handle_command("/scan-code ./nope")

    output = output_io.getvalue()
    assert "Folder not found: ./nope" in output
    assert cli.is_running is False


def test_cli_scan_llm_failure_shows_graceful_message_not_crash():
    mock_orch = _mock_orchestrator(side_effect=LLMCallError("LLM call failed after 2 attempt(s): boom"))
    cli, output_io = _cli_with_mock(mock_orch)

    result = cli.handle_command("/scan http://localhost:4000")

    assert result is True  # session keeps running, does not crash
    output = output_io.getvalue()
    assert "STRATEGIST" in output
    assert "LLM call failed" in output
    assert cli.is_running is False


def test_cli_report_redisplays_last_scan():
    mock_orch = _mock_orchestrator()
    cli, output_io = _cli_with_mock(mock_orch)

    cli.handle_command("/scan http://localhost:4000")
    mock_orch.reporter_agent.render_terminal.reset_mock()

    cli.handle_command("/report")
    mock_orch.reporter_agent.render_terminal.assert_called_once()


def test_cli_status_reflects_scan_history():
    mock_orch = _mock_orchestrator()
    cli, output_io = _cli_with_mock(mock_orch)

    cli.handle_command("/status")
    assert "no scans executed yet" in output_io.getvalue().lower()

    cli.handle_command("/scan http://localhost:4000")
    cli.handle_command("/status")
    assert "Previous scan report is ready" in output_io.getvalue()


def test_cli_run_loop_exit():
    cli, _ = _cli_with_mock()

    with patch("builtins.input", side_effect=["/help", "/exit"]):
        ret = cli.run()
        assert ret == 0


def test_cli_run_loop_eof():
    cli, _ = _cli_with_mock()

    with patch("builtins.input", side_effect=EOFError):
        ret = cli.run()
        assert ret == 0


def test_cli_run_loop_keyboard_interrupt_between_commands():
    cli, output_io = _cli_with_mock()

    with patch("builtins.input", side_effect=[KeyboardInterrupt, "/exit"]):
        ret = cli.run()
        assert ret == 0
        assert "Scan interrupted." in output_io.getvalue()


def test_cli_run_loop_keyboard_interrupt_mid_scan_returns_to_prompt():
    """Ctrl+C during a running scan must not kill the session (CLI.md section 6)."""
    mock_orch = _mock_orchestrator(side_effect=KeyboardInterrupt())
    cli, output_io = _cli_with_mock(mock_orch)

    with patch("builtins.input", side_effect=["/scan http://localhost:4000", "/exit"]):
        ret = cli.run()

    assert ret == 0
    assert "Scan interrupted." in output_io.getvalue()
    assert cli.is_running is False


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


def test_main_entry_point_demo_flag_enables_demo_mode():
    with patch("builtins.input", side_effect=["/exit"]):
        ret = main(argv=["--demo"])
        assert ret == 0


def test_cli_demo_mode_shows_banner_notice_and_uses_demo_agents():
    from sentrax.utils.demo_agents import DemoRemediationAgent, DemoStrategistAgent

    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console, demo_mode=True)

    assert isinstance(cli.orchestrator.strategist_agent, DemoStrategistAgent)
    assert isinstance(cli.orchestrator.remediation_agent, DemoRemediationAgent)

    cli.display_banner()
    assert "DEMO MODE" in output_io.getvalue()


def test_cli_non_demo_mode_shows_no_demo_notice():
    output_io = io.StringIO()
    console = Console(file=output_io, force_terminal=False, color_system=None)
    cli = SentraXCLI(console=console, orchestrator=_mock_orchestrator())

    cli.display_banner()
    assert "DEMO MODE" not in output_io.getvalue()
