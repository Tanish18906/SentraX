"""Tests for ReporterAgent (Phase 6)."""

import io
import json
from pathlib import Path
import pytest
from rich.console import Console

from sentrax.agents.reporter import ReporterAgent
from sentrax.utils.schema import FinalScanReport


SAMPLE_FIXTURES_PATH = Path("fixtures/sample_confirmed_finding.json")


def test_reporter_compile_and_markdown_generation(tmp_path: Path):
    with open(SAMPLE_FIXTURES_PATH) as f:
        findings = json.load(f)

    # Sample remediations paired with finding IDs
    remediations = [
        {
            "finding_id": "f1",
            "original_snippet": 'POST /api/login with email="' + "' OR 1=1--\"",
            "fixed_snippet": "db.query('SELECT * FROM users WHERE email = ?', [email])",
            "explanation": "Use parameterized queries to prevent SQL injection.",
        },
        {
            "finding_id": "f2",
            "original_snippet": '<div class="review-body">${comment}</div>',
            "fixed_snippet": '<div class="review-body"><%= escapeHtml(comment) %></div>',
            "explanation": "Escape HTML entities in user comments.",
        },
        {
            "finding_id": "f3",
            "original_snippet": "Order.findById(req.params.id)",
            "fixed_snippet": "Order.findOne({ _id: req.params.id, userId: req.user.id })",
            "explanation": "Enforce object ownership checks.",
        },
        {
            "finding_id": "f4",
            "original_snippet": 'const query = "SELECT * FROM users WHERE email=\'" + email + "\'";',
            "fixed_snippet": 'const query = "SELECT * FROM users WHERE email = ?"; db.query(query, [email]);',
            "explanation": "Parameterize queries to prevent concatenation.",
        },
        {
            "finding_id": "f5",
            "original_snippet": "app.post('/api/login', authHandler)",
            "fixed_snippet": "app.post('/api/login', rateLimit({ max: 5 }), authHandler)",
            "explanation": "Implement brute force rate limiting.",
        },
    ]

    out_console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
    agent = ReporterAgent(console=out_console, reports_dir=tmp_path / "reports")

    result = agent.run(
        target="http://localhost:4000",
        mode="dast",
        findings=findings,
        remediations=remediations,
        display=True,
    )

    # Validate Pydantic schema
    validated = FinalScanReport(**result)
    assert validated.target == "http://localhost:4000"
    assert validated.mode == "dast"
    assert validated.summary.total_findings == 5
    assert validated.summary.high_count == 3  # f1, f2, f4 are high
    assert validated.summary.medium_count == 2  # f3, f5 are medium
    assert validated.markdown_path is not None

    # Check that Markdown report file was created and contains expected content
    md_file = Path(validated.markdown_path)
    assert md_file.exists()
    md_content = md_file.read_text(encoding="utf-8")

    assert "# SentraX Security Scan Report" in md_content
    assert "http://localhost:4000" in md_content
    assert "SQL Injection" in md_content
    assert "Cross-Site Scripting (XSS)" in md_content
    assert "Insecure Direct Object Reference (IDOR)" in md_content
    assert "Broken Authentication" in md_content
    assert "db.query('SELECT * FROM users WHERE email = ?', [email])" in md_content


def test_reporter_terminal_rendering():
    out_io = io.StringIO()
    console = Console(file=out_io, force_terminal=False, color_system=None)
    agent = ReporterAgent(console=console)

    single_finding = [
        {
            "finding_id": "f1",
            "vuln_type": "sqli",
            "target": "/api/login",
            "mode": "dast",
            "confirmed": True,
            "evidence": {
                "request_sent": "POST /api/login with payload",
                "response_snippet": "HTTP 200 OK with token",
                "why_confirmed": "Authentication bypass verified",
            },
            "severity": "high",
        }
    ]
    single_rem = [
        {
            "finding_id": "f1",
            "original_snippet": "SELECT * FROM users",
            "fixed_snippet": "SELECT * FROM users WHERE email = ?",
            "explanation": "Parameterize input",
        }
    ]

    report = agent.compile_report("http://localhost:4000", "dast", single_finding, single_rem)
    agent.render_terminal(report)

    output = out_io.getvalue()
    assert "SentraX Security Scan Summary" in output
    assert "SQL Injection" in output
    assert "HIGH" in output
    assert "Authentication bypass verified" in output
    assert "SELECT * FROM users WHERE email = ?" in output


def test_reporter_empty_findings(tmp_path: Path):
    out_io = io.StringIO()
    console = Console(file=out_io, force_terminal=False, color_system=None)
    agent = ReporterAgent(console=console, reports_dir=tmp_path)

    result = agent.run("http://localhost:4000", "dast", findings=[], remediations=[])
    validated = FinalScanReport(**result)
    assert validated.summary.total_findings == 0
    assert len(validated.findings) == 0

    output = out_io.getvalue()
    assert "No vulnerabilities confirmed" in output

    md_file = Path(validated.markdown_path)
    assert md_file.exists()
    assert "No vulnerabilities were confirmed" in md_file.read_text(encoding="utf-8")


def test_reporter_skips_unconfirmed_findings(tmp_path: Path):
    agent = ReporterAgent(reports_dir=tmp_path)

    mixed_findings = [
        {
            "finding_id": "f1",
            "vuln_type": "sqli",
            "target": "/api/login",
            "mode": "dast",
            "confirmed": True,
            "evidence": {
                "request_sent": "a",
                "response_snippet": "b",
                "why_confirmed": "c",
            },
            "severity": "high",
        },
        {
            "finding_id": "f2",
            "vuln_type": "xss",
            "target": "/api/search",
            "mode": "dast",
            "confirmed": False,
            "evidence": {
                "request_sent": "a",
                "response_snippet": "b",
                "why_confirmed": "c",
            },
            "severity": "low",
        },
    ]

    result = agent.compile_report("http://localhost:4000", "dast", mixed_findings)
    assert result.summary.total_findings == 1
    assert result.findings[0].finding.finding_id == "f1"


def test_reporter_back_to_back_scans_do_not_collide_on_filename(tmp_path: Path):
    """Two scans finishing in the same wall-clock second must not overwrite each other's report."""
    agent = ReporterAgent(reports_dir=tmp_path)
    report_a = agent.compile_report("http://localhost:4000", "dast", [])
    report_b = agent.compile_report("./target", "sast", [])

    path_a = agent.save_markdown_report(report_a)
    path_b = agent.save_markdown_report(report_b)

    assert path_a != path_b
    assert path_a.exists()
    assert path_b.exists()
