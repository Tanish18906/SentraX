"""Tests for RemediationAgent (Phase 5)."""

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from sentrax.agents.remediation import RemediationAgent
from sentrax.utils.schema import RemediationFix


SAMPLE_FIXTURES_PATH = Path("fixtures/sample_confirmed_finding.json")


def test_remediation_runs_against_fixtures():
    with open(SAMPLE_FIXTURES_PATH) as f:
        findings = json.load(f)

    # Mock LLMClient that returns realistic fix recommendations
    mock_client = MagicMock()

    def mock_complete(system_prompt, user_prompt, *args, **kwargs):
        if "SQLI" in user_prompt:
            if "sast" in user_prompt.lower():
                return {
                    "finding_id": "f4",
                    "original_snippet": 'const query = "SELECT * FROM users WHERE email=\'" + email + "\'";',
                    "fixed_snippet": 'const query = "SELECT * FROM users WHERE email = ?"; db.query(query, [email]);',
                    "explanation": "Use parameterized queries with placeholders so user input is never concatenated into SQL.",
                }
            return {
                "finding_id": "f1",
                "original_snippet": "POST /api/login with unparameterized SQL",
                "fixed_snippet": "db.query('SELECT * FROM users WHERE email = ? AND password = ?', [email, hash(password)])",
                "explanation": "Parameterize credentials query to prevent authentication bypass via SQL injection.",
            }
        elif "XSS" in user_prompt:
            return {
                "finding_id": "f2",
                "original_snippet": '<div class="review-body">${comment}</div>',
                "fixed_snippet": '<div class="review-body"><%= escapeHtml(comment) %></div>',
                "explanation": "Escape HTML entities in user comments before rendering them into the page.",
            }
        elif "IDOR" in user_prompt:
            return {
                "finding_id": "f3",
                "original_snippet": "Order.findById(req.params.id)",
                "fixed_snippet": "Order.findOne({ _id: req.params.id, userId: req.user.id })",
                "explanation": "Verify resource ownership against the authenticated session before returning order details.",
            }
        elif "BROKEN_AUTH" in user_prompt:
            return {
                "finding_id": "f5",
                "original_snippet": "app.post('/api/login', loginHandler)",
                "fixed_snippet": "app.post('/api/login', rateLimiter({ max: 5, windowMs: 60000 }), loginHandler)",
                "explanation": "Enforce strict rate limiting on authentication endpoints to mitigate credential brute-forcing.",
            }
        return {
            "finding_id": "unknown",
            "original_snippet": "code",
            "fixed_snippet": "fixed",
            "explanation": "explanation",
        }

    mock_client.complete_json.side_effect = mock_complete

    agent = RemediationAgent(llm_client=mock_client)
    fixes = agent.run(findings)

    assert len(fixes) == len(findings)
    for fix in fixes:
        validated = RemediationFix(**fix)
        assert validated.finding_id.startswith("f")
        assert len(validated.original_snippet) > 0
        assert len(validated.fixed_snippet) > 0
        assert len(validated.explanation) > 0

    # Specifically check SAST exact fix vs DAST fix
    sast_fix = next(f for f in fixes if f["finding_id"] == "f4")
    assert "email" in sast_fix["original_snippet"]
    assert "parameterized" in sast_fix["explanation"].lower() or "?" in sast_fix["fixed_snippet"]


def test_remediation_fallback_on_llm_error():
    mock_client = MagicMock()
    mock_client.complete_json.side_effect = RuntimeError("API connection timeout")

    agent = RemediationAgent(llm_client=mock_client)

    finding = {
        "finding_id": "f_test_sqli",
        "vuln_type": "sqli",
        "target": "/api/login",
        "mode": "dast",
        "confirmed": True,
        "evidence": {
            "request_sent": "test",
            "response_snippet": "test",
            "why_confirmed": "test",
        },
        "severity": "high",
    }

    fix = agent.remediate_finding(finding)
    validated = RemediationFix(**fix)
    assert validated.finding_id == "f_test_sqli"
    assert "parameterized" in validated.explanation.lower() or "sql" in validated.explanation.lower()
    assert len(validated.fixed_snippet) > 0


def test_remediation_skips_unconfirmed_findings():
    agent = RemediationAgent()

    findings = [
        {"finding_id": "f1", "vuln_type": "sqli", "confirmed": True, "target": "/api/login"},
        {"finding_id": "f2", "vuln_type": "xss", "confirmed": False, "target": "/api/search"},
    ]

    mock_client = MagicMock()
    mock_client.complete_json.return_value = {
        "finding_id": "f1",
        "original_snippet": "vulnerable",
        "fixed_snippet": "fixed",
        "explanation": "safe",
    }
    agent.llm_client = mock_client

    fixes = agent.run(findings)
    assert len(fixes) == 1
    assert fixes[0]["finding_id"] == "f1"


def test_remediation_handles_single_dict_input():
    mock_client = MagicMock()
    mock_client.complete_json.return_value = {
        "finding_id": "f1",
        "original_snippet": "orig",
        "fixed_snippet": "fix",
        "explanation": "exp",
    }
    agent = RemediationAgent(llm_client=mock_client)

    fix = agent.run({"finding_id": "f1", "vuln_type": "idor", "confirmed": True})
    assert len(fix) == 1
    assert fix[0]["finding_id"] == "f1"
