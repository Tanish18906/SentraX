"""Tests for the --demo safety-net stand-ins (Phase 9, Docs/CLI.md section 7)."""

from unittest.mock import MagicMock

from sentrax.utils.demo_agents import DemoRemediationAgent, DemoStrategistAgent
from sentrax.utils.schema import StrategistResult


def test_demo_strategist_url_mode_returns_grounded_canned_tasks():
    agent = DemoStrategistAgent()
    result = agent.run({"mode": "url", "target": "http://localhost:4000", "pages": []})

    validated = StrategistResult(**result)
    vuln_types = {t.vuln_type for t in validated.tasks}
    assert vuln_types == {"sqli", "xss", "idor", "broken_auth"}
    for task in validated.tasks:
        assert task.reasoning


def test_demo_strategist_folder_mode_derives_tasks_from_real_findings():
    recon_output = {
        "mode": "folder",
        "target": "target",
        "findings_raw": [
            {"file": "server.js", "line": 197, "pattern": "sqli_concat", "snippet": "raw concat"},
            {"file": "server.js", "line": 251, "pattern": "xss_innerhtml", "snippet": "unescaped sink"},
            {"file": "server.js", "line": 462, "pattern": "idor_missing_authz", "snippet": "direct lookup"},
            # Unsupported pattern — must be silently dropped, not turned into a bogus task.
            {"file": "server.js", "line": 10, "pattern": "hardcoded_secret", "snippet": "SECRET_KEY='x'"},
        ],
    }

    agent = DemoStrategistAgent()
    result = agent.run(recon_output)

    validated = StrategistResult(**result)
    assert len(validated.tasks) == 3
    targets = {t.target for t in validated.tasks}
    assert targets == {"server.js:197", "server.js:251", "server.js:462"}


def test_demo_strategist_rejects_unsupported_mode():
    agent = DemoStrategistAgent()
    import pytest

    with pytest.raises(ValueError):
        agent.run({"mode": "something_else"})


def test_demo_remediation_never_calls_a_real_llm_even_with_key_present(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-key-should-never-be-used")
    agent = DemoRemediationAgent()

    # Even if a real LLMClient would happily construct here, the demo agent's
    # llm_client property must stay hard-pinned to None.
    assert agent.llm_client is None

    finding = {
        "finding_id": "f1",
        "vuln_type": "sqli",
        "target": "/api/login",
        "mode": "dast",
        "confirmed": True,
        "evidence": {"request_sent": "req", "response_snippet": "resp", "why_confirmed": "why"},
        "severity": "high",
    }
    fixes = agent.run([finding])
    assert len(fixes) == 1
    assert fixes[0]["finding_id"] == "f1"
    assert fixes[0]["fixed_snippet"]  # deterministic fallback template, not an LLM call
