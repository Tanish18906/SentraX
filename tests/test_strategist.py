"""Tests for StrategistAgent (Phase 3)."""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sentrax.agents.strategist import StrategistAgent
from sentrax.utils.llm_client import LLMCallError
from sentrax.utils.schema import StrategistResult


def _load_fixture(name: str) -> dict:
    with open(Path("fixtures") / name) as f:
        return json.load(f)


def test_strategist_url_mode_grounded_tasks():
    recon_output = _load_fixture("sample_recon_url.json")

    mock_llm = MagicMock()
    mock_llm.complete_json.return_value = {
        "tasks": [
            {
                "id": "task_1",
                "target": "/api/login",
                "vuln_type": "sqli",
                "reasoning": "Login form at /api/login takes email/password directly, classic SQLi injection point.",
            },
            {
                "id": "task_2",
                "target": "/api/login",
                "vuln_type": "broken_auth",
                "reasoning": "No rate-limiting observed on the /api/login form during recon.",
            },
            {
                "id": "task_3",
                "target": "/api/reviews",
                "vuln_type": "xss",
                "reasoning": "Reviews form has a free-text 'comment' field rendered back on /reviews.",
            },
            {
                "id": "task_4",
                "target": "/api/order/2",
                "vuln_type": "idor",
                "reasoning": "/api/order/2 is a numeric-ID endpoint observed alongside /api/order/1 on the account page.",
            },
        ]
    }

    agent = StrategistAgent(llm_client=mock_llm)
    result = agent.run(recon_output)

    validated = StrategistResult(**result)
    assert len(validated.tasks) == 4
    vuln_types = {t.vuln_type for t in validated.tasks}
    assert vuln_types == {"sqli", "broken_auth", "xss", "idor"}
    for task in validated.tasks:
        assert task.reasoning  # grounded, non-empty

    mock_llm.complete_json.assert_called_once()
    system_prompt, user_prompt = mock_llm.complete_json.call_args[0]
    assert "sqli" in system_prompt and "broken_auth" in system_prompt
    assert "/api/login" in user_prompt


def test_strategist_folder_mode_grounded_tasks():
    recon_output = _load_fixture("sample_recon_folder.json")

    mock_llm = MagicMock()
    mock_llm.complete_json.return_value = {
        "tasks": [
            {
                "id": "task_1",
                "target": "routes/login.js:42",
                "vuln_type": "sqli",
                "reasoning": "routes/login.js:42 concatenates raw email into a SELECT string.",
            },
            {
                "id": "task_2",
                "target": "views/reviews.js:18",
                "vuln_type": "xss",
                "reasoning": "views/reviews.js:18 assigns userReview directly to innerHTML.",
            },
            {
                "id": "task_3",
                "target": "routes/orders.js:25",
                "vuln_type": "idor",
                "reasoning": "routes/orders.js:25 calls Order.findById(req.params.id) with no ownership check.",
            },
        ]
    }

    agent = StrategistAgent(llm_client=mock_llm)
    result = agent.run(recon_output)

    validated = StrategistResult(**result)
    assert len(validated.tasks) == 3
    targets = {t.target for t in validated.tasks}
    assert targets == {"routes/login.js:42", "views/reviews.js:18", "routes/orders.js:25"}


def test_strategist_drops_unsupported_vuln_types():
    recon_output = _load_fixture("sample_recon_url.json")

    mock_llm = MagicMock()
    mock_llm.complete_json.return_value = {
        "tasks": [
            {"id": "task_1", "target": "/api/login", "vuln_type": "sqli", "reasoning": "grounded"},
            # Hallucinated vuln type outside the 4 supported ones — must be dropped, not raised.
            {"id": "task_2", "target": "/api/login", "vuln_type": "csrf", "reasoning": "invented type"},
        ]
    }

    agent = StrategistAgent(llm_client=mock_llm)
    result = agent.run(recon_output)

    validated = StrategistResult(**result)
    assert len(validated.tasks) == 1
    assert validated.tasks[0].vuln_type == "sqli"


def test_strategist_drops_malformed_task_entries():
    recon_output = _load_fixture("sample_recon_url.json")

    mock_llm = MagicMock()
    mock_llm.complete_json.return_value = {
        "tasks": [
            {"id": "task_1", "target": "/api/login", "vuln_type": "sqli", "reasoning": "grounded"},
            {"vuln_type": "xss"},  # missing required fields
            "not-a-dict",
        ]
    }

    agent = StrategistAgent(llm_client=mock_llm)
    result = agent.run(recon_output)

    assert len(result["tasks"]) == 1


def test_strategist_rejects_unsupported_recon_mode():
    agent = StrategistAgent(llm_client=MagicMock())
    with pytest.raises(ValueError):
        agent.run({"mode": "something_else"})


def test_strategist_propagates_llm_call_error():
    mock_llm = MagicMock()
    mock_llm.complete_json.side_effect = LLMCallError("LLM call failed after 2 attempt(s): boom")

    agent = StrategistAgent(llm_client=mock_llm)
    with pytest.raises(LLMCallError):
        agent.run(_load_fixture("sample_recon_url.json"))
