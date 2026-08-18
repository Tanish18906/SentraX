"""Tests for LLMClient (shared by Strategist and, later, Remediation)."""

from unittest.mock import MagicMock, patch

import pytest

from sentrax.utils.llm_client import LLMCallError, LLMClient


def test_missing_openai_key_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("SENTRAX_LLM_PROVIDER", "openai")
    with pytest.raises(LLMCallError):
        LLMClient()


def test_missing_anthropic_key_raises(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMCallError):
        LLMClient(provider="anthropic")


def test_unknown_provider_raises(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    with pytest.raises(LLMCallError):
        LLMClient(provider="not-a-real-provider")


def test_openai_complete_json_parses_response(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client = LLMClient(provider="openai", model="gpt-4o-mini")

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content='{"tasks": []}'))]
    client._client.chat.completions.create = MagicMock(return_value=fake_response)

    result = client.complete_json("system", "user")
    assert result == {"tasks": []}
    client._client.chat.completions.create.assert_called_once()


def test_complete_json_retries_then_raises(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client = LLMClient(provider="openai", max_retries=1)
    client._client.chat.completions.create = MagicMock(side_effect=RuntimeError("network blip"))

    with patch("time.sleep"):
        with pytest.raises(LLMCallError):
            client.complete_json("system", "user")

    assert client._client.chat.completions.create.call_count == 2  # initial attempt + 1 retry


def test_complete_json_retries_on_bad_json_then_succeeds(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client = LLMClient(provider="openai", max_retries=1)

    bad_response = MagicMock()
    bad_response.choices = [MagicMock(message=MagicMock(content="not json"))]
    good_response = MagicMock()
    good_response.choices = [MagicMock(message=MagicMock(content='{"tasks": []}'))]
    client._client.chat.completions.create = MagicMock(side_effect=[bad_response, good_response])

    with patch("time.sleep"):
        result = client.complete_json("system", "user")

    assert result == {"tasks": []}


def test_llm_model_env_var_used(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "gpt-5.6-terra")
    client = LLMClient(provider="openai")
    assert client.model == "gpt-5.6-terra"


def test_openai_fallback_when_temperature_unsupported(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    client = LLMClient(provider="openai", max_retries=0)

    fake_response = MagicMock()
    fake_response.choices = [MagicMock(message=MagicMock(content='{"tasks": []}'))]

    # First call with temperature raises unsupported_value, retry without temperature succeeds
    client._client.chat.completions.create = MagicMock(
        side_effect=[
            RuntimeError("Unsupported value: 'temperature' does not support 0.2 with this model. Only the default (1) value is supported."),
            fake_response,
        ]
    )

    result = client.complete_json("system", "user", temperature=0.2)
    assert result == {"tasks": []}
    assert client._client.chat.completions.create.call_count == 2


