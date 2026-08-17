"""SentraX AI — LLM Client Wrapper.

Reference: Docs/architecture.md section 4 (utils/llm_client.py).
Wraps the OpenAI/Anthropic chat call behind one interface so Strategist and
Remediation don't need to know which provider is configured. Provider/model
selection follows .env.example (SENTRAX_LLM_PROVIDER, SENTRAX_LLM_MODEL).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv()

DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-latest"


class LLMCallError(Exception):
    """Raised when the configured LLM provider fails to return a usable response."""


class LLMClient:
    """Thin wrapper around the OpenAI/Anthropic chat APIs, returning parsed JSON."""

    def __init__(
        self,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        max_retries: int = 1,
    ):
        self.provider = (provider or os.getenv("SENTRAX_LLM_PROVIDER", "openai")).lower()
        self.max_retries = max_retries

        if self.provider == "openai":
            from openai import OpenAI

            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise LLMCallError("OPENAI_API_KEY is not set (check .env).")
            self.model = model or os.getenv("SENTRAX_LLM_MODEL", DEFAULT_OPENAI_MODEL)
            self._client = OpenAI(api_key=api_key)
        elif self.provider == "anthropic":
            from anthropic import Anthropic

            api_key = os.getenv("ANTHROPIC_API_KEY")
            if not api_key:
                raise LLMCallError("ANTHROPIC_API_KEY is not set (check .env).")
            self.model = model or os.getenv("SENTRAX_LLM_MODEL", DEFAULT_ANTHROPIC_MODEL)
            self._client = Anthropic(api_key=api_key)
        else:
            raise LLMCallError(
                f"Unknown SENTRAX_LLM_PROVIDER: {self.provider!r} (expected 'openai' or 'anthropic')"
            )

    def complete_json(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> Dict[str, Any]:
        """Call the LLM and parse its response as a JSON object.

        Retries once (by default) on transient failures — network errors,
        rate limits, or a response that didn't parse as JSON — per the
        graceful-degradation behavior specified in Docs/CLI.md section 6.
        """
        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                raw_text = self._call(system_prompt, user_prompt, temperature)
                return json.loads(raw_text)
            except Exception as e:  # noqa: BLE001 - deliberately broad, see retry contract above
                last_error = e
                if attempt < self.max_retries:
                    time.sleep(1)
        raise LLMCallError(f"LLM call failed after {self.max_retries + 1} attempt(s): {last_error}") from last_error

    def _call(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        if self.provider == "openai":
            response = self._client.chat.completions.create(
                model=self.model,
                temperature=temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content or ""

        response = self._client.messages.create(
            model=self.model,
            max_tokens=2048,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text")
