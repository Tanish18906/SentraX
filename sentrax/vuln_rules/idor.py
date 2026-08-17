"""SentraX AI — Insecure Direct Object Reference (IDOR) confirmation rule.

Reference: Docs/Agents.md Section 3, Docs/custom-target.md Section 3.
Ground truth: log in as Alice (alice@vulnmart.test / alice123), request the
same resource type with a different ID (e.g. GET /api/order/2, Bob's order)
while still authenticated as Alice.

Confirmed (DAST) = response returns another user's actual data (a distinct
owner/email) while authenticated as Alice.
Confirmed (SAST) = the flagged line looks a resource up directly by a
request-supplied ID with no visible ownership check on the same line.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin

import requests

VULN_TYPE = "idor"
TIMEOUT = 10.0
LOGIN_PATH = "/api/login"

# Seed account from Docs/custom-target.md — the known-good identity to
# authenticate as before probing another user's resource.
SEED_EMAIL = "alice@vulnmart.test"
SEED_PASSWORD = "alice123"

_AUTHZ_CHECK_HINTS = re.compile(
    r"""req\.user\.id|request\.user\.id|current_user|owner_id\s*===?|\.owner\s*!==?""",
    re.IGNORECASE,
)
_ID_LOOKUP_PATTERN = re.compile(r"""(?:findById|findByPk|findOne|get_object_or_404)\s*\(""", re.IGNORECASE)


def _login(session: requests.Session, base_url: str) -> Optional[Dict[str, Any]]:
    try:
        resp = session.post(
            urljoin(base_url, LOGIN_PATH),
            json={"email": SEED_EMAIL, "password": SEED_PASSWORD},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except (requests.exceptions.RequestException, ValueError):
        return None


def confirm_dast(session: requests.Session, base_url: str, target: str) -> Tuple[bool, Dict[str, Any]]:
    """Authenticate as the seed user, then request `target` (another user's resource by ID)."""
    request_sent = f"Authenticate as {SEED_EMAIL}, then GET {target}"

    login_data = _login(session, base_url)
    if login_data is None:
        return False, {
            "request_sent": request_sent,
            "response_snippet": "",
            "why_confirmed": f"Could not authenticate as seed user {SEED_EMAIL}; cannot test ownership.",
        }

    token = login_data.get("token")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    own_email = (login_data.get("user") or {}).get("email", SEED_EMAIL)

    try:
        resp = session.get(urljoin(base_url, target), headers=headers, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, {
            "request_sent": request_sent,
            "response_snippet": f"Request failed: {e}",
            "why_confirmed": "Request could not be completed against the target; treating as not confirmed.",
        }

    snippet = resp.text[:500]
    if resp.status_code in (401, 403):
        return False, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": f"Access denied (HTTP {resp.status_code}) when requesting another user's "
            f"resource while authenticated as {own_email} — ownership check appears enforced.",
        }

    try:
        data = resp.json()
    except ValueError:
        return False, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "Response was not JSON; cannot verify whose data was returned.",
        }

    returned_owner = data.get("owner") or data.get("email") or (data.get("user") or {}).get("email")
    if resp.status_code == 200 and returned_owner and returned_owner != own_email:
        return True, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": f"Authenticated as {own_email} but received another user's data "
            f"(owner={returned_owner}) for {target}.",
        }

    return False, {
        "request_sent": request_sent,
        "response_snippet": snippet,
        "why_confirmed": "Endpoint returned the authenticated user's own data (or no distinguishing owner "
        "field) rather than another user's resource — ownership check appears enforced.",
    }


def confirm_sast(snippet: str, file: str, line: int) -> Tuple[bool, Dict[str, Any]]:
    """Independently re-check a flagged source line for a direct ID lookup with no visible ownership check."""
    request_sent = f"Static code re-check of {file}:{line}"

    if _AUTHZ_CHECK_HINTS.search(snippet):
        return False, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "An ownership/authorization check is present on this line — not exploitable "
            "as flagged.",
        }
    if _ID_LOOKUP_PATTERN.search(snippet):
        return True, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "Resource is looked up directly by a request-supplied ID with no visible "
            "ownership check on this line.",
        }
    return False, {
        "request_sent": request_sent,
        "response_snippet": snippet,
        "why_confirmed": "Independent re-check did not find a direct ID-lookup pattern on this line — "
        "likely a false positive from initial recon.",
    }
