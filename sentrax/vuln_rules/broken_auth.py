"""SentraX AI — Broken Authentication (no login rate limiting) confirmation rule.

Reference: Docs/Agents.md Section 3, Docs/custom-target.md Section 4.
Ground truth: send N consecutive failed login attempts against the same
account in quick succession.

Confirmed (DAST) = all N attempts return the same immediate failure with no
lockout/throttle/CAPTCHA signal and no meaningful latency growth.
Not confirmed = requests get blocked, rate-limited, or delayed after some
threshold.

There is no SAST signal for this vuln type — Recon's SAST_RULES don't (and
can't, from static source alone) detect missing rate limiting, so
confirm_sast() always reports not-confirmed with an explanatory reason
rather than guessing.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Tuple
from urllib.parse import urljoin

import requests

from sentrax.vuln_rules.idor import SEED_EMAIL

VULN_TYPE = "broken_auth"
TIMEOUT = 10.0
ATTEMPT_COUNT = 15
LATENCY_GROWTH_THRESHOLD = 5.0  # max/min latency ratio beyond this suggests throttling delay
MIN_MEANINGFUL_LATENCY = 0.05  # seconds; below this, ratio comparisons are just timer noise
LOCKOUT_KEYWORDS = ("locked", "captcha", "too many", "rate limit")


def confirm_dast(session: requests.Session, base_url: str, target: str) -> Tuple[bool, Dict[str, Any]]:
    """Send ATTEMPT_COUNT rapid failed logins against `target` (e.g. /api/login) and check for throttling."""
    url = urljoin(base_url, target)
    request_sent = f"{ATTEMPT_COUNT} consecutive failed POST {target} attempts against {SEED_EMAIL}"

    statuses = []
    latencies = []
    first_body = ""
    try:
        for i in range(ATTEMPT_COUNT):
            start = time.monotonic()
            resp = session.post(url, json={"email": SEED_EMAIL, "password": f"wrong-password-{i}"}, timeout=TIMEOUT)
            latencies.append(time.monotonic() - start)
            statuses.append(resp.status_code)
            if i == 0:
                first_body = resp.text[:300]
    except requests.exceptions.RequestException as e:
        return False, {
            "request_sent": request_sent,
            "response_snippet": f"Request failed mid-run: {e}",
            "why_confirmed": "Attempt sequence could not be completed; treating as not confirmed.",
        }

    throttle_status_seen = any(status == 429 or status >= 500 for status in statuses)
    body_flagged = any(keyword in first_body.lower() for keyword in LOCKOUT_KEYWORDS)
    min_latency = min(latencies) if latencies else 0
    max_latency = max(latencies) if latencies else 0
    latency_climbed = (
        min_latency > 0
        and max_latency > MIN_MEANINGFUL_LATENCY
        and (max_latency / min_latency) > LATENCY_GROWTH_THRESHOLD
    )
    consistent_status = len(set(statuses)) <= 1

    snippet = f"Status codes observed: {statuses}"

    if consistent_status and not throttle_status_seen and not body_flagged and not latency_climbed:
        return True, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": f"All {ATTEMPT_COUNT} failed attempts returned identical status "
            f"{statuses[0]} with no lockout, CAPTCHA, or increasing delay observed.",
        }
    return False, {
        "request_sent": request_sent,
        "response_snippet": snippet,
        "why_confirmed": "Requests were throttled, blocked, or delayed after repeated failures — rate "
        "limiting appears to be in place.",
    }


def confirm_sast(snippet: str, file: str, line: int) -> Tuple[bool, Dict[str, Any]]:
    """Broken auth (missing rate limiting) cannot be assessed from a single static source line."""
    return False, {
        "request_sent": f"Static code re-check of {file}:{line}",
        "response_snippet": snippet,
        "why_confirmed": "Broken authentication (missing rate limiting) cannot be confirmed via static "
        "code analysis — this vuln type requires live request behavior (DAST mode).",
    }
