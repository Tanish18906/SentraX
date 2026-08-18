"""SentraX AI — Cross-Site Scripting (XSS) confirmation rule.

Reference: Docs/Agents.md Section 3, Docs/custom-target.md Section 2.
Ground truth target: POST /api/reviews (comment field), reflected on GET /reviews.

Confirmed (DAST) = a unique marker payload appears back in the /reviews
response **unescaped** — the literal `<script>` tag, not `&lt;script&gt;`.
Confirmed (SAST) = the flagged line assigns into an unescaped HTML sink
(innerHTML / dangerouslySetInnerHTML / document.write) with no sanitize
call visible on the same line.
"""

from __future__ import annotations

import html
import re
import uuid
from typing import Any, Dict, Tuple
from urllib.parse import urljoin

import requests

VULN_TYPE = "xss"
TIMEOUT = 10.0
REVIEWS_PAGE_PATH = "/reviews"

_SANITIZE_HINTS = re.compile(r"""DOMPurify\.sanitize|sanitize\(|escape\(|textContent\s*=""", re.IGNORECASE)
_XSS_SINK_PATTERN = re.compile(
    r"""\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\("""
    # JS template literal interpolating a value directly into HTML markup, e.g.
    # <div class="review-comment">${r.comment}</div> — unescaped by construction.
    r"""|<[a-zA-Z][^>]*>\s*\$\{[a-zA-Z0-9_.]+\}"""
)


def confirm_dast(session: requests.Session, base_url: str, target: str) -> Tuple[bool, Dict[str, Any]]:
    """Submit a unique <script> marker via `target` (e.g. /api/reviews) and check it reflects unescaped."""
    nonce = uuid.uuid4().hex[:8]
    marker = f"<script>alert('sentrax-{nonce}')</script>"
    post_url = urljoin(base_url, target)
    reviews_url = urljoin(base_url, REVIEWS_PAGE_PATH)
    request_sent = f'POST {target} with comment="{marker}", then GET {REVIEWS_PAGE_PATH}'

    try:
        session.post(post_url, json={"rating": 5, "comment": marker}, timeout=TIMEOUT)
        get_resp = session.get(reviews_url, timeout=TIMEOUT)
    except requests.exceptions.RequestException as e:
        return False, {
            "request_sent": request_sent,
            "response_snippet": f"Request failed: {e}",
            "why_confirmed": "Request could not be completed against the target; treating as not confirmed.",
        }

    body = get_resp.text
    if marker in body:
        idx = body.find(marker)
        window_start = max(0, idx - 60)
        window_end = min(len(body), idx + len(marker) + 60)
        return True, {
            "request_sent": request_sent,
            "response_snippet": body[window_start:window_end],
            "why_confirmed": "Injected <script> payload was reflected verbatim, unescaped, in the "
            f"{REVIEWS_PAGE_PATH} response.",
        }

    if html.escape(marker) in body:
        return False, {
            "request_sent": request_sent,
            "response_snippet": html.escape(marker),
            "why_confirmed": "Payload was reflected but HTML-escaped — not exploitable as flagged.",
        }

    return False, {
        "request_sent": request_sent,
        "response_snippet": body[:300],
        "why_confirmed": "Payload did not appear in the response at all — likely stripped or filtered.",
    }


def confirm_sast(snippet: str, file: str, line: int) -> Tuple[bool, Dict[str, Any]]:
    """Independently re-check a flagged source line for an unescaped HTML sink assignment."""
    request_sent = f"Static code re-check of {file}:{line}"

    if _SANITIZE_HINTS.search(snippet):
        return False, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "An HTML sink is present, but a sanitize/escape call is also present on the "
            "same line — not exploitable as flagged.",
        }
    if _XSS_SINK_PATTERN.search(snippet):
        return True, {
            "request_sent": request_sent,
            "response_snippet": snippet,
            "why_confirmed": "Line assigns into an unescaped HTML sink (innerHTML/dangerouslySetInnerHTML/"
            "document.write) with no sanitization visible on this line.",
        }
    return False, {
        "request_sent": request_sent,
        "response_snippet": snippet,
        "why_confirmed": "Independent re-check did not find an unescaped HTML sink pattern on this line — "
        "likely a false positive from initial recon.",
    }
