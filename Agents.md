# SentraX AI — Agents Spec

Read `architecture.md` first for how these fit together. This doc is the source of truth for what each agent does internally. When your coding tool generates an agent, check its output against this doc line by line — especially section 3 (Exploit Agent), which is the most important section in this entire spec.

---

## 1. Recon Agent

**File:** `sentrax/agents/recon.py`
**Job:** map the attack surface. No reasoning, no judgment — just structured data collection.
**Two modes, same output shape family:**

### DAST mode (given a URL)
- Crawl the target starting from the given URL (follow links within the same domain only, reasonable depth limit — 2-3 levels is enough for a demo target)
- For each page found, collect: URL, any HTML forms (action, method, input field names/types), any API-looking endpoints (e.g. `/rest/...`, `/api/...` patterns visible in JS or network calls)
- If the target needs JS rendering to reveal content (check whether VulnMart's pages are plain server-rendered HTML or a JS-driven frontend), use Playwright instead of a plain `requests`+BeautifulSoup crawl if needed — check this early, it changes your tooling choice

**Output JSON shape:**
```json
{
  "mode": "url",
  "target": "http://localhost:3000",
  "pages": [
    {
      "url": "http://localhost:3000/#/login",
      "forms": [
        {"action": "/rest/user/login", "method": "POST", "fields": ["email", "password"]}
      ],
      "endpoints_observed": ["/rest/user/login", "/rest/products/search"]
    }
  ]
}
```

### SAST mode (given a folder path)
- Walk the directory, list source files by extension (`.js`, `.py`, `.ts`, whatever the target folder actually contains)
- For each file, run simple pattern checks (regex is enough for demo scope — this does not need to be a real AST parser):
  - SQLi-prone: string concatenation or f-strings feeding into something near the words `SELECT`, `query`, `execute`
  - XSS-prone: `innerHTML =`, `dangerouslySetInnerHTML`, unescaped template output
  - Hardcoded secrets: strings matching common API-key/password-looking patterns

**Output JSON shape:**
```json
{
  "mode": "folder",
  "target": "/path/to/scanned/folder",
  "findings_raw": [
    {"file": "routes/login.js", "line": 42, "pattern": "sqli_concat", "snippet": "\"SELECT * FROM users WHERE email='\" + email"}
  ]
}
```

**Note:** SAST-mode Recon output is already close to a "finding" — Strategist and Exploit still process it (Strategist prioritizes, Exploit confirms it's not a false positive), but there's less work for them to do in this mode. That's expected, not a bug.

---

## 2. Strategist Agent

**File:** `sentrax/agents/strategist.py`
**Job:** the one genuine LLM-reasoning showcase in the pipeline. Takes Recon's output, decides what's worth testing and why, produces a prioritized task list.
**LLM-driven.** This is the agent you review most carefully for prompt quality — write the "what good output looks like" description below into your prompt almost verbatim.

**Input:** Recon Agent's JSON output (either mode)

**What the prompt should ask the LLM to do:** given this attack surface, identify which specific vulnerability types are plausible at which specific locations, and briefly explain why — don't just list every vuln type against every endpoint, show actual judgment (e.g. a login form is a broken-auth and SQLi candidate; a product-detail URL with a numeric ID is an IDOR candidate; a search/comment field is an XSS candidate).

**Output JSON shape:**
```json
{
  "tasks": [
    {
      "id": "task_1",
      "target": "/rest/user/login",
      "vuln_type": "sqli",
      "reasoning": "Login form takes email/password directly into what is likely a DB query — classic SQLi injection point."
    },
    {
      "id": "task_2",
      "target": "/rest/user/login",
      "vuln_type": "broken_auth",
      "reasoning": "No visible rate-limiting on login attempts observed during recon."
    }
  ]
}
```

**Review checklist before accepting generated code here:**
- Does it only propose tasks that map to your 4 supported vuln types (sqli, xss, idor, broken_auth)? If the LLM starts inventing vuln types you haven't built Exploit-Agent logic for, the pipeline breaks downstream — constrain this explicitly in the prompt.
- Does the `reasoning` field actually reference something real from the Recon input, or is it generic filler? Generic filler is a sign the prompt needs tightening.

---

## 3. Exploit Agent — THE MOST IMPORTANT FILE IN THE PROJECT

**File:** `sentrax/agents/exploit.py` + `sentrax/vuln_rules/*.py`
**Job:** take each task from Strategist, actually attempt it, and **deterministically confirm** whether it worked by checking real output. Never let an LLM decide "yes this is vulnerable" — that decision must be code checking actual data.

**Why this matters more than any other file:** this is the difference between SentraX being a real tool and SentraX being an LLM that confidently asserts things. A judge asking "how do you know this isn't a false positive" is answered entirely by what's in this file.

### Confirmation rule per vuln type (write these into `vuln_rules/`, one file each)

**SQLi (`vuln_rules/sqli.py`)**
- Send a known payload (e.g. `' OR '1'='1` in the login form's password field, or a UNION-based payload in a search param)
- Confirmed = response demonstrably differs from a normal/failed request in a way that proves injection — e.g. login succeeds without correct credentials, or a search returns rows it shouldn't for that query, or a DB error message leaks query structure
- Not confirmed = generic error, no behavioral difference, or the payload was clearly sanitized/escaped in the response

**XSS (`vuln_rules/xss.py`)**
- Submit a payload like `<script>alert('sentrax')</script>` or a distinct marker string into an input field that gets reflected/stored and displayed
- Confirmed = fetch the page where the payload would render, check the raw HTML response for the **unescaped** payload (i.e. `<script>` appears literally, not as `&lt;script&gt;`)
- Not confirmed = payload appears HTML-escaped, or doesn't appear at all (was stripped/filtered)

**IDOR (`vuln_rules/idor.py`)**
- Authenticate as User A, note a resource ID belonging to User A (e.g. an order or profile ID)
- Request the same resource type but with a different ID (User B's), while still authenticated as User A
- Confirmed = response returns User B's actual data (verifiably different from User A's own data — check for a field that should be unique/private, like email or order contents)
- Not confirmed = 403/404, or an access-denied response, or it silently returns User A's own data instead

**Broken Auth (`vuln_rules/broken_auth.py`)**
- Send N consecutive failed login attempts (pick N — e.g. 10) against the same account in quick succession
- Confirmed = all N attempts are processed identically with no lockout, increasing delay, or CAPTCHA challenge triggered
- Not confirmed = requests get blocked, rate-limited, or delayed after some threshold

### Exploit Agent's job around these rules
- Take a task from Strategist, look up the matching rule file by `vuln_type`
- Execute the real HTTP request(s) (`requests`/`httpx`) against the DAST target, or re-check the SAST pattern match against the actual file content for SAST tasks
- Call that vuln type's `confirm()` function with the raw response data
- Only pass forward to Remediation + Reporter if `confirm()` returns True, with the evidence (request sent, response snippet, why it counts) attached

**Output JSON shape (per confirmed finding):**
```json
{
  "finding_id": "f1",
  "vuln_type": "sqli",
  "target": "/rest/user/login",
  "mode": "dast",
  "confirmed": true,
  "evidence": {
    "request_sent": "...",
    "response_snippet": "...",
    "why_confirmed": "Login succeeded using payload in password field, bypassing authentication."
  },
  "severity": "high"
}
```

**Before you trust any of this code:** manually reproduce each exploit by hand against your running VulnMart instance first (browser or Postman), and write down exactly what a confirmed response looks like versus a failed one. Only then write/review the `confirm()` logic — don't let the coding tool guess at what "success" looks like without you having seen it yourself.

**Concrete endpoints and payloads for all 4 vuln types are in `custom-target.md`** — use that as the real starting point for each `confirm()` function instead of inventing payloads from scratch. It's matched exactly to the deliberately-vulnerable practice app ("VulnMart") built from `custom-target-build-prompt.md`.

---

## 4. Remediation Agent

**File:** `sentrax/agents/remediation.py`
**Job:** for every confirmed finding, generate a concrete fix suggestion. LLM-driven, low-risk (text generation only, never edits real files/apps).

**Input:** a confirmed finding object (from Exploit Agent)

**Prompt should ask the LLM for:** the vulnerable code/request pattern in context, a corrected version, and one sentence explaining why the fix works — kept short and concrete, not a lecture.

**Output JSON shape:**
```json
{
  "finding_id": "f1",
  "original_snippet": "\"SELECT * FROM users WHERE email='\" + email + \"'\"",
  "fixed_snippet": "db.query(\"SELECT * FROM users WHERE email = ?\", [email])",
  "explanation": "Use parameterized queries so user input can never be interpreted as SQL syntax."
}
```

For DAST-mode findings where you don't have the target's actual source (you're attacking it as a black box, you may not have its code), the "fix" is necessarily more generic (e.g. "sanitize/parameterize the query backing this endpoint") rather than an exact line — that's fine and expected, don't force a fake code snippet you don't actually have. For SAST-mode findings you do have the real file/line, so the fix can be exact — make that distinction clear in the Reporter's output too.

---

## 5. Reporter Agent

**File:** `sentrax/agents/reporter.py`
**Job:** pure formatting. Takes the full list of confirmed findings (each with its remediation attached) and produces two outputs. No decisions made here.

**Output 1 — terminal display:** a `rich` table or set of panels, one per finding, showing vuln type, target, severity, evidence summary, and fix. This is what prints at the end of a `/scan` run.

**Output 2 — saved file:** a Markdown report written to `reports/` (filename with timestamp), same content, formatted for reading outside the terminal — this is your "deliverable" artifact, the thing that makes SentraX feel like a real product output rather than just console noise.

**Suggested report structure:**
```markdown
# SentraX Scan Report
Target: <url or folder>
Mode: <dast | sast>
Date: <timestamp>

## Summary
X vulnerabilities confirmed (Y high, Z medium)

## Findings

### 1. SQL Injection — /rest/user/login [HIGH]
**Evidence:** ...
**Suggested Fix:** ...
```

---

## Quick reference: which agents are LLM-driven vs deterministic

| Agent | LLM? | Why |
|---|---|---|
| Recon | No | Pure data collection |
| Strategist | Yes | Reasoning/prioritization is exactly what LLMs are good at |
| Exploit | No (confirmation logic) | Must be deterministic — this is the trust boundary of the whole project |
| Remediation | Yes | Text/code-suggestion generation, low risk since it never applies the fix |
| Reporter | No | Pure formatting |
