# SentraX AI — CLI Spec

Read `architecture.md` first. This doc specs the terminal shell layer only — `sentrax/cli.py`. It's what makes SentraX *feel* like a real agentic tool (in the spirit of tools like Claude Code's terminal interface) rather than a script that prints logs.

---

## 1. Entry point

`sentrax` must work as a real installed command, not "run this python file manually."

- Use `pyproject.toml` with a `[project.scripts]` entry: `sentrax = "sentrax.cli:main"`
- `pip install -e .` from the repo root makes `sentrax` available anywhere in the terminal
- Running `sentrax` with no arguments launches the interactive session (banner → prompt loop). Do not require arguments at launch — the target/command comes after, typed into the running session (this matters for the demo: typing on stage is part of the theater).

---

## 2. Launch sequence

1. Clear/prepare terminal
2. Print banner — name, short tagline, maybe a one-line hint (e.g. "Type /help to get started")
3. Drop into the prompt loop, waiting for input

**Banner content (adjust styling, keep the substance):**
```
 ____             _              __  __
/ ___|  ___ _ __ | |_ _ __ __ _ \ \/ /
\___ \ / _ \ '_ \| __| '__/ _` | \  /
 ___) |  __/ | | | |_| | | (_| | /  \
|____/ \___|_| |_|\__|_|  \__,_|/_/\_\

SentraX AI — autonomous security testing, explained.
Type /help for commands.
```
Use `rich`'s styling (color, maybe bold) rather than plain print — this is a one-line effort for real visual payoff.

---

## 3. Prompt loop behavior

- Show a distinct prompt symbol, e.g. `sentrax ▸` or `>` styled in a signature color
- Read a line of input
- If it starts with `/`, parse as a command (see section 4)
- If it doesn't start with `/`, treat as invalid input and show a short hint (e.g. "Not a recognized input — try /help") rather than crashing or silently doing nothing
- After a command finishes running, return to the prompt — the session stays open until the user exits
- Loop continues until `/exit` or `/quit`, or Ctrl+C (handle this gracefully, don't let it throw a raw traceback)

---

## 4. Commands

| Command | Behavior |
|---|---|
| `/scan <url>` | Runs the full pipeline in DAST mode against the given URL. Streams live agent activity (section 5), ends with the Reporter's terminal output. |
| `/scan-code <folder>` | Runs the full pipeline in SAST mode against the given local folder path. Same streaming/report behavior. |
| `/report` | Re-displays the most recent scan's report (from memory in the current session — no need to re-run). |
| `/status` | Shows what's currently running, if anything (mainly useful if you add any async/background behavior — otherwise can just say "idle" or "last scan: <summary>"). |
| `/help` | Lists all commands with a one-line description each. |
| `/clear` | Clears the terminal screen, re-shows the banner. |
| `/exit` or `/quit` | Ends the session cleanly. |

Unrecognized `/something` → show "Unknown command: /something — try /help", don't crash.

---

## 5. Live agent activity display (the core visual feature)

While `/scan` or `/scan-code` runs, this is what's on screen — it's the single most important visual element of the whole demo, worth the most build/polish time relative to its complexity.

**Per-agent visual identity (pick distinct colors, keep them consistent everywhere):**

| Agent | Suggested color | Label |
|---|---|---|
| Recon | cyan | `[RECON]` |
| Strategist | yellow | `[STRATEGIST]` |
| Exploit | red | `[EXPLOIT]` |
| Remediation | magenta | `[REMEDIATION]` |
| Reporter | green | `[REPORTER]` |

**Per-step output pattern**, roughly:
```
[RECON] Mapping attack surface at http://localhost:4000...
[RECON] Found 3 pages, 2 forms, 3 API endpoints.

[STRATEGIST] Analyzing attack surface...
[STRATEGIST] → /api/login: testing for SQLi (login form takes raw credentials)
[STRATEGIST] → /api/login: testing for broken auth (no rate-limit observed)
[STRATEGIST] → /api/order/1: testing for IDOR (numeric ID in URL)

[EXPLOIT] Attempting SQLi on /api/login...
[EXPLOIT] ✓ CONFIRMED — authentication bypassed with injected payload
[EXPLOIT] Attempting broken-auth check on /api/login...
[EXPLOIT] ✗ Ruled out — no distinguishing weakness found
[EXPLOIT] Attempting IDOR on /api/order/2...
[EXPLOIT] ✓ CONFIRMED — accessed another user's order data

[REMEDIATION] Generating fix for SQLi finding...
[REMEDIATION] Generating fix for IDOR finding...

[REPORTER] Compiling final report...
[REPORTER] Report saved to reports/scan_2026-08-17_2130.md
```

**Implementation notes:**
- Use `rich.console.Console.print` with styled markup (`[cyan][RECON][/cyan] ...`) for the colored labels
- Use `rich.status` or a spinner during any step that takes real time (LLM calls, HTTP requests) so the terminal never looks frozen/dead
- Streaming/typewriter text (character-by-character or line-by-line reveal with a small delay) makes it feel live even where the underlying call already returned — this is a legitimate and common technique, use it for narration lines, not for evidence data (evidence should appear as-is, don't fake-delay real proof)
- Show **ruled-out** attempts too (the `✗ Ruled out` line above), not just confirmed ones — this is your "judgment, not brute force" differentiator made visible, don't cut it for time

---

## 6. Error handling (must not crash live)

- Target unreachable (`/scan` to a URL that's not running) → clear message: "Could not reach http://localhost:3000 — is the target running?" not a raw connection-error traceback
- Invalid folder path (`/scan-code`) → "Folder not found: <path>"
- LLM API failure (network hiccup, rate limit) → catch it, show "LLM call failed, retrying..." with one retry, then a graceful fallback message rather than crashing the whole session
- Ctrl+C mid-scan → catch it, print "Scan interrupted." and return to the prompt, don't kill the whole program

---

## 7. Demo-day safety net

Given the "must work every time" constraint from earlier planning: consider a `--demo` flag or config toggle that uses cached/pre-verified responses for the LLM narration and confirmed findings (still running real requests against your real local VulnMart instance, so it's not fake — just removing dependency on live LLM latency/API availability for the parts that must not fail). Real-time LLM calls are fine for the flashy Strategist reasoning text since that's not asserting anything critical; the Exploit Agent's confirmations should always be based on real, freshly-executed requests against your live local target, not a cached response.
