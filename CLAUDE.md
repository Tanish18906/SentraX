# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SentraX is an installable CLI (`sentrax`) that runs a 5-agent pipeline to find and prove real vulnerabilities in either a live local web app (DAST, `/scan <url>`) or a local source folder (SAST, `/scan-code <folder>`), then suggests fixes and writes a report. It is a demo/hackathon-style build targeting a custom, deliberately-vulnerable local practice app ("VulnMart") — never a third-party or non-local target.

**Read `Docs/architecture.md` and `Docs/Agents.md` before writing any agent code.** They are the source of truth for data shapes and per-agent behavior; this file only orients you within the repo.

## Commands

```bash
# Install editable (from repo root; a .venv already exists here)
pip install -e .

# Run the interactive CLI
sentrax                    # or: python -m sentrax.cli

# Tests
pytest                             # full suite
pytest tests/test_recon.py         # one file
pytest tests/test_recon.py::test_recon_dast_mock_crawl   # one test
```

There is no lint/format tooling configured yet (no ruff/black/mypy config in `pyproject.toml`).

## Architecture

### The 5-agent pipeline

`Recon → Strategist → Exploit → Remediation → Reporter`, run in strict sequence by `sentrax/orchestrator.py`. Every agent takes JSON in and produces JSON out (shapes defined as pydantic models in `sentrax/utils/schema.py`) — this is what lets agents be tested in isolation against the fixtures in `fixtures/` before the whole pipeline exists.

Only two agents are LLM-driven: **Strategist** (decides what to test and why) and **Remediation** (suggests fixes). **Recon**, **Exploit**, and **Reporter** are deterministic code. This split is the central design invariant of the project:

- Recon and Exploit must never let an LLM decide "this is vulnerable" — `sentrax/agents/exploit.py` + `sentrax/vuln_rules/*.py` confirm findings by checking real response/request data against hardcoded rules (one file per vuln type: sqli, xss, idor, broken_auth). This is what makes a "confirmed" finding meaningful instead of an LLM guess. Treat this file as the most sensitive one in the repo — see `Docs/Agents.md` section 3 before touching it.
- SAST and DAST share the same Strategist/Exploit(rules)/Remediation/Reporter — only Recon and the exploit *execution* differ by mode (DAST sends real HTTP requests; SAST re-checks matched source lines).

### Current implementation status

Only **Recon** (`sentrax/agents/recon.py`) and the **CLI shell** (`sentrax/cli.py`) are implemented. `sentrax/orchestrator.py` and `sentrax/agents/strategist.py`, `exploit.py`, `remediation.py`, `reporter.py` do not exist yet — the CLI's `/scan` and `/scan-code` currently just print a placeholder line instead of invoking a real pipeline. `sentrax/vuln_rules/` is an empty package. Check `git log` / `Docs/implementation-plan.md` for the phase-based build order this project follows (Phase 0b–2 done; Phase 3+ outstanding) before assuming an agent exists.

### Recon Agent (`sentrax/agents/recon.py`)

- `scan_url()`: BFS crawl of a live target (same-host links only, depth-limited), extracts forms (action/method/fields) and candidate API endpoints via regex (`API_PATTERN`) from HTML, inline JS, and same-host external scripts. Raises `TargetUnreachableError` if the initial request fails.
- `scan_folder()`: walks a directory (skips `IGNORED_DIRS` like `.venv`/`node_modules`), regex-matches each source line against `SAST_RULES` (sqli concat, innerHTML/XSS, hardcoded secrets, missing-authz lookups).
- `run(target, mode)` dispatches to one of the above; output validates against `ReconURLResult`/`ReconFolderResult` in `utils/schema.py`.
- Fixtures in `fixtures/sample_recon_url.json` and `fixtures/sample_recon_folder.json` define the expected output shape — new Recon behavior should still validate against these schemas.

### Schema module (`sentrax/utils/schema.py`)

Single file defining the JSON contract for every agent boundary (Recon output, Strategist tasks, confirmed findings + evidence, remediation fixes, final report). When building a new agent, model its output as a pydantic class here first, matching the shape already documented in `Docs/Agents.md` — downstream agents and tests validate against these models.

### CLI (`sentrax/cli.py`)

`prompt_toolkit`-based interactive shell (not argument-driven — `sentrax` launches with no args into a prompt loop, per `Docs/CLI.md`). Commands are `/`-prefixed and parsed in `SentraXCLI.handle_command`; `COMMANDS_META` drives both the `/help` table and the live autocompletion dropdown (`get_command_completer`). When wiring real pipeline calls into `/scan`/`/scan-code` (replacing the current placeholders), follow the per-agent colored streaming output spec in `Docs/CLI.md` section 5 (`[RECON]` cyan, `[STRATEGIST]` yellow, `[EXPLOIT]` red, `[REMEDIATION]` magenta, `[REPORTER]` green) — this live "watching it think" output is treated as a core product feature, not incidental logging.

### Vuln target reference

`Docs/custom-target.md` documents the exact endpoints/payloads (`/api/login`, `/api/reviews`, `/api/order/<id>`) that the confirmation rules in `vuln_rules/` must be built against — use it instead of inventing payloads when implementing `confirm()` functions.

## Conventions

- Local-only targets: DAST targets are `localhost`, SAST targets are local folders — no code should be written assuming a remote/third-party target.
- Remediation only ever *suggests* fixes as text; nothing in this codebase should write/patch the scanned target's actual files.
- `reports/` holds generated Markdown scan output (gitignored except `.gitkeep`); `target/` is where a local practice app like VulnMart would run from, not tracked in this repo.
