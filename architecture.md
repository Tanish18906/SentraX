# SentraX AI — Architecture

Read this before prompting any code. Everything else (Agents.md, CLI.md, implementation-plan.md) assumes the shape defined here.

---

## 1. System summary

SentraX is a CLI tool, launched with `sentrax`, that runs a 5-agent pipeline against either a **live local target** (a running web app/API) or a **local code folder**. It finds real, proven vulnerabilities (not guesses), suggests concrete fixes, and produces a clean report — all running locally, no cloud infra dependency beyond LLM API calls.

Two modes, one pipeline:

- **DAST mode** (`/scan <url>`) — attacks a running app over HTTP
- **SAST mode** (`/scan-code <folder>`) — reads source files for vulnerable patterns

Both modes flow through the same 5 agents; only Recon and Exploit behave differently depending on mode. Strategist, Remediation, and Reporter are mode-agnostic — they just work with whatever structured data they're handed.

---

## 2. The 5-agent pipeline

```
┌──────────┐    ┌────────────┐    ┌─────────┐    ┌──────────────┐    ┌──────────┐
│  RECON   │───▶│ STRATEGIST │───▶│ EXPLOIT │───▶│ REMEDIATION  │───▶│ REPORTER │
│  Agent   │    │   Agent    │    │  Agent  │    │    Agent     │    │  Agent   │
└──────────┘    └────────────┘    └─────────┘    └──────────────┘    └──────────┘
 maps target      plans what to    proves it      suggests the        formats final
 (URL or folder)  test & why       actually        fix for each        output
                  (LLM reasoning)  works            confirmed          (terminal +
                                   (deterministic   finding            saved file)
                                   confirmation)    (LLM)
```

**Data contract between agents:** every agent takes JSON in, produces JSON out. This is what lets you test each one standalone (see implementation-plan.md Phase 0) and is also why the two operating modes can share the same pipeline — Strategist/Remediation/Reporter don't care whether the JSON came from a URL crawl or a folder scan, they just process the shape they're given.

Full input/output schema and internal logic for each agent lives in **Agents.md**. This doc only covers how they fit together.

---

## 3. Key design decisions (and why)

- **LLM reasoning is confined to Strategist and Remediation.** Recon (data collection) and Exploit (confirmation) are deterministic code. This is the single most important architectural decision in the project — it's what makes "confirmed" mean something. If you're ever tempted to let an LLM decide whether an exploit worked, don't — that's the exact gap between SentraX and a chatbot wrapper.
- **Local-only, no third-party targets.** Every scan target is either `localhost` (live app you're running) or a local folder (code you own). No exceptions. This isn't just a legal requirement — it's what makes demo behavior 100% reproducible.
- **JSON at every boundary.** Not because it's fancy, but because it lets you build and test agents in isolation with sample fixtures, in parallel, without the full pipeline existing yet.
- **Streaming/live terminal output, not silent processing.** The visual "watching it think" feel is a deliberate product decision, not just aesthetics — it's what makes the multi-agent architecture visible and legible to a judge in 90 seconds. See CLI.md.
- **SAST mode reuses the same downstream agents as DAST.** Don't build a second Strategist/Remediation/Reporter for code-scan mode — Recon and Exploit are the only mode-specific pieces. Keeping this shared is what makes SAST mode "cheap" to add on top of DAST, scope-wise.

---

## 4. Repo / folder structure

```
sentrax/
├── pyproject.toml              # console-script entry point: sentrax -> cli.main
├── requirements.txt
├── .env.example                 # LLM API key placeholder
├── sentrax/
│   ├── __init__.py
│   ├── cli.py                   # banner, prompt loop, command parsing (see CLI.md)
│   ├── orchestrator.py          # runs the 5-agent pipeline in sequence
│   ├── agents/
│   │   ├── recon.py             # both URL-crawl and folder-walk modes
│   │   ├── strategist.py        # LLM reasoning -> prioritized task list
│   │   ├── exploit.py           # deterministic confirmation logic per vuln type
│   │   ├── remediation.py       # LLM fix suggestions for confirmed findings
│   │   └── reporter.py          # terminal + saved-file output formatting
│   ├── vuln_rules/
│   │   ├── sqli.py              # confirmation rule + payloads
│   │   ├── xss.py
│   │   ├── idor.py
│   │   └── broken_auth.py
│   └── utils/
│       ├── llm_client.py        # wraps the LLM API call, used by strategist + remediation
│       └── schema.py            # shared JSON shape validators/dataclasses
├── fixtures/                     # sample JSON for standalone agent testing
│   ├── sample_recon_url.json
│   ├── sample_recon_folder.json
│   └── sample_confirmed_finding.json
├── target/                       # VulnMart (or any local test target) lives/runs separately, not in this repo
└── reports/                       # generated Markdown reports land here
```

Keep `vuln_rules/` separate from `agents/exploit.py` — one file per vuln type makes the confirmation logic easy to review individually (this maps directly to Agents.md section 3) and easy to extend later without touching the orchestration code.

---

## 5. Tech stack

| Piece | Choice | Why |
|---|---|---|
| Language | Python | Fastest path for both HTTP requests and LLM API calls; huge reference material for vibe coding |
| CLI/terminal UI | `rich` | Colored panels, spinners, live-updating regions, streaming text — does the visual work with minimal code |
| HTTP client | `requests` or `httpx` | For DAST mode — sending real requests to the target |
| HTML parsing | `BeautifulSoup` | For Recon Agent's crawl (parsing forms/links out of pages) |
| LLM | OpenAI or Claude API | Powers Strategist's reasoning and Remediation's fix suggestions only |
| Target app | VulnMart (custom-built) | Small deliberately-vulnerable practice app, built to spec so every bug's exact location and behavior is known in advance — see `custom-target.md` |
| Packaging | `pyproject.toml` console_scripts | Makes `sentrax` a real installed command, not "run this python file" |

---

## 6. What's explicitly out of scope for the demo build

Keep this list visible — it's your guardrail against scope creep mid-build:

- Live monitoring/alerting ("Sentinel"-style defense mode) — future roadmap only
- Auto-patching/auto-editing the target's actual code — Remediation Agent *suggests* fixes, never applies them
- Any vuln class beyond SQLi, XSS, IDOR, broken auth
- Any target other than your local VulnMart instance / your own local folder
- Dynamic/spawning multi-agent orchestration — the pipeline is a fixed 5-step sequence, not agents freely creating sub-agents
