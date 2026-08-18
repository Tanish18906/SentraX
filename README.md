# SentraX AI 🛡️

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-89%20passed-brightgreen.svg)]()
[![Architecture](https://img.shields.io/badge/architecture-5--Agent%20Pipeline-red.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Autonomous security testing, explained.**  
> SentraX AI is an autonomous multi-agent security testing CLI that finds, proves, explains, and fixes web application and source code vulnerabilities with deterministic evidence.

---

## 📑 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Supported Vulnerability Classes](#-supported-vulnerability-classes)
- [Quick Start & Setup Guide](#-quick-start--setup-guide)
  - [Prerequisites](#1-prerequisites)
  - [Installation](#2-installation)
  - [Environment Configuration](#3-environment-configuration)
  - [Starting the Practice Target (VulnMart)](#4-starting-the-practice-target-vulnmart)
- [Using SentraX CLI](#-using-sentrax-cli)
  - [Interactive Shell & Commands](#interactive-commands)
  - [Live Demo Mode (`--demo`)](#live-demo-mode---demo)
- [Scan Reports & Deliverables](#-scan-reports--deliverables)
- [Running Automated Tests](#-running-automated-tests)
- [Repository Structure](#-repository-structure)
- [License](#-license)

---

## 🧠 Overview & Architecture

Unlike traditional security scanners that generate noisy, unverified alerts or hallucinate vulnerabilities, SentraX uses a strict **5-Agent Autonomous Pipeline**. Every finding must be deterministically confirmed through real exploit simulation (DAST) or independent static verification (SAST) before reaching the report.

```
┌─────────────────┐     ┌───────────────────┐     ┌─────────────────┐     ┌───────────────────┐     ┌─────────────────┐
│   RECON AGENT   │ ──▶ │ STRATEGIST AGENT  │ ──▶ │  EXPLOIT AGENT  │ ──▶ │ REMEDIATION AGENT │ ──▶ │ REPORTER AGENT  │
└─────────────────┘     └───────────────────┘     └─────────────────┘     └───────────────────┘     └─────────────────┘
 [cyan][RECON][/cyan]        [yellow][STRATEGIST][/yellow]       [red][EXPLOIT][/red]           [magenta][REMEDIATION][/magenta]      [green][REPORTER][/green]
 Crawls forms, inputs    Constrained LLM      Executes payloads     Generates concrete       Renders terminal
 & API endpoints or      test planner for     & confirms exploits   secure code fixes        panels & exports
 walks source files      4 vuln classes       with real evidence    & developer rationale    Markdown reports
```

### The 5 Agents

1. **`[RECON]` Recon Agent (Track A)**: Maps the target's attack surface.
   - **DAST Mode**: Crawls pages, extracts HTML forms/inputs, and scans client-side JavaScript for hidden API endpoints.
   - **SAST Mode**: Recursively scans codebase files (JavaScript/Node.js, Python) for insecure pattern candidates.
2. **`[STRATEGIST]` Strategist Agent (Track B)**: Synthesizes recon data and generates a grounded test plan strictly constrained to supported vulnerability types.
3. **`[EXPLOIT]` Exploit Agent (Track B)**: The confirmation engine. Executes deterministic test probes against the live application or performs secondary code-level confirmation. If a test fails or is mitigated, it is ruled out.
4. **`[REMEDIATION]` Remediation Agent (Track A)**: Takes confirmed findings and generates actionable, syntax-highlighted fix suggestions (vulnerable vs. fixed code snippet and concise technical rationale).
5. **`[REPORTER]` Reporter Agent (Track A)**: Compiles results into beautiful terminal panels and exports publication-ready Markdown audit reports.

---

## 🎯 Supported Vulnerability Classes

SentraX currently covers four high-impact vulnerability classes across both live attack (DAST) and code review (SAST) vectors:

| Vulnerability Class | DAST Confirmation Rule | SAST Confirmation Rule |
|---|---|---|
| **SQL Injection (SQLi)** | Bypasses login authentication using `' OR 1=1--` payloads without credentials. | Identifies raw concatenation or template string interpolation into SQL queries without parameterization. |
| **Cross-Site Scripting (XSS)** | Injects unique `<script>` tags and verifies unescaped reflection in subsequent pages. | Detects unescaped user input interpolation into DOM sinks (`innerHTML`, template literals). |
| **Insecure Direct Object Reference (IDOR)** | Authenticates as User A and successfully retrieves private resources belonging to User B. | Flags direct database/model lookups by ID parameter lacking authorization or ownership checks. |
| **Broken Authentication** | Executes rapid authentication attempts to confirm lack of rate limiting or account lockout. | Verifies endpoint security policy. |

---

## 🚀 Quick Start & Setup Guide

Follow this guide to get SentraX running on any machine from scratch.

### 1. Prerequisites

- **Python**: `3.10` or higher (`python3 --version`)
- **Node.js**: `v18` or higher (required only to run the local practice target app) (`node -v`)
- **Git**: `git --version`

---

### 2. Installation

Clone the repository:
```bash
git clone https://github.com/Tanish18906/SentraX.git
cd SentraX
```

#### Option A: Global CLI Install via `pipx` (Recommended)
This gives you a seamless CLI experience (like `claude` or `gh`) available from any terminal without activating virtual environments.

1. Install `pipx` (if not already installed):
   ```bash
   # Debian / Ubuntu / WSL:
   sudo apt update && sudo apt install -y pipx
   pipx ensurepath

   # macOS (Homebrew):
   brew install pipx
   pipx ensurepath
   ```
   *(Restart your terminal once after running `pipx ensurepath`).*

2. Install SentraX globally in editable mode:
   ```bash
   pipx install -e .
   ```

#### Option B: Virtual Environment Install via `venv`
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

### 3. Environment Configuration

Copy the sample environment file:
```bash
cp .env.example .env
```

Open `.env` in your editor and configure your preferred LLM:

```env
# OpenAI Configuration (Default)
OPENAI_API_KEY=sk-your-openai-api-key-here
SENTRAX_LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini # or gpt-5.6-terra / gpt-4o

# Anthropic Configuration (Alternative)
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here
# SENTRAX_LLM_PROVIDER=anthropic
# LLM_MODEL=claude-3-5-sonnet-latest
```

> **Note:** If you don't have an API key right now, you can still run SentraX in **`--demo` mode** with zero setup!

---

### 4. Starting the Practice Target (VulnMart)

SentraX comes bundled with **VulnMart**, a deliberately vulnerable practice e-commerce store built to demonstrate all 4 vulnerability vectors.

In a separate terminal window:
```bash
cd target
npm install
npm start
```
VulnMart will start at **`http://localhost:4000`**.

#### Seed Test Accounts in VulnMart:
- **Alice**: `alice@vulnmart.test` / `alice123` (Order #1)
- **Bob**: `bob@vulnmart.test` / `bob123` (Order #2)

---

## 💻 Using SentraX CLI

Launch the interactive terminal shell:

```bash
sentrax
```

*(Or run `sentrax --demo` for offline demo mode).*

```
 ____             _              __  __
/ ___|  ___ _ __ | |_ _ __ __ _ \ \/ /
\___ \ / _ \ '_ \| __| '__/ _` | \  / 
 ___) |  __/ | | | |_| | | (_| | /  \ 
|____/ \___|_| |_|\__|_|  \__,_|/_/\_\ 

SentraX AI — autonomous security testing, explained.
Type /help for commands.

sentrax ▸ 
```

### Interactive Commands

Type `/` at the prompt to trigger the interactive autocompletion dropdown:

| Command | Description | Example |
|---|---|---|
| `/scan <url>` | Attack and test a live web application (DAST) | `/scan http://localhost:4000` |
| `/scan-code <folder>` | Audit local source code repository (SAST) | `/scan-code ./target` |
| `/report` | Re-display the most recent scan report panels | `/report` |
| `/status` | View target status and scan history metrics | `/status` |
| `/clear` | Clear terminal screen and re-render header | `/clear` |
| `/help` | Show list of available commands | `/help` |
| `/exit`, `/quit` | Exit the SentraX CLI session | `/exit` |

---

### Live Demo Mode (`--demo`)

When running in low-connectivity environments or during live presentations:

```bash
sentrax --demo
```

In demo mode:
- **Recon, Exploit (confirmation), and Reporter** remain **100% real** and execute live HTTP attacks against the target.
- **Strategist & Remediation** use grounded, cached reasoning to eliminate external API latency and costs.

---

## 📊 Scan Reports & Deliverables

Every scan produces two deliverables:

1. **Rich Terminal Display**: Styled panels highlighting confirmed findings, request/response proof, and code remediation snippets:
   ```
   ╭───────────────────────── #1. SQL Injection — [HIGH] ─────────────────────────╮
   │ Target: /api/login                                                           │
   │                                                                              │
   │ [ Evidence ]                                                                 │
   │ • Action: POST /api/login with email="' OR 1=1--" and password="anything"    │
   │ • Output: HTTP 200 OK: {"success": true, "token": "eyJhbGciOi..."}           │
   │ • Proof:  Authentication was successfully bypassed using SQL injection       │
   │           payload in email field without valid credentials.                  │
   │                                                                              │
   │ [ Suggested Fix ]                                                            │
   │ • Vulnerable: const query = `SELECT * FROM users WHERE email='${email}'`;    │
   │ • Fixed:      db.prepare("SELECT * FROM users WHERE email = ?").get(email)   │
   │ • Explanation: Use parameterized queries to prevent SQL syntax manipulation. │
   ╰──────────────────────────────────────────────────────────────────────────────╯
   ```

2. **Saved Markdown Artifact**: Saved to `reports/scan_YYYY-MM-DD_HHMMSS_microseconds.md` containing full executive summaries, structured tables, and developer remediation guides.

---

## 🧪 Running Automated Tests

SentraX includes a comprehensive unit and integration test suite (89 tests) covering all agents, error conditions, and end-to-end pipelines:

```bash
# Run the full test suite
pytest -v

# Run tests with output logging
pytest -v -s
```

```
============================== 89 passed in 1.85s ==============================
```

---

## 📁 Repository Structure

```
SentraX/
├── sentrax/                      # Core SentraX Python Package
│   ├── cli.py                    # Interactive terminal shell with prompt_toolkit & rich
│   ├── orchestrator.py           # 5-Agent sequential pipeline coordinator
│   ├── agents/                   # Autonomous Agents
│   │   ├── recon.py              # Recon Agent (DAST web crawler & SAST code scanner)
│   │   ├── strategist.py         # Strategist Agent (LLM test planner)
│   │   ├── exploit.py            # Exploit Agent (Deterministic exploit dispatcher)
│   │   ├── remediation.py        # Remediation Agent (LLM & fallback fix generator)
│   │   └── reporter.py           # Reporter Agent (Terminal panels & Markdown exporter)
│   ├── vuln_rules/               # Deterministic Confirmation Rules
│   │   ├── sqli.py               # SQL Injection confirmation engine
│   │   ├── xss.py                # Stored XSS confirmation engine
│   │   ├── idor.py               # IDOR cross-user access confirmation engine
│   │   └── broken_auth.py        # Rate limiting & auth confirmation engine
│   └── utils/
│       ├── llm_client.py         # Shared resilient LLM client wrapper (OpenAI/Claude)
│       ├── demo_agents.py        # Offline safety-net demo agents
│       └── schema.py             # Shared Pydantic data models across agent boundaries
│
├── target/                       # Practice Target Application (VulnMart)
│   ├── server.js                 # Express server with planted vulnerabilities
│   ├── database.js               # In-memory SQLite seed database
│   ├── test-verify.js            # Independent exploit verification script
│   └── public/                   # Frontend assets
│
├── tests/                        # Full Test Suite (89 tests)
│   ├── test_cli.py
│   ├── test_orchestrator.py
│   ├── test_recon.py
│   ├── test_strategist.py
│   ├── test_exploit.py
│   ├── test_remediation.py
│   ├── test_reporter.py
│   ├── test_vuln_rules.py
│   └── test_llm_client.py
│
├── reports/                      # Generated Scan Report Deliverables
├── pyproject.toml                # Package configuration & console scripts
├── requirements.txt              # Production & development dependencies
└── README.md                     # Documentation
```

---

## ⚖️ License

This project is licensed under the [MIT License](LICENSE).
