# SentraX AI — Project Overview
### Project Expo 2026 | Domain: Artificial Intelligence | SSIPMT Raipur

---

## 1. One-line pitch

**SentraX is an autonomous multi-agent AI system that attacks, finds, proves, and fixes security vulnerabilities in web apps and APIs — explaining every step in plain language, like a full security team compressed into a CLI tool.**

Positioning line: *"Strix validates vulnerabilities for security teams. SentraX explains them — built so any student, freelancer, or small team without a security budget can understand, learn from, and fix what it finds."*

---

## 2. The problem

- Real penetration testing is expensive and requires expertise most small teams, startups, and student developers don't have in-house.
- Traditional vulnerability scanners are fast but dumb — they flag "possible issues" with high false-positive rates, spitting out noise instead of proof.
- Manual human pentesting is thorough but slow, unscalable, and out of reach for anyone without a security budget.
- Most small dev teams in India (and elsewhere) ship code with zero security testing — not because they don't care, but because nothing accessible exists for them.

---

## 3. What SentraX does

SentraX is a **CLI tool** (`sentrax`) — launch it like Claude Code's terminal (`sentrax` → banner → interactive prompt) and either:

- Point it at a **running app/URL** → it attacks it live, finds real vulnerabilities, proves they're exploitable (not just "possibly vulnerable"), and reports them with evidence.
- Point it at a **local code folder** → it reads the source code and flags vulnerable patterns before the app is even running — catching bugs pre-deployment.

For every confirmed vulnerability, it also generates a **concrete fix recommendation** — the exact vulnerable line and the corrected version, explained in plain language.

This covers the full lifecycle: **Attack → Find → Fix → Report.**

---

## 4. The multi-agent architecture (core technical differentiator)

Five specialized AI agents, each with a distinct job, passing structured findings to the next:

| Agent | Job |
|---|---|
| **Recon Agent** | Maps the attack surface — crawls a live target (URLs, forms, API endpoints) *or* scans a local folder (files, language, structure) |
| **Strategist Agent** | The reasoning core. Decides what to test, where, and why, based on what Recon found. Prioritizes likely vulnerabilities instead of blindly trying everything. |
| **Exploit Agent** | Executes each planned test and **deterministically confirms** whether it actually worked — checking real output (extra database rows returned, script executed, another user's data leaked), never just trusting a guess. For code-scan mode, confirms a flagged pattern is a genuine risk, not a false positive. |
| **Remediation Agent** | For every *confirmed* finding, generates the exact fix — vulnerable snippet, corrected version, one-line reasoning. |
| **Reporter Agent** | Compiles everything into a clean, evidence-backed final report — the deliverable a human can act on. |

**Why this matters as a differentiator:** most AI security tools (including parts of what inspired this project) show you a final report and hide the reasoning. SentraX narrates *why* each agent does what it does, live, in the terminal — a transparency-first design, not just an efficiency-first one.

---

## 5. What it actually detects (demo scope)

Matched to the OWASP Top 10 — the industry-standard vocabulary for web vulnerabilities:

1. **SQL Injection (SQLi)** — malicious input tricks the database into running unintended commands
2. **Cross-Site Scripting (XSS)** — unescaped input lets an attacker's script run in another user's browser
3. **IDOR (Insecure Direct Object Reference)** — changing an ID in a URL exposes another user's private data
4. **Broken Authentication** — weak/missing protections like no login rate-limiting

*(Broader scope — network, infrastructure, mobile apps — is future roadmap, not part of the live demo.)*

---

## 6. Two operating modes

- **`/scan <url>`** — Live attack mode (DAST). Runs against a real, running app. Used against an intentionally-vulnerable practice app (industry-standard test target — same category app used to train and demo security tools worldwide) running locally.
- **`/scan-code <folder>`** — Source code mode (SAST). Reads code directly, flags vulnerable patterns (e.g. raw SQL string concatenation, unescaped output) with exact file + line number — before the app ever runs.

This dual-mode design mirrors a real, respected industry practice: **"shift-left security"** — catching vulnerabilities during development, not just after deployment.

---

## 7. Legal/safety framing (important — judges may ask)

SentraX only ever tests targets the operator owns or runs locally — never third-party live websites without authorization. This isn't a limitation, it's the actual product design: SentraX is built to run in your own local dev environment or CI pipeline, testing your own code before it ships. Zero legal ambiguity, zero deployment dependency, works entirely offline/on-machine.

---

## 8. Why SentraX, not just "a smaller version of an existing tool"

- **Transparency-first**: shows its reasoning live, including when it *rules something out* ("checked for stored XSS on comment field — ruled out, input is properly escaped") — signals judgment, not brute-force guessing.
- **Built for accessibility**: designed to run cheap and local, for the segment that currently gets zero security testing — students, freelancers, small dev teams — not enterprise security budgets.
- **Attack + Fix, not just Attack**: goes beyond validation into concrete, actionable remediation.
- **Pre-deployment first**: source-code scanning catches issues before an app ever goes live, not just after.

---

## 9. Tech stack (for the "how it's built" slide)

- Python backend orchestrating the 5-agent pipeline
- LLM (via API) powering the Strategist Agent's reasoning and Remediation Agent's fix generation
- `rich`-style terminal UI: colored per-agent output, streaming text, live panels — styled after modern agentic CLI tools
- Deterministic exploit-confirmation logic (not LLM-guessed) for every reported finding
- Runs entirely locally — no cloud infra dependency for the demo

---

## 10. Demo flow (for the "live demo" slide/section)

1. Open terminal, type `sentrax` → banner screen
2. `/scan-code <folder>` → SentraX reads source, flags a vulnerable pattern with file/line number, suggests a fix
3. `/scan <local-target-url>` → live multi-agent run: Recon maps the app → Strategist plans tests → Exploit Agent proves a real SQLi/XSS/IDOR/auth issue live on screen → Remediation Agent shows the fix
4. Final report screen — clean, evidence-backed summary

---

## 11. Team credibility note

Team has prior experience building real-time security systems — including a previously built DDoS detection and mitigation control plane — relevant background for this domain.

---

## 12. Suggested slide structure (10-slide cap)

1. Title + one-line pitch
2. The problem (security testing is expensive/inaccessible)
3. What SentraX does (attack → find → fix → report)
4. Multi-agent architecture diagram (5 agents)
5. What it detects (vuln categories, OWASP-aligned)
6. Two modes: live attack (DAST) vs code scan (SAST)
7. Differentiation (why not just "a smaller existing tool")
8. Legal/safety design (local-only, shift-left)
9. Tech stack + architecture visual
10. Live demo + closing/roadmap (future: monitoring, broader scope)
