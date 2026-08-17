# SentraX AI — Implementation Plan (Two-Agent Split)

Two coding agents build this in parallel: **Antigravity** and **Claude Code**. Each owns a separate track. Both must read `architecture.md`, `Agents.md`, and `CLI.md` first regardless of track — this doc only covers build order and ownership.

---

## ⚠️ READ THIS FIRST — which track are you

**If you are Antigravity: you own Track A only.** Build the phases listed under Track A below, in order. Do not touch Track B files or attempt Track B phases, even if they look related or you think you could do them — stop at the edge of your track and hand back control.

**If you are Claude Code: you own Track B only.** Build the phases listed under Track B below, in order. Do not touch Track A files or attempt Track A phases.

**If you are a human (Tanish):** two phases are yours alone, not either agent's — marked "HUMAN ONLY" below. No coding agent should attempt these.

Fixture files already exist at `fixtures/sample_recon_url.json`, `fixtures/sample_recon_folder.json`, and `fixtures/sample_confirmed_finding.json` — both tracks can build and test against these from minute one, without waiting on the other track to finish anything real. This is what makes true parallel work possible.

---

## Why the split is done this way

- **Track B (Claude Code)** gets the correctness-critical, reasoning-heavy, integration-heavy work: the Strategist's prompt logic, the Exploit Agent's confirmation rules (the single most important file in the project), and the two points where everything gets wired together.
- **Track A (Antigravity)** gets self-contained, mechanical, clear input→output work: data collection, templated LLM calls, formatting, and CLI scaffolding. Easy to test in isolation, hard to get subtly wrong.
- The two tracks only truly need each other at two merge points (Phase 7 and Phase 8, both Track B) — everything before that can run in parallel using the provided fixtures.

---

## HUMAN ONLY — Phase 0a: Ground truth (do this before either agent starts)

**Owner: Tanish, not a coding agent.**

- [ ] Hand `custom-target-build-prompt.md` to your friend (or their coding agent) to build the VulnMart practice app
- [ ] Get VulnMart running locally (`npm install && npm start`, `http://localhost:4000`)
- [ ] Manually reproduce each of the 4 exploits in `custom-target.md` by hand (browser or Postman/curl) — confirm they behave as specified. Since you defined these bugs yourselves, this should be a quick confirm, not a hunt — if something doesn't match, update `custom-target.md` to reflect what was actually built rather than what was originally specified.
- [ ] Get an LLM API key (OpenAI or Claude) and confirm it works with a trivial test call

**Definition of done:** you have a running VulnMart, a working API key, and you've personally seen all 4 exploits work by hand.

Only after this is done should either agent start Phase 0b / Phase 1 or 3.

---

## TRACK A — Antigravity

### Phase 0b — Repo scaffold
- [ ] Create the folder structure exactly as laid out in `architecture.md` section 4
- [ ] `pyproject.toml` with the `sentrax` console-script entry point (`sentrax = "sentrax.cli:main"`)
- [ ] `requirements.txt` / dependency list (rich, requests, beautifulsoup4, playwright if needed, openai or anthropic SDK)
- [ ] `.env.example` with an LLM API key placeholder
- [ ] Confirm `pip install -e .` + typing `sentrax` launches *something* (even a bare print statement) before anything else gets built on top

**Definition of done:** `sentrax` runs and prints something, folder structure matches architecture.md exactly.

---

### Phase 1 — CLI shell skeleton (no real agents yet)
Reference: `CLI.md` sections 2-4, 6.

- [ ] Banner display on launch (`CLI.md` section 2)
- [ ] Prompt loop reading input, parsing `/` commands
- [ ] `/help`, `/clear`, `/exit` fully working
- [ ] `/scan <url>` and `/scan-code <folder>` recognized and parsed correctly (extract the argument) but just print a placeholder — "would run scan on `<target>`" — no real pipeline call yet
- [ ] Error handling for unrecognized commands and Ctrl+C, per `CLI.md` section 6

**Definition of done:** every command runs, gives sensible output, exits cleanly — zero real agent logic behind it.

---

### Phase 2 — Recon Agent, both modes
Reference: `Agents.md` section 1.

- [ ] Build DAST-mode Recon (crawl a URL, extract forms/endpoints) — test directly against the real running VulnMart instance
- [ ] Build SAST-mode Recon (walk a folder, regex pattern-match) — test against a small sample folder
- [ ] Output should match the shape already in `fixtures/sample_recon_url.json` and `fixtures/sample_recon_folder.json` — compare your real output against these fixtures to sanity-check the shape is right

**Definition of done:** running Recon standalone against the real VulnMart instance produces JSON listing real forms/endpoints that actually match what's on the page.

---

### Phase 5 — Remediation Agent
Reference: `Agents.md` section 4.

- [ ] Build the LLM call: takes a confirmed finding, returns `{finding_id, original_snippet, fixed_snippet, explanation}`
- [ ] Test against `fixtures/sample_confirmed_finding.json` — you do not need to wait for Track B's real Exploit Agent, this fixture already has 4 realistic findings covering all 4 vuln types plus one SAST-mode example
- [ ] Check: for the SAST-mode fixture finding (f4), is the suggested fix specific/exact? For DAST-mode findings, is it appropriately general rather than a fabricated fake code snippet?

**Definition of done:** running against the fixture file produces 4 fix suggestions that read like something a competent developer would write.

---

### Phase 6 — Reporter Agent
Reference: `Agents.md` section 5.

- [ ] Build the `rich`-formatted terminal display (table/panels per finding)
- [ ] Build the Markdown file export to `reports/`
- [ ] Test against `fixtures/sample_confirmed_finding.json` combined with your Phase 5 remediation output — no need for the real pipeline

**Definition of done:** the printed report and saved file both look like a real deliverable, not a debug dump.

---

**Track A is done once Phases 0b, 1, 2, 5, 6 are all individually complete and tested against fixtures/the real VulnMart instance.** Hand off to the merge point (Phase 8) once Track B reaches it.

---

## TRACK B — Claude Code

### Phase 3 — Strategist Agent
Reference: `Agents.md` section 2.

- [ ] Write the reasoning prompt per `Agents.md` section 2's guidance — must only ever propose the 4 supported vuln types (sqli, xss, idor, broken_auth), constrain this explicitly in the prompt
- [ ] Test against `fixtures/sample_recon_url.json` and `fixtures/sample_recon_folder.json` — no need to wait for Track A's real Recon Agent, these fixtures are ready now
- [ ] Manually review every output: does every task map to a supported vuln type? Is the `reasoning` field grounded in the actual fixture input, not generic filler?

**Definition of done:** you've personally read the output and can say "yes, a human pentester might produce this task list" — not just "it ran without erroring."

---

### Phase 4 — Exploit Agent (the critical phase — budget the most time here)
Reference: `Agents.md` section 3, `custom-target.md` in full.

- [ ] Build `vuln_rules/sqli.py`, `xss.py`, `idor.py`, `broken_auth.py` — implement `confirm()` for each using the exact endpoints/payloads in `custom-target.md`, test each against the real running VulnMart instance
- [ ] Build `agents/exploit.py` to dispatch a Strategist task to the right rule file, execute the real request, call `confirm()`, package the result matching the shape in `fixtures/sample_confirmed_finding.json`
- [ ] **Deliberately test the negative case for each vuln type** — run against input that should NOT confirm (correctly-escaped input, requesting your own order ID, a correct password) and verify it correctly reports not-confirmed. A rule that always says "confirmed" is worse than useless.
- [ ] Cross-check your real output shape against `fixtures/sample_confirmed_finding.json` — they should match structurally

**Definition of done:** pointed at the real VulnMart instance, this independently confirms all 4 vulnerabilities documented in `custom-target.md` — and does not falsely confirm non-vulnerable behavior. This is the single most scrutinized file in the whole project — do not rush it, do not move on until it's solid.

---

### Phase 7 — Orchestration: wire the 5 agents together (merge point)
**This phase needs Track A's real Phase 2 (Recon), Phase 5 (Remediation), and Phase 6 (Reporter) to actually be finished — not just fixtures.** Confirm Track A has reached that point before starting this phase.

- [ ] Build `orchestrator.py`: Recon → Strategist → Exploit → Remediation → Reporter, in sequence, each agent's real output feeding the next
- [ ] Run end-to-end against the real VulnMart instance for DAST mode, and a real folder for SAST mode
- [ ] Fix shape mismatches at the seams — normal when independently-built agents get chained for the first time

**Definition of done:** running the orchestrator directly (no CLI) produces a real, correct final report from a cold start, both modes.

---

### Phase 8 — CLI integration (merge point)
**This phase needs Track A's real Phase 1 (CLI shell) finished.** Confirm before starting.
Reference: `CLI.md` in full.

- [ ] Replace Track A's Phase 1 placeholder scan behavior with real calls into your Phase 7 orchestrator
- [ ] Add the per-agent colored/labeled streaming output per `CLI.md` section 5 as each pipeline stage runs
- [ ] Add spinners/status indicators during slow steps (LLM calls, HTTP requests)
- [ ] Test the full `sentrax` → banner → `/scan <url>` → live output → report flow, start to finish

**Definition of done:** someone who's never seen the code can type `sentrax`, run `/scan`, and follow what's happening without narration.

---

### Phase 9 — Polish & demo safety net
- [ ] Error-handling pass — deliberately try to break it (wrong URL, wrong folder, Ctrl+C mid-scan), confirm graceful failure every time, per `CLI.md` section 6
- [ ] Consider the `--demo` safety-net mode from `CLI.md` section 7 if live LLM latency is a real risk
- [ ] Run the full flow 3-5 times back to back, confirm consistent behavior every time
- [ ] Clean up stray debug prints, TODOs, placeholder text

**Definition of done:** the exact demo sequence runs successfully at least 3 times in a row with no manual fixes in between.

---

## HUMAN ONLY — Phase 10: Demo rehearsal

**Owner: Tanish (and teammates), not a coding agent.**

- [ ] Practice narrating the run out loud while it plays
- [ ] Time a full `/scan` run so there are no surprises on stage
- [ ] Record a backup screen capture of a successful run in case of live failure (wifi, projector, etc.)
- [ ] Make sure at least one teammate besides you can explain the Exploit Agent's confirmation logic if pulled aside by a judge

**Definition of done:** you could run this cold, in front of strangers, without touching the keyboard nervously.

---

## Dependency map (who waits for whom)

```
Phase 0a (Human)  ─┬──────────────────────────────────────────┐
                    │                                          │
              TRACK A starts                              TRACK B starts
              (Antigravity)                                (Claude Code)
                    │                                          │
       Phase 0b → Phase 1 → Phase 2                Phase 3 → Phase 4
              → Phase 5 → Phase 6                   (both against fixtures,
        (against fixtures, no wait)                  no wait on Track A)
                    │                                          │
                    └──────────────┬───────────────────────────┘
                                    │
                         Phase 7 (Track B, needs Track A's
                         real Phase 2/5/6 done for real)
                                    │
                         Phase 8 (Track B, needs Track A's
                         real Phase 1 done for real)
                                    │
                         Phase 9 (Track B)
                                    │
                         Phase 10 (Human)
```

**In plain terms:** both tracks can start immediately after Phase 0a and work fully in parallel using the pre-built fixtures — nobody sits idle waiting. The only real waiting happens at Phase 7 and Phase 8, where Track B needs Track A's actual finished work, not just fixtures, to do the final wiring.

---

## Rough day-by-day mapping

| | Track A (Antigravity) | Track B (Claude Code) |
|---|---|---|
| **Day 1 morning** | Phase 0b, Phase 1 | Phase 3 |
| **Day 1 afternoon** | Phase 2 | Phase 4 (start — this runs long) |
| **Day 1 evening** | Phase 5, Phase 6 | Phase 4 (continue — most time here) |
| **Day 2 morning** | *(Track A done — available to help debug)* | Phase 7 |
| **Day 2 afternoon** | *(available to help debug)* | Phase 8 |
| **Day 2 evening** | Phase 10 (human, both) | Phase 9, then Phase 10 (human, both) |
