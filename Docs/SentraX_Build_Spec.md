# SentraX AI — Master Build Spec
### Solo build with vibe coding (Antigravity / Codex) — 2-day timeline

This is the index doc. Full detail lives in several companion docs — read them in this order, and feed them to your coding tool **one phase at a time**, not all at once. Dumping the whole spec in one prompt is how you get a plausible-looking pile of code nobody (including you) can debug on demo day.

---

## The four companion docs

1. **`architecture.md`** — the system design: how the two modes work, how the 5 agents pass data to each other, folder structure, tech stack, key decisions. Read this first, always, before prompting any code.

2. **`Agents.md`** — exact spec for each of the 5 agents: what goes in, what comes out, what's LLM-driven vs. deterministic, and (critically) the exact confirmation rules for the Exploit Agent per vulnerability type. This is your source of truth when reviewing AI-generated agent code.

3. **`CLI.md`** — exact spec for the terminal shell: banner, prompt loop, `/` commands, visual style, example transcript. Hand this to your coding tool when building the interactive CLI layer.

4. **`implementation-plan.md`** — the actual build order, broken into phases with a definition of done for each. This is what you feed your coding tool phase by phase. Do not let it jump ahead to Phase 5 while Phase 2 is still shaky — a working Phase 2 you understand beats a "finished" Phase 8 you don't.

---

## How to work with a coding agent on this, solo

- **One phase, one prompt, one review.** Finish and manually test a phase before moving to the next. Vibe coding fails hardest when errors compound silently across many features built in one shot.
- **You personally must understand two things line-by-line, no exceptions:** the Exploit Agent's confirmation logic per vuln type, and the Strategist Agent's prompt/reasoning flow. These are the two places a judge will probe, and "the AI wrote it, I'm not sure exactly how it works" is the answer that loses you the room.
- **Test every agent standalone before wiring them together.** Each agent's I/O is a JSON object — you can run any single agent against a hand-written sample JSON input and eyeball whether the output makes sense, without the rest of the pipeline existing yet.
- **Budget real time for Phase "Demo Rehearsal"** at the end (see implementation-plan.md) — a pipeline that works when you're debugging calmly is not the same as a pipeline that works live, on a timer, in front of judges.

---

## Target: a custom-built vulnerable practice app, not Juice Shop

The target is **VulnMart** — a small deliberately-vulnerable app built to your own spec, not OWASP Juice Shop. Building your own means every bug's exact location and behavior is known in advance, instead of having to reverse-engineer someone else's app by hand.

5. **`custom-target-build-prompt.md`** — the actual build spec, meant to be handed to a coding agent (yours, or a friend's) to build VulnMart: 3 pages, 4 deliberate bugs, seed data. This is a standalone, one-shot build — small enough not to need phasing.

6. **`custom-target.md`** — the ground truth: exact endpoints, payloads, and confirmation criteria for all 4 vulnerabilities, matched precisely to what's specified in `custom-target-build-prompt.md`. This is what Exploit Agent's `confirm()` functions get built against.

7. **`fixtures/`** — three ready-to-use sample JSON files (`sample_recon_url.json`, `sample_recon_folder.json`, `sample_confirmed_finding.json`) matching the schemas in `Agents.md`. These let both coding agents build and test their agents standalone from minute one, without waiting on each other or on VulnMart being finished.

## The build is now split across two coding agents

`implementation-plan.md` has been restructured into **Track A (Antigravity)** and **Track B (Claude Code)** — each agent should read only its own track and build only those phases. See that doc for the full split, dependency map, and day-by-day timeline. One phase (Phase 0a) and one phase (Phase 10) are human-only, not for either agent. Phase 0a now starts with handing `custom-target-build-prompt.md` to whoever's building VulnMart.

## What's still genuinely optional / can wait

- `requirements.txt` — falls out naturally once Phase 0b starts (Track A)
- Judge Q&A prep sheet and the PPT itself — explicitly deferred, come back to these after the build
