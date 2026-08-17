# Kickoff Prompts — Track A (Antigravity) and Track B (Claude Code)

Two separate prompts below. Copy each one whole into the respective tool. Don't mix them — Antigravity gets only the Track A prompt, Claude Code gets only the Track B prompt.

**Before sending either:** confirm Context7 MCP and Sequential Thinking MCP are actually connected/available in that tool. If a tool doesn't have MCP support or these servers aren't configured, it'll either error on the instruction or silently ignore it — check first rather than finding out mid-build.

---

## PROMPT FOR ANTIGRAVITY (Track A)

```
You are building Track A of a project called SentraX AI. Read these files
first, in this order, before writing any code:

1. architecture.md
2. Agents.md
3. CLI.md
4. implementation-plan.md

In implementation-plan.md, you own TRACK A ONLY: Phase 0b, Phase 1,
Phase 2, Phase 5, Phase 6, in that exact order. Do not attempt Track B
phases (3, 4, 7, 8, 9) under any circumstances, even if they look
related or you think you could help — that work belongs to a different
agent working in parallel with you, and touching it will cause conflicts.

Two hard rules for how you work:

1. BUILD ONE PHASE AT A TIME. Finish a phase completely, check it against
   its "Definition of done" in implementation-plan.md, and STOP. Do not
   continue to the next phase automatically. Report back what you built,
   what you tested, and wait for confirmation before starting the next
   phase. Do not batch multiple phases into one pass.

2. USE YOUR TOOLS THROUGHOUT:
   - Use Context7 MCP whenever you need current documentation for a
     library or API you're using (rich, requests, BeautifulSoup, the
     LLM SDK, etc.) — don't rely on memory for library APIs, pull the
     real current docs.
   - Use Sequential Thinking MCP for any non-trivial design decision
     within a phase (e.g. how to structure the crawler, how to shape
     the CLI's command parser) — think through the approach step by
     step before writing code, not after something breaks.

Start now with Phase 0b. Read the phase, confirm you understand the
definition of done, then build it. Stop after Phase 0b and report back.
```

---

## PROMPT FOR CLAUDE CODE (Track B)

```
You are building Track B of a project called SentraX AI. Read these
files first, in this order, before writing any code:

1. architecture.md
2. Agents.md
3. CLI.md
4. custom-target.md
5. implementation-plan.md

In implementation-plan.md, you own TRACK B ONLY: Phase 3, Phase 4,
Phase 7, Phase 8, Phase 9, in that exact order. Do not attempt Track A
phases (0b, 1, 2, 5, 6) under any circumstances — that work belongs to
a different agent working in parallel with you.

Two hard rules for how you work:

1. BUILD ONE PHASE AT A TIME. Finish a phase completely, check it
   against its "Definition of done" in implementation-plan.md, and
   STOP. Do not continue to the next phase automatically. Report back
   what you built, what you tested, and wait for confirmation before
   starting the next phase. Do not batch multiple phases into one pass.

2. USE YOUR TOOLS THROUGHOUT:
   - Use Context7 MCP whenever you need current documentation for a
     library or API you're using — don't rely on memory for library
     APIs, pull the real current docs.
   - Use Sequential Thinking MCP for every non-trivial design decision,
     and treat this as MANDATORY, not optional, for Phase 4 specifically
     (the Exploit Agent's confirm() logic) — this is the single most
     important file in the project. Before writing any confirm()
     function, think step by step through: what does a real confirmed
     response look like, what does a real non-vulnerable response look
     like, and how do you tell them apart programmatically. Do not
     write confirmation logic without working through this reasoning
     first.

IMPORTANT BLOCKER: Phase 4 requires a real running target (VulnMart) to
test against. Do NOT start Phase 4 until explicitly told the target is
ready — even if you finish Phase 3 early, stop and wait rather than
guessing at Phase 4 without a real target to verify against.

Start now with Phase 3. Read the phase, confirm you understand the
definition of done, then build it against fixtures/sample_recon_url.json
and fixtures/sample_recon_folder.json. Stop after Phase 3 and report
back.
```

---

## A note on phase-by-phase discipline

Both prompts tell the agent to stop after each phase and wait for you. In practice, keep enforcing this yourself too — when a phase finishes, actually look at what got built (or at least skim the report-back) before replying "continue to next phase." The whole point of phasing this build was to catch problems early and cheap instead of late and expensive; that only works if a human is actually checking in between, not just rubber-stamping "next" repeatedly.
