# SBOMix

Behavioral guidelines for Claude when working in this repo. Based on the gstack template.

## Project

SBOMix is a Node.js SBOM platform: a CLI that generates CycloneDX/SPDX SBOMs from lock files and GitHub repos, plus a hosted API (Express + Postgres) with billing, vuln enrichment, AI-BOM detection, and a dashboard.

Key paths:
- `src/` — core pipeline, parsers, generators, GitHub integration, KEV sync
- `src/api/` — Express API: routes, middleware, services, repositories
- `src/api/schema.sql` — canonical DB schema (migrations live in `deploy/`)
- `bin/` — CLI entrypoints
- `tests/` — Node built-in test runner
- `deploy/` — database migration scripts (`migrate_NNN_*.sql`)

**Security constraint:** Never store GitHub tokens in the database. The token is passed in memory only.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

## 5. Harness

```bash
npm test              # Node built-in test runner (tests/*.test.js)
npm run test:parsers  # Parser-only subset
npm run lint          # ESLint over src/ and bin/
```

No TypeScript — plain JS throughout. "Done" for API changes means:
1. `npm test` passes
2. `npm run lint` passes (zero errors)
3. The API container starts cleanly after `docker compose up -d --build api`
4. The specific endpoint returns the expected response

For schema changes, add a `deploy/migrate_NNN_*.sql` and apply it to the database.

## 6. Loops & Autonomy

Sections 4 and 5 define the loop and how to verify it. These rules govern running it without me approving every turn.

- "Done" is defined in section 5. If a task has no programmatic check, say so before starting rather than looping with no stop condition.
- Prefer the built-in autonomy commands over asking me to type "continue":
  - `/goal <verifiable end state>` for "keep working until it's correct" (test-fix-retest cycles, lint-clean, migrations with a clear stop condition).
  - `/loop <interval, or until: condition>` for polling or repeating a check (watch CI, re-run a suite).
  - `/batch <one mechanical change>` for a repetitive edit spread across many files. Requires git; it spawns parallel worktree agents and opens a PR per agent, so it also multiplies token usage.
- The `/goal` completion check is read from your output by a separate evaluator model, not from the filesystem. State conditions you can demonstrate in the transcript (show the passing test run), not silent file assertions.
- Always work on a git branch so changes can be reverted. Never start an autonomous loop without an iteration cap.
- Loops are for code with programmatic verification. Do not loop on judgment-heavy work, design decisions, or long compute jobs. Those are a script or my call, not a loop.
- If you are still stuck when the cap is reached, stop. Document what is blocking progress, what you tried, and suggested next steps. Do not thrash.

## Text

Rules for human-readable text you produce (PR descriptions, comments, docstrings, commit messages, docs):

- No em-dashes or other long dashes. Use commas, periods, or parentheses instead.
- Cut filler and hedging: "um", "basically", "essentially", "it's worth noting", "of course".
- Vary sentence length. Do not pad a short, correct statement into a long fuzzy one, and do not chain choppy fragments either.
- Avoid the usual LLM tells: no "it's not just X, it's Y", no "delve", no overwrought openers.
- Reread what you wrote before you finish. Delete anything that does not earn its place.
