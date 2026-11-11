# Nightfall — 3-Minute Demo Script (R3-owned)

> The judges grade autonomy, scope-safety, the report, and that both sponsors
> are load-bearing. This script lands all four in three minutes and never leaves
> us hostage to a live run. **Rehearse it; record it; keep the recording ready.**
> See [NIGHTFALL.md](./NIGHTFALL.md) §14 for the win thesis behind each beat.

## The rule of the demo

- **Narrate the story, not the terminal.** Every beat has one sentence to say
  and one thing on screen. If the live run drifts, cut to the recording and keep
  talking — the audience should not be able to tell.
- **Open on autonomy, close on the artifact.** First thing they see is us
  stepping back; last thing is a report a consultant would sign.
- **Every number on screen is real** (read from Bifrost / the ablation), never
  asserted out loud.

## Pre-flight checklist (do this before you present)

- [ ] Labs up: `docker compose -f labs/docker-compose.yml up -d` (Juice Shop :3000, DVWA :8081, WebGoat :8082).
- [ ] `.env` set: `BIFROST_BASE_URL`, `BIFROST_API_KEY`, `TAVILY_API_KEY`, model routing, a **low** `budgetUsd` in the runaway scope so the cap fires on cue.
- [ ] Deps built: `pnpm install && pnpm exec playwright install chromium && pnpm build`.
- [ ] Dry-run the exact commands once; confirm a clean run end-to-end.
- [ ] **Recorded take exported and open in a second window** as the fallback.
- [ ] Two scope files staged: the in-scope target, and an out-of-scope one for the gate beat.

## Commands used (copy-paste ready)

```bash
# Beat 1–4,6 — the autonomous run against the in-scope lab
pnpm --filter @nightfall/cli dev -- run --scope packages/core/src/scope/example.scope.yaml

# Beat 5 — the gate refusing an out-of-scope target (always available)
pnpm --filter @nightfall/core test            # adversarial gate suite, all green
# …and/or live: point the run at a host outside allow.hosts and show scope.blocked

# Closing slide — the Tavily ablation numbers
pnpm --filter @nightfall/cli dev -- ablate --targets apps/cli/example.targets.json --out runs/ablation.json
```

## The six beats (3:00 total)

| #   | ~Time     | Beat                          | On screen                                                              | Say (one line)                                                                                                                                     |
| --- | --------- | ----------------------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | 0:00–0:25 | **Hands off**                 | Scope file, then `run` launches; you fold your arms                    | "We hand it a scope file and a target, hit go — and step back. No human at the keyboard from here."                                                |
| 2   | 0:25–1:05 | **It decides**                | Live trace: an attempt fails → interpret → pivot → recover             | "Watch it read a failed attempt, decide to pivot, and recover on its own. That's the whole challenge — it has never seen this target."             |
| 3   | 1:05–1:40 | **Tavily caused the finding** | `tavily.cve` event → a recent CVE (post-cutoff) → the exploit it drove | "This CVE was published after the model's training cutoff. It couldn't have known it — Tavily pulled it live, and it's what led to the exploit."   |
| 4   | 1:40–2:10 | **Bifrost receipts**          | Cost/run, a cache hit, the budget cap halting a runaway loop           | "Every call routes through Bifrost: real cost per step, a cache hit here, and — on a deliberately runaway loop — the budget cap halting it live."  |
| 5   | 2:10–2:35 | **The gate refuses**          | Out-of-scope target → `scope.blocked`; or the green adversarial suite  | "Point it out of scope and it refuses — deny-by-default. We attacked this gate ourselves, including encoded path-traversal; every case is denied." |
| 6   | 2:35–3:00 | **The payoff**                | Open the client-ready report: findings, evidence, CVSS, remediation    | "And here's what a client gets: findings with evidence, CVSS severity, and remediation — not a JSON dump."                                         |

**Closing slide (after 3:00):** the ablation before/after — citation-validity and
freshness, grounded vs. ungrounded, on a recent-CVE target. One line: "We don't
claim Tavily helped — we measured it."

## Fallback plan (never skip this)

- **Primary failure mode — the live run stalls or loops.** Cut immediately to the
  recorded take (already open) and keep narrating the same beats. Do not debug on
  stage.
- **Beat 3 (Tavily) is flat on the chosen lab.** Switch narration to the
  recent-CVE target from the ablation set; the freshness delta is the proof, not
  the specific lab.
- **Beat 4 (budget cap) doesn't fire.** Lower `budgetUsd` in the runaway scope so
  the cap is guaranteed to trip; rehearse until it fires on cue.
- **Beat 5 (gate) — if a live out-of-scope run isn't ready**, show
  `pnpm --filter @nightfall/core test`: the adversarial suite denying out-of-scope
  hosts, path traversal, encoded traversal, host-confusion and non-HTTP schemes.
  This is always available and makes the same point.
- **Everything is on fire.** Play the full recorded take start to finish and
  narrate over it. A rehearsed recording beats a hopeful live terminal every time.

## Recording the fallback

- Record the full 3-minute run once it's clean; trim to the six beats; export at
  presentation resolution.
- Keep the raw end-to-end take too (unedited), in case a judge asks to see it run
  without cuts.
- Re-record after any change that affects on-screen numbers (cost, ablation).
