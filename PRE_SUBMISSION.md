# PRE-SUBMISSION — the loose ends between here and a report we'd sign

> **What this document is.** The honest gap list between the repo as it stands on
> **11 Nov 2026** and the thing we walk into judging with. Written in the project
> stance (`NIGHTFALL.md §1`): postmortem-driven, _measure don't assert_, **protect
> the cold run above all**, tell the honest story. Every task below is phrased the
> way we judge: not "do X" but "here is what a judge must see, here is why it wins
> or loses us the round, here is the acceptance test." Build window closes **15 Nov
> 2026**; judging is **29 Nov**. Order is by blast radius on the win thesis, not by
> how easy it is.
>
> **How to read the status tags.** `SOLID` = built, tested, we'd show it. `THIN` =
> exists but would embarrass us under a judge's gaze. `MISSING` = not written.
> `RISK` = works, but something outside the code can take it down on the night.

---

## Where we honestly are (the one-paragraph version)

The **plumbing and the measurement story are real and strong**: the decide/recover
loop is wired end-to-end (`loop/agent.ts`), the scope gate is hard-coded and tested,
Bifrost cost is sourced from the live catalog with no faked numbers, and Tavily
grounding is _measured_ load-bearing on two axes (freshness + citation validity),
reproducible from frozen inputs. 34 tests pass, build is green, Biome is clean. What
is weak is exactly the surface a **judge sees in the first two seconds**: the
client-ready report is a ten-line skeleton that emits blank findings, the projected
web view does not exist, and — the one that actually decides the challenge — **we have
no evidence the autonomous `run` has ever completed a cold loop against a live lab and
produced a report.** The hard engineering is done; the parts that win the interview
are the parts still open.

---

## TASK 1 — Prove the cold run. [status: RISK / UNVERIFIED] — owner: R1 + R2

**This is the whole challenge.** `NIGHTFALL.md §2.1`: the single differentiator is
hitting go on an unfamiliar target, stepping back, and having it _work_. Everything
else on this list is polish on top of this. If `run` stalls, loops, or produces
nothing on a cold lab, no report and no dashboard saves us — and roughly sixty teams
lose exactly here.

**The honest problem.** We have exercised the _measurement_ paths live — `ablate` and
`precision` ran against real labs and real reference targets and produced honest
numbers. We have **not** demonstrated the default `run` command driving the full
`recon → grounded hypothesis → attempt → interpret → evidence → report` loop to a
planted objective on a lab, end to end, with a human only watching. The loop is wired
and unit-tested offline with injected deps; that is necessary, not sufficient. Unit
tests prove the state machine; they do not prove it completes against a real Juice
Shop that returns real HTML.

**What a judge must see.** `pnpm --filter @nightfall/cli dev -- --scope <scope.yaml>`
launches, streams a readable trace, reaches (or cleanly caps out on) the objective
with no human nudge, and hands back findings — on a lab the operator did not tune
against.

**Acceptance test.**
1. Boot a fresh lab (`labs/`, Juice Shop pinned v20.3.0) under OrbStack.
2. Run the default command against `example.scope.yaml` with Cloudflare quota available.
3. The loop completes without a manual intervention, emits at least one finding, and
   terminates on objective-reached or a cap — not on an unhandled throw.
4. Capture the full trace to a file. **Record it** (see TASK 7) so the demo never
   depends on a live run.
5. If it does _not_ complete cleanly: write down exactly where it broke. That failure
   is the most valuable artifact we can produce this week — it is the list of what to
   fix before the 15th.

**Why it's a RISK not a MISSING:** the code to do this exists; what's missing is the
evidence it works outside the test harness. Until someone has watched a cold run
finish, we are a team that _believes_ it has the differentiator, which on the night is
the same as not having it.

---

## TASK 2 — A report a consultant would sign. [status: THIN] — owner: R3 (R2 feeds it)

`NIGHTFALL.md §2.4`: the rubric demands **client-ready** — findings, evidence, CVSS
severity, remediation, cleanly formatted, not a JSON dump. Judges tell in two seconds
who ships real things, and the report is the one artifact they take away and reread.

**The honest problem.** Two defects compound here:

- `report/generate.ts` is **ten lines of Markdown** with a `TODO(R3): PDF`. It prints
  a title, then per finding a heading and the `remediation` string — nothing else. No
  evidence block, no CVSS, no request/response receipts, no severity rationale.
- Upstream, `loop/agent.ts::toFinding` **hard-codes `severity: "high"` and leaves
  `remediation: ""`.** So even once the generator is good, it renders blank bodies at
  a uniform, unjustified severity. The data model (`evidence/models.ts`) has the
  fields; the loop simply isn't populating them.

So today a generated report is: a list of titles, every one "HIGH", every body empty.
That is a JSON dump wearing a header — precisely the thing §2.4 says loses.

**What a judge must see.** One finding, fully dressed: title, CVSS vector + score, the
in-scope request/response that is the _evidence_, a one-paragraph plain-English
remediation, severity that is _argued_ from the evidence, not asserted.

**Acceptance test.**
1. `toFinding` derives severity from the attempt result / interpret verdict, not a
   constant; populates `remediation` and an evidence receipt from the real
   request/response.
2. `toMarkdown` renders, per finding: severity + CVSS, the evidence block, remediation.
3. A real (or recorded) run's findings render to a document a security consultant
   would hand a client without edits.
4. Markdown is canonical; PDF (`marked → HTML → puppeteer`) is the polish-window
   stretch, not a blocker.

**R2's slice of this:** the finding data arrives through the gateway/hypothesis path I
own. If severity/CVSS wants a model call to summarize, it routes through Bifrost like
every other reasoning step — and I keep `gateway.complete` stable while doing it.

---

## TASK 3 — The scope-gate refusal, staged as a live beat. [status: SOLID code, UNSTAGED demo] — owner: R1 + all

`NIGHTFALL.md §2.3`: scope-safety is the **centerpiece, not a disclaimer**. An
offensive agent that can _prove_ it stays in bounds reads as mature; one that falls to
`/app/../admin` on the night is an **automatic failure**. The gate is deny-by-default,
hard-coded, has no LLM inside it, and is unit-tested (`da51f77`).

**The honest problem.** The gate is correct in code and in tests, but a passing test is
not a demo beat. We have not staged the thirty seconds where the agent is pointed at an
out-of-scope host and **visibly refuses**, with the audit log showing zero leakage.
§2 warns specifically about the gate that "passed the happy-path test but fell to
`/app/../admin` on the night" — so the staged beat must include a **path-traversal /
normalization attempt**, not just a clean out-of-scope hostname.

**What a judge must see.** Operator points Nightfall at a host outside the scope file;
the trace shows the gate denying it before any request leaves; the same for a
`../`-style escape against an in-scope host. Audit log shows nothing out-of-scope ever
went out.

**Acceptance test.** A scripted beat (CLI invocation + expected trace output) that
demonstrates refusal of (a) an out-of-scope host and (b) a traversal/normalization
escape, both backed by the audit log. Add a test for the traversal case if one isn't
already among the gate tests.

---

## TASK 4 — Bifrost, visibly load-bearing in three ways. [status: MIXED] — owner: R2

`NIGHTFALL.md §2.2`: Bifrost must do something a raw API key can't — **real cost
deltas, a cache hit, and a budget cap halting a runaway loop, live.** If Bifrost could
be ripped out without the demo changing, we bolted it on.

**The honest status, item by item (this is my column):**

- **Real cost / routing — SOLID.** Every call is priced from Bifrost's live `/v1/models`
  catalog (`gateway/catalog.ts`, `pricing.ts`), source-tagged on `gateway.call`. No
  faked numbers, which is the rule we cannot break. _Done._
- **Budget cap halting a runaway loop — SOLID code, UNSTAGED.** `Budget` +
  `BudgetExceededError` exist and are tested; the loop catches the throw and stops.
  Same gap as the gate: tested, not _staged_. We need the beat where a low budget cap
  visibly halts the agent mid-loop with a readable "budget exceeded, stopping" line.
- **Cache hit — BLOCKED Bifrost-side, documented honestly.** The `cache-demo`
  subcommand and the client's cache-key/hit handling are code-proven; enabling the
  semantic cache on this single-container, DB-backed Bifrost deploy is blocked (it
  demands a vector store the UI won't attach and the plugin API rejects with
  "store is required"). **The honest-story play:** show `cache-demo` proving the client
  is cache-correct, and say plainly that the cache is a Bifrost deployment config
  detail, not a hole in our integration. A judge who built the gateway respects the
  honest framing more than a faked hit. _Decision already taken; this task is to make
  sure the demo narrates it, not hides it._

**Acceptance test.** On screen during the demo: a per-run cost number that moves with
routing, and a budget cap halting the loop live. The cache beat is the `cache-demo`
proof + the one-sentence honest caveat.

---

## TASK 5 — Tavily, the _cause_ of a finding (not just a measured delta). [status: MEASURED, not yet CAUSAL on the live path] — owner: R2

`NIGHTFALL.md §2.2`: Tavily must be the **cause** of a finding — a current CVE the
model didn't know from training, pulled live, that leads to the exploit — _and_ we
measure it, not assert it.

**The honest status.** The **measurement** half is SOLID and is my strongest artifact:
the ablation shows grounding load-bearing on freshness (WebGoat: grounded 5 fresh CVEs
@ 100% vs ungrounded 0) and on citation validity (Log4j: grounded recovers the full
Log4Shell chain 4/4 vs the bare model's 2), frozen in `apps/cli/demo/`. What is _not_
yet shown is the **causal** half on the live `run` path: a Tavily-sourced fresh CVE
flowing through hypothesis → a successful `attempt` → a finding in the report. That
depends on TASK 1 (a completing cold run) and TASK 2 (findings that actually render).

**What a judge must see.** The trace shows Tavily returning a post-cutoff advisory the
model could not have known, that advisory becoming the hypothesis the loop acts on, and
that action producing a finding — the measured ablation on screen beside it as the
proof it generalizes.

**Acceptance test.** On a completing run, at least one finding traces its lineage back
to a `tavily.cve` event for a fresh (post-cutoff) CVE. The ablation table is shown as
the "and here's why that wasn't luck" evidence.

---

## TASK 6 — The projected web view. [status: MISSING] — owner: R3

`NIGHTFALL.md §2.5` + the rubric: the run should stream as something a judge _watches_,
not a hopeful terminal scroll. `apps/web/` is currently a **single README** that
defers the view to "day 11+, do not build until the core loop reliably completes a cold
run." It is now day 11, and that gating condition is exactly TASK 1.

**The honest problem.** Two things are missing, and one blocks the other:

- **`nightfall serve` (a `ws` socket on the CLI) does not exist.** The web README's own
  design has the view subscribing to the core event types over a socket the CLI
  exposes. No socket, no view.
- **The view itself (vite + react) is unwritten.** The design is good — trace on the
  left, Bifrost/Tavily/scope "receipts" gauges on the right, all just sinks on the
  existing event bus — but none of it is code.

**Deliberate call, in-persona.** §1 says _reliability over spectacle_ and §2 lists "a
beautiful interface wrapped around a flaky agent" as a top way strong teams lose. So:
**this task is explicitly behind TASK 1.** A rehearsed terminal trace of a run that
_completes_ beats a dashboard of a run that stalls. Build the view only once the cold
run is real; until then, the readable CLI trace _is_ the watch surface.

**Acceptance test (only once unblocked).** `nightfall serve` streams bus events over
`ws`; a vite+react view renders the live trace plus the three receipts gauges; it
survives a full run without the operator touching the keyboard.

---

## TASK 7 — The rehearsed 3-minute demo + the recording. [status: MISSING] — owner: all

`NIGHTFALL.md §2.5`: we win with a **rehearsed 3-minute demo, not a hopeful 6-minute
terminal scroll**, and §2 names "a demo held hostage to a live run with no recording"
as a way teams lose. This is the container every task above pays into.

**The honest problem.** There is no demo script and no recording. Right now our demo
_is_ a live run — which is also TASK 1, which is unverified — so we are currently the
exact "held hostage to a live run" failure mode the source-of-truth warns against.

**What this task is.**
- A written 3-minute beat sheet: cold run completes → Tavily causes a finding → the
  scope gate refuses out-of-scope → Bifrost cost + budget-cap halt → the signed report.
  Each beat maps to a task above and to a rubric row in `§4`.
- **A recorded run of each fragile beat**, so judging day never depends on live quota,
  a live lab, or a live model. The live run is the aspiration; the recording is the
  insurance.

**Acceptance test.** A teammate who has never seen the demo can deliver the 3 minutes
from the beat sheet, and every beat has a recorded fallback that lands the same payoff.

---

## TASK 8 — The demo-day quota plan. [status: RISK] — owner: R2

**The honest problem.** The model behind every reasoning step is Cloudflare Workers AI
(Llama 3.3 70B) on the **free tier: 10,000 neurons/day**, which today's runs exhausted
(429 until 00:00 UTC reset). A live demo that needs the first uncached call will fail if
the quota is spent — and there is no cache to cushion it (TASK 4).

**What this task is.** Decide and document the demo-day model posture: (a) reserve
quota — no ablation/precision runs on demo day before the live beat; and/or (b) a paid
tier or a second provider already configured in Bifrost as a fallback route; and/or
(c) lean on TASK 7's recording for the model-dependent beats. The decision matters more
than which option — an undecided quota posture is how a tuned demo dies on the night.

**Acceptance test.** A written line in the demo runbook stating exactly how the live
model beat is powered on 29 Nov, with a recorded fallback if it 429s.

---

## TASK 9 — Submission-package hygiene. [status: PARTIAL] — owner: all

The brief (`§3`) requires: working/reproducible demo; repo with README + setup +
architecture; which statement + how requirements are met; clear demonstration of both
integrations; test/measurement evidence; **safety & authorization docs**.

**The honest status.** The docs scaffold is strong — `NIGHTFALL.md`, `README.md`,
`ARCHITECTURE.md`, `CONTRIBUTING.md`, `AUTHORIZATION.md` exist. What remains is the
final pass that a judge will actually grade against: confirm the README quickstart runs
clean on a fresh clone, confirm the rubric map in `§4` matches what the code actually
does today (several rows are aspirational until TASKS 1–2 land), and make sure the
"test/measurement evidence" the brief asks for points a judge straight at the frozen
`apps/cli/demo/` ablation pair.

**Acceptance test.** A fresh clone, `pnpm install`, follow the README, and reach a
running trace without tribal knowledge. Every `§4` rubric row is either true in code or
honestly marked as a recording.

---

## The one-line summary for standup

The engine and the measured sponsor story are real; the report, the web view, and —
above all — **a verified cold run** are what stand between us and a submission we'd
sign. Protect the cold run. Everything else is polish on top of a run that completes.
