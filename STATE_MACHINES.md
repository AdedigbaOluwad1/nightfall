# State machines & reliability invariants

Nightfall runs on an unfamiliar, judge-supplied target, so "reliability" is a
state-machine-correctness problem: the dangerous states are the ones nobody
wrote down. This file enumerates every state machine — the one explicit loop and
the implicit ones — with a transition table that **includes the illegal row**,
the guard that enforces it (file:line), and an honest status.

**The single most important invariant:** the run is **strictly sequential**.
There is no `Promise.all`, `Promise.race`/`any`, or concurrent fan-out anywhere in
`packages/core/src`. The loop `await`s every `recon`, `hypothesize`, and `attempt`
before the next. This single fact defuses an entire class of races — concurrent
re-auth, check-then-spend budget overrun, candidate A/B interleaving — because no
two of these transitions can ever interleave in one run. Where a guard is "safe
only because sequential," that is stated, so adding concurrency later is a
conscious re-audit, not a silent regression.

This is **enforced, not a one-time grep**: `concurrency-guard.test.ts` scans
`core/src` on every CI run and fails on any `Promise.all/allSettled/race/any`. The
invariant cannot regress without someone deliberately deleting the guard and
reading why. It also holds **below** `agent.ts`: the Tier-2 browser session
(`browserSession.ts`) registers **no** `page.on(...)` event handlers — only bounded
`waitFor`/`waitForLoadState` (10s) — so there is no library-driven reentrancy
mutating shared state during an awaited step, and the Tier-1 cookie jar is mutated
within the awaited fetch, before the next request is constructed.

---

## 1. Loop control (explicit) — `loop/agent.ts`

States: `running → {objective | steps | budget | exhausted}` (terminal).

| from                       | event                   | to                        | guard                                                                                                                                                                                                              |
| -------------------------- | ----------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| running                    | `reachesObjective`      | objective (break)         | `agent.ts` sets `objectiveReached=true` then `break`, same tick, no await between                                                                                                                                  |
| running                    | `steps ≥ maxSteps`      | steps                     | checked at top of each iteration                                                                                                                                                                                   |
| running                    | `costUsd ≥ budgetUsd`   | budget                    | `overBudget()` before every attempt + hypothesis                                                                                                                                                                   |
| running                    | queue empty             | exhausted                 | `while` condition                                                                                                                                                                                                  |
| running                    | a request hangs         | transient → retry/abandon | **each request is time-bounded** — `fetchGated` aborts after `NF_HTTP_TIMEOUT_MS` (default 20s); the browser tier bounds `waitFor`/`waitForLoadState` at 10s. A hung request can't stall the single-threaded loop. |
| **objective/budget/steps** | **any further attempt** | **ILLEGAL**               | unreachable: each sets the flag and `break`s; the `while` guard is re-checked before any next `attempt`. Sequential ⇒ no in-flight attempt can complete after the break.                                           |

**Termination is bounded on three axes — count, cost, AND time.** `maxSteps` bounds
count, `budgetUsd` bounds cost, and the per-request timeout bounds wall-clock, so a
slow-loris/stalling target cannot make "always terminates" false (see §6).

**"Continue acting after the objective" bug:** not reachable. `objectiveReached`
is set and the loop `break`s in the same synchronous step; there is no queued
`attempt` still in flight (sequential), so no evidence is written for a target
after the goal is met.

## 2. Exploit-attempt recovery (explicit) — `loop/interpret.ts`, `loop/agent.ts`

States per candidate: `untried → in-progress → {retry → in-progress | escalate → in-progress(tier2) | pivot | abandon | confirmed}`.

| from            | event                               | to                                  | guard                                                                                                                              |
| --------------- | ----------------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| in-progress     | transient && `retries < maxRetries` | retry (re-queued, `retries+1`)      | `interpret.ts` compares `retries < ctx.maxRetries`; `agent.ts` re-queues `{...item, retries: item.retries+1}`                      |
| in-progress     | transient && `retries ≥ maxRetries` | abandon                             | same check falls through to `abandon`                                                                                              |
| in-progress     | `applicable === false`              | pivot                               | `interpret.ts`                                                                                                                     |
| in-progress     | tier 1 && `canEscalate`             | escalate (tier 2)                   | `interpret.ts`; `escalated` latch prevents re-escalation                                                                           |
| in-progress     | `ok`                                | confirmed (record once, `continue`) | `agent.ts`; **record is only reached on `ok`, then `continue` — never on a retry path**                                            |
| **in-progress** | **unbounded retry**                 | **ILLEGAL**                         | capped in **code**: `maxRetries` (default 2, `deps.maxRetries`), enforced at the `retries < maxRetries` comparison, not just prose |

- **Retry bound:** a candidate that always times out → `transient` → retry until
  `retries == maxRetries` → `abandon`. Finite.
- **Two decision states at once:** impossible — `interpret` is synchronous and
  pure, and the loop `await`s `attempt` for candidate A fully before shifting B.
- **Killed mid-`attempt()`:** nothing is recorded until `ok` (after the response
  is in hand), so a crash resumes as "untried" on a fresh run — wasteful, never
  ambiguous, never a duplicate out-of-scope request (every request re-checks the
  gate from scratch; no attempt state is persisted).
- **Double evidence write:** not possible — `record()` is called only on `ok`,
  and the `ok` branch `continue`s without re-queuing. Retry/escalate paths are
  the non-`ok` branches.

## 3. Session / auth (implicit) — `session/httpSession.ts`, `session/browserSession.ts`

States: `fresh → logging-in → authenticated → (expired) → auth-wall-observed`.

| from          | event                       | to                               | guard                                                                                                                                                                                                                                        |
| ------------- | --------------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| fresh         | `login()`                   | authenticated                    | idempotent via `loggedIn` latch (`httpSession.ts:63`)                                                                                                                                                                                        |
| authenticated | cookie/CSRF expires mid-run | auth-wall-observed               | **see below — now guarded**                                                                                                                                                                                                                  |
| any           | concurrent 2nd `login()`    | **ILLEGAL (would corrupt CSRF)** | not reachable: `login()` is awaited exactly once at loop start and the run is sequential. The `loggedIn` latch is a check-then-set, **safe only because single-threaded** — a mutex would be required before any concurrent caller is added. |

- **Session expiry mid-attempt (the real black-box failure):** an expired session
  that returns 401/403, or is redirected to a 200 login page, used to risk a
  **false positive** — a word from the objective echoing on a login screen read as
  "objective reached." Guarded: `probeObjective` now rejects an **auth wall**
  (401/403 or a login-form body) as `applicable:false`, never a finding
  (`actions.ts`, `isAuthWall`/`LOGIN_PAGE`). Regression test:
  `actions.test.ts` "does not confirm the objective off an auth wall".
- **Tier-1 / Tier-2 divergence:** the two sessions hold **independent** cookie
  stores (tough-cookie jar vs. Playwright context), so a fresh Tier-2 login
  cannot corrupt Tier-1's jar. They may hold two distinct server sessions; that
  is divergence without corruption. Tier-2 is only ever reached via `escalate`,
  after Tier-1, one-way (`escalated` latch) — the order is deterministic, not
  race-prone.

## 4. Scope gate (implicit state around a pure core) — `scope/gate.ts`, `session/httpSession.ts`

The gate itself is **pure and memo-free** per request (`gate.check` constructs a
fresh `URL`, consults only the static scope file; no cache, no DNS, no I/O). The
implicit state lives in the transport around it.

| concern                                                                                                                 | status                                                      | evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| in-scope → out-of-scope **redirect**                                                                                    | **guarded + tested**                                        | `fetchGated` follows redirects manually (`redirect:"manual"`), re-checks the gate on **every hop**, fails closed; method downgrade honored. `session-redirect.test.ts` reproduces an in-scope→127.0.0.1 redirect and asserts it never fires the request.                                                                                                                                                                                                                                      |
| non-http(s) scheme (e.g. `gopher://`)                                                                                   | guarded + tested                                            | scheme allowlist in `gate.check`; `gate.test.ts`                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| userinfo / trailing-dot / IDN host confusion                                                                            | guarded + tested                                            | `gate.test.ts` adversarial cases                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **SSRF / rebind to an internal or metadata IP** (e.g. a redirect to `169.254.169.254`)                                  | **blocked by deny-by-default**                              | every hop's host must be in `allow.hosts`, and an **IP literal or any unlisted host is refused** (`AUTHORIZATION.md` §gate). Cloud-metadata and private IPs are never in an isolated lab's allow-list, so a redirect to one is dropped.                                                                                                                                                                                                                                                       |
| **DNS TOCTOU on an allowed hostname** (the listed hostname's own DNS answer flips between the gate check and the fetch) | **narrow residual, tied to the isolated-lab authorization** | the gate authorizes by hostname and Node resolves DNS at fetch; a _listed_ hostname whose DNS flips to an internal IP would not be re-validated. This requires control of DNS for the authorized hostname — i.e. the operator attacking their own isolated lab (`AUTHORIZATION.md`: "isolated lab; that is the only class of target"). Full defense is per-request IP pinning; not implemented, named not hidden. The dangerous case (rebind to metadata) is already closed by the row above. |

## 5. Budget (implicit) — `gateway/budget.ts`, `gateway/bifrostClient.ts`, `loop/agent.ts`

States: `under → over → halted` (terminal).

| from       | event                                     | to                                  | guard                                                                                                                                                                             |
| ---------- | ----------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| under      | next call's worst-case still fits         | under                               | `assertCanAfford(est)` admits it _before_ issuing; `overBudget()` returns false                                                                                                   |
| under      | next call's worst-case would reach cap    | halted (break, `haltedBy="budget"`) | `assertCanAfford(est)` throws `BudgetExceededError` **before the call is issued** (the loop catches it and `break`s); `overBudget()` also `break`s if `spent ≥ cap` before a step |
| **halted** | **un-halt / keep spending**               | **ILLEGAL**                         | not reachable: the throw/`overBudget` both `break` the `while`; `budgetAnnounced` latch emits the halt once; nothing after the break spends.                                      |
| under      | two calls both pass check then both spend | **ILLEGAL (overrun by racing)**     | not reachable — sequential; no two model calls are ever in flight.                                                                                                                |

- **Hard pre-flight cap — overshoot \$0.00:** `assertCanAfford(est)` reserves each
  call's _worst-case_ cost (prompt tokens + a full `max_tokens` completion, priced
  from the sync catalog) and refuses the call if that reservation would reach the
  cap — _before_ the request is issued; `add()` records only actual spend
  afterward. So the call that would cross the line is never made and the overshoot
  is exactly **\$0.00** (not bounded-by-one-call). Sequential execution rules out a
  racing overshoot too. A free/local model (`est ≤ 0`) degrades to the plain
  post-hoc `assertUnder` check. _(An earlier draft described this as a soft cap that
  could overshoot by one in-flight call; that predates the reserve check and is no
  longer true.)_

## 6. Evidence store (implicit) — `evidence/store.ts`

| concern                           | status                  | evidence                                                                                                                                                                                                                                                                                                                                                             |
| --------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| half-recorded finding observable? | handled + **disclosed** | `record()` is a single synchronous `appendFileSync` of one line; a crash mid-write can leave a partial line. `readFindings` skips unparseable lines (a partial write never corrupts the report) **and counts them, emitting a visible `console.warn` when any are skipped** — a security trail never silently loses evidence; a reader is told it may be incomplete. |
| duplicate finding in the report   | not reachable           | see §2: `record()` only on `ok`, which `continue`s without re-queue.                                                                                                                                                                                                                                                                                                 |

---

## Pressure-test scorecard (the critique's named bets)

| claim                                             | verdict                                                                                                              | class               |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ------------------- |
| redirect in-scope→out-of-scope leak (TOCTOU)      | **handled** — manual re-gate per hop + test                                                                          | scope-leak (closed) |
| concurrent login corrupts CSRF                    | **not reachable + CI-enforced** — sequential; `concurrency-guard.test.ts`                                            | —                   |
| concurrent budget check-then-spend overrun        | **not reachable + CI-enforced** — sequential                                                                         | —                   |
| library-driven reentrancy (Playwright/cookie jar) | **not present** — no `page.on(...)`; jar mutated within the awaited fetch                                            | —                   |
| unbounded retry                                   | **bounded in code** — `maxRetries`                                                                                   | —                   |
| hung request stalls the loop (no time bound)      | **closed** — per-request `AbortController` timeout; browser 10s waits                                                | reliability (fixed) |
| act after objective reached                       | **not reachable** — set flag + `break`, sequential                                                                   | —                   |
| double evidence write on retry                    | **not possible** — record only on `ok` + `continue`                                                                  | —                   |
| crash mid-evidence-write silently drops a finding | **closed** — skipped lines counted + `console.warn`; disclosed, not hidden                                           | reliability (fixed) |
| session expiry read as a finding                  | **guarded** — auth-wall (401/403 or login-screen) rejection; conservative heuristic + both-direction tests           | reliability (fixed) |
| auth-wall guard too aggressive (false negative)   | **guarded** — needs password field AND login affordance; lone password field still confirms                          | reliability (fixed) |
| SSRF / rebind to metadata/private IP              | **blocked** — deny-by-default refuses unlisted + IP-literal hosts                                                    | scope-leak (closed) |
| DNS TOCTOU on an allowed hostname                 | **narrow residual** — needs control of the authorized host's DNS; isolated-lab scope                                 | documented          |
| SPA 200-shell client-redirect to login            | **residual** — HTTP-tier body check can miss it; covered by Tier-2 browser                                           | documented          |
| budget cap overshoot (formerly a soft cap)        | **closed** — worst-case reserved pre-flight (`assertCanAfford`); the crossing call is never issued, overshoot \$0.00 | reliability (fixed) |

Update this file in the same PR as any change to the machines above. It is **not
frozen**: it is re-run against whatever the cold dry-run (days 13–15) actually
breaks — the test of the audit is whether it still holds the first time reality
disagrees with it, not whether the table is internally consistent today.
