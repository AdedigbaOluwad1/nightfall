# State machines & reliability invariants

Nightfall runs on an unfamiliar, judge-supplied target, so "reliability" is a
state-machine-correctness problem: the dangerous states are the ones nobody
wrote down. This file enumerates every state machine — the one explicit loop and
the implicit ones — with a transition table that **includes the illegal row**,
the guard that enforces it (file:line), and an honest status.

**The single most important invariant:** the run is **strictly sequential**.
There is no `Promise.all`, `Promise.race`, or concurrent fan-out anywhere in
`packages/core/src` (`grep -rE "Promise\.(all|race|allSettled)"` → none). The loop
`await`s every `recon`, `hypothesize`, and `attempt` before the next. This single
fact defuses an entire class of races — concurrent re-auth, check-then-spend
budget overrun, candidate A/B interleaving — because no two of these transitions
can ever interleave in one run. Where a guard is "safe only because sequential,"
that is stated, so adding concurrency later is a conscious re-audit, not a silent
regression.

---

## 1. Loop control (explicit) — `loop/agent.ts`

States: `running → {objective | steps | budget | exhausted}` (terminal).

| from                       | event                   | to                | guard                                                                                                                                                                    |
| -------------------------- | ----------------------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| running                    | `reachesObjective`      | objective (break) | `agent.ts` sets `objectiveReached=true` then `break`, same tick, no await between                                                                                        |
| running                    | `steps ≥ maxSteps`      | steps             | checked at top of each iteration                                                                                                                                         |
| running                    | `costUsd ≥ budgetUsd`   | budget            | `overBudget()` before every attempt + hypothesis                                                                                                                         |
| running                    | queue empty             | exhausted         | `while` condition                                                                                                                                                        |
| **objective/budget/steps** | **any further attempt** | **ILLEGAL**       | unreachable: each sets the flag and `break`s; the `while` guard is re-checked before any next `attempt`. Sequential ⇒ no in-flight attempt can complete after the break. |

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

| concern                                                                                    | status                                            | evidence                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| in-scope → out-of-scope **redirect**                                                       | **guarded + tested**                              | `fetchGated` follows redirects manually (`redirect:"manual"`), re-checks the gate on **every hop**, fails closed; method downgrade honored. `session-redirect.test.ts` reproduces an in-scope→127.0.0.1 redirect and asserts it never fires the request.                                                                          |
| non-http(s) scheme (e.g. `gopher://`)                                                      | guarded + tested                                  | scheme allowlist in `gate.check`; `gate.test.ts`                                                                                                                                                                                                                                                                                  |
| userinfo / trailing-dot / IDN host confusion                                               | guarded + tested                                  | `gate.test.ts` adversarial cases                                                                                                                                                                                                                                                                                                  |
| **DNS TOCTOU** (host string passes the gate, DNS resolves to a different IP at fetch time) | **documented limitation, out of scope by design** | the gate authorizes by **hostname**, and Node resolves DNS independently at fetch. For the challenge's isolated-lab scope (`allow.hosts` is `localhost`/loopback), there is no DNS to race. Pinning the resolved IP would be required for public targets — which are never in scope here (`AUTHORIZATION.md`). Named, not hidden. |

## 5. Budget (implicit) — `gateway/budget.ts`, `gateway/bifrostClient.ts`, `loop/agent.ts`

States: `under → over → halted` (terminal).

| from       | event                                     | to                                  | guard                                                                                                                                        |
| ---------- | ----------------------------------------- | ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| under      | `spent < cap`                             | under                               | `assertUnder()` no-op; `overBudget()` returns false                                                                                          |
| under      | `spent ≥ cap`                             | halted (break, `haltedBy="budget"`) | `overBudget()` before each step; `assertUnder()` throws `BudgetExceededError` the loop catches                                               |
| **halted** | **un-halt / keep spending**               | **ILLEGAL**                         | not reachable: the throw/`overBudget` both `break` the `while`; `budgetAnnounced` latch emits the halt once; nothing after the break spends. |
| under      | two calls both pass check then both spend | **ILLEGAL (overrun by racing)**     | not reachable — sequential; no two model calls are ever in flight.                                                                           |

- **Honest limitation — soft cap:** `assertUnder()` is checked _before_ a call and
  `add()` runs _after_ it, so a single in-flight call can overshoot the cap by up
  to that one call's cost (e.g. pass at \$4.99, land at \$5.49). This is a soft
  cap, by design — it never _racing_-overshoots (sequential), and the overshoot is
  bounded by one call. A hard cap would require pre-charging an estimate.

## 6. Evidence store (implicit) — `evidence/store.ts`

| concern                           | status        | evidence                                                                                                                                                                                                                                                |
| --------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| half-recorded finding observable? | tolerated     | `record()` is a single synchronous `appendFileSync` of one line; a crash mid-write can leave a partial line, but `readFindings` wraps each line in `try/catch` + `safeParse` and **skips malformed lines** — a partial write never corrupts the report. |
| duplicate finding in the report   | not reachable | see §2: `record()` only on `ok`, which `continue`s without re-queue.                                                                                                                                                                                    |

---

## Pressure-test scorecard (the critique's named bets)

| claim                                        | verdict                                                            | class               |
| -------------------------------------------- | ------------------------------------------------------------------ | ------------------- |
| redirect in-scope→out-of-scope leak (TOCTOU) | **handled** — manual re-gate per hop + test                        | scope-leak (closed) |
| concurrent login corrupts CSRF               | **not reachable** — sequential, single awaited login               | —                   |
| concurrent budget check-then-spend overrun   | **not reachable** — sequential                                     | —                   |
| unbounded retry                              | **bounded in code** — `maxRetries`                                 | —                   |
| act after objective reached                  | **not reachable** — set flag + `break`, sequential                 | —                   |
| double evidence write on retry               | **not possible** — record only on `ok` + `continue`                | —                   |
| crash mid-evidence-write corrupts report     | **tolerated** — malformed lines skipped on read                    | cosmetic (closed)   |
| session expiry read as a finding             | **was a gap, now guarded** — auth-wall rejection + regression test | reliability (fixed) |
| DNS TOCTOU                                   | **documented limitation** — moot for loopback-only lab scope       | documented          |
| soft budget cap overshoot                    | **documented** — bounded by one call, by design                    | documented          |

Update this file in the same PR as any change to the machines above.
