# Safety & trust model

The question this file answers is not "does it find vulnerabilities" — it is
"does it **fail safe, stay fully attributable, and avoid creating new risk while
looking for old risk.**" Each property below is backed by code (file:line), not
assertion. See also [STATE_MACHINES.md](./STATE_MACHINES.md) (reliability
invariants) and [AUTHORIZATION.md](./AUTHORIZATION.md) (scope policy).

## 1. Can it be pointed at something it shouldn't touch — and does it know?

Deny-by-default, and it fails safe on input nobody rehearsed:

- **Malformed / typo scope file:** `loadScope` parses through a `zod` schema that
  is `.strict()` (unknown keys rejected) with `.url()` on `target`/`loginUrl`
  (`scope/schema.ts`, `scope/parser.ts`). A malformed file **throws before the run
  starts** — fail closed. A typo in a host _value_ doesn't widen scope: the host
  simply never matches, and deny-by-default drops it.
- **Redirect chain out of scope (the classic leak):** `fetchGated` follows
  redirects **manually** (`redirect:"manual"`) and re-checks the gate on **every
  hop**, fail-closed, up to a bounded 5 (`session/httpSession.ts`). Regression:
  `session-redirect.test.ts` drives an in-scope→loopback redirect and asserts the
  out-of-scope request never fires.
- **IDN homograph / userinfo / trailing-dot / non-http(s) scheme:** all covered by
  adversarial cases in `scope/gate.test.ts` (scheme allowlist, host confusion).
- **DNS rebinding to an internal IP:** the gate authorizes by **hostname**, and
  the scope the challenge mandates is loopback-only (`allow.hosts: [localhost]`,
  `AUTHORIZATION.md`), so there is no public DNS to rebind. For a public target
  this would require pinning the resolved IP — named as an explicit limitation,
  not left implicit.

## 2. Who is authorized, and can you prove it after the fact?

- **Scope binding on every finding.** Each finding is stamped with `scopeId` — a
  SHA-256 of the authorizing scope file's content (`loop/agent.ts` `scopeId()`,
  `evidence/models.ts`). The scope cannot be edited after the fact without the
  hash no longer matching the trail. The same hash is emitted on `run.start` and
  printed in the report header.
- **Timestamp on every finding.** `foundAt` (ISO) is recorded as the finding is
  written (`toFinding`), so the order and time of actions is reconstructable.
- **Append-only, crash-tolerant trail.** Evidence is one JSON object per line via
  `appendFileSync` (`evidence/store.ts`); a crash mid-write can leave a partial
  line, but `readFindings` wraps each line in `try/catch` + `safeParse` and skips
  malformed lines, so a partial write never corrupts the trail.
- **Blocked requests are evented** (`scope.blocked`) for the live trace. Full
  per-request audit logging (every request, not only those that produced a
  finding) is a documented extension, not yet persisted to disk.

## 3. Credential handling — does anything leak to a third-party LLM?

**No credential and no raw target-response body ever reaches a model.** This is
the strongest property here and it is structural:

- **Interpretation is deterministic** (`loop/interpret.ts`) — a pure function, no
  model call — so a response body is never shipped to an LLM to be "understood."
- **The hypothesis call** sends only `component`, `version`, and the Tavily
  advisory list (`hypothesis/tavilyClient.ts` `buildPrompt`) — never a response
  body, never a credential.
- **The planner call** sends only the objective, **artifact `{kind, label}`**
  (raw values — tokens — explicitly never leave the loop, `loop/planner.ts`
  `PlanInput`), finding titles, and candidate technique→url. No bodies, no creds.
- **Credentials from the scope** are used only to build the login POST
  (`httpSession.login`); they are never logged and never placed in a prompt.
- **Captured secrets are redacted** in the evidence trail (`redact()` in
  `loop/actions.ts`) — a bypassed JWT is proven real without printing it in full.

## 4. Does it know "found a vulnerability" vs. "caused damage"?

The boundary is **engineered, not accidental**: there is no generalized exploit
engine. Every attempt is a hand-written, **read-only** probe in one closed
`switch` (`loop/actions.ts`), with an explicit no-payload-library contract in the
file header. The offensive strings are fixed constants and non-destructive by
construction — an error-based SQLi quote probe (`'"`), a boolean auth-bypass
(`' OR 1=1--`) that only _reads_ the auth table, a benign XSS marker, a `; id`
command probe. Nothing issues a `DROP`/`DELETE`/`UPDATE`, deletes data, or locks
an account. Generalizing to a consequential action would require **adding a new
check to that switch** — a reviewable, deliberate act — not flipping a flag. The
safety property does not depend on the lab being disposable.

## 5. Non-repudiation of the autonomous decision

Every planner decision is attributable: the planner returns `{pick, reason}` and
the loop emits `plan.decision {chose, reason, fallback}` (`loop/agent.ts`,
`loop/planner.ts`), rendered in the live trace. The model is an **optimizer over a
deterministic floor** — front-of-queue runs when the plan is absent, invalid, or
budget-stopped — so "the LLM decided" is never the whole answer: there is always a
recorded reason, and a deterministic fallback that is itself explainable.
(Persisting the decision log to disk alongside findings is the next increment.)

## 6. Failure under a hostile target

- **Slow-loris / stalling target:** every request is bounded by an
  `AbortController` timeout (`NF_HTTP_TIMEOUT_MS`, default 20s,
  `httpSession.fetchGated`); a stall aborts, surfaces as a transient transport
  error, and the loop recovers (bounded retry → abandon) rather than hanging.
  Regression: `session-redirect.test.ts` "times out on a stalling target".
- **Honeypot feeding poisoned data to the LLM:** interpretation is deterministic
  (§3), and hypothesis keys off the _fingerprint_, not the response body — so a
  poisoned body cannot steer technique selection. A faked framework banner only
  wastes one re-grounding query; it cannot change the control flow.
- **WAF returning 200-with-benign-body instead of a block:** the checks confirm
  only on a specific signal (a real DB error, a reflected marker). A benign 200
  yields _no_ signal, so the failure mode is a **miss, never a false positive** —
  it fails safe, never over-claiming.
- **Auth wall misread as a finding:** an expired session redirected to a 200
  login page used to risk a false positive; now an auth wall (401/403, or a
  login-form body) is rejected as not-applicable (`isAuthWall`, `loop/actions.ts`),
  with a regression test.

## 7. Does the report hold up as evidence?

Yes, independently of the narrative. Each finding in the JSONL carries its raw
request/response pair, a timestamp (`foundAt`), the authorizing scope hash
(`scopeId`), the technique, and CVSS — and `readFindings` re-validates every line
against the schema. A client's security team can replay each finding from the
evidence store without trusting the summary; the report is rendered _from_ that
store, not hand-curated alongside it.

## Bottom line

Fails safe (deny-by-default, bounded requests, auth-wall rejection), is
attributable after the fact (scope-hash + timestamp on every finding, decision
reasons in the trace), and does not create new risk while testing (no creds or
bodies to any LLM, a closed read-only probe set). The two residual items are named
honestly, not hidden: a soft budget cap (overshoot bounded by one in-flight call,
never racing) and full per-request audit-log persistence.
