# Authorization & Safety

Nightfall is an autonomous penetration-testing agent that runs **only** against
authorized, isolated targets described by a scope file. This document states what that
means in practice, how the safety boundary is enforced in code, and how to verify it
yourself — because for an offensive agent, scope adherence has to be _provable_, not
promised.

## What Nightfall is, and is not

- It **is** a control loop, an in-scope crawler, a session layer, an LLM-gateway
  client, a live-research client, an evidence/report pipeline, and a deny-by-default
  safety gate.
- It is **not** a generalized exploit toolkit. It embeds no payload library. The one
  lab-specific surface (`loop/actions.ts`) holds a small set of hand-written,
  **read-only** checks (a quote probe for error-based SQLi, a benign reflection marker
  for XSS, a `;id` separator probe, a `../etc/passwd` read, cookie/SameSite inspection,
  an authenticated-surface GET). None mutate target state.

## The deny-by-default scope gate

`scope/gate.ts` sits in front of every outbound network action. It is deliberately
**outside the LLM** — strict scope adherence is pass/fail, so it must never depend on a
model choosing to behave. No model call may ever be added to this file.

A request is allowed **only if** all hold:

1. its host is in `allow.hosts` (exact hostname match — an IP literal or a different
   host is refused, and userinfo tricks like `host@evil.com` resolve to the real host);
2. its path matches an `allow.paths` prefix **on path-segment boundaries** — `/app`
   covers `/app` and `/app/...` but never `/apple` or `/app-secret`;
3. its path matches no `deny.paths` rule.

The gate checks the **normalized** URL path, so traversal escapes (`/app/../admin`) and
their percent-encoded forms (`/app/%2e%2e/admin`) resolve before the check and are
refused. Anything the gate cannot parse or does not explicitly allow is denied. It errs
closed.

## Verify it yourself

The gate's refusal is a measured, reproducible beat — no model, no lab, no quota:

```bash
pnpm --filter @nightfall/cli dev -- scope-check \
  --scope packages/core/src/scope/example.scope.yaml \
  --url http://localhost:3000/logout \
  --url http://evil.example.com/ \
  --url "http://localhost:3000/foo/%2e%2e/logout"
```

Pass `--url` as many times as needed (out-of-scope host, denied surface, sibling-path
leak, plain and encoded traversal, userinfo confusion, IP-vs-hostname) and the command
**fails non-zero** if any behaves out of scope. The gate's unit tests
(`packages/core/test/gate.test.ts`) lock the same cases.

## Kill switch & emergency stop

A run can be stopped three ways, and they are deliberately distinct:

- **Graceful bounds (automatic).** The per-run **budget cap** (Bifrost gateway) and the
  **step cap** are upper limits on a run that otherwise completes on its own. The
  per-request timeout (`NF_HTTP_TIMEOUT_MS`, default 20s) bounds any single stalled
  request. These keep a healthy run finite; they are not an emergency control.
- **Emergency stop (operator-initiated).** Pressing **Ctrl+C** (`SIGINT`, or `SIGTERM`)
  aborts the run **immediately** — it does not wait for the current step, the budget, or
  the step cap. The CLI acknowledges the signal on screen and exits. Because evidence is
  written append-only and **synchronously as each finding is confirmed**
  (`evidence/store.ts`), every finding found before the signal is already durable on
  disk; the abort loses no confirmed evidence. A second Ctrl+C force-quits.
- **Scope refusal (continuous).** The deny-by-default gate refuses any out-of-scope
  request for the entire run, independent of the above.

## Operator & point of contact

Nightfall is operated by a single named human who is accountable for the engagement.
Before any run, record here the operator authorizing it and how to reach them, so an
emergency stop or an out-of-scope observation has a real person to escalate to:

- **Operator / point of contact:** _(set per engagement — name + direct contact of the
  authorizing operator)_
- **Authorization source:** the scope file supplied for this engagement (its SHA-256 is
  stamped on every finding as `scopeId`; see [SAFETY.md](./SAFETY.md) §2).

The operator is present for the run and is the person who triggers the kill switch above.

## Operating rules

- **No public, real-world, or non-consenting targets, ever.** The challenge supplies an
  isolated lab; that is the only class of target.
- **Credentials authenticate; they never widen scope.** They are provided at runtime
  and never committed.
- **Runs are bounded.** A per-run budget cap (via the Bifrost gateway) and a step cap
  halt the loop; the budget cap halting a runaway loop is surfaced live in the trace.
- **Out-of-scope access is treated as a hard failure**, not a warning — consistent with
  the challenge rule that it is an automatic disqualification.

Everything here is legitimate, clearly-scoped security engineering intended for
authorized testing only.
