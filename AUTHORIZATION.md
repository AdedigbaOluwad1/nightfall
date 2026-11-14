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
