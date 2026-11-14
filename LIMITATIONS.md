# Where this breaks

An honest list of what Nightfall does **not** do well, surfaced by our own
adversarial testing. Each item is stated with the failure, the reason, the fix,
and the tradeoff we chose — because a named limitation is evidence of rigor, and
a hidden one is a liability a reviewer finds live. See [SAFETY.md](./SAFETY.md)
for the properties that _do_ hold.

The three items we judged cheap, clear wins are **already closed** (see the last
section) — we'd rather fix what we can than pad the list. What remains below is
genuine design tradeoffs, not unfinished work.

## 1. DNS rebinding of a _listed_ host (TOCTOU)

**What breaks.** The scope gate authorizes by **hostname**, not resolved IP. A
hostname that is in `allow.hosts` but whose DNS record flips between the gate check
and the socket connect could, in principle, resolve to a different address the
second time.

**Why.** Hostname is the unit of authorization in the scope file, and Node's fetch
resolves DNS itself at connect time — the gate does not pin the IP it validated.

**What a fix takes.** Resolve once, validate the resolved IP, and pin it for the
connection (custom lookup / agent).

**The tradeoff.** For the mandated scope this is **already closed**: the lab is
loopback-only (`allow.hosts: [localhost]`), and an unlisted host or a bare IP
literal is refused by deny-by-default — so the dangerous rebind (to a metadata or
private IP) can't be reached at all. The only residual is a _listed_ hostname's own
DNS flipping, i.e. the operator rebinding their own isolated lab against themselves.
Named, not dressed up as resolved.

## 2. Several finding classes are signal-based, not impact-confirmed

**What breaks.** Reflected XSS, CSRF, and the generic exposure class are confirmed
by a **signal** (an unencoded reflected marker, a missing anti-CSRF token, an
anomalous disclosure), not by driving the impact to completion. Reflected XSS, in
particular, is not executed in a headless browser as a matter of course.

**Why.** Executing every candidate end-to-end (popping a real XSS, forging a real
cross-site request) adds cost and risks crossing from "read-only probe" into state
change — the exact line the safety model draws.

**What a fix takes.** A headless-browser confirmation stage for the reflection
classes. The machinery exists (Tier 2 is wired, §SPA below), so this is a
deliberate, reviewed increment — not a flag flip.

**The tradeoff.** We prefer to **under-claim**: every finding states its
verification basis explicitly (SAFETY.md §7), so a signal-based finding is never
dressed up as an exploited one. Impact-confirmed classes (SQLi auth bypass,
privilege escalation, command injection, traversal) are labeled as such.

## 3. The probe set is narrow by design

**What breaks.** Nightfall is **not** a generalized exploit toolkit. It carries a
small set of hand-written, read-only checks in one closed `switch`
(`loop/actions.ts`); vulnerability classes outside that set are not attempted.

**Why.** This is the central safety decision, not an oversight: generalizing to a
consequential action requires _adding a reviewable check to that switch_, never
flipping a flag (SAFETY.md §4). A cold-target run (`COLD_RUN.md`) confirmed the
honest consequence: on an untuned target, the agent degrades gracefully and
confirms nothing rather than firing payloads it can't reason about.

**The tradeoff.** We chose provable, auditable narrowness over broad, unbounded
offense. Coverage grows by deliberate, reviewed additions — the safety property
does not depend on the lab being disposable.

## Closed since the first audit

These were on this list; we fixed them rather than excuse them.

- **Soft budget cap → bounded.** The budget now runs a **reserve check**: the
  worst-case cost of a call (prompt tokens + a full completion) is estimated and
  charged against the cap _before_ the call is made (`budget.ts` `assertCanAfford`,
  `bifrostClient.ts`). The call that would cross the cap is never issued, so
  overshoot is zero rather than "bounded by one in-flight call."
- **SPA 200-shell auth wall → reachable on Tier 2.** An unproven Tier-1 result now
  escalates to a real headless browser (`browserSession.ts`), which renders the
  page, **settles after load so a client-side redirect completes**, and re-probes
  the post-JS DOM — so a shell that redirects in JavaScript is no longer invisible.
- **Full per-request audit log → persisted.** The complete event stream (every
  request, plan decision, block, and gateway call — not only findings) is now
  written append-only to `*.audit.jsonl` as it happens (`events/audit.ts`), so a
  run is replayable end-to-end, not just its confirmed findings.

## What our testing still can't substitute for

- A **non-builder** running a cold target blind (we ran it ourselves; see
  `COLD_RUN.md`), and an independent reproduction of a finding from the README
  alone. These are human checks, not code we can ship.
