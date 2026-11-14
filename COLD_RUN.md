# Cold-target dry run — intervention log

The test everyone skips: point the agent at a **fourth, unfamiliar** vulnerable
app — one whose source none of us has read — and run it blind, logging every
moment we were tempted to step in. This is the honest version of the thing judges
actually worry about: not "does the rehearsed demo work," but "what does it do
when it meets something it wasn't tuned for."

- **Target:** OWASP Mutillidae II (`citizenstig/nowasp`), a PHP 5.5.9 / Apache
  2.4.7 app. We had never run it or read its source. Chosen precisely because its
  stack is one Nightfall does **not** special-case (no Express banner to
  re-ground on) — a real graceful-degradation test, not a home-field demo.
- **Setup (operator, not source-reading):** `docker run -p 8899:80`, then hit the
  app's own `set-up-database.php` to initialize its DB. Scope: loopback host,
  `/` allowed, `/logout.php` + `/set-up-database.php` denied, \$3 budget, 30 steps.
- **Date:** 2026-11-14.

## What happened, and every time we almost intervened

**Run 1 — 0 findings, and every probe failed.** Recon and hypothesis worked
cleanly (fingerprinted Apache 2.4.7 + PHP 5.5.9, pulled live CVEs via Tavily), but
_every single exploit attempt_ returned `transport error: fetch failed`. The run
abandoned all 30 steps with nothing.

> **Intervention point #1.** The obvious move was to shrug: "the lab's broken,
> try another." We didn't — a cold run that surfaces a failure is doing its job.
> We investigated instead.

**Misdiagnosis, and backing it out.** The error was
`ERR_SSL_WRONG_VERSION_NUMBER` — a TLS handshake against a plaintext port. First
hypothesis: undici's shared connection pool reusing a TLS socket (from the HTTPS
calls to Tavily) for the plaintext target. We added a per-session connection pool
to isolate it — and re-ran. **It still failed.**

> **Intervention point #2.** A wrong fix that doesn't work is a fork in the road:
> layer another guess on top, or revert and re-diagnose. We reverted the whole
> change (including the new dependency) rather than keep a fix that didn't earn
> its place.

**Root cause.** The real trigger: the actual request URL had become
`https://localhost:8899/…`. Mutillidae enforces SSL **per session**, via a
`?do=toggle-enforce-ssl` link in its own navigation. Our **recon crawler was
firing that link** — a state-changing GET — which flipped the agent's own session
into "redirect everything to https," and since the lab only exposes plaintext, every
later probe hit an unreachable TLS endpoint. We confirmed it in isolation:
`login.php` returned 200 _before_ recon and failed _after_ recon. The agent was
sabotaging itself.

This is a genuine reliability bug **and** an ethos violation: recon is supposed to
be read-only, and firing `toggle-enforce-ssl` / `logout` is a state change.

**The fix (shipped).** Recon now refuses to fire state-changing links —
`logout`, `?do=toggle|reset|clear|enable|disable|delete|destroy`,
`?action=delete|logout|reset` — both as crawl targets and as recorded attack
surface. A regression test locks it. This keeps recon passive, which is what the
safety story already claimed.

**Run 2 — healthy.** After the fix: **0 transport failures** (down from 27), real
probes reaching live `200`s, the scope gate correctly **blocking 2** out-of-scope
requests, and a clean, bounded halt on `exhausted` instead of thrashing a dead
session. Wall-clock: 41.8s (recon 2%, hypothesis 37%, exploit 60%).

> **Intervention point #3.** Still 0 confirmed findings. The tempting fix: point
> the scope at a Mutillidae endpoint we _know_ is vulnerable, to manufacture a win.
> We declined — that is exactly the rehearsed demo this exercise exists to avoid.

## The honest result

- **A real bug, found and fixed** that a cold target exposed and our three
  home labs never would have (none of them weaponize their own navigation against
  a crawler).
- **The reliability posture held the whole time:** zero out-of-scope requests
  (2 correctly blocked), no crash, per-attempt recovery (retry → abandon), and a
  bounded termination. The failures were _graceful_, which is the claim.
- **Zero confirmed findings, and we know why:** Nightfall's probe set is
  deliberately narrow and hand-written (see [LIMITATIONS.md](./LIMITATIONS.md) §6),
  and on an untuned target the model also proposed out-of-domain techniques
  (buffer overflow on a PHP web app) that the closed read-only `switch` doesn't
  implement. On a cold target, no confirmation without tuning is the _expected_
  outcome of that safety tradeoff — not a surprise we're hiding.

## What this run would need to be stronger

- A **non-builder** running it blind (we ran it ourselves; the discipline is
  honored, the full effect — an independent tester's intervention log — is not).
- Either a cold target whose easy wins fall inside the current probe set, or a
  broadened (still reviewed, still read-only) probe set — a deliberate increment,
  not a demo-day hack.
