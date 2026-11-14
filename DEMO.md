# DEMO — the rehearsed 3 minutes

> **What this is.** The beat sheet for judging day and the **recordings that back each
> beat**, so the demo is never hostage to a live run, a live model, or live quota
> (`NIGHTFALL.md §2.5`: a rehearsed 3-minute demo, not a hopeful 6-minute terminal
> scroll; §2 names "a demo held hostage to a live run with no recording" as a way
> teams lose). Every beat below names the command, the one line to say, the payoff a
> judge sees, the rubric row (`§4`) it satisfies, and a captured transcript to fall
> back on. Run order is deliberate: open on the thing that is pure correctness
> (scope), land the autonomous run, then prove the sponsors are load-bearing.

---

## Beat 1 — Scope is sacred (0:00–0:40) · rubric: respect scope strictly

**Say:** "Before it attacks anything, it proves it can't act out of bounds."

```bash
pnpm --filter @nightfall/cli dev -- scope-check \
  --scope packages/core/src/scope/example.scope.yaml \
  --url http://localhost:3000/logout \
  --url http://evil.example.com/ \
  --url "http://localhost:3000/foo/%2e%2e/logout"
```

**Payoff:** every adversarial probe behaves as scoped — an out-of-scope host, a denied
surface, plain and encoded traversal — each refused with the gate's own reason. The
command exits non-zero on any out-of-scope behavior, so this is a measured proof.
**No model, no lab, no quota.**

---

## Beat 2 — Hit go on a cold target and step back (0:40–1:40) · rubric: enumerate / interpret-recover / complete objective / client-ready report

**Say:** "Now I point it at a lab and take my hands off the keyboard."

```bash
docker compose -f labs/docker-compose.yml up -d juiceshop
pnpm --filter @nightfall/cli dev -- --scope packages/core/src/scope/example.scope.yaml
```

**Payoff:** the trace streams recon → fingerprint → attempt → a **confirmed finding**
(unauthenticated access to `/rest/admin/application-configuration` — Broken Access
Control) → objective reached → a client-ready report drops to disk. It completes with
no human nudge and halts cleanly (`halted: objective`).

---

## Beat 3 — Tavily, measured (1:40–2:20) · rubric: meaningful Tavily use

**Say:** "We don't assert Tavily helps — we measured it, two ways, from frozen input."

- **Freshness:** grounded surfaces **5** post-cutoff CVEs on WebGoat vs **0** ungrounded.
- **Citation validity:** grounded recovers the **full Log4Shell chain (4/4)** vs the
  bare model's 2.

```bash
# (regenerate live when quota is available)
pnpm --filter @nightfall/cli dev -- ablate --targets apps/cli/reference.targets.json
```

---

## Beat 4 — Bifrost, load-bearing (2:20–2:50) · rubric: meaningful Bifrost use

**Say:** "Every model call routes through Bifrost — real cost, a budget cap that halts
a runaway loop, and routing a raw key can't do."

- **Real cost:** every call is priced from Bifrost's live `/v1/models` catalog,
  source-tagged on `gateway.call` — no faked numbers.
- **Budget cap:** a low cap emits a `budget.exceeded` beat and halts the loop live
  (`⛔ budget … halting`), with `halted: budget` on the summary.
- **Cache:** the `cache-demo` subcommand proves the client is cache-correct; enabling
  the semantic cache is a Bifrost deployment detail on this single-container instance
  (documented honestly, not faked).

---

## Beat 5 — Close (2:50–3:00)

**Say:** "A report a consultant would sign, from an agent that provably stays in bounds
— and we'll tell you exactly what's measured versus still in flight."

---

## Honesty notes (say these if asked — they win trust, they don't lose it)

- **Grounding is currently quota-blocked live.** On the free Cloudflare tier (10k
  neurons/day, account-wide) the model 429s, so a live cold run degrades to ungrounded
  — and the trace **says so** (`⚠ grounding … degraded, running ungrounded`) rather
  than hiding it. The Tavily _value_ is shown via the frozen ablation (Beat 3); the
  live causal link (a Tavily CVE → a finding) is the one beat still gated on quota.
- **The cache hit is code-proven, not live** on this Bifrost deployment.
- Recon is an in-scope crawler with header/cookie/body fingerprinting plus optional
  `httpx` tech-detect — not a `nuclei`/`ffuf` wrapper.

Full per-row status: [`PRE_SUBMISSION.md`](./PRE_SUBMISSION.md).
