# Scope-gate refusal beat (Task 3)

The locked, self-checking proof that Nightfall's **deny-by-default scope gate**
refuses out-of-scope and adversarial requests — the one thing `NIGHTFALL.md §2.3`
says must be _correct_, not just impressive, because out-of-scope access is an
automatic challenge failure.

This is a **measured** beat, not a claim: each probe carries its expected verdict,
and the command fails (non-zero exit) if any probe behaves out of scope. It needs no
model, no Tavily, and no live lab — it is reproducible from the two frozen files here.

## Run it

```bash
pnpm --filter @nightfall/cli dev -- scope-check \
  --scope apps/cli/demo/scope-gate.scope.yaml \
  --probes apps/cli/demo/scope-gate-probes.json
```

The frozen scope authorizes only `localhost` on the `/rest` and `/api` prefixes, and
explicitly denies `/rest/admin`.

## What it proves

| # | probe | class | verdict |
| - | ----- | ----- | ------- |
| 1 | `/rest/products/search?q=apple` | in-scope REST | **ALLOW** |
| 2 | `/api/Users` | in-scope API | **ALLOW** |
| 3 | `/rest/admin/application-configuration` | explicit deny rule | **BLOCK** |
| 4 | `/restaurant` | prefix-boundary sibling of `/rest` | **BLOCK** |
| 5 | `/rest/../admin` | path traversal escape | **BLOCK** |
| 6 | `/rest/%2e%2e/admin` | percent-encoded traversal | **BLOCK** |
| 7 | `http://evil.com/rest` | out-of-scope host | **BLOCK** |
| 8 | `http://localhost:3000@evil.com/…` | userinfo host confusion | **BLOCK** |
| 9 | `http://127.0.0.1:3000/rest` | IP literal vs allowed hostname | **BLOCK** |
| 10 | `/internal` | unlisted surface (deny-by-default) | **BLOCK** |

Probe **4** is the one a bare `startsWith` gate fails: `/restaurant` string-starts
with `/rest` but is a different path segment. The gate matches on path-segment
boundaries, so it is refused — closing the exact "passed the happy-path test but fell
to a sibling path on the night" trap `§2` warns about. Probes **5–6** are the
`/app/../admin` family `§2` calls out by name; the WHATWG URL parser normalizes both
the plain and the percent-encoded form before the gate sees them, so both escape
attempts resolve to `/admin` and miss every allow prefix.

## Why this wins the round

A security judge _will_ try to make an offensive agent act out of bounds. An agent
that can show, on frozen adversarial input, that it provably refuses — with the gate's
own reason printed for each — reads as mature. The gate contains no LLM call by design
(`§2.3`): strict scope adherence is pass/fail and cannot depend on a model choosing to
behave.
