# Nightfall

Nightfall is an autonomous **black-box** web-application pentest agent built for the
Geek Room Global AI Hackathon (**Track A / Challenge 03**, with the Bifrost and Tavily
integrations). You hand it a scope file — a target URL and an objective, **no
credentials and no prior knowledge of the stack** — and it fingerprints, hypothesizes,
exploits, and reports on its own. It runs **only** against authorized, isolated targets
described by that scope file, behind a deny-by-default scope gate.

> Authenticated testing is supported (an optional `credentials` block in the scope
> file) but is **off by default** — the judged demo is zero-credential, zero-knowledge.

> **Start here:** [NIGHTFALL.md](./NIGHTFALL.md) is the project overview (what it is,
> the challenge, and how each requirement is met); [ARCHITECTURE.md](./ARCHITECTURE.md)
> is the full design — the scope gate, the agent loop, the session tiers, and how
> Bifrost and Tavily fit in.

## Quickstart

```bash
git clone https://github.com/AdedigbaOluwad1/nightfall.git
cd nightfall
pnpm install
pnpm exec playwright install chromium   # only needed for the Tier-2 browser session
cp .env.example .env                     # then add your own Bifrost + Tavily keys

# Bring up a practice lab and point the agent at it:
docker compose -f labs/docker-compose.yml up -d juiceshop
pnpm --filter @nightfall/cli dev -- --scope packages/core/src/scope/example.scope.yaml
```

Bring your own API keys: a Bifrost gateway endpoint (`BIFROST_BASE_URL` +
`BIFROST_API_KEY`) and a `TAVILY_API_KEY`. See `.env.example` for the full list,
including the `NF_MODEL_*` routing roles.

The default `run` drives the full autonomous loop against a lab (bring one up with
`docker compose -f labs/docker-compose.yml up -d juiceshop`) and needs model quota.
It writes findings to `nightfall-findings.jsonl` and auto-writes a Markdown report
beside it.

## Demo beats (reproducible)

The two model-free beats run from a clean clone with no lab and no API quota — each is
a **measured** proof, not a claim:

```bash
# Scope safety: the deny-by-default gate refuses adversarial out-of-scope probes.
pnpm --filter @nightfall/cli dev -- scope-check \
  --scope packages/core/src/scope/example.scope.yaml \
  --url http://localhost:3000/logout \
  --url http://evil.example.com/ \
  --url "http://localhost:3000/foo/%2e%2e/logout"

# Client-ready report: render a signed-quality report from a run's evidence JSONL.
pnpm --filter @nightfall/cli dev -- report \
  --in nightfall-findings.jsonl --target http://localhost:3000/
```

The Tavily grounding proof needs model quota:

```bash
# Grounded-vs-ungrounded ablation (freshness + citation validity).
pnpm --filter @nightfall/cli dev -- ablate --targets apps/cli/reference.targets.json
```

## What Bifrost does (and a raw API key can't)

- **Real per-call cost.** Every model call is priced from Bifrost's live `/v1/models`
  catalog and tagged on the `gateway.call` event — no estimated or faked numbers.
- **A budget cap that halts a runaway loop.** Spend accumulates against the scope's
  `budgetUsd`; crossing it raises a typed `BudgetExceededError` the loop catches and
  halts on (`halted: budget`) — proven live, not a mocked check.
- **Model-tier routing + cache.** `NF_MODEL_CHEAP`/`STRONG`/`WRITE` route per step
  through one gateway; the client reads the `x-bifrost-cache-hit` header so a repeated
  call is served at $0.

## What Tavily does (and the bare model can't)

- **Grounds hypotheses in current advisories.** For each fingerprint, Tavily retrieves
  live CVE/advisory pages that seed the exploit-technique ranking.
- **It is load-bearing, measured two ways** (not asserted): grounded-vs-ungrounded
  **freshness** (WebGoat 2026.5: grounded surfaces 5 post-cutoff CVEs vs 0) and
  **citation validity** (Log4j: grounded recovers the full Log4Shell chain 4/4 vs 2).
- **It re-grounds mid-run as the surface expands.** On a cold Juice Shop run the
  agent's first probe forces a DB error that leaks `Express ^4.22.1` — a fingerprint
  passive recon never saw. Grounding on, it re-queries Tavily _mid-chain_ and the
  disclosed stack scores **2/2 valid CVE citations, one of them a post-cutoff 2026 CVE**;
  grounding off, the bare model still cites CVEs but **0/2 are valid** (hallucinated).
  Both runs reach the objective via the deterministic chain — grounding is what keeps
  the expanding surface real and current. Measured by `ablate` (active-disclosure row).

How each Challenge 03 requirement is met is mapped in [NIGHTFALL.md](./NIGHTFALL.md).

## Layout

- `packages/core` — event bus, scope gate, session layer, gateway, evidence, report.
- `apps/cli` — the streaming trace runner.
- `apps/web` — live view (vite + react) over the `serve` WebSocket.
- `labs` — docker-compose practice targets (Juice Shop, DVWA, WebGoat).

## Docs

- [NIGHTFALL.md](./NIGHTFALL.md) — project overview and how each requirement is met.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — full system design.
- [AUTHORIZATION.md](./AUTHORIZATION.md) — scope policy and safety.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — branching, PR flow, commit style, CI rules.
