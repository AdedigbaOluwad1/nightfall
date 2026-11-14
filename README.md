# Nightfall

Nightfall is an autonomous web-application pentest agent built for the Geek Room
Global AI Hackathon (Track A / Challenge 03). It runs **only** against authorized,
isolated targets described by a scope file, behind a deny-by-default scope gate.

> **Start here:** [NIGHTFALL.md](./NIGHTFALL.md) is the project's source of truth —
> the win thesis, operating persona, full architecture diagram, the agent loop, and
> how every piece fits. When anything is unclear, that document is the answer.

## Quickstart

```bash
pnpm install
pnpm exec playwright install chromium   # only needed for the Tier-2 browser session
pnpm --filter @nightfall/cli dev -- --scope packages/core/src/scope/example.scope.yaml
```

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

Current build status per rubric row is tracked in [`PRE_SUBMISSION.md`](./PRE_SUBMISSION.md).

## Layout

- `packages/core` — event bus, scope gate, session layer, gateway, evidence, report.
- `apps/cli` — the streaming trace runner.
- `apps/web` — deferred projected demo view.
- `labs` — docker-compose practice targets (Juice Shop, DVWA, WebGoat).

## Docs

- [NIGHTFALL.md](./NIGHTFALL.md) — source of truth (architecture, persona, plan).
- [CONTRIBUTING.md](./CONTRIBUTING.md) — branching, PR flow, commit style, CI rules.
- [AUTHORIZATION.md](./AUTHORIZATION.md) — scope policy and safety.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — architecture overview.
