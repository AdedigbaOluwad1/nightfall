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
pnpm exec playwright install chromium
pnpm --filter @nightfall/cli dev -- --scope packages/core/src/scope/example.scope.yaml
```

## Layout

- `packages/core` — event bus, scope gate, session layer, gateway, evidence, report.
- `apps/cli` — the streaming trace runner.
- `apps/web` — deferred projected demo view.
- `labs` — docker-compose practice targets (Juice Shop, DVWA, WebGoat).

## Docs

- [NIGHTFALL.md](./NIGHTFALL.md) — source of truth (architecture, persona, plan).
- [AUTHORIZATION.md](./AUTHORIZATION.md) — scope policy and safety.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — architecture overview.