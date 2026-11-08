# Nightfall

Nightfall is an autonomous web-application pentest agent built for the Geek Room
Global AI Hackathon (Track A / Challenge 03). It runs **only** against authorized,
isolated targets described by a scope file, behind a deny-by-default scope gate.

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

See [AUTHORIZATION.md](./AUTHORIZATION.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).
The full PRD lives alongside this repo.
