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
pnpm --filter @nightfall/cli dev -- run --scope packages/core/src/scope/example.scope.yaml
```

Measure Tavily's contribution with the ablation:

```bash
pnpm --filter @nightfall/cli dev -- ablate --targets apps/cli/example.targets.json
```

## Layout

- `packages/core` — event bus, scope gate, session layer, gateway, evidence, report.
- `apps/cli` — the streaming trace runner (`run`, `ablate`).
- `apps/web` — deferred projected demo view.
- `labs` — docker-compose practice targets (Juice Shop, DVWA, WebGoat).

## Reports

Findings are captured as they happen into an append-only JSONL evidence log, then
rendered to a client-ready report. Markdown is canonical and needs no extra
dependencies; HTML (`toHtml`) and PDF (`toPdf`) build on it. PDF export is opt-in:

```bash
pnpm add -D puppeteer   # only needed for toPdf; markdown/HTML need nothing extra
```

Each finding carries evidence, CVSS severity, and remediation. See a worked example
of the output shape in the demo materials.

## Testing

```bash
pnpm test          # vitest across the workspace
pnpm lint          # biome check .
```

The adversarial scope-gate suite (`packages/core/test/gate.test.ts`) proves the gate
denies every out-of-scope and traversal case, including encoded path-separators — it
must always stay green.

## Docs

- [NIGHTFALL.md](./NIGHTFALL.md) — source of truth (architecture, persona, plan).
- [DEMO.md](./DEMO.md) — the rehearsed 3-minute demo script and fallback plan.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — branching, PR flow, commit style, CI rules.
- [AUTHORIZATION.md](./AUTHORIZATION.md) — scope policy and safety.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — architecture overview.
