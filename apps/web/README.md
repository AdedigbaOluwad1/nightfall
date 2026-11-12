# Nightfall web view — Control Centre

A live projected view of a run, styled as a dark mission console: the live trace on
the left, the Bifrost / Tavily / scope "receipts" as a control-list of readouts on the
right, and a running status ticker along the bottom. One emerald signal carries
armed / live / confirmed; everything else is graphite and hairlines. Dark-first with a
full light theme (toggle, top-right) and `prefers-color-scheme` respected.

It is a thin sink on the same `@nightfall/core` event stream the CLI renders — the
CLI's `serve` command runs the loop and forwards every typed event over a WebSocket,
and this vite + react app subscribes and renders.

## Run it

Two processes:

```bash
# 1. Run the loop and stream events (bring up a lab first, e.g. juiceshop).
pnpm --filter @nightfall/cli dev -- serve --scope packages/core/src/scope/example.scope.yaml

# 2. Open the view (http://localhost:5317).
pnpm --filter @nightfall/web dev
```

The view connects to `ws://localhost:4317` by default; override with `?ws=` in the URL
(e.g. `http://localhost:5317/?ws=ws://host:4317`). It reconnects on its own, and a
late-joining view still receives the full run because `serve` replays the backlog.
