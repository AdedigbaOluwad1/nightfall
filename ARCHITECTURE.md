# Architecture

Nightfall puts a deny-by-default scope gate in front of every network action, then
runs a six-step loop — recon → hypothesis (grounded via Tavily) → exploit → interpret
→ evidence → report — until the objective is reached or the step/budget cap is hit.
Every model call flows through the Bifrost gateway for routing, budgeting, and cost
accounting, and a two-tier session layer (stateful HTTP and a Playwright browser) sits
behind one `Session` interface so the loop never cares which tier is live. The event bus
is the backbone: every module emits typed events, and the CLI, web view, and evidence
store are sinks.

**Scope safety.** The gate is deliberately outside the LLM — pure, deterministic,
deny-by-default, and it refuses encoded path-traversal so an escaped prefix can't
leak. See [AUTHORIZATION.md](./AUTHORIZATION.md).

**Evidence & report.** Evidence is captured as it happens into an append-only JSONL
log (`evidence/store.ts`) — the durable source of truth the report reads back, by
merging each request/response pair into the finding it supports. The report generator
(`report/`) emits a client-ready document: markdown is canonical (zero dependencies),
with HTML (`toHtml`, via `marked`) and PDF (`toPdf`, via an opt-in puppeteer) layered
on top. Every finding carries evidence, CVSS severity, and remediation.

See [NIGHTFALL.md](./NIGHTFALL.md) for the full data-flow diagram and the win thesis.
