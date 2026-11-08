# Architecture

Nightfall puts a deny-by-default scope gate in front of every network action, then
runs a six-step loop — recon → hypothesis (grounded via Tavily) → exploit → interpret
→ evidence → report — until the objective is reached or the step/budget cap is hit.
Every model call flows through the Bifrost gateway for routing, budgeting, and cost
accounting, and a two-tier session layer (stateful HTTP and a Playwright browser) sits
behind one `Session` interface so the loop never cares which tier is live. The event bus
is the backbone: every module emits typed events, and the CLI, web view, and evidence
store are sinks.

See the PRD diagram for the full data flow.
