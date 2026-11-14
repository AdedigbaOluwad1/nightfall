# Nightfall — Project Overview

Nightfall is an autonomous agent that performs an **authorized, black-box penetration
test** of a web application with no human at the keyboard. Given a scope file and a
target, it enumerates only in-scope surface, forms vulnerability hypotheses grounded in
live data (Tavily), attempts them, interprets the results, recovers from failures on its
own, and produces a client-ready report (findings, evidence, CVSS severity, remediation).
Every model call routes through the Bifrost gateway for cost-aware routing, a per-run
budget cap, and caching. A deny-by-default scope gate sits in front of everything so the
agent provably cannot act out of bounds.

For how the system is built, see [ARCHITECTURE.md](./ARCHITECTURE.md). For the safety and
authorization model, see [AUTHORIZATION.md](./AUTHORIZATION.md). To run it, see the
[README](./README.md).

## Context & authorization

Nightfall is an entry for the Geek Room Global AI Hackathon 2026, **Track A / Challenge
03 — autonomous penetration-testing agent, isolated lab only**, using the Bifrost and
Tavily integrations.

The agent runs **only** inside an isolated lab the operator or organizer supplies — the
scope file, the target, and the objective are provided; no public, real-world, or
non-consenting systems are ever in scope. This repository is a control loop, a crawler, a
session layer, an LLM-gateway client, a web-research client, an evidence/report pipeline,
and a deny-by-default safety gate. It contains no generalized exploit toolkit; attempt
logic is written narrowly against the sanctioned lab. Everything here is clearly-scoped
security engineering.

## Challenge requirements

Challenge 03 requires an agent that: enumerates only authorized hosts/ports/services/
versions with real tools; interprets tool output, chooses next actions, and recovers from
failed attempts; completes the lab objective, including multi-step exploitation where
allowed; **respects the scope file strictly — out-of-scope access is an automatic
failure**; and produces a client-ready report with findings, evidence, severity, and
remediation. Every submission must make **meaningful use of both Bifrost and Tavily**. On
judging day the target, scope, and objective may be unfamiliar, and the isolated lab is
supplied by the judges.

## How each requirement is met

| Requirement                                       | Feature                                                                 | How it's demonstrated                                                       |
| ------------------------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Enumerate only authorized surface with real tools | Scope gate + in-scope crawler with fingerprinting; optional `httpx`     | Recon trace shows only in-scope targets; every request passed the gate      |
| Interpret output, choose next actions, recover    | Stateful decide/recover loop                                            | Live trace: a failed attempt, a pivot, a recovery — autonomously            |
| Complete the objective, incl. multi-step          | Objective tracker; loop runs to objective or cap                        | Agent reaches the planted objective on an unfamiliar lab                    |
| Respect scope strictly (out-of-scope = auto-fail) | Hard-coded deny-by-default gate, no LLM inside, enforced at both layers | `scope-check` refuses adversarial out-of-scope probes; audit log shows none |
| Client-ready report                               | Report generator over structured findings                               | Markdown report with CVSS, evidence, and remediation per finding            |
| Meaningful Bifrost use                            | Gateway: routing, real per-call cost, budget cap, cache                 | On screen: cost per run, a cache hit, a budget cap halting a runaway loop   |
| Meaningful Tavily use                             | Live CVE/advisory grounding + a measured ablation                       | Grounding changes the finding; measured grounded-vs-ungrounded numbers      |
| Safety & authorization docs                       | AUTHORIZATION.md + the scope-enforcement design                         | Present and clear; deny-by-default explained                                |

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the design behind each feature.
