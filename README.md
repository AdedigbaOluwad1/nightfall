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

## Testing an auth-gated target

To test a login-gated app, add a `credentials` block to the scope file. The agent fetches
the login page, **auto-detects the form** — carrying any hidden CSRF token and the submit
control verbatim — posts the credentials, and then **verifies the session actually took**:
the trace shows a green `authenticated` or a red `LOGIN FAILED — probing continues
UNAUTHENTICATED`, so a broken login is never silently reported as an honest clean scan.

```yaml
# add to your scope file (array — one entry per auth boundary)
credentials:
  - boundary: user # a logical auth-boundary label; does NOT widen scope
    loginUrl: "http://localhost:8081/login.php"
    username: "admin"
    password: "password"
```

A ready-to-run example ships at
[`packages/core/src/scope/example.auth.scope.yaml`](./packages/core/src/scope/example.auth.scope.yaml)
(credentialed DVWA):

```bash
docker compose -f labs/docker-compose.yml up -d dvwa
# one-time: open http://localhost:8081/setup.php and click "Create / Reset Database"
pnpm --filter @nightfall/cli dev -- --scope packages/core/src/scope/example.auth.scope.yaml
```

Credentials authenticate an authorized test; they never relax the deny-by-default gate.
The login flow generalises across form shapes with no per-app tuning — a hidden-token +
named-submit form (DVWA), a `<button name=…>` submit (bWAPP), and a Spring Security form
with no submit button and no CSRF (WebGoat) all authenticate; a JS-driven login escalates
to the Tier-2 headless browser, which verifies the session the same way. Once in, every
probe runs with the authenticated session — these are the `credentialed` rows in
[Results across labs](#results-across-labs).

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
- **The re-grounding is a generic mechanism, not Juice-Shop logic.** Any confirmed
  probe that surfaces a new `component@version` re-queries Tavily for it (deduped,
  budget-guarded) — there is no per-lab branch (`loop/agent.ts`). What feeds it
  mid-chain today is one disclosure extractor: the injection error-page banner (the
  `(framework version)` shape an error leaks). Passive recon still fingerprints headers,
  cookies, and `generator` meta generically at the start; broadening the set of
  _mid-chain_ leak patterns is additive and named in [LIMITATIONS.md](./LIMITATIONS.md).

How each Challenge 03 requirement is met is mapped in [NIGHTFALL.md](./NIGHTFALL.md).

## Results across labs

Nightfall was run against nine intentionally-vulnerable apps spanning four languages and
four surface types, with no code tuned to any target. Every finding is **control-verified**
— the signal is present under the payload and **absent** under an otherwise-identical
benign request — so the table carries no false positives, and the two zeros are reported
with their specific cause, not a vague "gated".

| Lab        | Stack        | Surface        | Auth           | Findings                                                                                            |
| ---------- | ------------ | -------------- | -------------- | --------------------------------------------------------------------------------------------------- |
| Mutillidae | PHP          | HTML           | unauth         | **14** — 6 SQLi, 7 XSS, 1 LFI                                                                       |
| DVWA       | PHP          | HTML form      | credentialed   | **5** — 2 SQLi, 2 XSS, 1 cmdi                                                                       |
| DVNA       | Node/Express | HTML form      | credentialed   | **4** — 2 SQLi, 1 cmdi, 1 XSS                                                                       |
| Juice Shop | Node/Express | SPA + REST     | unauth → chain | **3** — SQLi, auth-bypass, BAC priv-esc                                                             |
| DVGA       | Python       | GraphQL        | unauth         | **2** — SQLi, cmdi                                                                                  |
| VAmPI      | Python/Flask | REST (OpenAPI) | unauth         | **1** — SQLi (path param)                                                                           |
| BodgeIt    | Java/JSP     | HTML           | unauth         | **1** — reflected XSS                                                                               |
| bWAPP      | PHP          | HTML           | credentialed   | **0** — login succeeds; injectable pages sit behind a bug-selection form the crawler does not drive |
| WebGoat    | Java/Spring  | lesson SPA     | credentialed   | **0** — login succeeds; interactive lesson endpoints a flat crawler does not reach                  |

Thirty confirmed findings across seven labs, plus two honest zeros — each a named,
specific limitation, not a shared "gated" label. The per-lab narrative — including the
one login-flow bug that once hid behind three of these labs, and the nav-menu
false-positive class since removed from the SQLi detector — is in
[COLD_RUN.md](./COLD_RUN.md).

## Layout

- `packages/core` — event bus, scope gate, session layer, gateway, evidence, report.
- `apps/cli` — the streaming trace runner.
- `apps/web` — live view (vite + react) over the `serve` WebSocket.
- `labs` — docker-compose practice targets (Juice Shop, DVWA, WebGoat).

## Docs

- [NIGHTFALL.md](./NIGHTFALL.md) — project overview and how each requirement is met.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — full system design.
- [AUTHORIZATION.md](./AUTHORIZATION.md) — scope policy and safety.
- [SAFETY.md](./SAFETY.md) — trust model: fail-safe, attributability, no new risk.
- [STATE_MACHINES.md](./STATE_MACHINES.md) — state machines + reliability invariants.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — branching, PR flow, commit style, CI rules.
