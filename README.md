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

## Prerequisites

- **Node.js 20+** (developed on 22) and **pnpm 11+** — the repo pins `pnpm@11.25.0`.
- **Docker + Docker Compose** — to bring up the intentionally-vulnerable practice labs.
- **Real API keys for a genuine run:** a Bifrost gateway (`BIFROST_BASE_URL` +
  `BIFROST_API_KEY`) and a `TAVILY_API_KEY`. These are **required**, not optional — see
  the warning below.

> **A run without a working model key does not error — it degrades.** `.env.example`
> ships placeholder values; copying it without filling in real keys lets the loop run on
> its **deterministic probe floor** with no model planning and no live CVE grounding. Such
> a run is now marked **`DEGRADED`** — loudly in the terminal summary and as a banner at
> the top of the report, with `model calls: 0` — so a `$0.00`, no-model run can never be
> mistaken for the AI-driven result. For a genuine, grounded run, set real keys first.

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

**Cheapest zero-config demo (OWASP Bricks).** For the fastest reproducible run — a
tiny PHP/MySQL app, unauth, ~15 steps to two findings — use the helper, which boots
the container and provisions its database (waiting for MySQL _and_ Apache first, so a
half-started lab can't silently serve "Unable to connect"):

```bash
scripts/pull-legacy-image.sh citizenstig/owaspbricks:latest   # one-time: its manifest is schema1
./labs/bricks/up.sh                                            # boot + provision + verify
pnpm --filter @nightfall/cli dev -- --scope demo-bricks.scope.yaml   # → SQLi + reflected XSS
docker rm -f nf-demo                                           # tear down
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

### Two-principal broken-access-control differential

List the **lower-privilege** account first and mark a second `role: "admin"`, and the
agent runs a vertical function-level-authorization check: a surface the low-privilege
principal reaches is a finding only when it is privilege-denoting (admin/management/
config), an anonymous request to it is **denied**, and the elevated principal also
serves it. Each gate rejects a false-positive class a keyword match cannot — public
pages, authorized admin use, per-user resources — so this never reintroduces the
reachable-plus-keyword flood. A failed login collapses to anonymous and confirms
nothing. Validated end-to-end against DVNA's `/app/admin` (reachable by a non-admin
user, denied to anonymous → Impact-confirmed); its reach is bounded by what recon
discovers — see [LIMITATIONS.md](./LIMITATIONS.md) §4.

```yaml
credentials:
  - boundary: user # listed first = the principal under test (lower privilege)
    loginUrl: "http://localhost:8087/login"
    username: "nfuser"
    password: "Passw0rd!"
    role: user
  - boundary: admin # the elevated baseline
    loginUrl: "http://localhost:8087/login"
    username: "nfadmin"
    password: "Passw0rd!"
    role: admin
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

# Client-ready report: render a signed-quality report from a real run's evidence.
# apps/cli/sample.findings.jsonl is a committed Juice Shop run (3 findings, one chain) —
# so this renders with no lab, no quota, and no prior run of your own.
pnpm --filter @nightfall/cli dev -- report \
  --in apps/cli/sample.findings.jsonl --target http://localhost:3000/ \
  --objective "Find and prove an injection or access-control flaw"
```

Your own `run` writes `nightfall-findings.jsonl`; point `report --in` at that to render
a report for a run you drove yourself.

> `run` auto-writes the report to a file beside the evidence; the standalone `report`
> command prints to stdout by default (it is a filter) — pass `--out <path>` to write it
> to a file instead.

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
- **Per-role, multi-provider model routing + cache.** The gateway maps three step roles to
  three independently-configured models — `NF_MODEL_CHEAP` (classification), `NF_MODEL_STRONG`
  (exploit reasoning), `NF_MODEL_WRITE` (report) — and **each role can name a different model
  on a different provider**, all behind the one Bifrost endpoint, swappable without touching
  code (`modelForStep` in `gateway/routing.ts`). `.env.example` ships ready-to-use configs for
  Gemini, Cloudflare Workers AI **Llama 3.3 70B** (`cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast`),
  local Ollama, and the flagship, and any role can point at any of them.
  **Honest scope of what runs today:** the loop's model calls all go through the `exploit_reason`
  role (the planner and the Tavily-grounded hypothesis step); **classification and report
  generation are deterministic and make no model call**, so the `CHEAP` and `WRITE` roles are
  wired and ready but currently idle. The practical lever is therefore `NF_MODEL_STRONG`: point
  it at Cloudflare Llama and the whole run's model load moves off the Gemini quota onto the
  Cloudflare neuron budget — verified on the XVWA cold run (41/41 calls on Llama 3.3 70B, 0 on
  Gemini, no 429, two findings). Each call is tagged on the `gateway.call` event with the exact
  model that served it, so the backend split is observable, not asserted; the client reads the
  `x-bifrost-cache-hit` header so a repeated call is served at $0.

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

## What the model does that the deterministic floor can't

The detection floor is a fixed battery: every probe injects a **fixed** payload set
(`' OR '1'='1`, `0/**/OR/**/1=1`, `../etc/passwd`, …). That makes it reliable and
quota-free — but a server-side input filter that neutralizes those fixed payloads
defeats it, however injectable the sink actually is. This is the one place model
reasoning is **load-bearing for detection**, not just planning:

- **Filter-bypass payload synthesis, confirmed by the app's own differential.** When a
  SQLi probe draws no signal yet the parameter still visibly reacts to input, the loop
  hands the model the filter's observed behaviour and asks for boolean-oracle bypass
  pairs. The model's payloads are **never trusted on its word** — each is confirmed only
  when its true-leg reproduces the application's own row-present fingerprint and its
  false-leg suppresses it. A hallucinated payload that does not actually work yields no
  finding, so this adds a capability with **zero false-positive surface** (`loop/actions.ts`,
  `modelBypassConfirm`).
- **Proven on a target the floor is blind to.** sqli-labs **Less-25a** is a numeric
  **blind** SQLi (no error echoed) behind a filter that strips `or`/`and`. The fixed probes
  fail both ways: the `'"` error probe raises no visible error, and `0 OR 1=1` is rewritten
  to `0  1=1` (broken). The model reasoned out a **compound** bypass —
  `0/**/oorr/**/1=1` (keyword-doubling survives one strip → `or`, inline comments stand in
  for filtered spaces) — and the engine confirmed it against the app's true/false split.
  The trace shows it as a distinct `ADAPT` step; the floor alone returns nothing here, and a
  regression test locks both directions (`actions.test.ts`).
- **Generalizes across injection context and a stricter filter.** The same mechanism also
  confirmed sqli-labs **Less-26a** — a **string**-context blind SQLi wrapped in parentheses
  (`WHERE id=('$id')`) behind a WAF that strips spaces, comments, and `or`/`and` outright. A
  quote-context probe (`'` appended) tells the engine the sink is injectable, and the model
  closes the quote and parenthesis it cannot see from the fixed probes, confirming via
  `1' && '1'='1` / `1' && '1'='2` (logical `&&` in place of the stripped `and`). The oracle
  stays row-based throughout — no payload is believed until the app's own true/false split
  reproduces under it.
- **It degrades honestly.** No model / a 429 → the smith returns nothing and the loop is
  exactly the fixed floor again, so this never becomes a hidden dependency, and a
  no-model run is still surfaced as DEGRADED rather than passing as AI-driven.

How each Challenge 03 requirement is met is mapped in [NIGHTFALL.md](./NIGHTFALL.md).

## Results across labs

Nightfall was run against nine intentionally-vulnerable apps spanning four languages and
four surface types, with no code tuned to any target. Every finding is **control-verified**
— the signal is present under the payload and **absent** under an otherwise-identical
benign request — so the table carries no false positives, and the two zeros are reported
with their specific cause, not a vague "gated".

| Lab            | Stack         | Surface        | Auth           | Findings                                                                                                                                                                                                                                                     |
| -------------- | ------------- | -------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Mutillidae     | PHP           | HTML           | unauth         | **14** — 6 SQLi, 7 XSS, 1 LFI                                                                                                                                                                                                                                |
| DVWA           | PHP           | HTML form      | credentialed   | **5** — 2 SQLi, 2 XSS, 1 cmdi                                                                                                                                                                                                                                |
| DVNA           | Node/Express  | HTML form      | credentialed   | **4** — 2 SQLi, 1 cmdi, 1 XSS                                                                                                                                                                                                                                |
| Juice Shop     | Node/Express  | SPA + REST     | unauth → chain | **3** — SQLi, auth-bypass, BAC priv-esc                                                                                                                                                                                                                      |
| DVGA           | Python        | GraphQL        | unauth         | **2** — SQLi, cmdi                                                                                                                                                                                                                                           |
| VAmPI          | Python/Flask  | REST (OpenAPI) | unauth         | **1** — SQLi (path param)                                                                                                                                                                                                                                    |
| DSVW †         | Python        | query params   | unauth         | **1** — SQLi (`?id=`, numeric context)                                                                                                                                                                                                                       |
| DVWS ‡         | Python/spyne  | SOAP / WSDL    | unauth         | **1** — SQLi (`findUsersByName`, boolean oracle over result elements)                                                                                                                                                                                        |
| sqli-labs ‡    | PHP/MySQL     | query params   | unauth         | **4** — error-based SQLi (Less-1 string, Less-2 numeric) + two blind SQLi confirmed via model-synthesized bypasses the fixed floor cannot reach: Less-25a (numeric, OR/AND filter) and Less-26a (string-in-parens, WAF stripping spaces/comments/`or`/`and`) |
| Pikachu ‡      | PHP/MySQL     | HTML forms     | unauth         | **8** — 3 SQLi, 4 XSS, 1 OS command injection (all hand-verified; broad multi-class)                                                                                                                                                                         |
| XVWA ‡         | PHP/MySQL     | HTML forms     | unauth         | **3** — SQLi, OS command injection, LFI/path traversal (on the Cloudflare Llama backend)                                                                                                                                                                     |
| WackoPicko ‡   | PHP/MySQL     | HTML forms     | unauth         | **2** — SQLi (login), reflected XSS; login SQLi recovered by a malformed-form recon fix                                                                                                                                                                      |
| PyGoat ‡       | Python/Django | HTML form      | credentialed   | **2** — OS command injection, reflected XSS; shell-error→SQLi false positive found & fixed                                                                                                                                                                   |
| OWASP Bricks ‡ | PHP/MySQL     | query + form   | unauth         | **3** — SQLi (login), 2 reflected XSS (content + login); content-brick error-based SQLi a named miss                                                                                                                                                         |
| BodgeIt        | Java/JSP      | HTML           | unauth         | **1** — reflected XSS                                                                                                                                                                                                                                        |
| bWAPP          | PHP           | HTML           | credentialed   | **0** — login succeeds; injectable pages sit behind a bug-selection form the crawler does not drive                                                                                                                                                          |
| WebGoat        | Java/Spring   | lesson SPA     | credentialed   | **0** — login succeeds; interactive lesson endpoints a flat crawler does not reach                                                                                                                                                                           |

> **⚠️ Submission record vs. post-submission expansion.** The submitted pitch deck is the
> frozen system of record at **thirty findings across seven labs**, and is deliberately left
> unchanged. Everything in the table marked **†** or **‡** is **post-submission** work (the
> 2026-11-15 expansion pass and after) and is **not** part of the submitted numbers. The nine
> unmarked rows above are the seven original labs (thirty findings) plus their two honest zeros,
> as submitted; the eight marked rows carry the tally to **fifty-four / fifteen** here only. If a reviewer compares the
> deck to this repo, the deck's thirty / seven is authoritative for the submission; this README
> tracks continued work past it.

Submitted baseline: **thirty confirmed findings across seven labs** (unmarked rows).
Post-submission total (this repo): **fifty-four findings across fifteen labs**, plus two honest
zeros — each a named, specific limitation, not a shared "gated" label.

> † / ‡ **Post-submission additions.** **†** DSVW (numeric-context boolean oracle; see
> [COLD_RUN.md](./COLD_RUN.md#dsvw--the-minimal-chrome-edge-case-and-a-numeric-context-blind-spot)).
> **‡** DVWS (SOAP/WSDL), sqli-labs, and Pikachu, added after submission. All are genuine
> cold-run, hand-verified findings — they simply postdate the deck, so they are tracked here and
> kept out of the submitted count. The per-lab narrative — including the one login-flow bug that
> once hid behind three of these labs, the nav-menu false-positive class since removed from the
> SQLi detector, and how DVGA went from a named "no GraphQL support" gap to two findings once
> introspection-driven GraphQL
> probing [shipped](./COLD_RUN.md#api-surface--rest-discovery-and-the-graphql-frontier) —
> is in [COLD_RUN.md](./COLD_RUN.md).

> ‡ **DVWS (SOAP / WSDL) — blind spot closed and counted.** The same pass turned the named
> SOAP/WSDL blind spot into a working capability: recon now discovers a WSDL, enumerates its
> read-like operations' string parameters, and the battery confirms SQLi over a SOAP envelope
> by counting repeated result elements (the engine error hides behind a generic SOAP fault, so
> the boolean oracle is the confirmation path). Unlike the other rows it was validated against
> a **purpose-built spyne WSDL fixture** (a genuine raw-concat SOAP SQLi), not an off-the-shelf
> community image — the public WSDL-based DVWS ships no clean container. The finding is real
> and live-confirmed, so it is counted, with this provenance stated plainly. Detail:
> [COLD_RUN.md](./COLD_RUN.md#dvws-soap--from-blind-spot-to-confirmed-capability),
> [LIMITATIONS.md](./LIMITATIONS.md).

> ‡ **sqli-labs — cold runs on a canonical public benchmark, counted conservatively.** The
> same pass added `acgpiano/sqli-labs` (the 65-lesson SQLi training app), run cold on two
> representative lessons: Less-1 (string) and Less-2 (numeric), both confirmed as error-based
> SQLi (22 model calls each, not degraded). Because the app is by construction 65 near-identical
> SQLi challenges, only the representative string + numeric pair is counted — running all 65
> would inflate the tally meaninglessly. These are error-based disclosures, not a numeric-oracle
> showcase (that remains DSVW's). Detail:
> [COLD_RUN.md](./COLD_RUN.md#sqli-labs--cold-runs-on-a-canonical-public-sqli-benchmark).

> ‡ **Pikachu — the broad-class run.** `area39/pikachu` (multi-class PHP/MySQL) is the first
> expansion target exercising SQLi **and** XSS **and** OS command injection together: a root
> crawl confirmed 7 (3 SQLi, 4 reflected XSS) and a scoped RCE run impact-confirmed command
> injection at `rce_ping.php` (`; id` output, benign-control differential, read-only) — 8 in
> all, **every one hand-verified** before counting (SQLi leaks the parser error, XSS reflects a
> raw marker un-escaped, cmdi returns live `id` output). The agent honestly abandoned two
> hallucinated-CVE escalations with "no command output observed." Residual classes (PHP-eval,
> file inclusion, SSRF, upload, CSRF) are named, not claimed. Detail:
> [COLD_RUN.md](./COLD_RUN.md#pikachu--a-broad-class-cold-run-sqli--xss--command-injection).

## Layout

- `packages/core` — event bus, scope gate, session layer, gateway, evidence, report.
- `apps/cli` — the streaming trace runner.
- `apps/web` — live view (vite + react) over the `serve` WebSocket.
- `labs` — docker-compose practice targets (Juice Shop, DVWA, WebGoat) and `bricks/up.sh`, the zero-config OWASP Bricks demo.

## Docs

- [NIGHTFALL.md](./NIGHTFALL.md) — project overview and how each requirement is met.
- [ARCHITECTURE.md](./ARCHITECTURE.md) — full system design.
- [AUTHORIZATION.md](./AUTHORIZATION.md) — scope policy and safety.
- [SAFETY.md](./SAFETY.md) — trust model: fail-safe, attributability, no new risk.
- [STATE_MACHINES.md](./STATE_MACHINES.md) — state machines + reliability invariants.
- [CONTRIBUTING.md](./CONTRIBUTING.md) — branching, PR flow, commit style, CI rules.
