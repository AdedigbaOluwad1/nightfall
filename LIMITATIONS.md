# Where this breaks

An honest list of what Nightfall does **not** do well, surfaced by our own
adversarial testing. Each item is stated with the failure, the reason, the fix,
and the tradeoff we chose — because a named limitation is evidence of rigor, and
a hidden one is a liability a reviewer finds live. See [SAFETY.md](./SAFETY.md)
for the properties that _do_ hold.

The three items we judged cheap, clear wins are **already closed** (see the last
section) — we'd rather fix what we can than pad the list. What remains below is
genuine design tradeoffs, not unfinished work.

## 1. DNS rebinding of a _listed_ host (TOCTOU)

**What breaks.** The scope gate authorizes by **hostname**, not resolved IP. A
hostname that is in `allow.hosts` but whose DNS record flips between the gate check
and the socket connect could, in principle, resolve to a different address the
second time.

**Why.** Hostname is the unit of authorization in the scope file, and Node's fetch
resolves DNS itself at connect time — the gate does not pin the IP it validated.

**What a fix takes.** Resolve once, validate the resolved IP, and pin it for the
connection (custom lookup / agent).

**The tradeoff.** For the mandated scope this is **already closed**: the lab is
loopback-only (`allow.hosts: [localhost]`), and an unlisted host or a bare IP
literal is refused by deny-by-default — so the dangerous rebind (to a metadata or
private IP) can't be reached at all. The only residual is a _listed_ hostname's own
DNS flipping, i.e. the operator rebinding their own isolated lab against themselves.
Named, not dressed up as resolved.

## 2. Several finding classes are signal-based, not impact-confirmed

**What breaks.** Reflected XSS, CSRF, and the generic exposure class are confirmed
by a **signal** (an unencoded reflected marker, a missing anti-CSRF token, an
anomalous disclosure), not by driving the impact to completion. Reflected XSS, in
particular, is not executed in a headless browser as a matter of course.

**Why.** Executing every candidate end-to-end (popping a real XSS, forging a real
cross-site request) adds cost and risks crossing from "read-only probe" into state
change — the exact line the safety model draws.

**What a fix takes.** A headless-browser confirmation stage for the reflection
classes. The machinery exists (Tier 2 is wired, §SPA below), so this is a
deliberate, reviewed increment — not a flag flip.

**The tradeoff.** We prefer to **under-claim**: every finding states its
verification basis explicitly (SAFETY.md §7), so a signal-based finding is never
dressed up as an exploited one. Impact-confirmed classes (SQLi auth bypass,
privilege escalation, command injection, traversal) are labeled as such.

## 3. The probe set is narrow by design

**What breaks.** Nightfall is **not** a generalized exploit toolkit. It carries a
small set of hand-written, read-only checks in one closed `switch`
(`loop/actions.ts`); vulnerability classes outside that set are not attempted.

**Why.** This is the central safety decision, not an oversight: generalizing to a
consequential action requires _adding a reviewable check to that switch_, never
flipping a flag (SAFETY.md §4). A cold-target run (`COLD_RUN.md`) confirmed the
honest consequence: on an untuned target, the agent degrades gracefully and
confirms nothing rather than firing payloads it can't reason about.

**The tradeoff.** We chose provable, auditable narrowness over broad, unbounded
offense. Coverage grows by deliberate, reviewed additions — the safety property
does not depend on the lab being disposable. Two such additions:

- **The credentialed DVNA pass** (`COLD_RUN.md`): form-aware, boolean-oracle SQL
  injection on a discovered form, which landed a real critical finding read-only.
- **The full injection battery is now form- and parameter-aware across the whole
  discovered surface**, not only the first target's conventional `?q=`/`?file=`
  shape. SQL injection, reflected XSS, OS command injection, and path traversal
  each probe every injectable form field and query parameter recon captured, in a
  read-only guard that **skips any state-changing form** (create/update/delete/…)
  — a POST injection never writes to a mutating sink; GETs are always allowed. The
  classes (the closed `switch`) are unchanged; what widened is _where_ each probe
  looks. Validated across intentionally-vulnerable labs spanning stacks (Mutillidae
  PHP, BodgeIt Java/JSP, DVNA Node): the same probes confirm real SQLi, XSS, and
  LFI on each without per-lab tuning.
- **REST API surface via OpenAPI.** A JSON/REST API publishes no crawlable HTML,
  so the HTML crawl saw nothing. Recon now reads a served OpenAPI/Swagger contract
  to enumerate GET endpoints and their path/query parameters, and the SQLi/XSS/
  traversal/cmdi battery probes those inputs (path-template parameters included) —
  still read-only (GET only; state-changing bodies are the next increment, below).
  Validated against VAmPI (Python/Flask JSON API): 0 discovered endpoints → the two
  path-param routes → a real critical SQL injection on `/users/v1/{username}`.
- **GraphQL surface via introspection.** A GraphQL API is a single POST endpoint
  whose schema is read by introspection, not OpenAPI. Recon probes the conventional
  GraphQL paths with a read-only `{__typename}` query, introspects a GraphQL-shaped
  reply, and enumerates every **Query** field's string arguments as injectable
  inputs (a valid selection set derived from each field's return type). Query only,
  never Mutation — read-only by construction. The same battery then probes them.
  Validated against DVGA: 0 discovered endpoints → 8 Query-field probes → two real
  criticals, error-based SQLi on `pastes(filter)` and command injection on
  `systemDebug(arg)`, with no code tuned to DVGA.

**Still outside the set (named, not hidden).** **JSON/body injection on POST/PUT/
DELETE** is not yet probed: those verbs are state-changing, so the read-only line
holds until a reviewed body-injection increment lands. (A GraphQL _mutation_ is in
this same category and is deliberately never enumerated.) This is additive to the
same closed `switch`, not a flag flip.

## 4. Broken access control is not confirmed on an authenticated run

**What breaks.** When the agent runs with operator credentials, it does **not**
emit broken-access-control findings from a plain reachable-plus-keyword signal — so
a genuine _missing_ access control (e.g. DVNA's `/app/admin` reachable by a non-
admin user) goes unreported in that mode.

**Why.** Confirming BAC soundly needs a baseline: either no session (reaching a
gated surface unauthenticated) or a second, lower-privilege principal to show a
boundary was crossed. Authenticated with a single principal, "this page loaded" is
just authorized access — and the alternative, flagging every reachable feature page
that echoes an objective word, is exactly the false-positive flood we removed.

**What a fix takes.** A two-principal (or authenticated-vs-anonymous) differential:
fetch the same resource under two privilege levels and confirm only on a delta —
the same oracle shape the boolean-SQLi check already uses.

**The tradeoff.** We under-claim: one honest critical beats one honest critical
buried under five wrong highs. Unauthenticated BAC confirmation is unaffected.

## 5. Mid-chain re-grounding keys on one disclosure pattern

**What breaks.** The agent re-grounds live when a probe forces the stack to leak a new
`component@version` mid-run (an injection error page naming the framework), re-querying
Tavily so the expanding surface stays current. The re-grounding **loop itself is generic**
— any confirmed probe that emits a new fingerprint artifact re-grounds it, deduped and
budget-guarded, with no per-lab branch (`loop/agent.ts`). What is narrow is the set of
_mid-chain disclosure extractors_ that feed it: today there is **one**, the error-page
framework banner matching the `(Name version)` shape (`actions.ts` `bannerArtifact`,
`FRAMEWORK_BANNER`). A stack that leaks its version mid-chain in a different shape — prose
in an error body, a `Server` header re-appearing on a later hop — would not currently
re-fire the re-grounding, even though passive recon fingerprints those same signals
generically at the start of the run.

**Why.** The one shape we implemented is the one a cold run actually produced (Juice
Shop's Express 500 page). We did not want to assert broad "any version string re-grounds"
coverage the code does not yet have — that would be the same over-claim the rest of this
file refuses.

**What a fix takes.** Additional mid-chain extractors (a `Server`/`X-Powered-By` re-read
on later responses, a prose-version matcher), each emitting the same `fingerprint`
artifact the generic loop already consumes. Additive — it does not touch the re-grounding
mechanism.

**The tradeoff.** We name the mid-chain coverage precisely rather than let a single
demonstrated case read as universal. The generic part (the re-grounding loop) is real;
the breadth of what trips it mid-run is honestly bounded.

## Closed since the first audit

These were on this list; we fixed them rather than excuse them.

- **Soft budget cap → bounded.** The budget now runs a **reserve check**: the
  worst-case cost of a call (prompt tokens + a full completion) is estimated and
  charged against the cap _before_ the call is made (`budget.ts` `assertCanAfford`,
  `bifrostClient.ts`). The call that would cross the cap is never issued, so
  overshoot is zero rather than "bounded by one in-flight call."
- **SPA 200-shell auth wall → reachable on Tier 2.** An unproven Tier-1 result now
  escalates to a real headless browser (`browserSession.ts`), which renders the
  page, **settles after load so a client-side redirect completes**, and re-probes
  the post-JS DOM — so a shell that redirects in JavaScript is no longer invisible.
- **Full per-request audit log → persisted.** The complete event stream (every
  request, plan decision, block, and gateway call — not only findings) is now
  written append-only to `*.audit.jsonl` as it happens (`events/audit.ts`), so a
  run is replayable end-to-end, not just its confirmed findings.
- **Head-only signal detection → whole-body scan.** Every signal check (SQLi error
  strings, reflected-XSS marker, command output, traversal file contents, leaked
  token, CSRF-token presence) read only the first 2 KB of a response — so a real
  flaw whose output landed below a large nav/framework shell was a silent false
  negative that scaled with page size, not with the vuln. Mutillidae reflected its
  DNS-lookup command output ~49 KB into a 52 KB page and went unreported while the
  identical probe found a small page's XSS. Detection now scans the whole body
  (bounded to 512 KB); the evidence snippet shown in a finding stays bounded at
  2 KB. On the labs this turned a 0-finding Mutillidae run into 12 real findings
  with no code tuned to the target (`actions.ts` `rawSend`, `DETECT_MAX`).
- **Silent login failure → verified authentication.** The credentialed path
  claimed success it never achieved: `parseLoginForm` captured the hidden, user, and
  password fields but **dropped the submit control**, so an app that gates on the
  button (`isset($_POST['Login'])`) never processed the post; `login()` then set
  `loggedIn = true` unconditionally; and the agent swallowed the whole thing with a
  `.catch(() => undefined)`. The result was the worst failure shape there is — a
  broken capability reported as an honest zero (a login-gated target would show a
  clean 0 findings and look fine). Fixed: `parseLoginForm` now carries the submit
  `<input>` **and** `<button type=submit name=…>` verbatim; `login()` reads the
  response and **verifies** it (failure = bounced back to the login URL or the
  password field still present), emits `session.login{ok}`, and throws on failure;
  the CLI renders a green `authenticated` or a red `LOGIN FAILED — probing continues
  UNAUTHENTICATED`, so a broken login can never again masquerade as a clean run. The
  Tier-2 browser session got the same verification. Proven on three independent login
  shapes that were silent zeros before — DVWA (hidden `user_token` + a named submit
  input), bWAPP (a `<button name=form value=submit>`), and WebGoat (a Spring Security
  form, no submit button, no CSRF) — each of which now authenticates (`httpSession.ts`,
  `browserSession.ts`, `agent.ts`, `render.ts`). The _findings_ a credentialed run then
  lands are a separate matter: see the false-positive correction below, which is the
  reason the counts here are smaller than an earlier draft claimed.
- **Isolated-field injection → complete-form resubmission.** The injection battery
  sent only the one field it was testing, so an app gating on a sibling control saw
  an incomplete post and did nothing (DVWA's SQLi runs only with `?Submit=Submit`
  present; `id='` alone confirmed nothing, `id='` **plus** `Submit` confirmed the
  flaw). Recon now captures the form's full control set with default values
  (`formData`), and an injection **resubmits the complete form** with the single
  payload override — so a probe exercises the sink exactly as a browser would. This
  is what took credentialed DVWA from 0 to its **5 real findings** (2 SQLi, 2 XSS, 1
  command injection, each on a genuinely vulnerable page) once the false positives
  below were removed (`recon`, `actions.ts`, `agent.ts`).
- **A leaked-DB-error signal matched the _topic word_ "SQL" → real error signatures
  plus a benign control.** The error-based SQLi check matched a pattern that included
  the bare word `sql`. Scanned across a whole page body (and, on Tier 2, a rendered
  SPA DOM), that matched application content, not a leaked error: a nav menu or
  dropdown listing "SQL Injection", a security-teaching app's lesson titles. It
  produced **critical false positives** — the exact over-claim §2 and SAFETY.md §7
  promise never to make. A WebGoat run surfaced it; a re-audit found it had inflated
  several counts (DVWA 7 of 9 SQLi, bWAPP all 6, Mutillidae 3 — every one a page whose
  only "evidence" was the menu naming SQL). Two fixes: the pattern now matches only
  real engine/driver error signatures (`error in your SQL syntax`, `SQLITE_ERROR`,
  `ORA-…`, `sqlite3.OperationalError`, …), never the subject word; and every
  presence-based signal (DB error, leaked file, shell output) now confirms only when
  it is **absent from an otherwise-identical request carrying a benign value**, so
  content that is present regardless of input can never be read as payload-caused
  evidence. Real findings are unaffected — DVGA/VAmPI (sqlite3), DVWA `sqli`/`brute`
  and Mutillidae `user-info` (MySQL) still confirm, each verified present under the
  payload and absent under the control (`actions.ts` `SQL_ERROR`,
  `signalIsPayloadCaused`). See COLD_RUN.md.

## What our testing still can't substitute for

- A **non-builder** running a cold target blind (we ran it ourselves; see
  `COLD_RUN.md`), and an independent reproduction of a finding from the README
  alone. These are human checks, not code we can ship.
