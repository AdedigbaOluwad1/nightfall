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

**The tradeoff.** The _dangerous_ rebind is unreachable **for any scope**, not just
a loopback one: deny-by-default refuses an unlisted host and a bare IP literal, so a
hostname cannot flip to a metadata or private-range address the gate never
authorized — the classic SSRF-rebind target is blocked regardless of what the judged
lab turns out to be. The only residual is a _listed_ hostname's own DNS flipping
between check and connect — the operator rebinding their own authorized lab against
itself — which is a self-inflicted edge, not an escalation. Our own example scope is
loopback (`allow.hosts: [localhost]`), which removes even that residual; we do not
assume the judged target is loopback, because the property above does not depend on
it. Fully closing the residual is the IP-pin fix named above. Named, not dressed up
as resolved.

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
- **Numeric-context SQL injection.** The SQLi battery was string-context only (a
  quote-pair error probe and a `' OR '1'='1` boolean oracle). An **unquoted numeric**
  sink (`WHERE id=<value>`) defeats both — the quote probe's leaked error appears under
  a benign value too (an alphanumeric control is itself an invalid column reference), so
  the benign-control differential correctly suppresses it; and the string boolean payloads
  only error. A numeric boolean oracle now probes each field with `0 OR 1=1` (every row)
  vs `0 AND 1=1` (none) and confirms on a row differential — the same impact basis as the
  string oracle, immune to the menu-name false positive, and read-only (SELECT-side). The
  payload's spaces are written as `/**/` inline comments so a raw query parser that does
  not decode `+`→space cannot mangle them. Validated against DSVW (Python, numeric sqlite
  sink): a cold run that found 0 now confirms the real critical SQLi on `?id=`, with no
  code tuned to DSVW. See COLD_RUN.md.

**Still outside the set (named, not hidden).** **JSON/body injection on POST/PUT/
DELETE** is not yet probed: those verbs are state-changing, so the read-only line
holds until a reviewed body-injection increment lands. (A GraphQL _mutation_ is in
this same category and is deliberately never enumerated.) This is additive to the
same closed `switch`, not a flag flip.

**SOAP / WSDL — now covered (XML-RPC still a blind spot).** The SOAP gap flagged in the
2026-11-15 expansion pass is closed. Recon probes the conventional WSDL locations
(`/?wsdl`, `/service?wsdl`, …); when a WSDL answers it parses the target namespace, the
service address, each operation's SOAPAction, and the operations' string parameters, and
emits one injectable endpoint per (read-like operation, string parameter). The injection
battery grows a SOAP branch: it builds a SOAP 1.1 envelope placing the payload at the
target parameter (XML-escaped, so the envelope stays well-formed and the parser hands the
raw metacharacter to the sink) with siblings at benign defaults, and confirms SQLi by the
**boolean oracle counting repeated result elements** — a spyne/.NET/JAX-WS service hides the
engine error behind a generic SOAP fault, so error-based never fires and the row-count
differential (`' OR '1'='1` → N result elements vs `' AND '1'='2` → 0) is the confirmation
path. Read-only by construction: an allow-list of read-like operation names (get/find/
search/list/read/…) with a state-changing-verb deny check, mirroring the GraphQL Query-only
guard. Validated live against a spyne WSDL service (operation `findUsersByName`, raw-concat
SQLi): recon discovered the probe and the oracle confirmed 3 result rows vs 0 (see
[COLD_RUN.md](./COLD_RUN.md#dvws-soap--from-blind-spot-to-confirmed-capability)).
Residual: **XML-RPC** (and SOAP operations whose only injectable input is a non-string type,
or document/literal services that do not name the request wrapper after the operation) are
still out of scope — additive from here.

**Two residuals the DSVW cold run surfaced — both now closed.**
- **GET-payload `+` encoding on raw-query apps → `%20` (fixed).** `withParam` serialized a
  GET value's spaces to `+`. Form-decoding stacks (PHP, Express) turn `+` back into a
  space, so the string payloads worked; an app with a *raw* query parser (Python's
  `http.server`, as in DSVW) does not, so `' OR '1'='1` arrived as `'+OR+'1'='1` and
  misfired. `withParam` now emits `%20` for spaces in the serialized query — decoded to a
  space by every parser, accepted identically by the form stacks, so it is transparent to
  every lab already validated and correct on the raw-query ones. A regression test asserts
  no probe URL carries a `+` separator (`actions.test.ts`).
- **Finding de-duplication (fixed).** Findings are now de-duplicated by weakness class +
  endpoint scope (host + path + the sorted set of parameter *keys*, never payload values),
  so the same injectable parameter reached through several discovered URL variants (DSVW
  lists example-payload links to its own `?id=` sink) is recorded once, while two genuinely
  different parameters on one path stay distinct. It under-merges rather than ever hides a
  finding. DSVW's cold run went from 4 emitted findings for one bug to a correct **1**; a
  regression test locks both directions (`loop.test.ts`).
- **Path-traversal probe depth (fixed; surfaced by the XVWA cold run).** The traversal probe
  sent a single fixed `../../../../etc/passwd` (four levels). A file-inclusion endpoint nested
  deep below the web root (XVWA's is six levels down) is never climbed out of by four dots, so a
  real, trivially-readable `/etc/passwd` leak read as a clean negative — the agent honestly
  abandoned it rather than fabricate. `pathTraversalCheck` now probes an absolute path plus a
  range of depths (3/5/7/10 `../`); excess `../` collapses at the root, and every payload still
  names the same benign, world-readable file (read-only). The XVWA LFI confirmed on the re-run,
  and a regression test locks that a leak only at depth ≥ 6 (or absolute) is caught while a
  never-leaking include is not (`actions.test.ts`). Residual: a sink that leaks only a
  *non*-`/etc/passwd` file, or needs a null-byte/wrapper trick, is still out of scope.
- **Malformed-form field recovery (fixed; surfaced by the WackoPicko cold run).** A form whose
  inputs are wrapped in `<tr>`/`<td>` with no enclosing `<table>` (WackoPicko's login, and a
  common legacy-PHP pattern) is emptied by HTML5 foster-parenting — the inputs are hoisted out
  of the `<form>`, so cheerio reports no fields and the form's entire POST injection surface
  goes invisible (the probe degrades to a GET `?q=`). `recon` now falls back to a raw
  form-region scan when the parse tree yields an empty form, recovering the named controls; the
  WackoPicko login SQLi confirmed once its `username` field was restored. A regression test
  locks the recovery (`recon-routing.test.ts`). Residual: a form split across *multiple*
  mis-nested regions, or fields injected by client-side JS after load, still needs the Tier-2
  browser session.
- **Shell error misread as error-based SQLi (fixed; surfaced by the PyGoat cold run).** A POSIX
  shell prints `/bin/sh: 1: Syntax error: Unterminated quoted string` on an unbalanced quote, and
  the phrase *"unterminated quoted string"* is also a `SQL_ERROR` alternative. At an OS-command-
  injection sink (PyGoat's `/cmd_lab` shells out `dig {domain}`), the error-based SQLi quote probe
  therefore tripped the SQL signature — benign-control differential and all — and confirmed a
  phantom SQL injection on a page that runs no SQL. A `SHELL_ERROR` guard (`/bin/sh:`, `sh: <n>:`,
  `command not found`, … — text no DB driver emits) now withholds the SQLi signal when the matched
  error is shell-produced; the (real) command-injection finding is unaffected. A regression test
  locks it (`actions.test.ts`). General hardening for every `nslookup`/`ping`/`dig` shell-out sink.
- **Injection sinks on password-type inputs are not probed (residual; surfaced by the PyGoat cold
  run).** Recon excludes `password`-type inputs from injectable sinks by design — injecting a
  password field causes account lockouts and login noise, and it is almost never a real sink.
  PyGoat's `/sql_lab` is the rare exception: it concatenates the **password** field raw into its
  query, behind an ORM-safe gate (`login.objects.filter(user=name)`) that first requires the
  **username** to match a seeded row. So the one injectable sink (`pass`) is skipped, and the one
  probed field (`name`) is gated and yields no differential — the SQLi is a true, hand-verified
  miss. This is left **unpatched**: broadening injection to password fields trades one buried
  finding for lockouts and false positives across every normal login. Recorded as a known miss,
  not counted. The run's capability was otherwise proven (same style confirmed CMDi and XSS).

## 4. Authenticated broken-access-control confirmation is bounded by surface discovery

**What breaks.** The agent now **does** confirm authenticated broken access control
— a two-principal differential ships (below) — but it can only confirm a surface it
reaches. A privilege-denoting endpoint that is unlinked for the principals the agent
drives, and not named in scope, will not be probed, so a real missing access control
on an undiscovered URL still goes unreported.

**What now works (shipped, validated).** A vertical function-level-authorization
differential (`loop/actions.ts` `accessControlDifferential`). List the lower-
privilege account first in `credentials`; mark a second `role: "admin"`. A finding
requires, in order: the lower-privilege principal reaches the surface with the
objective signal; the surface is privilege-denoting (admin/management/config URL);
an anonymous request to it is **denied** (proving it is gated); and — when an
elevated principal is supplied — that principal **also** serves it (proving shared
privileged functionality, not a per-user resource). Each gate independently rejects
a false-positive class the removed keyword match could not: public pages (anon
reaches them), authorized admin use (the principal is non-admin by scope), and
per-user resources. A failed login collapses the primary into an anonymous
principal, so a broken login cannot manufacture a finding either. Verified
end-to-end against live DVNA: `/app/admin`, reachable by a registered non-admin user
and denied to anonymous, confirms **Impact-confirmed**, while `/app/products`
(reachable but not privilege-denoting) correctly does not. Seven unit tests lock
each gate.

**Why the residual.** Black-box discovery is link-following recon; an admin surface
with no inbound link from the crawled set is invisible until it is named in scope or
surfaced some other way. The detector is sound; the limit is reach, not confirmation.

**What a fuller fix takes.** Authenticated recon that crawls as each principal (an
admin link an anonymous crawl never sees), plus a horizontal (IDOR) differential for
per-user resources. Additive; the differential oracle is already in place.

**The tradeoff.** We still under-claim over guess: the detector fires only behind
four independent gates, so a surface it never reaches is a missed finding, never a
wrong one.

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
