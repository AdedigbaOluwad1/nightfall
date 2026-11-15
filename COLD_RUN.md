# Cold-target dry run — intervention log

The test everyone skips: point the agent at a **fourth, unfamiliar** vulnerable
app — one whose source none of us has read — and run it blind, logging every
moment we were tempted to step in. This is the honest version of the thing judges
actually worry about: not "does the rehearsed demo work," but "what does it do
when it meets something it wasn't tuned for."

> **The most significant finding in this file was not found by us.** A true
> non-builder, on a fresh clone with nothing but the README, caught the one thing
> every other entry here missed: a `$0.00`, no-model run that still reported
> "objective reached." It is written up last, under
> [_The degraded run that still claimed the objective_](#the-degraded-run-that-still-claimed-the-objective--found-by-someone-who-didnt-build-it),
> because it is the sharpest test of all — our own numbers, read by someone with no
> stake in them.

- **Target:** OWASP Mutillidae II (`citizenstig/nowasp`), a PHP 5.5.9 / Apache
  2.4.7 app. We had never run it or read its source. Chosen precisely because its
  stack is one Nightfall does **not** special-case (no Express banner to
  re-ground on) — a real graceful-degradation test, not a home-field demo.
- **Setup (operator, not source-reading):** `docker run -p 8899:80`, then hit the
  app's own `set-up-database.php` to initialize its DB. Scope: loopback host,
  `/` allowed, `/logout.php` + `/set-up-database.php` denied, \$3 budget, 30 steps.
- **Date:** 2026-11-14.

## What happened, and every time we almost intervened

**Run 1 — 0 findings, and every probe failed.** Recon and hypothesis worked
cleanly (fingerprinted Apache 2.4.7 + PHP 5.5.9, pulled live CVEs via Tavily), but
_every single exploit attempt_ returned `transport error: fetch failed`. The run
abandoned all 30 steps with nothing.

> **Intervention point #1.** The obvious move was to shrug: "the lab's broken,
> try another." We didn't — a cold run that surfaces a failure is doing its job.
> We investigated instead.

**Misdiagnosis, and backing it out.** The error was
`ERR_SSL_WRONG_VERSION_NUMBER` — a TLS handshake against a plaintext port. First
hypothesis: undici's shared connection pool reusing a TLS socket (from the HTTPS
calls to Tavily) for the plaintext target. We added a per-session connection pool
to isolate it — and re-ran. **It still failed.**

> **Intervention point #2.** A wrong fix that doesn't work is a fork in the road:
> layer another guess on top, or revert and re-diagnose. We reverted the whole
> change (including the new dependency) rather than keep a fix that didn't earn
> its place.

**Root cause.** The real trigger: the actual request URL had become
`https://localhost:8899/…`. Mutillidae enforces SSL **per session**, via a
`?do=toggle-enforce-ssl` link in its own navigation. Our **recon crawler was
firing that link** — a state-changing GET — which flipped the agent's own session
into "redirect everything to https," and since the lab only exposes plaintext, every
later probe hit an unreachable TLS endpoint. We confirmed it in isolation:
`login.php` returned 200 _before_ recon and failed _after_ recon. The agent was
sabotaging itself.

This is a genuine reliability bug **and** an ethos violation: recon is supposed to
be read-only, and firing `toggle-enforce-ssl` / `logout` is a state change.

**The fix (shipped).** Recon now refuses to fire state-changing links —
`logout`, `?do=toggle|reset|clear|enable|disable|delete|destroy`,
`?action=delete|logout|reset` — both as crawl targets and as recorded attack
surface. A regression test locks it. This keeps recon passive, which is what the
safety story already claimed.

**Run 2 — healthy.** After the fix: **0 transport failures** (down from 27), real
probes reaching live `200`s, the scope gate correctly **blocking 2** out-of-scope
requests, and a clean, bounded halt on `exhausted` instead of thrashing a dead
session. Wall-clock: 41.8s (recon 2%, hypothesis 37%, exploit 60%).

> **Intervention point #3.** Still 0 confirmed findings. The tempting fix: point
> the scope at a Mutillidae endpoint we _know_ is vulnerable, to manufacture a win.
> We declined — that is exactly the rehearsed demo this exercise exists to avoid.

## The honest result

- **A real bug, found and fixed** that a cold target exposed and our three
  home labs never would have (none of them weaponize their own navigation against
  a crawler).
- **The reliability posture held the whole time:** zero out-of-scope requests
  (2 correctly blocked), no crash, per-attempt recovery (retry → abandon), and a
  bounded termination. The failures were _graceful_, which is the claim.
- **Zero confirmed findings, and we know why:** Nightfall's probe set is
  deliberately narrow and hand-written (see [LIMITATIONS.md](./LIMITATIONS.md) §6),
  and on an untuned target the model also proposed out-of-domain techniques
  (buffer overflow on a PHP web app) that the closed read-only `switch` doesn't
  implement. On a cold target, no confirmation without tuning is the _expected_
  outcome of that safety tradeoff — not a surprise we're hiding.

## What this run would need to be stronger

- Either a cold target whose easy wins fall inside the current probe set, or a
  broadened (still reviewed, still read-only) probe set — a deliberate increment,
  not a demo-day hack.

## Multi-lab generalization pass (four more unseen stacks)

To prove the agent isn't overfit to its three home labs, we ran it against four
further targets whose source we hadn't read, spanning different languages and
frameworks — the real "does it travel" test. Same harness, same loopback-only
scope, \$3 budget, 25 steps, local model.

| Lab     | Stack                    | Result                                                                  | Transport fails | Crashes | Scope blocks         |
| ------- | ------------------------ | ----------------------------------------------------------------------- | --------------- | ------- | -------------------- |
| bWAPP   | PHP 5.5.9 / Apache 2.4.7 | 0 findings, clean halt                                                  | 0               | 0       | 0                    |
| WebGoat | Java / Spring            | 0 findings, clean halt                                                  | 0               | 0       | 0                    |
| DVNA    | Node / Express           | FP found & fixed → 0 unauth; **1 real critical SQLi when credentialed** | 0               | 0       | 3–15 (external CDNs) |

On every stack recon GET-safety held (0 transport fails, versus 27 on Mutillidae
_before_ the fix), the full recovery vocabulary (RETRY / PIVOT / ABANDON /
ESCALATE) fired without a single parse error from the local model, and Tier-2
ESCALATE exercised live on the auth-gated labs with no crash.

### The bug DVNA found — a false "Impact-confirmed"

DVNA is a Node/Express app, the one stack Nightfall _does_ special-case. On the
first run it reported **four high-severity Broken Access Control findings** — on
`/login`, `/register`, and `/forgotpw` (one of them twice). Those pages are
**public by design**: serving a login form to an anonymous caller is correct, not
a vulnerability. Worse, each was stamped basis **"Impact-confirmed"** — the exact
over-claim the whole safety story (SAFETY.md §7, [LIMITATIONS.md](./LIMITATIONS.md)
§2) promises never to make.

> **Intervention point.** The tempting read: "four highs on the first Express
> target that isn't Juice Shop — the generalization works." It didn't. We read the
> findings instead of counting them, saw they were garbage, and treated a wrong
> _confirmation_ as more dangerous than a missed one.

**Root cause.** The access probe confirms when a page returns `<400` and its body
contains an objective keyword. DVNA's page `<title>` is "Damn Vulnerable NodeJS
**Application**," and the objective was "gain administrative **access** to the
**application**" — so the generic word "application" in the site chrome matched on
every page. The response snippet is also capped _before_ the login `<form>`, so
the existing auth-wall guard (which needs to see a password field) never fired.

**The fix (shipped).** An inherently-public auth-entry path — `login`, `register`,
`signup`, `forgot/reset-password` and their variants — can **never** be a
broken-access-control finding, because authorization is not expected there. The
guard keys on the **URL**, not the body, so a truncated snippet can't defeat it,
and it deliberately does not touch genuine gated surfaces (an `/admin` page still
confirms). A regression test locks all three DVNA paths plus a real gated surface.
After the fix DVNA reports **0 findings** — honest, matching bWAPP and WebGoat.

This is the **second** real bug a cold target has exposed that our home labs never
would (the first was recon firing a state-changing GET, above). Both were found by
_reading what the agent did_, not by trusting a green number — which is the only
reason a cold run is worth running at all.

### Credentialed pass — landing a real finding, and what it took

After the FP fix, DVNA honestly reported **0 findings** — but DVNA is full of real
vulnerabilities, so 0 was a coverage result, not a clean bill. We asked the honest
follow-up: _why_ nothing, and could a reviewed, read-only increment reach one?

**Why nothing.** The agent ran entirely **unauthenticated**, and DVNA (like bWAPP
and WebGoat) gates every vulnerable route behind a login — `/app/*` 302-redirects
to `/login`. The probes never reached a vulnerable surface. Two further mismatches
compounded it: the agent's only login path was a Juice-Shop-specific JSON SQLi-
bypass (DVNA uses a form login), and the injection probes were shaped to Juice
Shop (param `q`, REST paths), not DVNA's form fields.

**The increment (shipped, reviewed, read-only).** Credentialed black-box testing —
the `credentials:` field the scope schema already carries — plus four probe-set
broadenings, each with a regression test:

1. **Recon follows markdown-rendered links.** DVNA's `/learn/*` hub links to the
   real `/app/*` surface as _markdown_ (`[User Search](/app/usersearch)`) rendered
   client-side, invisible to an `<a href>` crawl. Recon now also extracts markdown
   link targets — so the authenticated surface is discovered over plain HTTP.
2. **Recon captures form fields.** Each form endpoint now records its method and
   injectable field names, so a probe targets the input recon actually found.
3. **Form-aware SQL injection with a boolean oracle.** When an app swallows the
   engine error (DVNA returns a generic "Internal Error"), the check sends two
   payloads differing only in a boolean — `' OR '1'='1` vs `' AND '1'='2` — and
   confirms when the always-true one returns rows the always-false one does not.
   Read-only: it injects SELECT-side logic, never a write.
4. **Row counting robust to page chrome.** The differential counts table rows (and
   JSON records only in a JSON body), not the CSS/JS braces that first masked it.

**Result:** against DVNA, authenticated with a registered test user, Nightfall now
confirms exactly one finding — **SQL Injection at `POST /app/usersearch` (CWE-89,
critical), Impact-confirmed** by the boolean oracle (`always-false → 0 rows;
always-true → 2`) — and **no false positives** (the earlier authenticated-BAC
noise is gone; see below). One honest critical, not a pile of inflated highs.

> **Intervention point.** The first credentialed run produced **five** high
> "Broken Access Control" findings on ordinary `/app/*` feature pages — because,
> logged in, the access probe flagged every reachable page that echoed an
> objective word. But an authorized user reaching a feature they're entitled to is
> not broken access. We suppressed keyword-based BAC on authenticated runs (no
> lower-privilege baseline ⇒ under-claim) rather than ship five wrong highs next to
> the one right critical. The coverage this forgoes — DVNA's genuine _missing_
> access control on `/app/admin` — is named in [LIMITATIONS.md](./LIMITATIONS.md),
> not quietly claimed.

**Operator setup (provisioning, not source-reading):** register one test user via
DVNA's own `/register`, put its credentials in the scope file. This is the same
category as `docker run` or Mutillidae's DB-init — standard credentialed black-box
access, not reading the app's source.

## Widened battery + whole-body detection — the page-size false negative

After broadening the injection battery to fire form- and parameter-aware across the
whole discovered surface (SQLi, reflected XSS, OS command injection, path traversal
on every injectable input recon found, with a read-only guard that skips any
state-changing form), we re-ran two unseen targets on the **cloud backend**
(Gemini-4-Hydrogen via Bifrost, a different model from the local one above) to check
the widened probes travelled: **Mutillidae** (PHP, huge pages) and **BodgeIt**
(Java/JSP, small pages). Same loopback scope, \$3 budget, 40 steps.

**First result: BodgeIt confirmed a real reflected XSS; Mutillidae found nothing —
through two rounds of fixes.** Recon was correct (it captured every vulnerable form
field — `target_host`, `textfile`, `ToolID`, `username`), and after a queue-ordering
fix the probes demonstrably reached those forms. Still zero.

> **Intervention point.** The tempting read: "Mutillidae is just hardened, move on."
> We didn't. BodgeIt and Mutillidae ran the _identical_ probe code; the only
> difference was that BodgeIt's pages are small and Mutillidae's are large. A result
> that depends on page size, not on the vulnerability, is a detector bug, not a
> target property.

**Root cause.** Every signal check tested `response.slice(0, 2000)` — the first 2 KB
of the body. Mutillidae wraps its output in a ~49 KB navigation/framework shell, so
the reflected marker, the command output, and the leaked `/etc/passwd` all landed
_below_ the window. We confirmed it directly: the DNS-lookup command output
(`uid=33(www-data)…`) sits at byte **49,277 of a 52,326-byte page**. BodgeIt's XSS
was found only because its signal fell inside the first 2 KB. A false negative that
scales with page size.

**The fix (shipped).** Detection now scans the whole response body (bounded to
512 KB against a pathological payload); the evidence snippet shown in a finding stays
bounded at 2 KB. Same probes, same payloads, same model — nothing tuned to either
target. After the fix, on the **same run harness**:

| Lab        | Stack        | Before fix | After whole-body detection                                     | Crashes | Model parse errors |
| ---------- | ------------ | ---------- | -------------------------------------------------------------- | ------- | ------------------ |
| Mutillidae | PHP / Apache | 0 findings | **12** — 9× SQLi (critical), 2× reflected XSS, 1× LFI (high)   | 0       | 0                  |
| BodgeIt    | Java / JSP   | 1 XSS      | **1** reflected XSS at `/search.jsp` (unchanged — small pages) | 0       | 0                  |

Zero broken-access false positives in Mutillidae's twelve (the authenticated-BAC and
privilege-surface precision work held), zero crashes, and the cloud model drove the
full recovery vocabulary with no parse errors — so the backend swap was clean too.

> **Correction (added later).** That "9× SQLi" was wrong. Widening detection to the
> whole body was right, but it was paired with a loose error pattern that matched the
> bare word "SQL" — so Mutillidae's own menus inflated the SQLi count. A later audit
> (see _The false positives hiding in the counts_ at the end of this file) put the
> real figure at **6 SQLi**; the XSS and LFI, which key on a unique injected marker or
> on leaked file contents, were never affected. We leave the original number visible
> and corrected rather than silently edited, because the whole point of this file is
> not trusting a count until you have read what produced it.

This is the **third** real bug a cold/unseen target has exposed by _reading what the
agent did_ rather than trusting a number — here, trusting a _zero_. A small
follow-on: the command-injection probe prefixes a routable host
(`127.0.0.1; id`) so a host-expecting sink (`nslookup`/`ping`) returns promptly
instead of blocking on an empty argument until the probe times out, and it now tries
both `;` and `|` separators.

## API surface — REST discovery, and the GraphQL frontier

Every target so far is an HTML app. Modern targets are APIs, and our whole pipeline
was HTML-centric: recon crawls `<a>`/`<form>`, so a JSON API — which serves none —
was invisible. We pointed the agent at **VAmPI** (Python/Flask JSON REST API) to see
it fail honestly: recon found **0 endpoints**. Not a hardened target, a blind spot.

**The gap, concretely.** A REST API's surface isn't in its HTML, it's in its
machine-readable contract. VAmPI serves a full **OpenAPI 3** spec at `/openapi.json`
enumerating every route, method, and parameter — including the path parameters
(`/users/v1/{username}`) where its SQL injection lives.

**The increment (shipped, reviewed, read-only).** Recon now fetches an OpenAPI/
Swagger spec from the conventional locations (all gate-checked) and enumerates its
**GET** operations with their path and query parameters; the injection battery
injects into a path template by substituting the payload into that segment. GET
only — a GET carries read semantics, and state-changing bodies (POST/PUT/DELETE
JSON) stay outside the read-only line until a reviewed body-injection increment.
**Result:** against VAmPI, recon went from 0 endpoints to the two path-param routes,
and the existing error-based check confirmed **one real critical SQL injection on
`/users/v1/{username}`** (`sqlite3.OperationalError` on a quote probe) — no code
tuned to VAmPI.

> **Intervention point — a regression caught by re-reading the numbers.** Teaching
> the probe to use spec-declared fields first made a GET endpoint probe _only_ its
> form field, which silently masked the injectable `?page=` router parameter —
> Mutillidae's LFI vector. The re-run dropped from 12 findings to 10. We didn't
> wave it through as noise: a GET can carry both an injectable form field and an
> injectable query param, so the probe now takes the **union** of the two. Mutillidae
> is back to 12 (9 SQLi, 2 XSS, 1 LFI) and VAmPI holds at 1 — the same re-read-the-
> result discipline that found the three bugs above, applied to our own change.

**The next frontier — then closed.** We stood up **DVGA** (Damn Vulnerable GraphQL
App). GraphQL exposes a single POST `/graphql` endpoint enumerated by _introspection_,
not OpenAPI — so our spec crawl found nothing (**0 endpoints**, confirmed). Rather
than only name it, we built the read-only increment: recon probes the GraphQL paths
with a `{__typename}` query, introspects a GraphQL-shaped reply, and enumerates every
**Query** field's string arguments (never a Mutation — read-only by construction),
deriving a valid selection set from each field's return type. The same battery then
probes them. **Result:** recon went from 0 endpoints to **8 Query-field probes**, and
the existing checks confirmed **two real criticals** — error-based SQL injection on
`pastes(filter)` (an `sqlite3.OperationalError` leaking the live `SELECT ... FROM
pastes`) and command injection on `systemDebug(arg)` (`uid=1000(dvga)` output) — with
no code tuned to DVGA. One bug surfaced and fixed in the same pass: a field returning
a **union** (`search → [SearchResult]`) was given an empty selection, making its probe
query invalid; unions now select `__typename`, which is valid on any composite type.

The remaining named gap is **JSON/body injection on state-changing verbs** (POST/PUT/
DELETE, and GraphQL mutations) — held outside the read-only line until a reviewed
body-injection increment, per [LIMITATIONS.md](./LIMITATIONS.md) §3.

## The "honest zeros" that weren't — a silent login failure

The multi-lab table above records **bWAPP** and **WebGoat** as "0 findings, clean
halt," filed next to DVNA's honest 0 as evidence the agent degrades gracefully. That
reading was wrong, and catching it is the single most important result in this file.

> **Intervention point.** Three login-gated labs in a row reported a clean zero. The
> comfortable story is "they're gated, honest miss" — the same honest-zero we'd just
> earned on DVNA. But a zero from a correct probe and a zero from a capability that
> silently never ran are **indistinguishable in the findings count**, and if a
> judge's target sits behind a login, the second kind loses the entire result while
> looking fine. We stopped counting and tested the login itself.

**Root cause — three faults stacked into one silent lie.** Against DVWA, login
genuinely failed yet reported success. `parseLoginForm` captured the hidden
`user_token`, the username, and the password, but **dropped the submit button** —
and DVWA authenticates only when `$_POST['Login']` is set, so every login POST was
silently rejected. `login()` then set `loggedIn = true` **without reading the
response**, and `agent.ts` wrapped the call in `.catch(() => undefined)`. We proved
it in isolation: the same POST **without** the Login button returned 200 and stayed
denied; **with** it, 302 to an authenticated page. The agent had been probing every
gated lab logged out while reporting a healthy session.

**The fix (shipped).** `parseLoginForm` now carries the submit control verbatim —
both `<input type=submit name=…>` and `<button type=submit name=…>`. `login()`
reads the post-login response and **verifies** it (failure = bounced back to the
login URL, or the password field still present in the body), emits
`session.login{ok}`, and **throws** on failure instead of swallowing it. The CLI
renders a green `authenticated` or a red `LOGIN FAILED — probing continues
UNAUTHENTICATED`. The Tier-2 browser session got the same verification. A new
`session-login.test.ts` locks the CSRF-token carry, the required submit button, and
both the success and failure verdicts.

**A second fault the first one hid — incomplete form posts.** With login fixed, DVWA
still found nothing, because injecting one field in isolation isn't how its sinks
fire: the SQLi runs only when `?Submit=Submit` rides along (`id='` alone confirmed
nothing; `id='` **with** `Submit` confirmed it). Recon now captures the form's full
control set with defaults (`formData`), and an injection **resubmits the complete
form** with a single payload override — exercising the sink as a browser would.

**Result — the login was genuinely broken.** Credentialed login now authenticates on
every shape we threw at it, each a silent zero before:

| Lab     | Login shape                                  | Login before → after     |
| ------- | -------------------------------------------- | ------------------------ |
| DVWA    | hidden `user_token` + `<input name=Login>`   | silent fail → **tier 1** |
| bWAPP   | `<button name=form value=submit>`            | silent fail → **tier 1** |
| WebGoat | Spring Security form, no submit btn, no CSRF | auth wall → **tier 1**   |

This is the **fourth** real bug a skeptical re-read of a number exposed, and the
costliest had it shipped: not a crash, not a false positive, but a false _negative
dressed as a clean result_ — the one failure mode an honest zero is supposed to rule
out. WebGoat, named in an earlier draft as "still not run," now authenticates too.

**But the first counts this unblocked were themselves wrong.** An earlier draft of
this section put the credentialed results at "DVWA 12 (9 SQLi…)" and "bWAPP 6 SQLi."
Reading what produced those numbers — the discipline this whole file is about —
showed most were false positives from a separate detector bug. The honest figures,
and how we found them, are the next section. We leave the inflated draft numbers
named here rather than quietly overwritten, because pretending the first pass was
clean is exactly the self-deception the rest of this file argues against.

**Operator setup (provisioning, not source-reading):** DVWA — run `setup.php` to
create the DB, log in `admin`/`password`, security level defaults to low; bWAPP —
install via `/install.php?install=yes`, log in `bee`/`bug`; WebGoat — register a user
via `/WebGoat/registration`, log in with it. Same credentialed black-box category as
every setup above.

## The false positives hiding in the counts

Running WebGoat credentialed (login now working) returned **one** finding: a
_critical_ SQL injection on `start.mvc`. It was wrong, and chasing why overturned
several numbers above.

> **Intervention point.** A critical on the first try against a famously-hard target
> is the result you _want_ to believe. Three facts said don't: `start.mvc` is a menu
> shell that ignores the injected parameter; the Tier-1 (raw HTTP) probe found
> nothing and only Tier 2 (the rendered SPA DOM) "confirmed"; and `start.mvc`
> returned **byte-identical** bodies for the payload, a benign value, and no value at
> all. An injection that changes nothing in the response is not an injection.

**Root cause.** The error-based SQLi check matched a pattern that included the bare
word `sql`. Scanned across the whole response body — and, on Tier 2, across a
JavaScript-rendered DOM — that matched the application's own content, not a leaked
error. WebGoat is a security-teaching app; its lesson menu literally lists
`1.sql.injection.title`. The word "SQL" in a nav link became "evidence" of SQL
injection.

**The audit.** If a menu naming "SQL Injection" can confirm SQLi, every HTML lab
with such a menu was suspect. Re-running each with the signal that the fire _was_
caused by the payload:

| Lab        | Earlier count | Real (true-positive) count | False positives were…                                                                            |
| ---------- | ------------- | -------------------------- | ------------------------------------------------------------------------------------------------ |
| WebGoat    | 1 SQLi        | **0**                      | the lesson menu                                                                                  |
| DVWA       | 9 SQLi        | **2 SQLi**                 | 7 pages whose only "error" was the nav (home, CSP, the _cmdi_ page, `sqli_blind`, two XSS pages) |
| bWAPP      | 6 SQLi        | **0**                      | all 6 — the bug-selection dropdown (38 "SQL Injection" strings on `portal.php` alone)            |
| Mutillidae | 9 SQLi        | **6 SQLi**                 | 3 menu matches                                                                                   |
| DVGA/VAmPI | 2 / 1         | **2 / 1** (unchanged)      | none — a JSON/GraphQL API has no nav menu                                                        |

The XSS and traversal/LFI findings were never affected: they key on a _unique
injected marker_ reflected un-escaped, or on leaked host-file contents — neither of
which is a word the app says about itself.

**The fix (shipped).** Two layers, in `loop/actions.ts`:

1. **Real error signatures, not the topic word.** `SQL_ERROR` now matches only text a
   database or driver emits on failure (`error in your SQL syntax`, `SQLITE_ERROR`,
   `ORA-…`, `sqlite3.OperationalError`, `unrecognized token`, …), never the bare word
   "sql" or "postgres". Validated against the real leaked errors from DVGA, VAmPI,
   DVWA, Mutillidae and Juice Shop (all still match) and against the menus that fooled
   it (none match).
2. **A benign-control differential.** Every presence-based signal — a DB error, leaked
   file contents, shell output — now re-sends the same request with a _benign_ value
   and confirms the signal is **absent** from that control. A signal that appears
   regardless of input is application content, not payload-caused evidence, and no
   longer confirms. Spot-proven live: Mutillidae's `user-info.php` leaks
   `error in your SQL syntax` under a quote (at byte > 2 KB, so whole-body detection
   is still doing its job) and comes back clean under a benign value.

**The honest post-fix scorecard**, every finding re-run and verified payload-caused
across all nine labs: Mutillidae **14** (6 SQLi, 7 XSS, 1 LFI) · DVWA **5** (2 SQLi,
2 XSS, 1 cmdi) · DVNA **4** (2 SQLi, 1 cmdi, 1 XSS) · Juice Shop **3** (SQLi,
auth-bypass, BAC priv-esc) · DVGA **2** · VAmPI **1** · BodgeIt **1** · bWAPP **0** ·
WebGoat **0** — 30 findings across seven labs plus two honest zeros (the full table,
with stacks and surfaces, is in [README.md](./README.md)). DVNA rose from the single
credentialed SQLi above to four once the widened battery reached `POST /app/ping`
(error-based SQLi **and** command injection) and `POST /app/products` (reflected XSS),
each confirmed by the control differential or the boolean oracle. bWAPP's zero is now
honest in a second sense: its real injectable pages sit behind a bug-selection dropdown
the crawler doesn't drive, so they were never reached — a coverage gap, named, not a
graceful miss. This is the **fifth** bug a cold/unseen target exposed by reading the
agent's work, and the only one where the number that lied was a _finding_, not a zero.

## The degraded run that still claimed the objective — found by someone who didn't build it

Every bug above was found by the team re-reading its own numbers. This one wasn't. We
handed the repo to a **true non-builder** — no stake in the result, no knowledge of the
code — and asked them to follow the README cold on a fresh clone. They ran the flagship
Juice Shop beat and it reported **3 findings, "objective reached."** Then they noticed
what we never had: the run had spent **`$0.00`**, and the trace was full of
`fallback: true`. The headline demo had reached its objective **without the model ever
running**.

> **Intervention point — the one we didn't catch ourselves.** Every other entry here is
> about the _accuracy of a finding_. This is upstream of all of them: whether the
> flagship claim is **AI-driven at all**. A reader who shrugs — "it still found three
> things" — misses it. Our tester didn't. `$0.00` + `fallback: true` sitting next to
> "objective reached" is precisely the juxtaposition that should scream and didn't. We
> treated it as the single most serious reporting-honesty bug in the project, above even
> the silent login, because it touches our own headline rather than a side capability.
> **Date:** 2026-11-15.

**Root cause — a legitimate design, dangerously unlabeled.** Nightfall is built so the
model is an _optimizer over a deterministic floor_, never a single point of failure:
`planner.ts` returns `undefined` when it can't decide and the loop runs the
front-of-queue order; the flagship auth-bypass chain is seeded deterministically and
"runs even when grounding is unavailable" (`agent.ts`). That floor is **general** — it is
built from recon'd endpoints, not scripted to Juice Shop — and the hand-written probes,
not the model, are what set `objectiveReached`. All of that is sound. The bug was what
happened when the model wasn't merely _undecided_ but **unreachable**: an invalid or
absent `BIFROST_API_KEY` makes `gateway.complete` throw a 401. `assertCanAfford` has
already passed and `budget.add` is never reached, so **spend stays $0.00**; the throw is
caught in both the planner and the hypothesis paths, neither is a `BudgetExceededError`,
so each is swallowed into a silent fall back to the deterministic floor. The run then
completes the scripted chain, reaches the objective, and writes a report whose only trace
of any of this was a single `model spend: $0.0000` line — no banner, no flag, no halt.
The `fallback: true` signal existed only in the per-decision `.audit.jsonl`, exactly
where a cold reader scrolls past it. `RunState` carried no count of model calls at all,
so nothing downstream could even ask "did the model run?" And the `run` command did no
up-front key check — a missing key was a silent degrade, not an error.

**Is it Juice-Shop-specific? No — and that cuts both ways.** It is generic resilience, so
it is _not_ scripted Juice-Shop logic masquerading as an agent (the worse of the two
possibilities). But because the floor runs on every lab, _any_ run with a broken key
would have degraded the same way and looked identical to a grounded one. Nothing in the
output distinguished the two.

**The decision.** Should a degraded run ever be allowed to claim "objective reached"? We
kept the deterministic floor — it is a real resilience property and its findings are real
and replayable — but ruled that it may **never again be presented as the AI-driven
result**. If the model is never reached, the run is now **degraded**, and that is stated
unmissably, not inferred from a `$0.00`.

**The fix (shipped, test-locked).**

1. `RunState` now counts `modelCalls` (completed gateway calls, cache hits included) and
   `modelErrors` (calls that threw a non-budget error). `isDegraded` = _a call was
   attempted and every one missed_ (`modelCalls === 0 && modelErrors > 0`) — so a run
   that simply never needed the model is **not** falsely flagged.
2. `run.end` now carries `modelCalls` and `degraded`. The terminal summary prints the
   model-call count and, on a degraded run, a red **`⚠ DEGRADED RUN`** banner spelling out
   that findings are deterministic-only with no live grounding.
3. The report renders a **`DEGRADED RUN — NO MODEL GROUNDING`** banner _above the
   executive summary_, adds `model calls: N` to the run line, and softens the attack-chain
   language so "objective reached" is never dressed as model reasoning on such a run.
4. The CLI warns up front when `BIFROST_API_KEY` is unset, and the README now lists
   prerequisites and states plainly that `.env.example` without real keys degrades rather
   than errors.
5. `loop.test.ts` locks that an unreachable model yields `degraded` + `modelCalls: 0` on
   both the state and the `run.end` event while a real success does not; `report.test.ts`
   locks that the banner appears above the summary on a degraded run and is absent on a
   grounded one.

**The honest result.** The finding _counts_ in the results table are unaffected —
detection was always deterministic, so the model was never load-bearing for _whether_ a
vulnerability is found. What a degraded run genuinely loses is the planning and the live
CVE grounding — the Tavily story — and that loss is now impossible to miss instead of
invisible. The standing rule for the submission follows directly: **the flagship beats
must be run with real keys and show `model calls: N > 0` plus `tavily.cve` events** (the
honest proof the model was load-bearing), or they are not the grounded result and must
not be presented as one. Note that **spend is _not_ the signal**: a live-verified run on
2026-11-15 against Juice Shop confirmed all three findings with 3 model calls and 4 live
Tavily CVEs, yet reported `$0.00` — the gateway model was priced at zero (`NF_PRICING`
override), and a run routed through a free/zero-priced model spends nothing while being
fully AI-driven. Keying the check on spend would have falsely flagged it; keying it on
`modelCalls` does not. This is the **sixth** bug a skeptical read exposed, the first found
from outside the team, and the only one that touched not a number but the claim the whole
system rests on.

## DSVW — the minimal-chrome edge case, and a numeric-context blind spot

A new multi-lab expansion pass (new stacks/surfaces, same cold discipline) opened with
**DSVW (Damn Small Vulnerable Web)** — a single-file, ~98-line Python app whose entire
injectable surface is query parameters on `/` (`?id=`, `?name=`, `?domain=`, `?xml=`, …),
served with almost no page chrome. It is the deliberate opposite of Mutillidae's 49 KB
shell: the stress test for whether detection still works when there is barely any HTML to
scan. We had not read its vulnerability logic (only its listen port and bind address, to
containerize it — operator-level, like a `docker run`).

- **Target:** DSVW (`stamparm/DSVW`), containerized `python:3.12-slim`, rebound to
  `0.0.0.0` inside the container and published loopback-only on `127.0.0.1:65412`.
- **Setup:** `allow.hosts: [localhost]`, `/` allowed, `$3` budget, 30 steps — the standing
  cold-run rigor, nothing loosened.
- **Date:** 2026-11-15.
- **Backend note (flagged):** this pass began on a role split (`exploit_reason` →
  `gemini-3.5-flash`, the rest → `gemini-3.5-flash-lite`). Mid-pass the strong model hit a
  hard **~20-requests/day** free-tier cap (the whole flagship **and** Flash tier carry it;
  only Flash-**Lite** has ~500/day), so all roles were moved to `gemini-3.5-flash-lite`
  until the quota resets. Flagged for review, one line to revert. The existing 30 findings
  were produced on the `gemini-4-hydrogen` flagship; this pass runs a weaker model, so its
  results under-claim relative to those, never over-claim.

**Run 1 — 0 findings, 9 model calls (not degraded).** A clean zero on an app that is
*nothing but* trivially-injectable parameters is exactly the honest-zero-that-isn't the
rest of this file is about. We did not accept it.

> **Intervention point #1.** The comfortable read: "minimal app, graceful miss." But DSVW's
> `/?id=` is a textbook SQL injection. We reproduced the agent's probes by hand and read
> the raw responses. `/?id=2'` → **HTTP 500 with `sqlite3.OperationalError` in the body**;
> `/?id=2 AND 1=1` vs `/?id=2 AND 1=2` → **different row counts**; `/?id=2 UNION SELECT …`
> → **leaks `admin`**. The vulnerability is real and confirmable three ways. The agent
> missed all three.

**Root cause — a numeric-context blind spot, doubly masked.** DSVW's sink is
`WHERE id=<value>` — an **unquoted, numeric** context. Nightfall's SQLi battery was
string-context only: a quote-pair error probe and a `' OR '1'='1` / `' AND '1'='2` boolean
oracle. Against `WHERE id=<value>` both fail, and *two* precision mechanisms conspired to
make the failure silent:

1. The quote probe *does* trip `sqlite3.OperationalError` — but a **benign control value**
   (`nf…`, alphanumeric) is itself an invalid column reference in `WHERE id=nf…`, so the
   control **also** errors. The benign-control differential (the WebGoat-FP backstop)
   correctly concluded "present regardless of input" and suppressed it. The backstop
   working as designed produced a false negative.
2. The string boolean payloads (`nf…' OR '1'='1`) only yield the same parse error for both
   arms — no row differential — so that oracle fell through to the 5xx status contract,
   which classifies a 500 as a transient server error and abandons.

Net: a real SQLi, abandoned as "transient server error 500." A numeric boolean oracle
(`0 OR 1=1` → every row vs `0 AND 1=1` → none) separates all-rows from none and confirms
on a pure row differential — the same impact basis as the string oracle, so it cannot be
fooled by menu chrome and never touches the suppressing error-control path.

**The fix, and getting it wrong first (the honest part).** We added a numeric-context
boolean oracle beside the string one. First pass used literal-space payloads (`0 OR 1=1`).
Unit test green, hand-curl with `%20` green — but the **live re-run still found 0**.

> **Intervention point #2 — our own fix didn't fire, and we read the live run instead of
> trusting the passing unit test.** The planner was correctly targeting `/?id=2`; the
> oracle was reached; it still missed. The cause was encoding: `withParam` serializes a
> GET value's spaces to `+`, and DSVW's raw Python query parser does **not** decode `+`
> back to a space — so `0+OR+1=1` is invalid SQL and 500s, while `0%20OR%201%3D1` works.
> The unit test, driving an in-memory stub, never exercised the wire encoding, so it passed
> on a payload the real target rejected. (The same `+` issue silently weakens the *string*
> oracle on any raw-query app that doesn't decode `+` — named below, not fixed here.) The
> fix: write the oracle's spaces as SQL inline comments `/**/`, which carry no space to
> encode and read as whitespace to every engine. `0/**/OR/**/1=1` survives both parsers.

**The honest result.** After the comment-payload fix, a cold re-run (21 model calls, not
degraded, no code tuned to DSVW) **confirms the SQL injection** on the `id` parameter —
CWE-89, critical, **Impact-confirmed** by the numeric boolean oracle (`0 OR 1=1` returned
every record; `0 AND 1=1` returned none). Zero false positives: every confirmation is a
row differential, so DSVW's vuln-name index menu — the Mutillidae/WebGoat FP trap — never
fires.

Two honest caveats, both under-claimed rather than dressed up:

- **It is one finding, not four — now enforced in code.** The first fixed run emitted
  **four** SQLi findings — all the *same* `id`-parameter vulnerability, reached through four
  URL variants DSVW lists as example links on its index (`?id=2`, `?id=2 UNION …`,
  `?id=(SELECT CASE …)`, …). True positives of one bug, not four. Finding de-duplication now
  keys on weakness class + endpoint scope (host + path + sorted parameter *keys*, never
  payload values), so the re-run reports a correct **1** directly, while two genuinely
  different parameters on one path still count separately. A regression test
  (`loop.test.ts`) locks both directions. (Numbers shown as corrected, not silently edited:
  4 → 1.)
- **The `+`-encoding masking, fixed.** The first fix's spaces serialized to `+` (above); the
  general cause — `withParam` emitting `+` for spaces, which a raw query parser does not
  decode — is now fixed at the source (`withParam` emits `%20`), so every space-bearing GET
  payload survives a raw parser, not just the numeric oracle's `/**/` form.
- **SQLi only (named residual).** DSVW's XSS (`?v=`), OS command injection (`?domain=`), LFI
  (`?path=`/`?include=`) and XXE (`?xml=`) were attempted but **not** confirmed even after the
  `%20` fix — their checks have their own detection-shape mismatches against DSVW's sinks
  (reflection target, command-output signal, XML body), separate from the encoding issue.
  Named as residual coverage, not claimed.

This is the **seventh** bug a cold target exposed by reading what the agent did rather than
trusting a number — here a *zero*, on an app too small to hide behind. Its regression test
(`actions.test.ts`, "confirms boolean-based SQLi in a NUMERIC context …") locks that the
numeric oracle confirms where the quote and string-boolean probes are defeated, and does
not fire on a stable endpoint.

## DVWS (SOAP) — from blind spot to confirmed capability

Lab #5 targeted the SOAP/WSDL surface, where Nightfall had **zero** coverage. The honest
first outcome was reached before any scan: the only community "DVWS" Docker image
(`tssoffsec/dvws`) stood up as a **DVWA-style HTML-form clone** — its index links
`brute-force.php`, `error-sql-injection.php`, `reflected-xss.php`, … and every WSDL path
404s — not a SOAP service. The genuine WSDL-based DVWS (`interference-security/DVWS`) ships
no clean image (manual XAMPP + PHP SOAP extension).

> **Intervention point — don't fake a SOAP run on a non-SOAP app.** The temptation was to
> point the agent at the "DVWS" image anyway and record a result. But it isn't a SOAP
> target, so any number from it would be a second DVWA, mislabeled. Instead we verified the
> gap at its source: a grep of `packages/core/src` for `wsdl|soap` returned nothing — recon
> had no WSDL discovery and the battery no SOAP-envelope injector. A live run on that image
> would only reproduce a 0 the gap already predicts, so it was named in
> [LIMITATIONS.md](./LIMITATIONS.md) as a code-verified blind spot, not dressed up as a pass.

**Then the gap was closed, with a real target.** Rather than leave SOAP named-but-untested,
a genuine vulnerable WSDL service was stood up to build and validate the capability against:
a [spyne](https://spyne.io) service (`nf-lab-soap`, loopback-only on `127.0.0.1:8891`)
exposing `findUsersByName(username)` whose handler builds `SELECT name FROM users WHERE
username='<username>'` by raw string concatenation — a real SOAP SQLi, with the engine error
hidden behind spyne's generic `faultstring>Internal Error` (so error-based can't fire).

The capability mirrors the existing GraphQL path (discover a contract → enumerate injectable
inputs → read-only battery):

- **Recon** probes the conventional WSDL locations; on a hit it parses the target namespace,
  the service address, each operation's SOAPAction, and the request-wrapper's string
  parameters, emitting one endpoint per (operation, parameter). Read-only by construction —
  an allow-list of read-like operation verbs (get/find/search/list/read/…) with a
  state-changing-verb deny check, the SOAP analogue of GraphQL's Query-only rule.
- **Injection** builds a SOAP 1.1 envelope with the payload XML-escaped into the target
  element (the server's XML parser decodes it back, so the raw quote still reaches the sink)
  and siblings at benign defaults.
- **Confirmation** is the boolean oracle, extended to count repeated SOAP **result elements**:
  a generic fault defeats error-based, but `' OR '1'='1` returns N `<tns:string>` rows and
  `' AND '1'='2` returns 0 — the same impact-confirmed differential the HTML/JSON oracle uses.

Live result against the fixture — recon found the probe and the oracle confirmed, unaided:

```
recon endpoints: 1 | soap probes: 1
  SOAP: {"operation":"findUsersByName","param":"username", … ,"soapAction":"findUsersByName"}
attempt.ok = true
note  = always-true condition returned 3 record(s) vs 0 for always-false on
        'findUsersByName.username' — boolean-based SQLi
basis = Impact-confirmed: two requests differing only in a boolean … read rows unauthorized.
```

A benign/non-injectable operation (same result set for both payloads) yields no differential
and does not confirm — locked by a unit test alongside the live check. The residual **XML-RPC**
surface, and SOAP inputs that are not string-typed, remain named in
[LIMITATIONS.md](./LIMITATIONS.md) for a later increment.

## sqli-labs — cold runs on a canonical public SQLi benchmark

With the legacy-manifest pull path fixed (see below), `acgpiano/sqli-labs` stood up
loopback-only (`127.0.0.1:8899`) — the 65-lesson SQLi training app ("Welcome Dhakkan").
Two representative lessons were run **cold**, each as its own scope targeting the lesson's
`?id=` entry point (sqli-labs hides the injectable parameter behind instructional text, so a
crawl from `/` never seeds it — the operator supplies the entry URL, as on a real engagement):

- **Less-1 (string context)** — recon discovered `/Less-1/?id=1`, fingerprinted Apache
  2.4.7 / PHP 5.5.9, and the battery confirmed **SQL Injection (critical)** error-based: an
  unmatched quote returned the MySQL parser error, absent from a benign control. 22 model
  calls, `$0.00`, halted on an exhausted queue — not degraded. The agent then tried an
  auth-bypass escalation and **honestly abandoned it** (Less-1 is not a login surface).
- **Less-2 (numeric context)** — same outcome at `/Less-2/?id=1`: error-based SQLi confirmed,
  22 model calls, not degraded.

**Honest framing — no metric-gaming.** Both confirmations are error-based disclosures;
sqli-labs leaks the engine error openly, so the error path short-circuits before the boolean
oracles are even reached. These runs are **not** a numeric-oracle showcase (that remains
DSVW's, where the error path is defeated). And because sqli-labs is, by construction, 65
near-identical SQLi challenges, running all of them would inflate the tally meaninglessly — a
representative string + numeric pair is counted, not the full set.

## Infrastructure — the legacy schema1 manifest blocker (and the general fix)

This host runs Docker 29.8.2 with the containerd store (containerd 2.1), which refuses the old
schema1 manifest format (`application/vnd.docker.distribution.manifest.v1+prettyjws`). Many
classic vulnerable-app images (xvwa, owaspbricks, old mutillidae, …) were pushed years ago in
schema1 and fail a direct `docker pull`. `scripts/pull-legacy-image.sh` converts schema1 →
v2s2 with skopeo (run from `quay.io/skopeo/stable`, nothing installed on the host) and loads
the result into the daemon — proven on `owaspbricks` and `xvwa`. crAPI was never blocked by
this (its images were already local); its only gap was a missing compose file, now durable at
`labs/crapi/` (all ten images present, binds loopback by default, booted and verified serving
the real "crAPI" web + identity API before teardown).

## Pikachu — a broad-class cold run (SQLi + XSS + command injection)

`area39/pikachu` (loopback-only, `127.0.0.1:8900`, DB initialised via its `install.php`) is a
multi-class PHP/MySQL training app — the first expansion target that exercises the XSS and
OS-command-injection paths at breadth, not just SQLi. Two cold runs:

**Root crawl (`/`, 40-step cap).** Recon crawled the vuln surface (sqli / xss / csrf /
bruteforce pages) and the battery confirmed **7 findings** — 29 model calls, `$0.00`, halted
on the step cap (not degraded):
- **3 SQLi (critical)** — `sqli_id.php`, `sqli_str.php`, `sqli_search.php`, all error-based.
- **4 reflected XSS (high)** — `xss_reflected_get.php`, `xss_stored.php`, `xss_01.php`,
  `xss_04.php`.

**Targeted RCE run (`/vul/rce/`, scoped path).** Recon found `rce_ping.php` / `rce_eval.php`
and the battery **impact-confirmed OS Command Injection (critical)** at `rce_ping.php`: a
benign appended `; id` returned its output (`uid=…www-data`), absent from a benign control —
read-only, no destructive command. 25 model calls, not degraded; the scope gate blocked 96
out-of-path URLs (deny-by-default working). The agent then **honestly abandoned** two
escalation attempts ("Unauthenticated RCE via php2shell" against the PHP-`eval` page) with
"no command output observed" rather than fabricate a result.

**FP audit (mandatory on a high count).** All 8 findings were independently ground-truthed by
hand before being counted: each SQLi leaks the MySQL parser error on a quoted probe; each XSS
reflects a raw `<i>` marker un-escaped while a bracket-free control does not; the cmdi returns
live `id` output. No false positives. One honest **under-label**: `xss_stored.php` is a
*stored* XSS surface that the detector confirmed via its immediate reflection and reported as
"Reflected" — the finding is real, the class label understates its severity. (`xss_01.php` /
`xss_04.php` are additional reflective endpoints this image ships beyond the canonical
reflected/stored pages; each is an independently injectable URL.)

Pikachu's remaining classes — PHP-`eval` code injection, file inclusion, SSRF, unsafe upload,
CSRF — are out of the current battery and left as named residuals, not claimed.

## XVWA — a broad-class run on the Cloudflare Llama backend, and a traversal-depth fix

`tuxotron/xvwa` (loopback-only, `127.0.0.1:8901`, DB initialised) was run cold — and this time
on the **Cloudflare Workers AI Llama 3.3 70B** backend: `NF_MODEL_STRONG` pointed at
`cloudflare/@cf/meta/llama-3.3-70b-instruct-fp8-fast`, so every model call (the loop's only
model-calling role, `exploit_reason`) ran on Cloudflare. The root crawl confirmed **SQL
Injection** and **OS Command Injection** (41/41 calls on Llama, 0 on Gemini, not degraded) —
proof the "shed load to a second free-tier quota" lever works end to end.

**FP audit — a decoy parameter caught and dismissed.** XVWA's SQLi page carries the literal
words "SQL" and "error" in its own lesson text, and its GET `?item=` parameter is a **decoy**:
every GET payload (`1`, `1'`, a benign string, boolean pairs) returns the byte-identical 8923-
byte page. A naive error-string match would fire on the static text and report a false SQLi.
It did not: the injection is on the **POST** form (`<select name=item>` / `search`), which recon
captured, and there `item=1'` leaks a genuine MySQL parser error while the benign control
`item=nf…` does not — the benign-control differential both confirmed the real POST injection and
suppressed the decoy GET surface. (Verified by hand before counting.)

**An honest miss that drove a real fix.** XVWA's file-inclusion module leaks `/etc/passwd`, but
the first targeted Path-Traversal run **abandoned** it — "no file contents leaked" — rather than
fabricate. Reading the raw responses showed why: the module sits at
`/var/www/html/xvwa/vulnerabilities/fi/` (six levels below `/`), and the probe used a single
fixed `../../../../etc/passwd` (four levels) that never climbs out of the module directory. The
file leaks only with an **absolute** path or a **≥6-level** traversal.

> **Intervention point — fix the detector, don't fudge the result.** The miss was a genuine
> coverage gap, not a hardened target. `pathTraversalCheck` now probes an absolute path plus a
> range of depths (3/5/7/10 `../`) instead of one fixed depth — excess `../` collapses at the
> root, so an over-deep sequence is harmless, and every payload still names the same benign,
> world-readable file (read-only). A regression test locks it: an include that leaks only at
> depth ≥ 6 (or absolute) is now confirmed, while one that never leaves its directory is not.
> The re-run then confirmed **Path Traversal / File Inclusion** via the `/etc/passwd` payload,
> absent from a benign control — 21 model calls, not degraded.

**XVWA total: 3 findings** — SQL Injection, OS Command Injection, Path Traversal / File
Inclusion — all hand-verified, the LFI landed only after the depth fix. (The re-run reported the
LFI twice under two URL scopes of the same `file` parameter; it is one vulnerability, counted
once.) The stored/reflected XSS and file-upload modules were not reached within the step caps and
are named residuals, not claimed.

## WackoPicko — a recon fix for malformed forms, and the Cloudflare quota wall

`adamdoupe/wackopicko` (the author's image, loopback-only on `127.0.0.1:8902`) is a canonical
scanner-benchmark app. The first cold run (on the Cloudflare Llama backend) confirmed **1**
finding — reflected XSS at `/pictures/search.php` (the search term is escaped in the input
`value` but reflected **un-escaped** in the "Pictures tagged as '…'" heading). But a hand
ground-truth showed the login form is a textbook SQLi (`username=admin'` → a raw MySQL
syntax error), and the agent **missed** it — so, per the "never accept a miss without proving
why" rule, this was run down rather than shrugged off.

**Root cause — a recon form-parsing gap.** WackoPicko's login form wraps its inputs in
`<tr>`/`<td>` with **no enclosing `<table>`** (invalid HTML). HTML5 foster-parenting then
hoists those inputs *out* of the `<form>` element, so cheerio's `$(form).find("input")` returns
nothing: recon recorded the POST endpoint with **no fields**, and the SQLi probe — with nothing
to inject — degraded to a harmless GET `?q=` on the wrong surface. A recon+attempt diagnostic
pinned it exactly: `{method: "POST", hasParams: true}` with `fields`/`formData` both empty.

> **Intervention point — fix recon, don't tune to the lab.** `recon` now falls back to a raw
> form-region scan when the parse tree yields an empty form, recovering the named controls that
> foster-parenting stripped (`recon/index.ts`). With the fix recon captures
> `fields: ["username"], formData: {username, password}`, and the error-based check confirms the
> login SQLi on the `username` sink (benign-control differential). A regression test locks it: a
> form whose inputs are foster-parented out still yields its injectable fields
> (`recon-routing.test.ts`). This is a general robustness win — legacy PHP apps routinely ship
> table-wrapped form inputs — not a WackoPicko special-case.

**An honesty beat — the Cloudflare quota wall and the degraded banner.** The re-run (still on
the Llama backend) hit a hard **429 — "you have used up your daily free allocation of 10,000
neurons"** on every model call. The run came back **DEGRADED (0 model calls)** and the report
led with the explicit banner — *"NOT the AI-driven result"* — exactly as designed. The
deterministic probe floor still confirmed **both** findings (including the login SQLi, proving
the recon fix stands without the model), but a degraded run is never counted as the AI-driven
result. Per STOP-on-429, `NF_MODEL_STRONG` reverted to Gemini flash-lite (ample RPD left) and
the lab was re-run clean: **2 findings — SQL Injection (login, critical) + reflected XSS
(high)** — 33 model calls, not degraded. That is the counted result.

**WackoPicko total: 2 findings**, both hand-verified. The file-inclusion and stored-XSS modules
were not confirmed (the `sample.php` LFI did not leak `/etc/passwd` on the probed parameters)
and are named residuals, not claimed.

## PyGoat — a Python/Django broad-class run, and a shell-error false positive

`pygoat/pygoat` (OWASP's Django teaching app, loopback-only on `127.0.0.1:8903`) is the first
**Python/Django** target in the battery — a deliberate break from the PHP lineage, to see the
detectors against a different framework and a different error vocabulary. Every lab is behind a
Django login, so this was also the second end-to-end **authenticated** run (after WackoPicko).

**Capability proof first — login, then a known-true finding.** Per the "never report a broken
capability as an honest zero" rule, nothing was trusted until the agent was proven to drive the
app. A `nfuser` account was registered, and the session's CSRF-aware login (hidden-token capture
+ persisted `csrftoken` cookie) was confirmed to reach the gated labs. The capability was then
proven on the lab whose vuln was hand-verified true: **OS Command Injection** at `/cmd_lab`
(`dig {domain}` via `shell=True`; `domain=127.0.0.1; id` → `uid=0(root)`). The agent confirmed
it (impact-confirmed, `; id` output absent from a benign control) — proving authenticated,
CSRF-protected POST attacks work end-to-end.

> **Intervention point — a shell error masquerading as SQLi.** That same `/cmd_lab` run returned
> a **second** finding: error-based SQL Injection on the `domain` field. A quote probe (`'"`) made
> the page print `/bin/sh: 1: Syntax error: Unterminated quoted string`, and the phrase
> *"unterminated quoted string"* is one of `SQL_ERROR`'s alternatives — so the shell's own parse
> error, emitted by the (real) command-injection sink, tripped the SQLi signature, benign-control
> differential and all. cmd_lab runs no SQL at all: this was a false positive. The fix adds a
> `SHELL_ERROR` guard (`/bin/sh:`, `sh: <n>:`, `command not found`, … — text no DB driver emits);
> when the matched "SQL error" is actually shell-produced, the SQLi signal is withheld. A
> regression test locks it: a `/bin/sh` syntax error at a command-injection sink must not confirm
> SQLi (`actions.test.ts`). Re-run: `/cmd_lab` now reports exactly **1** finding — the command
> injection — and the phantom SQLi is gone. A general hardening against every nslookup/ping/dig
> shell-out sink, not a PyGoat special-case.

**Reflected XSS — and a scope-prefix lesson.** `/xssL` reflects the `q` search term un-escaped
into an `<h3>` (`q=NF<b>` → raw `<b>`). The first run **missed** it. Root cause was neither the
detector nor the model: the search form's `action` is `/xssL1` (a distinct path alias of the same
view), and the scope allow-list named `/xssL` — which, under the gate's **segment-boundary**
prefix match (`/xssL` covers `/xssL` and `/xssL/…`, *not* `/xssL1`), dropped the form endpoint at
recon time, so the `q` sink was never probed. This is a scope-config correctness point, not a
code change: with `/xssL1` added to scope, the agent confirmed **Reflected XSS** via `q` (marker
reflected un-escaped). Worth recording because a too-narrow allow-list produces a silent miss that
*looks* like a clean negative — the opposite of the honesty posture.

**An honest miss, left as a miss — the gated password sink.** `/sql_lab` is a real SQLi, but an
unusually buried one: the view runs `login.objects.filter(user=name)` (ORM-safe) as a **gate**
before concatenating — so the injectable sink is the **`pass`** field, reached only when `name`
exactly matches a seeded user. The agent found nothing, and the miss is double-caused and
legitimate: (1) recon deliberately excludes `password`-type inputs from injectable sinks
(injecting a password field causes lockouts/noise and is almost never a sink), so `pass` is never
probed; (2) the only probed field, `name`, is ORM-gated, so it yields no differential. Even
lifting the password exclusion would not reach it without knowing `name=admin`. This is a true
negative with a proven cause — **not** a broken-capability zero (the same run style confirmed
CMDi and XSS, login worked, 18 model calls) — so it is documented as a limitation, not patched
around. See [LIMITATIONS.md](./LIMITATIONS.md).

**PyGoat total: 2 findings** — OS Command Injection (critical) + Reflected XSS (high), both on
the Gemini flash-lite backend, not degraded. The run's lasting artifact is the `SHELL_ERROR`
guard: a false positive that only a different-framework, shell-based sink would surface.

## OWASP Bricks — a canonical SQLi/XSS benchmark, and a dual-reflection brick

`citizenstig/owaspbricks` (loopback-only on `127.0.0.1:8904`, `inject` DB provisioned via its own
`config/setup.php`) is a classic deliberately-vulnerable PHP/MySQL benchmark organised into
"bricks": content pages (`/content-1/…/content-6/`), login pages (`/login-1/…`), and file-upload
pages. Run cold on two bricks of different classes.

**content-1 — a brick that is XSS *and* SQLi at once.** The page echoes its own query verbatim
(`SELECT * FROM users WHERE idusers=<id> LIMIT 1`), so the `id` parameter is reflected un-escaped
*and* concatenated into a numeric SQL context. The agent confirmed **Reflected XSS** (`id=nfx7q9<i>`
→ raw `<i>` in the echoed query — hand-verified). It **missed** the co-located error-based SQLi
within the step budget: the planner wandered into hallucinated-CVE escalations (PHP-FPM RCE, a
mod_proxy DoS, an open-redirect) instead of completing the quote probe — the same hallucinated-CVE
pattern seen on Pikachu, and honestly abandoned each with no signal. The SQLi is real
(`id=1'"` → *"You have an error in your SQL syntax"*; the benign control `id=nfabc123` yields only
*"Unknown column"*, which is **not** a `SQL_ERROR` alternative, so the differential is clean) — and
the identical error-based SQLi class **is** confirmed on the next brick, so this is a per-endpoint
miss, not a detector gap. Counted conservatively: content-1 = **1** (the XSS actually confirmed).

**login-1 — error-based SQLi and reflected XSS on the username sink.** The login form concatenates
`username` raw into `WHERE name='<username>' and password=…`. The agent confirmed **SQL Injection**
(critical — quote probe on `username` leaks the MySQL error, absent from a benign control) and
**Reflected XSS** (the username echoes un-escaped into the query string on the page). Both
hand-verified: `username=admin'` → MySQL syntax error; `username=' OR '1'='1' -- -` → *"logged
in."* (auth bypass); `username=nfx7q9<i>` → raw `<i>` reflected. login-1 = **2**.

**OWASP Bricks total: 3 findings** — Reflected XSS (content-1), SQL Injection + Reflected XSS
(login-1) — all hand-verified, on the Gemini flash-lite backend, not degraded. Residuals, named not
claimed: content-1's error-based SQLi (a within-budget planner miss, class confirmed on login-1),
and the remaining content/login/file-upload bricks (not run).
