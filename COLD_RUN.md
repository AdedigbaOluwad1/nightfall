# Cold-target dry run — intervention log

The test everyone skips: point the agent at a **fourth, unfamiliar** vulnerable
app — one whose source none of us has read — and run it blind, logging every
moment we were tempted to step in. This is the honest version of the thing judges
actually worry about: not "does the rehearsed demo work," but "what does it do
when it meets something it wasn't tuned for."

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
