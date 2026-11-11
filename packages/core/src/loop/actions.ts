import type { Session, SessionRequest, SessionResponse } from "../session/index.js";

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
}

export interface AttemptOpts {
  /** Route through the stateful session (vs. a raw tool call). */
  useSession: boolean;
  /** The specific in-scope URL this attempt targets. */
  url: string;
  /** Lowercased tokens from the objective used as a generic success signal. */
  objectiveHint?: string[];
}

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
  const direct = await probeObjective(session, technique, opts.url, hint);
  if (direct.ok || !steer || !isRoot(opts.url)) return direct;

  // Root with no signal: try the known broken-access surface before giving up.
  const admin = surfaceFor(opts.url, ADMIN_CONFIG_SURFACE);
  if (admin === opts.url) return direct;
  const viaAdmin = await probeObjective(session, technique, admin, hint);
  return viaAdmin.ok ? viaAdmin : direct;
}
