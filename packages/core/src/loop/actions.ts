import type { Session } from "../session/index.js";

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
 * The baseline below is a safe, non-destructive access probe: it routes a
 * gated request through the session and reports a structured, interpretable
 * result (confirmed / transient / not-applicable) for the recover loop.
 */
export async function attempt(
  session: Session,
  technique: string,
  opts: AttemptOpts,
): Promise<AttemptResult> {
  const request = `GET ${opts.url}`;
  let res: { status: number; body: string };
  try {
    res = await session.request({ url: opts.url });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // A scope block is a hard not-applicable; anything else is transient.
    const blocked = msg.startsWith("blocked by scope gate");
    return {
      ok: false,
      note: blocked ? "blocked by gate" : `transport error: ${msg}`,
      transient: !blocked,
      applicable: !blocked,
    };
  }

  const snippet = res.body.slice(0, 2000);
  const base = { status: res.status, evidence: { request, response: snippet } };

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

  // Generic success signal: a reachable page that matches the objective tokens
  // (e.g. an admin surface served without the expected auth) — broken access
  // control, provable without any payload.
  const hint = opts.objectiveHint ?? [];
  const hay = `${opts.url} ${snippet}`.toLowerCase();
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
