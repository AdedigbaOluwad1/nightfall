import type { AttemptResult } from "./actions.js";

export type Decision = "retry" | "escalate" | "abandon" | "pivot";

export interface InterpretCtx {
  /** Retries already spent on this exact technique. */
  retries: number;
  /** Cap on retries per technique before we give up on it. */
  maxRetries: number;
  /** Current session tier the attempt ran on. */
  tier: 1 | 2;
  /** A higher-capability path (Tier-2 browser) is available and not yet tried. */
  canEscalate: boolean;
}

export interface Interpretation {
  decision: Decision;
  note: string;
}

/**
 * Pure, deterministic recovery logic — no model call, so the loop behaves
 * identically on a cold target as on the one we rehearsed. Given a parsed
 * attempt result, decide how to recover. Success is handled by the caller
 * (record the finding); this function runs on everything that did NOT confirm.
 */
export function interpret(result: AttemptResult, ctx: InterpretCtx): Interpretation {
  // Transient failure (network error, 5xx, timeout): try the same thing again,
  // up to the cap. This is the "recover from a flaky step" path.
  if (result.transient && ctx.retries < ctx.maxRetries) {
    return { decision: "retry", note: `transient (${result.note}); retry ${ctx.retries + 1}` };
  }

  // The technique doesn't apply here at all (404, blocked, wrong stack): don't
  // waste steps hammering it — move to the next candidate.
  if (result.applicable === false) {
    return { decision: "pivot", note: `not applicable (${result.note}); pivot` };
  }

  // Plausible but unproven on this tier, and a stronger tier is available:
  // escalate (e.g. a JS-gated flow that raw HTTP can't reach).
  if (ctx.tier === 1 && ctx.canEscalate) {
    return {
      decision: "escalate",
      note: `unproven on tier 1 (${result.note}); escalate to tier 2`,
    };
  }

  // Out of retries or out of options: abandon this technique cleanly.
  return { decision: "abandon", note: `exhausted (${result.note}); abandon` };
}
