import { appendFileSync } from "node:fs";
import type { Bus } from "./bus.js";
import type { NightfallEventName } from "./types.js";

/**
 * Persist the full event stream to disk, one JSON object per line, as it happens.
 * Findings alone are the evidentiary artifact (`evidence/store.ts`); this is the
 * complete per-action trace — every request, plan decision, block, and gateway
 * call, not only the steps that produced a finding — so a run is replayable and a
 * reviewer can see exactly what the agent did and when. Append-only and
 * synchronous, like the evidence store, so a crash never loses prior lines; a
 * write error is swallowed so audit logging can never break a run.
 */
export class AuditLog {
  private readonly unsubscribe: () => void;

  constructor(
    bus: Bus,
    private readonly path: string,
    now: () => string = () => new Date().toISOString(),
  ) {
    this.unsubscribe = bus.onAny((type, payload) => {
      try {
        appendFileSync(
          this.path,
          `${JSON.stringify({ t: now(), type: type as NightfallEventName, payload })}\n`,
        );
      } catch {
        /* an audit-log write must never take the run down */
      }
    });
  }

  /** Stop recording. Safe to call more than once. */
  stop(): void {
    this.unsubscribe();
  }
}
