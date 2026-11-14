/**
 * The run's world-model (blackboard). Attempts read artifacts discovered by
 * earlier steps and write what they discover, so a later step can depend on an
 * earlier one — the thing that turns a flat list of probes into a real
 * multi-step chain. Shared by the loop and the per-technique checks.
 */

export type ArtifactKind =
  | "token"
  | "credential"
  | "endpoint"
  | "fingerprint"
  | "identifier"
  | "data";

export interface Artifact {
  kind: ArtifactKind;
  /** The raw value (a JWT, a URL, an id, a `component@version`, a data snippet). */
  value: string;
  /** Human label for the trace/report, e.g. "admin session JWT". */
  label: string;
  /** The technique that produced it. */
  from: string;
}

/** A follow-up step a confirmed attempt seeds for the loop to pursue next. */
export interface SeedStep {
  technique: string;
  url?: string;
  cve?: string;
  reason?: string;
}

export interface AttackContext {
  objective: string;
  objectiveHint: string[];
  artifacts: Artifact[];
  /** `${technique}|${url}` keys already attempted — the cycle guard. */
  visited: Set<string>;
}

export function newContext(objective: string, objectiveHint: string[]): AttackContext {
  return { objective, objectiveHint, artifacts: [], visited: new Set() };
}

/** The most recently discovered artifact of a kind, if any. */
export function latestArtifact(ctx: AttackContext, kind: ArtifactKind): Artifact | undefined {
  for (let i = ctx.artifacts.length - 1; i >= 0; i--) {
    if (ctx.artifacts[i]?.kind === kind) return ctx.artifacts[i];
  }
  return undefined;
}
