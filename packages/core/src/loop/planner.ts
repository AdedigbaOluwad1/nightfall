import type { Gateway } from "../gateway/bifrostClient.js";

/** One candidate action the planner may choose next. */
export interface PlanAction {
  technique: string;
  url: string;
}

export interface PlanInput {
  objective: string;
  /** Artifacts discovered so far (kind + label only — raw values never leave the loop). */
  artifacts: { kind: string; label: string }[];
  findings: { title: string; severity: string }[];
  /** Untried candidate actions, in current queue order. */
  pending: PlanAction[];
}

export interface PlanDecision {
  /** Index into `pending` of the action to run next. */
  pick: number;
  reason: string;
}

/**
 * Chooses the next action. Returns `undefined` when it cannot decide (the loop
 * then falls back to the deterministic front-of-queue order), so the model is
 * an optimizer over a reliable floor, never a single point of failure.
 */
export type Planner = (input: PlanInput) => Promise<PlanDecision | undefined>;

function buildPrompt(input: PlanInput): string {
  const artifacts =
    input.artifacts.length > 0
      ? input.artifacts.map((a) => `- ${a.kind}: ${a.label}`).join("\n")
      : "- (none yet)";
  const findings =
    input.findings.length > 0
      ? input.findings.map((f) => `- ${f.severity}: ${f.title}`).join("\n")
      : "- (none yet)";
  const actions = input.pending.map((a, i) => `${i}: ${a.technique}  →  ${a.url}`).join("\n");
  return [
    "You are the planning step of an authorized, in-scope black-box penetration-testing agent.",
    `Objective: "${input.objective}".`,
    "",
    "Artifacts already captured (usable as inputs to a next step):",
    artifacts,
    "",
    "Findings confirmed so far:",
    findings,
    "",
    "Candidate next actions:",
    actions,
    "",
    "Choose the ONE action most likely to advance toward the objective. Strongly prefer an",
    "action that USES an already-captured artifact (e.g. a session token) to escalate, over",
    "re-probing surfaces. Respond with ONLY a JSON object, no prose:",
    '{"pick": <index into the candidate list>, "reason": "<one concise sentence>"}',
  ].join("\n");
}

/** Extract and validate the planner's JSON decision; undefined on any doubt. */
export function parsePlan(raw: string, pendingCount: number): PlanDecision | undefined {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start === -1 || end <= start) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.slice(start, end + 1));
  } catch {
    return undefined;
  }
  const row = parsed as { pick?: unknown; reason?: unknown };
  const pick = typeof row.pick === "number" && Number.isInteger(row.pick) ? row.pick : undefined;
  if (pick === undefined || pick < 0 || pick >= pendingCount) return undefined;
  const reason =
    typeof row.reason === "string" && row.reason.trim() ? row.reason.trim() : "selected";
  return { pick, reason };
}

/** The default planner: one strong-model call through Bifrost per decision. */
export function makeGatewayPlanner(gateway: Gateway): Planner {
  return async (input) => {
    const raw = await gateway.complete("exploit_reason", buildPrompt(input));
    return parsePlan(raw, input.pending.length);
  };
}
