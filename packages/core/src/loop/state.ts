import type { HaltReason } from "../events/types.js";

export interface RunState {
  runId: string;
  steps: number;
  maxSteps: number;
  objectiveReached: boolean;
  findings: number;
  blocked: number;
  costUsd: number;
  /** Model calls that completed (a cache hit counts): the run's grounded work. */
  modelCalls: number;
  /** Model calls that threw a non-budget error — the model was reached for and missed. */
  modelErrors: number;
  /** Why the loop stopped — set once, read by the run summary and report. */
  haltedBy?: HaltReason;
}

/**
 * A run is degraded when the model was needed and never answered: every call
 * failed and none succeeded, so findings came from the deterministic floor alone
 * with no live grounding. A run that simply never needed a model call is not
 * degraded — it only becomes so once a call is attempted and all of them miss.
 */
export function isDegraded(state: RunState): boolean {
  return state.modelCalls === 0 && state.modelErrors > 0;
}

export function initialState(runId: string, maxSteps: number): RunState {
  return {
    runId,
    steps: 0,
    maxSteps,
    objectiveReached: false,
    findings: 0,
    blocked: 0,
    costUsd: 0,
    modelCalls: 0,
    modelErrors: 0,
  };
}
