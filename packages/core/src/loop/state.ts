import type { HaltReason } from "../events/types.js";

export interface RunState {
  runId: string;
  steps: number;
  maxSteps: number;
  objectiveReached: boolean;
  findings: number;
  blocked: number;
  costUsd: number;
  /** Why the loop stopped — set once, read by the run summary and report. */
  haltedBy?: HaltReason;
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
  };
}
