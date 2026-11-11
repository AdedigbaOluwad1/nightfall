import { z } from "zod";

export const Severity = z.enum(["info", "low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof Severity>;

export const StepType = z.enum(["classify", "exploit_reason", "report_write"]);
export type StepType = z.infer<typeof StepType>;

/** One typed event per interesting thing that happens during a run. */
export interface NightfallEvents {
  "run.start": { runId: string; target: string; objective: string };
  "scope.loaded": { hosts: number; paths: number };
  "scope.blocked": { url: string; reason: string };
  "recon.found": { endpoint: string; component?: string; version?: string };
  "tavily.cve": {
    component: string;
    version: string;
    cve: string;
    url: string;
    freshAfterCutoff?: boolean;
  };
  "hypothesis.ranked": { candidates: number; grounded: boolean };
  "exploit.attempt": { technique: string; target: string; n: number };
  "exploit.interpret": { decision: "retry" | "escalate" | "abandon" | "pivot"; note: string };
  "gateway.call": {
    step: StepType;
    model: string;
    costUsd: number;
    cacheHit: boolean;
    priceSource?: "override" | "catalog" | "table" | "estimate";
  };
  "session.login": { boundary: string; tier: 1 | 2 };
  "finding.confirmed": { id: string; title: string; severity: Severity };
  "objective.reached": { via: string; steps: number; costUsd: number };
  "run.end": { runId: string; findings: number; blocked: number; costUsd: number };
}

export type NightfallEventName = keyof NightfallEvents;
