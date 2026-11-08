import { bus } from "../events/bus.js";
import type { Gateway } from "../gateway/bifrostClient.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";

/** The decide/recover loop. TODO(R1): implement the real state machine. */
export async function runLoop(
  scope: ScopeFile,
  _gate: ScopeGate,
  _gateway: Gateway,
): Promise<void> {
  const runId = crypto.randomUUID();
  bus.emit("run.start", { runId, target: scope.target, objective: scope.objective });
  // TODO(R1): recon -> hypothesis -> attempt -> interpret -> evidence, until
  // objective reached OR maxSteps/budget hit.
  bus.emit("run.end", { runId, findings: 0, blocked: 0, costUsd: 0 });
}
