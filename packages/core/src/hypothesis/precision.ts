import type { Finding } from "../evidence/models.js";
import type { Gateway } from "../gateway/bifrostClient.js";
import type { LoopDeps } from "../loop/agent.js";
import { runLoop } from "../loop/agent.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";
import type { Candidate } from "./tavilyClient.js";

export interface PrecisionScore {
  k: number;
  repeats: number;
  attributed: number;
  trials: number;
  precisionAtK: number;
}

export interface PrecisionOptions {
  k?: number;
  repeats?: number;
}

function attributedToCandidate(findings: Finding[], candidate: Candidate): boolean {
  return findings.some((f) => f.title.startsWith(`${candidate.technique} `));
}

export async function precisionAtK(
  scope: ScopeFile,
  gate: ScopeGate,
  gateway: Gateway,
  candidates: Candidate[],
  options: PrecisionOptions = {},
  override: Partial<LoopDeps> = {},
): Promise<PrecisionScore> {
  const k = options.k ?? 3;
  const repeats = options.repeats ?? 3;
  const top = candidates.slice(0, k);
  let attributed = 0;
  let trials = 0;

  for (const candidate of top) {
    for (let r = 0; r < repeats; r++) {
      const found: Finding[] = [];
      await runLoop(scope, gate, gateway, {
        ...override,
        hypothesize: async () => [candidate],
        record: (f) => found.push(f),
      });
      if (attributedToCandidate(found, candidate)) attributed += 1;
      trials += 1;
    }
  }

  return {
    k,
    repeats,
    attributed,
    trials,
    precisionAtK: trials === 0 ? 0 : attributed / trials,
  };
}
