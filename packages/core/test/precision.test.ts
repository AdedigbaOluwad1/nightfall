import { afterEach, describe, expect, it } from "vitest";
import { bus } from "../src/events/bus.js";
import type { Gateway } from "../src/gateway/bifrostClient.js";
import { precisionAtK } from "../src/hypothesis/precision.js";
import type { Candidate } from "../src/hypothesis/tavilyClient.js";
import type { LoopDeps } from "../src/loop/agent.js";
import { ScopeGate } from "../src/scope/gate.js";
import { ScopeFile } from "../src/scope/schema.js";
import type { Session, SessionResponse } from "../src/session/index.js";

const scope = ScopeFile.parse({
  target: "http://localhost:3000/",
  objective: "Reach the admin dashboard",
  allow: { hosts: ["localhost"], paths: ["/"] },
  maxSteps: 5,
  budgetUsd: 1,
});
const gate = new ScopeGate(scope);
const gateway = {} as Gateway;

class FakeSession implements Session {
  readonly tier = 1 as const;
  async login(): Promise<void> {}
  async request(): Promise<SessionResponse> {
    return { status: 200, headers: {}, body: "" };
  }
  async dispose(): Promise<void> {}
}

function injected(winner: string): Partial<LoopDeps> {
  return {
    session: new FakeSession(),
    recon: async () => ({ fingerprints: [{ component: "App", version: "1.0" }], endpoints: [] }),
    escalate: async () => undefined,
    maxRetries: 0,
    attempt: async (_s, technique) =>
      technique === winner
        ? { ok: true, note: "objective signal", applicable: true }
        : { ok: false, note: "no signal", applicable: true },
  };
}

afterEach(() => bus.clearListeners());

describe("precisionAtK — supporting ablation metric", () => {
  it("attributes a confirmed finding only to the candidate whose technique caused it", async () => {
    const candidates: Candidate[] = [
      { technique: "winner", rationale: "" },
      { technique: "loser", rationale: "" },
    ];

    const score = await precisionAtK(
      scope,
      gate,
      gateway,
      candidates,
      { k: 3, repeats: 2 },
      injected("winner"),
    );

    expect(score.trials).toBe(4);
    expect(score.attributed).toBe(2);
    expect(score.precisionAtK).toBe(0.5);
  });

  it("is reproducible across runs with the same frozen input", async () => {
    const candidates: Candidate[] = [{ technique: "winner", rationale: "" }];
    const run = () =>
      precisionAtK(scope, gate, gateway, candidates, { k: 3, repeats: 3 }, injected("winner"));

    const a = await run();
    const b = await run();
    expect(a.precisionAtK).toBe(1);
    expect(b.precisionAtK).toBe(a.precisionAtK);
  });
});
