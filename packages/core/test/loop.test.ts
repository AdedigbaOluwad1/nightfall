import { afterEach, describe, expect, it } from "vitest";
import { bus } from "../src/events/bus.js";
import type { Finding } from "../src/evidence/models.js";
import type { Gateway } from "../src/gateway/bifrostClient.js";
import { type LoopDeps, runLoop } from "../src/loop/agent.js";
import { ScopeGate } from "../src/scope/gate.js";
import { ScopeFile } from "../src/scope/schema.js";
import type { Session, SessionResponse } from "../src/session/index.js";

const scope = ScopeFile.parse({
  target: "http://localhost:3000/",
  objective: "Reach the admin dashboard",
  allow: { hosts: ["localhost"], paths: ["/"] },
  maxSteps: 5,
  budgetUsd: 0.01,
});
const gate = new ScopeGate(scope);
const gateway = {} as Gateway; // unused when deps are injected

class FakeSession implements Session {
  readonly tier = 1 as const;
  async login(): Promise<void> {}
  async request(): Promise<SessionResponse> {
    return { status: 200, headers: {}, body: "" };
  }
  async dispose(): Promise<void> {}
}

function baseDeps(over: Partial<LoopDeps>): Partial<LoopDeps> {
  return {
    session: new FakeSession(),
    recon: async () => ({ fingerprints: [], endpoints: [] }),
    hypothesize: async () => [],
    escalate: async () => undefined,
    plan: async () => undefined,
    record: () => {},
    maxRetries: 2,
    ...over,
  };
}

afterEach(() => bus.clearListeners());

/** Drain the async event bus (Emittery dispatches listeners on a later tick). */
const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe("runLoop — the decide/recover loop", () => {
  it("recovers from a failed attempt and reaches the objective without a human", async () => {
    const decisions: string[] = [];
    bus.on("exploit.interpret", (e) => {
      decisions.push(e.decision);
    });
    const findings: Finding[] = [];
    let call = 0;

    const state = await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        attempt: async () => {
          call++;
          return call === 1
            ? { ok: false, note: "flaky", transient: true, applicable: true }
            : { ok: true, reachesObjective: true, note: "admin reached", applicable: true };
        },
        record: (f) => findings.push(f),
      }),
    );
    await flush();

    expect(decisions).toContain("retry"); // it chose to recover
    expect(state.objectiveReached).toBe(true);
    expect(state.findings).toBe(1);
    expect(findings).toHaveLength(1);
    expect(call).toBe(2); // failed once, then succeeded
  });

  it("halts a deliberately stuck run at the step cap — no crash, no infinite loop", async () => {
    const state = await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        maxRetries: Number.MAX_SAFE_INTEGER, // never give up voluntarily
        attempt: async () => ({ ok: false, note: "stuck", transient: true, applicable: true }),
      }),
    );

    expect(state.steps).toBe(scope.maxSteps); // the cap stopped it
    expect(state.objectiveReached).toBe(false);
    expect(state.findings).toBe(0);
  });

  it("halts when the budget cap is reached, and announces it as a visible beat", async () => {
    const halts: { capUsd: number; spentUsd: number; stage: string }[] = [];
    bus.on("budget.exceeded", (e) => {
      halts.push(e);
    });

    const state = await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        recon: async () => ({
          fingerprints: [{ component: "nginx", version: "1.0" }],
          endpoints: [],
        }),
        hypothesize: async () => {
          await bus.emit("gateway.call", {
            step: "exploit_reason",
            model: "x",
            costUsd: 1,
            cacheHit: false,
          });
          return [];
        },
        attempt: async () => {
          throw new Error("attempt must not run once the budget is blown");
        },
      }),
    );

    expect(state.costUsd).toBeGreaterThanOrEqual(scope.budgetUsd);
    expect(state.steps).toBe(0);
    expect(state.haltedBy).toBe("budget");
    expect(halts).toHaveLength(1); // announced exactly once, not per guard
    expect(halts[0]?.capUsd).toBe(scope.budgetUsd);
    expect(halts[0]?.spentUsd).toBeGreaterThanOrEqual(scope.budgetUsd);
  });

  it("surfaces a grounding failure instead of swallowing it, and keeps running", async () => {
    const failures: { component: string; reason: string }[] = [];
    bus.on("hypothesis.failed", (e) => {
      failures.push(e);
    });

    const state = await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        recon: async () => ({
          fingerprints: [{ component: "OWASP Juice Shop", version: "unknown" }],
          endpoints: [],
        }),
        hypothesize: async () => {
          throw new Error("429 daily free allocation of 10,000 neurons exhausted");
        },
        attempt: async () => ({ ok: false, note: "n/a", applicable: false }),
      }),
    );
    await flush();

    expect(failures).toHaveLength(1); // not silently swallowed
    expect(failures[0]?.component).toBe("OWASP Juice Shop");
    expect(failures[0]?.reason).toContain("429");
    expect(state.haltedBy).toBe("exhausted"); // loop still finished cleanly
  });

  it("re-grounds mid-run: a fingerprint a step discloses is grounded live against advisories", async () => {
    const regroundEvents: string[] = [];
    bus.on("chain.step", (e) => {
      if (e.produced?.startsWith("re-grounded")) regroundEvents.push(e.produced);
    });
    const grounded: { component: string; version: string }[] = [];
    let call = 0;

    await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        hypothesize: async (fp) => {
          grounded.push({ component: fp.component, version: fp.version });
          return [
            {
              technique: "Prototype Pollution",
              cve: "CVE-2024-29041",
              rationale: "Express < 4.17.3 is affected",
            },
          ];
        },
        attempt: async () => {
          call++;
          return call === 1
            ? {
                ok: true,
                note: "stack disclosed",
                applicable: true,
                discovered: [
                  {
                    kind: "fingerprint",
                    value: "Express@4.22.1",
                    label: "Express 4.22.1",
                    from: "x",
                  },
                ],
              }
            : { ok: false, note: "n/a", applicable: false };
        },
      }),
    );
    await flush();

    // The disclosed framework was grounded live, mid-run — not only at recon.
    expect(grounded).toContainEqual({ component: "Express", version: "4.22.1" });
    expect(regroundEvents[0]).toContain("Express");
  });

  it("records the halt reason on a clean objective reach and an exhausted queue", async () => {
    const reached = await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        attempt: async () => ({
          ok: true,
          reachesObjective: true,
          note: "admin reached",
          applicable: true,
        }),
      }),
    );
    expect(reached.haltedBy).toBe("objective");

    const drained = await runLoop(
      scope,
      gate,
      gateway,
      baseDeps({
        attempt: async () => ({ ok: false, note: "n/a", applicable: false }),
      }),
    );
    expect(drained.objectiveReached).toBe(false);
    expect(drained.haltedBy).toBe("exhausted");
  });
});
