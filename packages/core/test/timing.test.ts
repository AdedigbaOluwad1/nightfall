import Emittery from "emittery";
import { describe, expect, it } from "vitest";
import { formatTiming, RunTimeline } from "../src/events/timing.js";
import type { NightfallEvents } from "../src/events/types.js";

describe("RunTimeline — wall-clock attributed to phases", () => {
  it("attributes each interval to the phase active when it opened, summing to total", async () => {
    const bus = new Emittery<NightfallEvents>();
    let clock = 0;
    const timeline = new RunTimeline(bus, () => clock);

    clock = 0;
    await bus.emit("run.start", { runId: "r", target: "t", objective: "o", scopeId: "s" });
    clock = 1000;
    await bus.emit("recon.found", { endpoint: "/" });
    clock = 1500;
    await bus.emit("hypothesis.ranked", { candidates: 3, grounded: true });
    clock = 4500;
    await bus.emit("exploit.attempt", { technique: "sqli", target: "/", n: 1 });
    clock = 6500;
    await bus.emit("objective.reached", { via: "chain", steps: 2, costUsd: 0.02 });
    clock = 7000;
    await bus.emit("run.end", { runId: "r", findings: 1, blocked: 0, costUsd: 0.02 });
    timeline.stop();

    const b = timeline.breakdown();
    const by = Object.fromEntries(b.phases.map((p) => [p.phase, p.ms]));
    // [0,1500) recon, [1500,4500) hypothesis, [4500,6500) exploit, [6500,7000) report.
    expect(by.recon).toBe(1500);
    expect(by.hypothesis).toBe(3000);
    expect(by.exploit).toBe(2000);
    expect(by.report).toBe(500);
    expect(b.totalMs).toBe(7000);
    expect(b.phases.reduce((s, p) => s + p.ms, 0)).toBe(b.totalMs);
  });

  it("is empty-safe for a run with fewer than two events", async () => {
    const bus = new Emittery<NightfallEvents>();
    const timeline = new RunTimeline(bus, () => 0);
    await bus.emit("run.start", { runId: "r", target: "t", objective: "o", scopeId: "s" });
    timeline.stop();
    const b = timeline.breakdown();
    expect(b.totalMs).toBe(0);
    expect(b.phases).toHaveLength(4);
    expect(formatTiming(b)).toContain("wall-clock breakdown");
  });
});
