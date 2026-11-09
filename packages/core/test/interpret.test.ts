import { describe, expect, it } from "vitest";
import type { AttemptResult } from "../src/loop/actions.js";
import { interpret } from "../src/loop/interpret.js";

const ctx = { retries: 0, maxRetries: 2, tier: 1 as const, canEscalate: false };

describe("interpret — deterministic recovery", () => {
  it("retries a transient failure under the cap", () => {
    const r: AttemptResult = { ok: false, note: "5xx", transient: true, applicable: true };
    expect(interpret(r, ctx).decision).toBe("retry");
  });

  it("stops retrying once the cap is hit", () => {
    const r: AttemptResult = { ok: false, note: "5xx", transient: true, applicable: true };
    expect(interpret(r, { ...ctx, retries: 2 }).decision).toBe("abandon");
  });

  it("pivots when the technique is not applicable", () => {
    const r: AttemptResult = { ok: false, note: "404", applicable: false };
    expect(interpret(r, ctx).decision).toBe("pivot");
  });

  it("escalates an unproven tier-1 result when a stronger tier is available", () => {
    const r: AttemptResult = { ok: false, note: "needs JS", applicable: true };
    expect(interpret(r, { ...ctx, canEscalate: true }).decision).toBe("escalate");
  });

  it("abandons when unproven on tier 2 with nothing left", () => {
    const r: AttemptResult = { ok: false, note: "no signal", applicable: true };
    expect(interpret(r, { ...ctx, tier: 2 }).decision).toBe("abandon");
  });
});
