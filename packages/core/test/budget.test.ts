import { describe, expect, it } from "vitest";
import { Budget, BudgetExceededError } from "../src/gateway/budget.js";

describe("Budget — reserve check bounds overshoot to zero", () => {
  it("refuses a call whose worst-case cost would reach the cap, before it is made", () => {
    const b = new Budget(1.0);
    b.add(0.8);
    // 0.8 spent + 0.3 reserve = 1.1 ≥ 1.0 → refuse now, don't let it overshoot.
    expect(() => b.assertCanAfford(0.3)).toThrow(BudgetExceededError);
    expect(b.total).toBe(0.8); // nothing was spent on the refused call
  });

  it("allows a call that fits within the cap after reserving its worst case", () => {
    const b = new Budget(1.0);
    b.add(0.5);
    expect(() => b.assertCanAfford(0.2)).not.toThrow();
  });

  it("degrades to the plain under-cap check for a free (zero-cost) model", () => {
    const b = new Budget(1.0);
    b.add(0.999);
    expect(() => b.assertCanAfford(0)).not.toThrow(); // still under the cap
    b.add(0.001);
    expect(() => b.assertCanAfford(0)).toThrow(BudgetExceededError); // now at the cap
  });
});
