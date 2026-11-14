import { describe, expect, it } from "vitest";
import {
  type AblationRow,
  type ConditionScore,
  formatAblationTable,
  formatRegrounding,
  summarizeRegrounding,
} from "../src/hypothesis/ablation.js";

const sc = (over: Partial<ConditionScore> = {}): ConditionScore => ({
  candidates: 0,
  withCve: 0,
  validCitations: 0,
  citationValidity: 0,
  freshCitations: 0,
  freshnessRate: 0,
  ...over,
});

const rows: AblationRow[] = [
  {
    target: { lab: "ref-log4j", component: "Apache Log4j", version: "2.14.1" },
    grounded: sc({ candidates: 4, withCve: 4, freshCitations: 0 }),
    ungrounded: sc({ candidates: 2, withCve: 0 }),
    raw: { grounded: [], ungrounded: [] },
  },
  {
    target: {
      lab: "juice-shop",
      component: "Express",
      version: "4.22.1",
      disclosure: "active",
    },
    grounded: sc({ candidates: 5, withCve: 2, validCitations: 2, freshCitations: 1 }),
    ungrounded: sc({ candidates: 5, withCve: 2, validCitations: 0, freshCitations: 0 }),
    raw: { grounded: [], ungrounded: [] },
  },
];

describe("ablation — re-grounding (active disclosure) metric", () => {
  it("aggregates only active-disclosure rows, grounded vs ungrounded", () => {
    const s = summarizeRegrounding(rows);
    expect(s.activeTargets).toBe(1);
    expect(s.grounded).toEqual({ candidates: 5, withCve: 2, validCitations: 2, freshCitations: 1 });
    expect(s.ungrounded).toEqual({
      candidates: 5,
      withCve: 2,
      validCitations: 0,
      freshCitations: 0,
    });
  });

  it("formats a headline only when an active target is present", () => {
    expect(formatRegrounding(rows)).toContain(
      "5 candidate(s) · 2 CVE-cited · 2 valid · 1 post-cutoff",
    );
    expect(formatRegrounding(rows)).toContain(
      "5 candidate(s) · 2 CVE-cited · 0 valid · 0 post-cutoff",
    );
    const passiveOnly = rows.filter((r) => r.target.disclosure !== "active");
    expect(formatRegrounding(passiveOnly)).toBe("");
  });

  it("marks an active row in the table so re-grounding is visible", () => {
    const table = formatAblationTable(rows);
    expect(table).toMatch(/juice-shop ⟳/);
    expect(table).not.toMatch(/ref-log4j ⟳/);
  });
});
