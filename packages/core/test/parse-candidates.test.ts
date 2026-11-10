import { describe, expect, it } from "vitest";
import { parseCandidates } from "../src/hypothesis/tavilyClient.js";

describe("parseCandidates", () => {
  it("parses a clean JSON array", () => {
    const raw = '[{"technique":"SQLi","cve":"CVE-2021-44228","rationale":"r"}]';
    const out = parseCandidates(raw);
    expect(out).toHaveLength(1);
    expect(out[0]?.technique).toBe("SQLi");
    expect(out[0]?.cve).toBe("CVE-2021-44228");
  });

  it("salvages complete objects from a truncated array (no closing bracket)", () => {
    const raw =
      '[\n  {"technique":"A","cve":null,"rationale":"first"},\n' +
      '  {"technique":"B","cve":"CVE-2017-5638","rationale":"second"},\n' +
      '  {"technique":"C","cve":"CVE-2022-26134","rationale":"cut off mid-sent';
    const out = parseCandidates(raw);
    expect(out.map((c) => c.technique)).toEqual(["A", "B"]);
    expect(out[1]?.cve).toBe("CVE-2017-5638");
  });

  it("ignores prose wrapped around the array", () => {
    const raw = 'Here you go:\n[{"technique":"XSS","rationale":"r"}]\nHope that helps.';
    expect(parseCandidates(raw)).toHaveLength(1);
  });

  it("returns empty when there is no array", () => {
    expect(parseCandidates("no json here")).toEqual([]);
  });

  it("drops items without a technique and normalizes a bad cve to undefined", () => {
    const raw =
      '[{"rationale":"no technique"},{"technique":"T","cve":"not-a-cve","rationale":"r"}]';
    const out = parseCandidates(raw);
    expect(out).toHaveLength(1);
    expect(out[0]?.technique).toBe("T");
    expect(out[0]?.cve).toBeUndefined();
  });
});
