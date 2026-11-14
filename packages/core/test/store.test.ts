import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { readFindings } from "../src/evidence/store.js";

const valid = JSON.stringify({
  id: "1",
  title: "SQL injection at /x",
  severity: "critical",
  evidence: [{ request: "GET /x", response: "err", note: "" }],
});

afterEach(() => vi.restoreAllMocks());

describe("evidence store — a dropped line is disclosed, never silent", () => {
  it("returns valid findings and warns when a line is unreadable", () => {
    const dir = mkdtempSync(join(tmpdir(), "nf-store-"));
    const path = join(dir, "findings.jsonl");
    writeFileSync(path, `${valid}\n{ this is not json\n`);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const findings = readFindings(path);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("1");
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toMatch(/unreadable line\(s\)/);
  });

  it("does not warn on a clean trail", () => {
    const dir = mkdtempSync(join(tmpdir(), "nf-store-"));
    const path = join(dir, "clean.jsonl");
    writeFileSync(path, `${valid}\n`);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    expect(readFindings(path)).toHaveLength(1);
    expect(warn).not.toHaveBeenCalled();
  });
});
