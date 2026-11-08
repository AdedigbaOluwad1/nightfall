import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import type { Finding } from "../src/evidence/models.js";
import { EvidenceStore } from "../src/evidence/store.js";

let path: string;
beforeEach(() => {
  path = join(mkdtempSync(join(tmpdir(), "nf-evidence-")), "evidence.jsonl");
});

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "F-1",
  title: "Reflected XSS in search",
  severity: "high",
  cvss: { score: 7.4, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" },
  description: "User input is reflected without encoding.",
  evidence: [],
  remediation: "Context-encode output.",
  ...over,
});

describe("EvidenceStore", () => {
  it("returns [] when the log does not exist yet", () => {
    expect(EvidenceStore.load(path)).toEqual([]);
  });

  it("round-trips a finding with its own evidence", () => {
    const store = new EvidenceStore(path);
    const f = finding({
      evidence: [{ request: "GET /app?q=<script>", response: "200 ...<script>", note: "" }],
    });
    store.record(f);
    const loaded = store.load();
    expect(loaded).toHaveLength(1);
    expect(loaded[0]?.title).toBe(f.title);
    expect(loaded[0]?.evidence).toHaveLength(1);
    expect(loaded[0]?.cvss?.score).toBe(7.4);
  });

  it("merges streamed evidence into its finding", () => {
    const store = new EvidenceStore(path);
    store.captureEvidence("F-1", { request: "GET /app/1", response: "200", note: "step 1" });
    store.captureEvidence("F-1", { request: "GET /app/2", response: "200", note: "step 2" });
    store.record(finding());
    const [loaded] = store.load();
    expect(loaded?.evidence).toHaveLength(2);
    expect(loaded?.evidence[0]?.note).toBe("step 1");
  });

  it("captures evidence even if the finding is never recorded (no crash, no orphan)", () => {
    const store = new EvidenceStore(path);
    store.captureEvidence("F-ghost", { request: "GET /app", response: "500", note: "" });
    expect(store.load()).toEqual([]);
  });

  it("does not duplicate evidence already present on a recorded finding", () => {
    const store = new EvidenceStore(path);
    const e = { request: "GET /app", response: "200", note: "once" };
    store.record(finding({ evidence: [e] }));
    store.captureEvidence("F-1", e);
    const [loaded] = store.load();
    expect(loaded?.evidence).toHaveLength(1);
  });
});
