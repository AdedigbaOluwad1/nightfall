import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Emittery from "emittery";
import { describe, expect, it } from "vitest";
import { AuditLog } from "../src/events/audit.js";
import type { NightfallEvents } from "../src/events/types.js";

describe("AuditLog — the full event stream is persisted, append-only", () => {
  it("writes one valid JSON line per event, in order, and stops cleanly", async () => {
    const bus = new Emittery<NightfallEvents>();
    const dir = mkdtempSync(join(tmpdir(), "nf-audit-"));
    const path = join(dir, "run.audit.jsonl");
    let clock = 0;
    const audit = new AuditLog(bus, path, () => `t${clock}`);

    clock = 1;
    await bus.emit("run.start", {
      runId: "r",
      target: "t",
      objective: "o",
      scopeId: "s",
    });
    clock = 2;
    await bus.emit("exploit.attempt", {
      technique: "sqli",
      target: "/x",
      n: 1,
    });
    clock = 3;
    await bus.emit("scope.blocked", {
      url: "http://evil/",
      reason: "out of scope",
    });
    audit.stop();
    await bus.emit("run.end", {
      runId: "r",
      findings: 0,
      blocked: 1,
      costUsd: 0,
      modelCalls: 0,
      degraded: false,
    });

    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3); // nothing recorded after stop()
    const parsed = lines.map((l) => JSON.parse(l));
    expect(parsed.map((p) => p.type)).toEqual(["run.start", "exploit.attempt", "scope.blocked"]);
    expect(parsed[0]).toMatchObject({ t: "t1", payload: { runId: "r" } });
    expect(parsed[2]).toMatchObject({
      t: "t3",
      payload: { reason: "out of scope" },
    });
  });
});
