import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

// The whole safety argument in STATE_MACHINES.md ("not reachable" for concurrent
// re-auth, check-then-spend budget overrun, candidate interleaving) rests on the
// run being strictly sequential. This test makes that an ENFORCED invariant, not
// a one-time grep: adding a parallel fan-out to core/src fails CI, so the guard
// cannot regress without someone deliberately removing it (and reading why).
const BANNED = /\bPromise\.(all|allSettled|race|any)\b/;

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...tsFiles(full));
    else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) out.push(full);
  }
  return out;
}

describe("concurrency guard — the run must stay strictly sequential", () => {
  it("has no Promise.all/allSettled/race/any anywhere in core/src", () => {
    const offenders = tsFiles(SRC).filter((f) => BANNED.test(readFileSync(f, "utf8")));
    expect(
      offenders,
      "parallel execution would invalidate the sequential-execution safety invariant (STATE_MACHINES.md); remove the guard deliberately and re-audit if concurrency is truly intended",
    ).toEqual([]);
  });
});
