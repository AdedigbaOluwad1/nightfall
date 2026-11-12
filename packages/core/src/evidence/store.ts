import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { Finding } from "./models.js";

/** Append-only JSONL. The event stream, persisted = source of truth. */
export class EvidenceStore {
  constructor(private readonly path: string) {}
  record(finding: Finding) {
    appendFileSync(this.path, `${JSON.stringify(finding)}\n`);
  }
}

/**
 * Read persisted findings back from a JSONL evidence file, validated against
 * the Finding schema. A missing file is an empty run, not an error; a malformed
 * line is skipped rather than aborting the whole report.
 */
export function readFindings(path: string): Finding[] {
  if (!existsSync(path)) return [];
  const findings: Finding[] = [];
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = Finding.safeParse(JSON.parse(trimmed));
      if (parsed.success) findings.push(parsed.data);
    } catch {}
  }
  return findings;
}
