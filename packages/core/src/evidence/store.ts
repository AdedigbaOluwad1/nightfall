import { appendFileSync } from "node:fs";
import type { Finding } from "./models.js";

/** Append-only JSONL. The event stream, persisted = source of truth. */
export class EvidenceStore {
  constructor(private readonly path: string) {}
  record(finding: Finding) {
    appendFileSync(this.path, `${JSON.stringify(finding)}\n`);
  }
}
