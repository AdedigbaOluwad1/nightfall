import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { z } from "zod";
import { Evidence, Finding } from "./models.js";

/**
 * Append-only evidence log (JSONL) — the durable source of truth the report
 * reads back. Two line kinds are written:
 *
 *   { k: "evidence", findingId, ts, ... }  captured the instant a req/resp
 *                                          pair is seen, so proof exists even
 *                                          if the run later crashes.
 *   { k: "finding",  ts, ... }             the structured finding itself.
 *
 * Nothing is ever mutated or reordered; `load()` reconstructs findings by
 * merging in any streamed evidence. Every record is validated before it is
 * written and again when it is read — a malformed line never enters the trail.
 */
const EvidenceLine = Evidence.extend({
  k: z.literal("evidence"),
  findingId: z.string(),
  ts: z.string(),
});

const FindingLine = Finding.extend({
  k: z.literal("finding"),
  ts: z.string(),
});

const Line = z.discriminatedUnion("k", [EvidenceLine, FindingLine]);

export class EvidenceStore {
  constructor(private readonly path: string) {}

  /** Append one request/response pair as it happens, tied to its finding. */
  captureEvidence(findingId: string, evidence: Evidence): void {
    const line = EvidenceLine.parse({
      k: "evidence",
      findingId,
      ts: new Date().toISOString(),
      ...Evidence.parse(evidence),
    });
    this.append(line);
  }

  /** Append a confirmed finding. Evidence already on it is preserved as-is. */
  record(finding: Finding): void {
    const line = FindingLine.parse({
      k: "finding",
      ts: new Date().toISOString(),
      ...Finding.parse(finding),
    });
    this.append(line);
  }

  private append(line: unknown): void {
    appendFileSync(this.path, `${JSON.stringify(line)}\n`);
  }

  /** Read the log back into findings, merging any streamed evidence in order. */
  load(): Finding[] {
    return EvidenceStore.load(this.path);
  }

  static load(path: string): Finding[] {
    if (!existsSync(path)) return [];
    const findings = new Map<string, Finding>();
    const streamed = new Map<string, Evidence[]>();

    for (const raw of readFileSync(path, "utf8").split("\n")) {
      const text = raw.trim();
      if (!text) continue;
      const line = Line.parse(JSON.parse(text));
      if (line.k === "finding") {
        const { k, ts, ...finding } = line;
        findings.set(finding.id, Finding.parse(finding));
      } else {
        const { k, ts, findingId, ...evidence } = line;
        const list = streamed.get(findingId) ?? [];
        list.push(Evidence.parse(evidence));
        streamed.set(findingId, list);
      }
    }

    for (const [id, evidence] of streamed) {
      const finding = findings.get(id);
      if (!finding) continue;
      const seen = new Set(finding.evidence.map((e) => JSON.stringify(e)));
      for (const e of evidence) {
        if (!seen.has(JSON.stringify(e))) finding.evidence.push(e);
      }
    }

    return [...findings.values()];
  }
}
