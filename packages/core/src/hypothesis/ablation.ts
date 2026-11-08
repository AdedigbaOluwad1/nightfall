import { tavily } from "@tavily/core";
import type { Candidate } from "./tavilyClient.js";
import { groundedLookup, ungroundedLookup } from "./tavilyClient.js";

export interface FrozenTarget {
  lab: string;
  component: string;
  version: string;
}

export interface ConditionScore {
  candidates: number;
  withCve: number;
  validCitations: number;
  citationValidity: number;
  freshCitations: number;
  freshnessRate: number;
}

export interface AblationRow {
  target: FrozenTarget;
  grounded: ConditionScore;
  ungrounded: ConditionScore;
  raw: {
    grounded: Candidate[];
    ungrounded: Candidate[];
  };
}

const verifyCache = new Map<string, boolean>();

async function verifyCitation(cve: string, component: string, version: string): Promise<boolean> {
  const key = `${cve}|${component}|${version}`;
  const cached = verifyCache.get(key);
  if (cached !== undefined) return cached;
  const tvly = tavily({ apiKey: process.env.TAVILY_API_KEY ?? "" });
  const res = await tvly.search(`${cve} ${component} affected versions`, { maxResults: 3 });
  const corpus = (res.results ?? [])
    .map((r) => `${r.title ?? ""} ${r.content ?? ""}`)
    .join(" ")
    .toLowerCase();
  const applies =
    corpus.includes(cve.toLowerCase()) &&
    corpus.includes(component.toLowerCase()) &&
    corpus.includes(version.toLowerCase());
  verifyCache.set(key, applies);
  return applies;
}

async function score(
  candidates: Candidate[],
  component: string,
  version: string,
): Promise<ConditionScore> {
  const cited = candidates.filter((c) => c.cve);
  let validCitations = 0;
  let freshCitations = 0;
  for (const c of cited) {
    if (c.cve && (await verifyCitation(c.cve, component, version))) validCitations += 1;
    if (c.freshAfterCutoff) freshCitations += 1;
  }
  const withCve = cited.length;
  return {
    candidates: candidates.length,
    withCve,
    validCitations,
    citationValidity: withCve === 0 ? 0 : validCitations / withCve,
    freshCitations,
    freshnessRate: withCve === 0 ? 0 : freshCitations / withCve,
  };
}

export async function runAblation(frozen: FrozenTarget[]): Promise<AblationRow[]> {
  const rows: AblationRow[] = [];
  for (const target of frozen) {
    const grounded = await groundedLookup(target.component, target.version);
    const ungrounded = await ungroundedLookup(target.component, target.version);
    rows.push({
      target,
      grounded: await score(grounded, target.component, target.version),
      ungrounded: await score(ungrounded, target.component, target.version),
      raw: { grounded, ungrounded },
    });
  }
  return rows;
}

export function formatAblationTable(rows: AblationRow[]): string {
  const header =
    "lab".padEnd(14) +
    "component".padEnd(18) +
    "cond".padEnd(12) +
    "cites".padEnd(7) +
    "valid".padEnd(7) +
    "fresh";
  const lines = [header];
  for (const row of rows) {
    for (const [cond, s] of [
      ["grounded", row.grounded],
      ["ungrounded", row.ungrounded],
    ] as const) {
      lines.push(
        row.target.lab.padEnd(14) +
          `${row.target.component} ${row.target.version}`.padEnd(18) +
          cond.padEnd(12) +
          String(s.withCve).padEnd(7) +
          `${(s.citationValidity * 100).toFixed(0)}%`.padEnd(7) +
          `${(s.freshnessRate * 100).toFixed(0)}%`,
      );
    }
  }
  return lines.join("\n");
}
