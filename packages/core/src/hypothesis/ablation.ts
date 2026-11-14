import { tavily } from "@tavily/core";
import type { Candidate } from "./tavilyClient.js";
import { groundedLookup, ungroundedLookup } from "./tavilyClient.js";

export interface FrozenTarget {
  lab: string;
  component: string;
  version: string;
  /**
   * Whether passive recon exposed this fingerprint, or an exploitation step had
   * to provoke the stack to disclose it. An `active` target is the re-grounding
   * case: the fingerprint is reachable only by attacking, and useful only when
   * grounded live mid-chain.
   */
  disclosure?: "passive" | "active";
  /** How an active fingerprint was disclosed — for the report narrative. */
  note?: string;
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

function componentNeedle(component: string): string {
  return component
    .toLowerCase()
    .replace(/^(owasp|the)\s+/, "")
    .trim();
}

async function verifyCitation(cve: string, component: string): Promise<boolean> {
  const key = `${cve}|${component}`;
  const cached = verifyCache.get(key);
  if (cached !== undefined) return cached;
  const tvly = tavily({ apiKey: process.env.TAVILY_API_KEY ?? "" });
  const res = await tvly.search(`${cve} vulnerability`, { maxResults: 5 });
  const corpus = (res.results ?? [])
    .map((r) => `${r.title ?? ""} ${r.content ?? ""}`)
    .join(" ")
    .toLowerCase();
  const applies = corpus.includes(cve.toLowerCase()) && corpus.includes(componentNeedle(component));
  verifyCache.set(key, applies);
  return applies;
}

async function score(candidates: Candidate[], component: string): Promise<ConditionScore> {
  const cited = candidates.filter((c) => c.cve);
  let validCitations = 0;
  let freshCitations = 0;
  for (const c of cited) {
    if (c.cve && (await verifyCitation(c.cve, component))) validCitations += 1;
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
      grounded: await score(grounded, target.component),
      ungrounded: await score(ungrounded, target.component),
      raw: { grounded, ungrounded },
    });
  }
  return rows;
}

interface RegroundingTally {
  candidates: number;
  withCve: number;
  validCitations: number;
  freshCitations: number;
}

export interface RegroundingSummary {
  activeTargets: number;
  grounded: RegroundingTally;
  ungrounded: RegroundingTally;
}

/**
 * Aggregate the re-grounding (active-disclosure) rows: candidates that exist
 * only because an exploitation step disclosed the stack AND grounding was live.
 * Reporting grounded vs ungrounded makes the value of mid-chain re-grounding
 * measurable rather than asserted.
 */
export function summarizeRegrounding(rows: AblationRow[]): RegroundingSummary {
  const active = rows.filter((r) => r.target.disclosure === "active");
  const sum = (cond: "grounded" | "ungrounded", pick: (s: ConditionScore) => number): number =>
    active.reduce((n, r) => n + pick(r[cond]), 0);
  const tally = (cond: "grounded" | "ungrounded"): RegroundingTally => ({
    candidates: sum(cond, (s) => s.candidates),
    withCve: sum(cond, (s) => s.withCve),
    validCitations: sum(cond, (s) => s.validCitations),
    freshCitations: sum(cond, (s) => s.freshCitations),
  });
  return {
    activeTargets: active.length,
    grounded: tally("grounded"),
    ungrounded: tally("ungrounded"),
  };
}

/** A human-readable headline for the re-grounding delta; empty if no active rows. */
export function formatRegrounding(rows: AblationRow[]): string {
  const s = summarizeRegrounding(rows);
  if (s.activeTargets === 0) return "";
  const g = s.grounded;
  const u = s.ungrounded;
  return [
    `re-grounding (mid-chain, active disclosure) — ${s.activeTargets} fingerprint(s) provoked from the stack, then grounded live:`,
    `  grounded   → ${g.candidates} candidate(s) · ${g.withCve} CVE-cited · ${g.validCitations} valid · ${g.freshCitations} post-cutoff`,
    `  ungrounded → ${u.candidates} candidate(s) · ${u.withCve} CVE-cited · ${u.validCitations} valid · ${u.freshCitations} post-cutoff`,
  ].join("\n");
}

function cell(value: string, width: number): string {
  return value.length >= width ? `${value.slice(0, width - 1)} ` : value.padEnd(width);
}

export function formatAblationTable(rows: AblationRow[]): string {
  const header =
    cell("lab", 14) +
    cell("component", 26) +
    cell("cond", 12) +
    cell("cand", 6) +
    cell("cites", 7) +
    cell("valid", 7) +
    "fresh";
  const lines = [header];
  for (const row of rows) {
    for (const [cond, s] of [
      ["grounded", row.grounded],
      ["ungrounded", row.ungrounded],
    ] as const) {
      const lab = row.target.disclosure === "active" ? `${row.target.lab} ⟳` : row.target.lab;
      lines.push(
        cell(lab, 14) +
          cell(`${row.target.component} ${row.target.version}`, 26) +
          cell(cond, 12) +
          cell(String(s.candidates), 6) +
          cell(String(s.withCve), 7) +
          cell(`${(s.citationValidity * 100).toFixed(0)}%`, 7) +
          `${(s.freshnessRate * 100).toFixed(0)}%`,
      );
    }
  }
  return lines.join("\n");
}
