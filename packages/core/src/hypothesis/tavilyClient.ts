import { tavily } from "@tavily/core";
import { bus } from "../events/bus.js";
import { Gateway } from "../gateway/bifrostClient.js";
import { Budget } from "../gateway/budget.js";

export interface Candidate {
  technique: string;
  cve?: string;
  sourceUrl?: string;
  rationale: string;
  freshAfterCutoff?: boolean;
}

interface Advisory {
  cve: string;
  url: string;
  title: string;
  publishedDate?: string;
}

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

let sharedGateway: Gateway | undefined;

export function setHypothesisGateway(gateway: Gateway): void {
  sharedGateway = gateway;
}

function gateway(): Gateway {
  if (!sharedGateway) {
    sharedGateway = new Gateway(new Budget(Number(process.env.NF_BUDGET_USD ?? "2")));
  }
  return sharedGateway;
}

function cutoffYear(): number {
  const raw = process.env.NF_MODEL_CUTOFF ?? "2024-06";
  const year = Number(raw.slice(0, 4));
  return Number.isFinite(year) ? year : 2024;
}

function cveYear(cve: string): number {
  return Number(cve.split("-")[1]);
}

function isFresh(cve: string): boolean {
  return cveYear(cve) > cutoffYear();
}

async function retrieve(component: string, version: string): Promise<Advisory[]> {
  const tvly = tavily({ apiKey: process.env.TAVILY_API_KEY ?? "" });
  const res = await tvly.search(`${component} ${version} CVE vulnerability advisory`, {
    maxResults: 5,
  });
  const seen = new Set<string>();
  const advisories: Advisory[] = [];
  for (const r of res.results ?? []) {
    const haystack = `${r.title ?? ""} ${r.content ?? ""}`;
    const matches = haystack.match(CVE_RE) ?? [];
    for (const raw of matches) {
      const cve = raw.toUpperCase();
      if (seen.has(cve)) continue;
      seen.add(cve);
      advisories.push({
        cve,
        url: r.url,
        title: r.title ?? cve,
        publishedDate: (r as { publishedDate?: string }).publishedDate,
      });
    }
  }
  return advisories;
}

function buildPrompt(component: string, version: string, advisories?: Advisory[]): string {
  const context =
    advisories && advisories.length > 0
      ? `Known advisories (retrieved live):\n${advisories
          .map((a) => `- ${a.cve}: ${a.title} (${a.url})`)
          .join("\n")}\n\n`
      : "";
  return (
    `You are a web-application security analyst assessing an authorized lab target.\n` +
    `The target is running ${component} version ${version}.\n\n` +
    context +
    `List up to 5 candidate vulnerability techniques worth investigating, each tied to a ` +
    `specific CVE id when one applies to this exact version.\n` +
    `Respond with ONLY a JSON array; each item is {"technique": string, "cve": string | null, ` +
    `"rationale": string}.`
  );
}

function salvageObjects(body: string): unknown[] {
  const objects: unknown[] = [];
  let depth = 0;
  let objStart = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') inString = true;
    else if (ch === "{") {
      if (depth === 0) objStart = i;
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0 && objStart !== -1) {
        try {
          objects.push(JSON.parse(body.slice(objStart, i + 1)));
        } catch {}
        objStart = -1;
      }
    }
  }
  return objects;
}

export function parseCandidates(raw: string, advisories?: Advisory[]): Candidate[] {
  const start = raw.indexOf("[");
  if (start === -1) return [];
  const end = raw.lastIndexOf("]");
  let parsed: unknown;
  try {
    if (end <= start) throw new Error("unterminated array");
    parsed = JSON.parse(raw.slice(start, end + 1));
  } catch {
    parsed = salvageObjects(raw.slice(start));
  }
  if (!Array.isArray(parsed)) return [];
  const byCve = new Map(advisories?.map((a) => [a.cve, a.url]));
  const candidates: Candidate[] = [];
  for (const item of parsed) {
    if (typeof item !== "object" || item === null) continue;
    const row = item as { technique?: unknown; cve?: unknown; rationale?: unknown };
    const technique = typeof row.technique === "string" ? row.technique : undefined;
    if (!technique) continue;
    const cveMatch = typeof row.cve === "string" ? row.cve.toUpperCase().match(CVE_RE) : null;
    const cve = cveMatch ? cveMatch[0] : undefined;
    candidates.push({
      technique,
      cve,
      sourceUrl: cve ? byCve.get(cve) : undefined,
      rationale: typeof row.rationale === "string" ? row.rationale : "",
      freshAfterCutoff: cve ? isFresh(cve) : undefined,
    });
  }
  return candidates;
}

async function hypothesize(
  component: string,
  version: string,
  grounded: boolean,
): Promise<Candidate[]> {
  const advisories = grounded ? await retrieve(component, version) : undefined;
  if (advisories) {
    for (const a of advisories) {
      bus.emit("tavily.cve", {
        component,
        version,
        cve: a.cve,
        url: a.url,
        freshAfterCutoff: isFresh(a.cve),
      });
    }
  }
  const raw = await gateway().complete(
    "exploit_reason",
    buildPrompt(component, version, advisories),
  );
  const candidates = parseCandidates(raw, advisories);
  bus.emit("hypothesis.ranked", { candidates: candidates.length, grounded });
  return candidates;
}

export function groundedLookup(component: string, version: string): Promise<Candidate[]> {
  return hypothesize(component, version, true);
}

export function ungroundedLookup(component: string, version: string): Promise<Candidate[]> {
  return hypothesize(component, version, false);
}
