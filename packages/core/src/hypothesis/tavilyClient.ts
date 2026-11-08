import { tavily } from "@tavily/core";
import { bus } from "../events/bus.js";

export interface Candidate {
  technique: string;
  cve?: string;
  sourceUrl?: string;
  rationale: string;
}

/**
 * Grounded hypothesis lookup. For a fingerprinted (component, version), query
 * Tavily for current CVEs/advisories. The ablation's condition B stubs THIS out.
 */
export async function groundedLookup(component: string, version: string): Promise<Candidate[]> {
  const tvly = tavily({ apiKey: process.env.TAVILY_API_KEY! });
  const res = await tvly.search(`${component} ${version} CVE vulnerability advisory`, {
    maxResults: 5,
  });
  // TODO(R2): extract CVE ids + applicability from res.results; rank candidates.
  for (const r of res.results ?? []) {
    bus.emit("tavily.cve", { component, version, cve: "TODO", url: r.url });
  }
  return []; // TODO(R2)
}

/** Ablation condition B: same shape, no live data. */
export async function ungroundedLookup(_component: string, _version: string): Promise<Candidate[]> {
  // TODO(R2): same prompt scaffold through the gateway, no Tavily context block.
  return [];
}
