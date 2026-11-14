import type { HaltReason, Severity } from "../events/types.js";
import type { Finding } from "../evidence/models.js";

export interface ReportMeta {
  target: string;
  objective?: string;
  runId?: string;
  /** Content hash of the authorizing scope — chain-of-custody for the report. */
  scopeId?: string;
  haltedBy?: HaltReason;
  costUsd?: number;
  generatedAt?: Date;
}

const ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function bySeverity(a: Finding, b: Finding): number {
  return ORDER[a.severity] - ORDER[b.severity];
}

/** Confirmation basis split: impact actually achieved vs signal observed. */
function confirmationSplit(findings: Finding[]): { impact: number; signal: number } {
  let impact = 0;
  let signal = 0;
  for (const f of findings) {
    if (f.basis.startsWith("Impact-confirmed")) impact += 1;
    else if (f.basis.startsWith("Signal-based")) signal += 1;
  }
  return { impact, signal };
}

/**
 * A non-technical executive summary: what the engagement covered, the headline
 * risk in business terms, and an honest confirmation posture (how many findings
 * were impact-confirmed versus signal-based). Kept deliberately separate from
 * the technical body so a reader who stops here is not misled.
 */
function executiveSummary(findings: Finding[], m: ReportMeta): string {
  const lines = [`## Executive summary`, ``];
  if (findings.length === 0) {
    lines.push(
      `An authorized black-box penetration test of ${m.target} completed without` +
        ` confirming an exploitable vulnerability within the run's time and cost budget.` +
        ` This is not a proof of security: it bounds what this engagement exercised, not` +
        ` what exists.`,
      ``,
    );
    return lines.join("\n");
  }
  const top = findings[0] as Finding;
  const { impact, signal } = confirmationSplit(findings);
  const chainReached = attackChain(findings).length >= 2;
  const postureBits: string[] = [];
  if (impact > 0) postureBits.push(`${impact} impact-confirmed (exploitation observed)`);
  if (signal > 0)
    postureBits.push(`${signal} signal-based (strong indicator, manual confirmation advised)`);
  lines.push(
    `An authorized black-box penetration test of ${m.target} confirmed` +
      ` ${findings.length} finding${findings.length === 1 ? "" : "s"}. The most severe is` +
      ` **${top.title.split(" at ")[0]}** (${top.severity}${top.cvssScore !== undefined ? `, CVSS ${top.cvssScore.toFixed(1)}` : ""}).`,
    ``,
  );
  if (chainReached) {
    lines.push(
      `The findings are not isolated: the agent chained them into a working path to the` +
        ` stated objective, demonstrating real-world impact rather than a list of` +
        ` theoretical weaknesses.`,
      ``,
    );
  }
  if (postureBits.length > 0) {
    lines.push(`**Confirmation posture:** ${postureBits.join("; ")}.`, ``);
  }
  return lines.join("\n");
}

function summarize(findings: Finding[]): string {
  if (findings.length === 0) return "No findings confirmed.";
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const parts = (["critical", "high", "medium", "low", "info"] as Severity[])
    .filter((s) => counts.has(s))
    .map((s) => `${counts.get(s)} ${s}`);
  const total = findings.length;
  return `${total} finding${total === 1 ? "" : "s"} — ${parts.join(", ")}.`;
}

function fence(body: string, lang = ""): string {
  const safe = body.replace(/```/g, "ʼʼʼ");
  return `\`\`\`${lang}\n${safe}\n\`\`\``;
}

function truncate(body: string, max = 1200): string {
  if (body.length <= max) return body;
  return `${body.slice(0, max)}\n… [${body.length - max} more bytes truncated]`;
}

/**
 * The ordered attack chain: findings linked by parentId / step. A finding is in
 * the chain if it was seeded by another (has a parent) or seeds another (is a
 * parent). Standalone findings are left to the Findings section only.
 */
function attackChain(findings: Finding[]): Finding[] {
  const parents = new Set(findings.map((f) => f.parentId).filter(Boolean) as string[]);
  const chain = findings.filter((f) => f.parentId !== undefined || parents.has(f.id));
  return chain.sort((a, b) => (a.step ?? 1) - (b.step ?? 1));
}

function chainSection(chain: Finding[]): string {
  const lines = [
    `## Attack chain`,
    ``,
    `The agent reached the objective by chaining ${chain.length} dependent steps, each consuming what the previous one produced:`,
    ``,
  ];
  chain.forEach((f, i) => {
    const flow: string[] = [];
    if (f.consumed) flow.push(`uses the **${f.consumed}**`);
    if (f.produced?.length) flow.push(`yields the **${f.produced.join(", ")}**`);
    const edge = flow.length ? ` — ${flow.join(", ")}` : "";
    const impact = i === chain.length - 1 ? " **← objective reached.**" : "";
    lines.push(`${i + 1}. **${f.title.split(" at ")[0]}** (${f.severity})${edge}${impact}`);
  });
  lines.push(``);
  return lines.join("\n");
}

function findingSection(f: Finding, index: number): string {
  const scoreTag = f.cvssScore !== undefined ? ` (CVSS ${f.cvssScore.toFixed(1)})` : "";
  const lines = [
    `### ${index}. ${f.title} — ${f.severity.toUpperCase()}${scoreTag}`,
    ``,
    `- **Severity:** ${f.severity}`,
  ];
  if (f.cwe) lines.push(`- **Weakness:** ${f.cwe}`);
  if (f.cve) lines.push(`- **Known vulnerability:** ${f.cve}`);
  if (f.cvss) lines.push(`- **CVSS vector:** \`${f.cvss}\``);
  if (f.step !== undefined && (f.parentId || f.consumed || f.produced?.length)) {
    const bits: string[] = [`chain step ${f.step}`];
    if (f.consumed) bits.push(`consumes the ${f.consumed}`);
    if (f.produced?.length) bits.push(`produces the ${f.produced.join(", ")}`);
    lines.push(`- **Attack chain:** ${bits.join(" · ")}`);
  }
  if (f.basis) lines.push(``, `**Verification**`, ``, f.basis);
  lines.push(``, `**Evidence**`, ``);
  if (f.evidence.length === 0) {
    lines.push("_No evidence captured._", ``);
  }
  for (const e of f.evidence) {
    lines.push(fence(e.request, "http"));
    if (e.response.trim()) lines.push(``, fence(truncate(e.response)));
    if (e.note) lines.push(``, `_${e.note}_`);
    lines.push(``);
  }
  if (f.evidence[0]?.request) {
    lines.push(
      `**Reproduction**`,
      ``,
      `Replay the request above against the target in the authorized scope; the response reproduces the signal recorded here. No additional state or tooling is required.`,
      ``,
    );
  }
  lines.push(`**Remediation**`, ``, f.remediation || "_Remediation pending._", ``);
  return lines.join("\n");
}

/**
 * Render confirmed findings as a client-ready Markdown report: a metadata
 * header, a non-technical executive summary, a PTES methodology note, and a
 * technical body with one fully-dressed section per finding — severity, CWE,
 * any grounding CVE, CVSS vector/score, the verification basis (signal vs
 * impact), the in-scope request/response evidence, reproduction, and concrete
 * remediation — ordered most-severe first. Markdown is canonical; PDF
 * (marked → HTML → puppeteer) is a later polish, not a blocker.
 */
export function toMarkdown(findings: Finding[], meta: ReportMeta | string): string {
  const m: ReportMeta = typeof meta === "string" ? { target: meta } : meta;
  const when = (m.generatedAt ?? new Date()).toISOString().slice(0, 10);
  const sorted = [...findings].sort(bySeverity);

  const header = [`# Nightfall — Penetration Test Report`, ``, `**Target:** ${m.target}`];
  if (m.objective) header.push(`**Objective:** ${m.objective}`);
  header.push(`**Date:** ${when}`);
  const runBits: string[] = [];
  if (m.runId) runBits.push(`run \`${m.runId}\``);
  if (m.scopeId) runBits.push(`scope \`${m.scopeId}\``);
  if (m.haltedBy) runBits.push(`stopped: ${m.haltedBy}`);
  if (m.costUsd !== undefined) runBits.push(`model spend: $${m.costUsd.toFixed(4)}`);
  if (runBits.length > 0) header.push(`**Run:** ${runBits.join(" · ")}`);

  const body = [``, executiveSummary(sorted, m)];
  body.push(
    `## Methodology`,
    ``,
    `Testing followed the PTES (Penetration Testing Execution Standard) phases —` +
      ` intelligence gathering, threat modeling, vulnerability analysis, and exploitation` +
      ` — executed autonomously against the authorized scope. Every attempt is a` +
      ` hand-written, read-only probe; confirmation is signal-based or impact-confirmed as` +
      ` stated per finding, and no destructive action is ever issued. See` +
      ` [SAFETY.md](./SAFETY.md) for the full trust model.`,
    ``,
  );
  body.push(`## Technical findings`, ``, summarize(sorted), ``);
  const chain = attackChain(sorted);
  if (chain.length >= 2) body.push(chainSection(chain));
  if (sorted.length === 0) {
    body.push(
      "The agent completed its authorized run without confirming an in-scope vulnerability.",
      "",
    );
  } else {
    sorted.forEach((f, i) => {
      body.push(findingSection(f, i + 1), `---`, ``);
    });
  }

  return [...header, ...body].join("\n").replace(/\n+$/, "\n");
}
