import type { HaltReason, Severity } from "../events/types.js";
import type { Finding } from "../evidence/models.js";

export interface ReportMeta {
  target: string;
  objective?: string;
  runId?: string;
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

function findingSection(f: Finding, index: number): string {
  const scoreTag = f.cvssScore !== undefined ? ` (CVSS ${f.cvssScore.toFixed(1)})` : "";
  const lines = [
    `### ${index}. ${f.title} — ${f.severity.toUpperCase()}${scoreTag}`,
    ``,
    `- **Severity:** ${f.severity}`,
  ];
  if (f.cvss) lines.push(`- **CVSS vector:** \`${f.cvss}\``);
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
  lines.push(`**Remediation**`, ``, f.remediation || "_Remediation pending._", ``);
  return lines.join("\n");
}

/**
 * Render confirmed findings as a client-ready Markdown report: a metadata
 * header, an executive summary counted by severity, and one fully-dressed
 * section per finding — severity, CVSS vector/score, the in-scope
 * request/response that is the evidence, and concrete remediation — ordered
 * most-severe first. Markdown is canonical; PDF (marked → HTML → puppeteer) is
 * a later polish, not a blocker.
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
  if (m.haltedBy) runBits.push(`stopped: ${m.haltedBy}`);
  if (m.costUsd !== undefined) runBits.push(`model spend: $${m.costUsd.toFixed(4)}`);
  if (runBits.length > 0) header.push(`**Run:** ${runBits.join(" · ")}`);

  const body = [``, `## Summary`, ``, summarize(sorted), ``, `## Findings`, ``];
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
