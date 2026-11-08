import type { Finding } from "../evidence/models.js";

/** Markdown is canonical. TODO(R3): PDF via marked -> HTML -> puppeteer (polish window). */
export function toMarkdown(findings: Finding[], target: string): string {
  const lines = [`# Nightfall — Pentest Report`, ``, `**Target:** ${target}`, ``];
  for (const f of findings) {
    lines.push(`## ${f.title} — ${f.severity.toUpperCase()}`, ``, f.remediation, ``);
  }
  return lines.join("\n");
}
