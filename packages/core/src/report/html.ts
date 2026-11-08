import { marked } from "marked";
import type { Finding } from "../evidence/models.js";
import { type ReportMeta, toMarkdown } from "./generate.js";

/**
 * Render the canonical markdown report to a self-contained, print-ready HTML
 * document. Uses `marked` (already a dependency) — no browser required. Open it
 * and "Print → Save as PDF" for a client deliverable, or feed it to `toPdf`.
 */
const STYLE = `
  :root { color-scheme: light; }
  body { margin: 0; background: #f6f7f9; }
  .report {
    max-width: 820px; margin: 0 auto; padding: 48px 56px; background: #fff;
    color: #1b1f24; font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  .report h1 { font-size: 26px; margin: 0 0 4px; }
  .report h2 { font-size: 19px; margin: 32px 0 12px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }
  .report h3 { font-size: 16px; margin: 28px 0 10px; }
  .report hr { border: 0; border-top: 1px solid #eceef1; margin: 28px 0; }
  .report table { border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 14px; }
  .report th, .report td { border: 1px solid #e5e7eb; padding: 7px 10px; text-align: left; }
  .report th { background: #f3f4f6; }
  .report pre {
    background: #0f1419; color: #e6edf3; padding: 12px 14px; border-radius: 6px;
    overflow-x: auto; font-size: 12.5px; line-height: 1.5;
  }
  .report code { font-family: "SF Mono", ui-monospace, Menlo, Consolas, monospace; }
  .report :not(pre) > code { background: #eef1f4; padding: 1px 6px; border-radius: 4px; font-size: 12.5px; }
  .report img { max-width: 100%; border: 1px solid #e5e7eb; border-radius: 6px; }
  @media print {
    body { background: #fff; }
    .report { max-width: none; margin: 0; padding: 0; }
    .report h2, .report h3 { break-after: avoid; }
    .report pre, .report table { break-inside: avoid; }
  }
`;

export async function toHtml(
  findings: Finding[],
  target: string,
  meta: ReportMeta = {},
): Promise<string> {
  const body = await marked.parse(toMarkdown(findings, target, meta));
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Nightfall — Penetration Test Report</title>",
    `<style>${STYLE}</style>`,
    "</head>",
    '<body><main class="report">',
    body,
    "</main></body>",
    "</html>",
  ].join("\n");
}
