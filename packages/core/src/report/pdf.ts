import type { Finding } from "../evidence/models.js";
import type { ReportMeta } from "./generate.js";
import { toHtml } from "./html.js";

/**
 * Optional PDF export. Puppeteer is a heavy, optional peer dependency — the
 * markdown and HTML paths never load it. Install it only when you want PDFs:
 *
 *   pnpm add -D puppeteer
 *
 * The import specifier is built at runtime so the bundler leaves puppeteer
 * external; if it isn't installed, this throws a clear, actionable error.
 */
export async function toPdf(
  findings: Finding[],
  target: string,
  outPath: string,
  meta: ReportMeta = {},
): Promise<string> {
  const html = await toHtml(findings, target, meta);

  const specifier = ["puppe", "teer"].join("");
  let puppeteer: { launch: (opts?: unknown) => Promise<PuppeteerBrowser> };
  try {
    puppeteer = (await import(specifier)).default;
  } catch {
    throw new Error(
      "PDF export needs puppeteer. Install it with `pnpm add -D puppeteer`. " +
        "Markdown (toMarkdown) and HTML (toHtml) export need no extra dependencies.",
    );
  }

  const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });
    await page.pdf({
      path: outPath,
      format: "A4",
      printBackground: true,
      margin: { top: "18mm", bottom: "18mm", left: "14mm", right: "14mm" },
    });
    return outPath;
  } finally {
    await browser.close();
  }
}

interface PuppeteerBrowser {
  newPage: () => Promise<PuppeteerPage>;
  close: () => Promise<void>;
}
interface PuppeteerPage {
  setContent: (html: string, opts?: unknown) => Promise<void>;
  pdf: (opts?: unknown) => Promise<unknown>;
}
