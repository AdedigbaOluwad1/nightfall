import { describe, expect, it } from "vitest";
import type { Finding } from "../src/evidence/models.js";
import { toHtml } from "../src/report/html.js";

const finding: Finding = {
  id: "F-1",
  title: "SQL injection in login",
  severity: "critical",
  cvss: { score: 9.8 },
  description: "Input is concatenated into the query.",
  evidence: [{ request: "POST /app/login", response: "200 welcome admin", note: "auth bypass" }],
  remediation: "Use parameterized queries.",
};

describe("toHtml", () => {
  it("produces a self-contained HTML document from the findings", async () => {
    const html = await toHtml([finding], "http://localhost:3000/", { generatedOn: "2026-11-08" });
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("<title>Nightfall — Penetration Test Report</title>");
    expect(html).toContain("<style>");
    expect(html).toContain("SQL injection in login");
    expect(html).toContain("Use parameterized queries.");
    // Markdown was converted to HTML (code fence -> <pre>).
    expect(html).toContain("<pre>");
    expect(html).toContain("</html>");
  });

  it("renders an empty-findings report without throwing", async () => {
    const html = await toHtml([], "http://localhost:3000/");
    expect(html).toContain("No vulnerabilities were confirmed");
  });
});
