import { describe, expect, it } from "vitest";
import type { Finding } from "../src/evidence/models.js";
import { toMarkdown } from "../src/report/generate.js";

const base = (over: Partial<Finding>): Finding => ({
  id: "F",
  title: "Finding",
  severity: "medium",
  description: "",
  evidence: [],
  remediation: "",
  ...over,
});

describe("toMarkdown", () => {
  it("renders target, severity, CVSS, evidence and remediation for a finding", () => {
    const md = toMarkdown(
      [
        base({
          id: "F-1",
          title: "SQL injection in login",
          severity: "critical",
          cvss: { score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
          description: "The login form concatenates input into a query.",
          evidence: [
            { request: "POST /app/login", response: "200 welcome admin", note: "auth bypass" },
          ],
          remediation: "Use parameterized queries.",
        }),
      ],
      "http://localhost:3000/",
      { generatedOn: "2026-11-08", objective: "Reach the admin dashboard" },
    );
    expect(md).toContain("**Target:** http://localhost:3000/");
    expect(md).toContain("**Objective:** Reach the admin dashboard");
    expect(md).toContain("### 1. SQL injection in login `CRITICAL`");
    expect(md).toContain("**CVSS:** 9.8 (Critical)");
    expect(md).toContain("POST /app/login");
    expect(md).toContain("auth bypass");
    expect(md).toContain("Use parameterized queries.");
  });

  it("orders findings by severity, critical first", () => {
    const md = toMarkdown(
      [
        base({ id: "a", title: "Low one", severity: "low" }),
        base({ id: "b", title: "Crit one", severity: "critical" }),
      ],
      "t",
    );
    expect(md.indexOf("Crit one")).toBeLessThan(md.indexOf("Low one"));
  });

  it("states clearly when there are no findings", () => {
    const md = toMarkdown([], "http://localhost:3000/");
    expect(md).toContain("No vulnerabilities were confirmed");
  });

  it("embeds a Tier-2 screenshot as execution proof", () => {
    const md = toMarkdown(
      [
        base({
          severity: "high",
          evidence: [{ request: "r", response: "r", note: "", screenshot: "shots/xss.png" }],
        }),
      ],
      "t",
    );
    expect(md).toContain("![Execution proof](shots/xss.png)");
  });

  it("is not broken by backticks inside a response body", () => {
    const md = toMarkdown(
      [base({ evidence: [{ request: "GET /", response: "render: ```code```", note: "" }] })],
      "t",
    );
    expect(md).toContain("render: ```code```");
    // The wrapping fence must be longer than any backtick run inside the body.
    expect(md).toContain("````http");
  });
});
