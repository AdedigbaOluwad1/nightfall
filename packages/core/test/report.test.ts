import { describe, expect, it } from "vitest";
import type { Finding } from "../src/evidence/models.js";
import { toMarkdown } from "../src/report/generate.js";

const sqli: Finding = {
  id: "1",
  title: "SQL injection at /rest/products/search",
  technique: "sql injection",
  severity: "critical",
  cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  cvssScore: 9.8,
  evidence: [
    {
      request: "GET /rest/products/search?q='\"",
      response: 'SQLITE_ERROR: near "\'"',
      note: "DB error surfaced",
    },
  ],
  remediation: "Use parameterized queries.",
};

const bac: Finding = {
  id: "2",
  title: "Broken access control at /rest/admin/application-configuration",
  technique: "access-probe",
  severity: "high",
  cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  cvssScore: 7.5,
  evidence: [
    { request: "GET /rest/admin/application-configuration", response: '{"config":{}}', note: "" },
  ],
  remediation: "Enforce server-side authorization.",
};

describe("toMarkdown — a report a consultant would sign", () => {
  it("renders metadata, a severity summary, and a dressed section per finding", () => {
    const md = toMarkdown([bac, sqli], {
      target: "http://localhost:3000/",
      objective: "Reach the admin dashboard",
      runId: "run-xyz",
      haltedBy: "objective",
      costUsd: 0.0123,
    });

    expect(md).toContain("# Nightfall — Penetration Test Report");
    expect(md).toContain("**Target:** http://localhost:3000/");
    expect(md).toContain("**Objective:** Reach the admin dashboard");
    expect(md).toContain("run `run-xyz`");
    expect(md).toContain("2 findings — 1 critical, 1 high.");
    // Every finding carries its CVSS vector, score, and remediation.
    expect(md).toContain("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(md).toContain("(CVSS 9.8)");
    expect(md).toContain("Use parameterized queries.");
    expect(md).toContain("GET /rest/admin/application-configuration");
  });

  it("orders findings most-severe first regardless of input order", () => {
    const md = toMarkdown([bac, sqli], { target: "x" });
    expect(md.indexOf("CRITICAL")).toBeLessThan(md.indexOf("— HIGH"));
  });

  it("escapes a fenced response body so it cannot break out of the code block", () => {
    const evil: Finding = {
      id: "3",
      title: "x",
      technique: "x",
      severity: "low",
      cvss: "",
      evidence: [{ request: "GET /", response: "```\nnot a fence\n```", note: "" }],
      remediation: "",
    };
    const md = toMarkdown([evil], { target: "x" });
    expect(md).not.toContain("\n```\nnot a fence");
  });

  it("states honestly when a run confirmed nothing", () => {
    const md = toMarkdown([], { target: "http://localhost:3000/" });
    expect(md).toContain("No findings confirmed.");
    expect(md).toContain("without confirming an in-scope vulnerability");
  });

  it("renders linked findings as an ordered attack chain", () => {
    const step1: Finding = {
      id: "s1",
      title: "SQL Injection — Authentication Bypass at http://x/",
      technique: "SQL Injection — authentication bypass",
      severity: "critical",
      cvss: "",
      evidence: [{ request: "POST /login", response: "token", note: "" }],
      remediation: "",
      step: 1,
      produced: ["admin session JWT"],
    };
    const step2: Finding = {
      id: "s2",
      title: "Broken Access Control — Privilege Escalation at http://x/",
      technique: "Authenticated admin access",
      severity: "high",
      cvss: "",
      evidence: [{ request: "GET /api/Users", response: "users", note: "" }],
      remediation: "",
      step: 2,
      parentId: "s1",
      consumed: "admin session JWT",
      produced: ["admin-only user records"],
    };
    const md = toMarkdown([step2, step1], { target: "x" });
    expect(md).toContain("## Attack chain");
    // Ordered by step regardless of input order.
    expect(md.indexOf("1. **SQL Injection")).toBeLessThan(md.indexOf("2. **Broken Access"));
    expect(md).toContain("uses the **admin session JWT**");
    expect(md).toContain("← objective reached.");
  });
});
