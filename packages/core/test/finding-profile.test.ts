import { describe, expect, it } from "vitest";
import { findingProfile } from "../src/loop/actions.js";

describe("findingProfile — client-ready severity and remediation", () => {
  it("argues severity from the vulnerability class, never a hard-coded high", () => {
    expect(findingProfile("blind SQL injection").severity).toBe("critical");
    expect(findingProfile("reflected cross-site scripting").severity).toBe("high");
    expect(findingProfile("CSRF on the password form").severity).toBe("medium");
    expect(findingProfile("path traversal via file param").severity).toBe("high");
    expect(findingProfile("OS command injection").severity).toBe("critical");
    expect(findingProfile("broken access control").severity).toBe("high");
  });

  it("carries a parseable CVSS v3.1 vector, a concrete remediation, and a client-ready name", () => {
    const p = findingProfile("SQL injection");
    expect(p.cvss).toMatch(/^CVSS:3\.1\//);
    expect(p.cvssScore).toBeGreaterThan(0);
    expect(p.remediation.length).toBeGreaterThan(20);
    expect(p.name).toBe("SQL Injection");
    expect(findingProfile("access-probe").name).toBe("Broken Access Control");
  });

  it("falls back to a safe medium profile for an unrecognized technique", () => {
    const p = findingProfile("some novel logic flaw");
    expect(p.severity).toBe("medium");
    expect(p.remediation).toMatch(/manually/i);
  });

  it("appends a patch directive when a CVE is cited", () => {
    const withCve = findingProfile("SQL injection", "CVE-2021-44228");
    const without = findingProfile("SQL injection");
    expect(withCve.remediation).toContain("CVE-2021-44228");
    expect(withCve.remediation.length).toBeGreaterThan(without.remediation.length);
  });
});
