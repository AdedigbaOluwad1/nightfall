import { describe, expect, it } from "vitest";
import { ScopeGate } from "../src/scope/gate.js";
import { ScopeFile } from "../src/scope/schema.js";

const scope = ScopeFile.parse({
  target: "http://localhost:3000/",
  objective: "test",
  allow: { hosts: ["localhost"], paths: ["/app"] },
  deny: { paths: ["/app/admin/delete"] },
});
const gate = new ScopeGate(scope);

describe("ScopeGate — deny by default", () => {
  it("allows an in-scope host + path", () => {
    expect(gate.check("http://localhost:3000/app/x").allowed).toBe(true);
  });
  it("blocks an out-of-scope host", () => {
    expect(gate.check("http://evil.com/app").allowed).toBe(false);
  });
  it("blocks a path outside the allow prefix", () => {
    expect(gate.check("http://localhost:3000/other").allowed).toBe(false);
  });
  it("blocks an explicitly denied path even under an allow prefix", () => {
    expect(gate.check("http://localhost:3000/app/admin/delete").allowed).toBe(false);
  });
  it("blocks an unparseable URL", () => {
    expect(gate.check("not a url").allowed).toBe(false);
  });
  // TODO(R3): add adversarial cases — encoded hosts, path traversal (/app/../admin),
  // case tricks, userinfo@host confusion, SSRF-style redirects.
});
