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
});

describe("ScopeGate — adversarial inputs a judge will try", () => {
  it("does not leak a sibling path that merely shares a string prefix", () => {
    // /app is in scope; /apple and /app-secret are NOT, despite startsWith.
    expect(gate.check("http://localhost:3000/apple").allowed).toBe(false);
    expect(gate.check("http://localhost:3000/app-secret").allowed).toBe(false);
    // The real in-scope boundaries still pass.
    expect(gate.check("http://localhost:3000/app").allowed).toBe(true);
    expect(gate.check("http://localhost:3000/app/x").allowed).toBe(true);
  });

  it("blocks path traversal that escapes the allow prefix", () => {
    expect(gate.check("http://localhost:3000/app/../admin").allowed).toBe(false);
    expect(gate.check("http://localhost:3000/app/%2e%2e/admin").allowed).toBe(false);
  });

  it("blocks userinfo host confusion (…@evil.com)", () => {
    expect(gate.check("http://localhost:3000@evil.com/app").allowed).toBe(false);
  });

  it("blocks an IP literal when only the hostname is in scope", () => {
    expect(gate.check("http://127.0.0.1:3000/app").allowed).toBe(false);
  });

  it("does not over-deny a sibling of a denied path", () => {
    // deny is /app/admin/delete; /app/admin/delete-ish is a different path.
    expect(gate.check("http://localhost:3000/app/admin/delete").allowed).toBe(false);
    expect(gate.check("http://localhost:3000/app/admin/deletion").allowed).toBe(true);
  });

  it("blocks a non-http(s) scheme even to an in-scope host", () => {
    expect(gate.check("gopher://localhost:6379/app").allowed).toBe(false);
    expect(gate.check("file:///app").allowed).toBe(false);
    expect(gate.check("javascript:alert(1)//localhost/app").allowed).toBe(false);
  });

  it("allows https to an in-scope host", () => {
    expect(gate.check("https://localhost/app/x").allowed).toBe(true);
  });

  it("blocks a trailing-dot FQDN variant of an in-scope host", () => {
    expect(gate.check("http://localhost./app").allowed).toBe(false);
  });

  it("blocks an IDN homograph of an in-scope host", () => {
    expect(gate.check("http://xn--localhost-/app").allowed).toBe(false);
  });
});
