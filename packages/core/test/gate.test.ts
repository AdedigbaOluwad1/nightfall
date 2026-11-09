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
const allowed = (url: string) => gate.check(url).allowed;

describe("ScopeGate — allows only in-scope requests", () => {
  it("allows an in-scope host + path", () => {
    expect(allowed("http://localhost:3000/app/x")).toBe(true);
  });

  it("allows a host whose case differs (hostnames are case-insensitive)", () => {
    expect(allowed("http://LOCALHOST:3000/app")).toBe(true);
  });

  it("uses the real host, not userinfo — evil.com in userinfo is still localhost", () => {
    // Host is localhost; `evil.com` here is only the userinfo portion.
    expect(allowed("http://evil.com@localhost:3000/app")).toBe(true);
  });
});

describe("ScopeGate — denies out-of-scope and adversarial requests", () => {
  const denied: [string, string][] = [
    ["out-of-scope host", "http://evil.com/app"],
    ["path outside the allow prefix", "http://localhost:3000/other"],
    ["explicitly denied path under an allow prefix", "http://localhost:3000/app/admin/delete"],
    ["root path when only /app is allowed", "http://localhost:3000/"],
    ["path-case trick (paths are case-sensitive)", "http://localhost:3000/APP"],
    ["plain path traversal", "http://localhost:3000/app/../admin"],
    ["percent-encoded dot segments", "http://localhost:3000/app/%2e%2e/admin"],
    ["encoded-slash traversal", "http://localhost:3000/app/%2e%2e%2f%2e%2e/admin"],
    ["encoded single-slash traversal", "http://localhost:3000/app/..%2fadmin"],
    ["double-encoded dot segments", "http://localhost:3000/app/%252e%252e/admin"],
    ["userinfo@host confusion", "http://localhost@evil.com/app"],
    ["trailing-dot host", "http://localhost.:3000/app"],
    ["loopback IP instead of hostname", "http://127.0.0.1:3000/app"],
    ["IPv6 loopback instead of hostname", "http://[::1]:3000/app"],
    ["non-HTTP scheme (file)", "file:///etc/passwd"],
    ["non-HTTP scheme (javascript)", "javascript:alert(1)"],
    ["unparseable URL", "not a url"],
  ];

  it.each(denied)("blocks %s", (_label, url) => {
    expect(allowed(url)).toBe(false);
  });
});
