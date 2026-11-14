import { afterEach, describe, expect, it } from "vitest";
import { bus } from "../src/events/bus.js";
import { recon } from "../src/recon/index.js";
import { ScopeGate } from "../src/scope/gate.js";
import { ScopeFile } from "../src/scope/schema.js";
import type { Session, SessionRequest, SessionResponse } from "../src/session/index.js";

const scope = ScopeFile.parse({
  target: "http://localhost:3000/",
  objective: "test",
  allow: { hosts: ["localhost"], paths: ["/"] },
});
const gate = new ScopeGate(scope);

const HTML = `<html><body>
  <a href="/app/one">in scope</a>
  <a href="http://evil.com/x">off scope</a>
  <a href="//evil.com/y">protocol-relative off scope</a>
  <a href="/index.php?do=toggle-enforce-ssl">state-changing toggle</a>
  <a href="/logout">logout</a>
  <a href="/index.php?action=delete&id=1">destructive action</a>
  <form action="http://evil.com/post" method="post"></form>
  <form action="/app/login" method="post"></form>
</body></html>`;

class RecordingSession implements Session {
  readonly tier = 1 as const;
  readonly requested: string[] = [];
  async login(): Promise<void> {}
  async request(req: SessionRequest): Promise<SessionResponse> {
    this.requested.push(req.url);
    return { status: 200, headers: { "content-type": "text/html" }, body: HTML };
  }
  async dispose(): Promise<void> {}
}

afterEach(() => bus.clearListeners());

describe("recon — gate routing (zero out-of-scope)", () => {
  it("only ever requests in-scope URLs and never follows off-scope links", async () => {
    const session = new RecordingSession();
    const result = await recon(session, gate, scope);

    expect(session.requested.length).toBeGreaterThan(0);
    for (const url of session.requested) {
      expect(gate.check(url).allowed).toBe(true);
      expect(url).not.toContain("evil.com");
    }
    for (const ep of result.endpoints) {
      expect(ep.url).not.toContain("evil.com");
      expect(gate.check(ep.url).allowed).toBe(true);
    }
  });

  it("never fires a state-changing GET — recon stays read-only", async () => {
    const session = new RecordingSession();
    const result = await recon(session, gate, scope);

    const all = [...session.requested, ...result.endpoints.map((e) => e.url)].join(" ");
    expect(all).not.toContain("toggle-enforce-ssl");
    expect(all).not.toMatch(/\/logout\b/);
    expect(all).not.toContain("action=delete");
  });
});

const OPENAPI_SPEC = JSON.stringify({
  openapi: "3.0.1",
  servers: [{ url: "/" }],
  paths: {
    "/users/v1/{username}": {
      get: { parameters: [{ name: "username", in: "path" }] },
      delete: { parameters: [{ name: "username", in: "path" }] },
    },
    "/books/v1/{book_title}": { get: { parameters: [{ name: "book_title", in: "path" }] } },
    "/search": { get: { parameters: [{ name: "q", in: "query" }] } },
    "/users/v1/register": { post: {} },
    "/health": { get: {} },
  },
});

class SpecSession implements Session {
  readonly tier = 1 as const;
  async login(): Promise<void> {}
  async request(req: SessionRequest): Promise<SessionResponse> {
    if (req.url.endsWith("/openapi.json")) {
      return { status: 200, headers: { "content-type": "application/json" }, body: OPENAPI_SPEC };
    }
    return { status: 200, headers: { "content-type": "application/json" }, body: "{}" };
  }
  async dispose(): Promise<void> {}
}

describe("recon — OpenAPI ingestion (JSON API surface)", () => {
  it("enumerates GET path/query params from a served spec and skips non-GET ops", async () => {
    const result = await recon(new SpecSession(), gate, scope);
    const byUrl = Object.fromEntries(result.endpoints.map((e) => [e.url, e]));

    // GET path-param endpoints discovered with their injectable field.
    expect(byUrl["http://localhost:3000/users/v1/{username}"]?.fields).toEqual(["username"]);
    expect(byUrl["http://localhost:3000/books/v1/{book_title}"]?.fields).toEqual(["book_title"]);
    // GET query param discovered.
    expect(byUrl["http://localhost:3000/search"]?.fields).toEqual(["q"]);

    // A state-changing POST is not emitted (read-only), and a GET with no input is skipped.
    const urls = result.endpoints.map((e) => e.url);
    expect(urls).not.toContain("http://localhost:3000/users/v1/register");
    expect(urls).not.toContain("http://localhost:3000/health");

    // Every emitted endpoint stays in scope.
    for (const ep of result.endpoints)
      expect(gate.check(ep.url.replace(/\{[^}]+\}/g, "1")).allowed).toBe(true);
  });
});
