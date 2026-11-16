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

describe("recon — malformed form field recovery", () => {
  // A legacy app (WackoPicko's login) wraps a form's inputs in <tr>/<td> with no
  // enclosing <table>. HTML5 foster-parenting hoists those inputs OUT of the form
  // element, so the parse tree sees an empty form and the whole POST injection
  // surface (the username sink) vanishes. recon must recover the fields from the
  // raw form region so the sink stays probeable.
  const MALFORMED = `<html><body>
    <form action="/users/login.php" method="POST">
      <tr><td>Username :</td><td> <input type="text" name="username" /></td></tr>
      <tr><td>Password :</td><td> <input type="password" name="password" /></td></tr>
      <tr><td><input type="submit" value="login" /></td></tr>
    </form>
  </body></html>`;

  class FormSession implements Session {
    readonly tier = 1 as const;
    async login(): Promise<void> {}
    async request(): Promise<SessionResponse> {
      return { status: 200, headers: { "content-type": "text/html" }, body: MALFORMED };
    }
    async dispose(): Promise<void> {}
  }

  it("recovers a POST form's injectable fields when its inputs are foster-parented out of the form", async () => {
    const s = ScopeFile.parse({
      target: "http://localhost:3000/users/login.php",
      objective: "t",
      allow: { hosts: ["localhost"], paths: ["/"] },
    });
    const result = await recon(new FormSession(), new ScopeGate(s), s);
    const login = result.endpoints.find(
      (e) => e.url.endsWith("/users/login.php") && e.method === "POST",
    );
    expect(login).toBeDefined();
    expect(login?.fields).toContain("username"); // the injectable sink survived
    expect(login?.formData).toMatchObject({ username: "", password: "" }); // full form for resubmission
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

const GQL_SCHEMA = JSON.stringify({
  data: {
    __schema: {
      queryType: { name: "Query" },
      types: [
        {
          kind: "OBJECT",
          name: "Query",
          fields: [
            {
              name: "systemDebug",
              args: [{ name: "arg", type: { kind: "SCALAR", name: "String" } }],
              type: { kind: "SCALAR", name: "String" },
            },
            {
              name: "pastes",
              args: [{ name: "filter", type: { kind: "SCALAR", name: "String" } }],
              type: { kind: "LIST", name: null, ofType: { kind: "OBJECT", name: "PasteObject" } },
            },
            { name: "health", args: [], type: { kind: "SCALAR", name: "String" } },
          ],
        },
        {
          kind: "OBJECT",
          name: "PasteObject",
          fields: [{ name: "id", type: { kind: "SCALAR", name: "ID" } }],
        },
      ],
    },
  },
});

class GqlSession implements Session {
  readonly tier = 1 as const;
  async login(): Promise<void> {}
  async request(req: SessionRequest): Promise<SessionResponse> {
    if (req.method === "POST") {
      const body = req.body ?? "";
      if (body.includes("__schema")) {
        return { status: 200, headers: { "content-type": "application/json" }, body: GQL_SCHEMA };
      }
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: '{"data":{"__typename":"Query"}}',
      };
    }
    return { status: 200, headers: { "content-type": "text/html" }, body: "<html></html>" };
  }
  async dispose(): Promise<void> {}
}

describe("recon — GraphQL introspection (Query-only, read-only)", () => {
  it("enumerates Query fields' string args with a valid selection, skipping no-arg fields", async () => {
    const result = await recon(new GqlSession(), gate, scope);
    const probes = result.endpoints.filter((e) => e.graphql).map((e) => e.graphql);

    const debug = probes.find((g) => g?.field === "systemDebug");
    expect(debug).toBeDefined();
    expect(debug?.arg).toBe("arg");
    expect(debug?.selection).toBe(""); // scalar return needs no selection

    const pastes = probes.find((g) => g?.field === "pastes");
    expect(pastes?.arg).toBe("filter");
    expect(pastes?.selection).toBe(" { id }"); // object return needs a scalar subfield

    // A field with no string argument is not a probe.
    expect(probes.some((g) => g?.field === "health")).toBe(false);
    // Every GraphQL endpoint is the gated POST endpoint.
    for (const e of result.endpoints.filter((x) => x.graphql)) {
      expect(e.method).toBe("POST");
      expect(gate.check(e.url).allowed).toBe(true);
    }
  });
});

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
