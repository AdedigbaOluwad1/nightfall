import { describe, expect, it } from "vitest";
import { type AttemptOpts, attempt } from "../src/loop/actions.js";
import type { Session, SessionRequest, SessionResponse } from "../src/session/index.js";

/** A session whose response is computed from the (possibly mutated) request. */
class StubSession implements Session {
  readonly tier = 1 as const;
  constructor(private readonly handler: (req: SessionRequest) => Partial<SessionResponse>) {}
  async login(): Promise<void> {}
  async request(req: SessionRequest): Promise<SessionResponse> {
    return { status: 200, headers: {}, body: "", ...this.handler(req) };
  }
  async dispose(): Promise<void> {}
}

const opts = (over: Partial<AttemptOpts> = {}): AttemptOpts => ({
  useSession: true,
  url: "http://localhost:3000/rest/products/search",
  ...over,
});

describe("attempt — technique-aware dispatch", () => {
  it("confirms SQL injection only when a DB error surfaces from the quote probe", async () => {
    // The leaked DB error rides a 500 (as it does live on Juice Shop). A 5xx is
    // normally transient, but here the SQLi check reads the body first and
    // confirms — a leaked error is a finding, not a flaky failure.
    const vulnerable = new StubSession((req) =>
      req.url.includes("q=%27%22")
        ? { status: 500, body: 'SQLITE_ERROR: near ")": syntax error' }
        : { body: "ok" },
    );
    const hit = await attempt(vulnerable, "SQL Injection", opts());
    expect(hit.ok).toBe(true);
    expect(hit.transient).toBeFalsy();

    // A 200 that still leaks a SQL error also confirms.
    const reflectErr = new StubSession((req) =>
      req.url.includes("q=%27%22")
        ? { status: 200, body: 'SQL syntax error near "\'"' }
        : { body: "" },
    );
    const ok = await attempt(reflectErr, "SQLi", opts());
    expect(ok.ok).toBe(true);
    expect(ok.note).toMatch(/SQLi/);

    // A clean 500 with no DB error stays transient — the contract still holds.
    const flaky = new StubSession(() => ({ status: 500, body: "Internal Server Error" }));
    const transient = await attempt(flaky, "SQL injection", opts());
    expect(transient.ok).toBe(false);
    expect(transient.transient).toBe(true);

    const safe = new StubSession(() => ({ status: 200, body: "no results" }));
    const miss = await attempt(safe, "blind SQL injection", opts());
    expect(miss.ok).toBe(false);
    expect(miss.applicable).toBe(true);
  });

  it("confirms boolean-based SQLi on a POST form when an always-true condition returns more rows", async () => {
    // DVNA's /app/usersearch swallows the engine error (generic page) but builds
    // the query by concatenation: an always-true tautology dumps rows an always-
    // false one does not. The benign/false bodies also carry CSS braces, which
    // must NOT be counted as records (the chrome-robustness fix).
    const db = new StubSession((req) => {
      const body = decodeURIComponent(req.body ?? "");
      if (body.includes("1'='1")) {
        return { status: 200, body: "<table><tr><td>admin</td></tr><tr><td>bob</td></tr></table>" };
      }
      return { status: 200, body: "<style>.a{color:red}.b{x:y}</style><p>no results</p>" };
    });
    const hit = await attempt(
      db,
      "SQL Injection",
      opts({ url: "http://localhost:3000/app/usersearch", method: "POST", fields: ["login"] }),
    );
    expect(hit.ok).toBe(true);
    expect(hit.note).toMatch(/boolean-based/);
    expect(hit.basis).toMatch(/Impact-confirmed/);

    // No injection: an endpoint that returns the same for every payload (rows and
    // all) yields no differential, so it never confirms.
    const stable = new StubSession(() => ({
      status: 200,
      body: "<table><tr><td>fixed</td></tr></table>",
    }));
    const miss = await attempt(
      stable,
      "SQL Injection",
      opts({ url: "http://localhost:3000/app/products", method: "POST", fields: ["name"] }),
    );
    expect(miss.ok).toBe(false);
  });

  it("does not flag an authorized resource as broken access control on an authenticated run", async () => {
    // Logged in with operator credentials, reaching a feature page you are
    // authorized for is expected — not BAC — even when its chrome echoes an
    // objective word. Without a lower-privilege baseline we under-claim.
    const page = new StubSession(() => ({ status: 200, body: "user dashboard — application" }));
    const authed = await attempt(
      page,
      "Broken Access Control",
      opts({
        url: "http://localhost:3000/app/usersearch",
        authenticated: true,
        objectiveHint: ["user", "application"],
      }),
    );
    expect(authed.ok).toBe(false);
    expect(authed.note).toMatch(/authenticated principal/);

    // Unauthenticated, reachable admin content still confirms — the flagship
    // (no-credentials) access-control finding is unaffected.
    const admin = new StubSession(() => ({ status: 200, body: "admin application-configuration" }));
    const unauth = await attempt(
      admin,
      "Broken Access Control",
      opts({
        url: "http://localhost:3000/rest/admin/application-configuration",
        objectiveHint: ["admin"],
      }),
    );
    expect(unauth.ok).toBe(true);
  });

  it("extracts a leaked framework banner from the SQL error page as a fingerprint artifact", async () => {
    // Juice Shop's 500 error page is titled "OWASP Juice Shop (Express ^4.22.1)":
    // the quote probe both confirms SQLi AND discloses the stack to re-ground.
    const leaky = new StubSession((req) =>
      req.url.includes("q=%27%22")
        ? {
            status: 500,
            body: "<h1>OWASP Juice Shop (Express ^4.22.1)</h1> SQLITE_ERROR: syntax error",
          }
        : { body: "" },
    );
    const hit = await attempt(leaky, "SQL Injection", opts());
    expect(hit.ok).toBe(true);
    const fp = hit.discovered?.find((a) => a.kind === "fingerprint");
    expect(fp?.value).toBe("Express@4.22.1");

    // No banner in the error → a clean confirm with no fingerprint discovered.
    const noBanner = new StubSession((req) =>
      req.url.includes("q=%27%22") ? { status: 500, body: "SQLITE_ERROR: syntax error" } : {},
    );
    const plain = await attempt(noBanner, "SQL Injection", opts());
    expect(plain.ok).toBe(true);
    expect(plain.discovered?.some((a) => a.kind === "fingerprint")).toBeFalsy();
  });

  it("confirms reflected XSS only when the marker echoes un-escaped into HTML", async () => {
    const reflecting = new StubSession((req) => {
      const u = new URL(req.url);
      const q = u.searchParams.get("q") ?? "";
      return { headers: { "content-type": "text/html" }, body: `<div>${q}</div>` };
    });
    const ok = await attempt(reflecting, "Cross-Site Scripting (XSS)", opts());
    expect(ok.ok).toBe(true);

    const escaping = new StubSession((req) => {
      const u = new URL(req.url);
      const q = (u.searchParams.get("q") ?? "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      return { headers: { "content-type": "text/html" }, body: `<div>${q}</div>` };
    });
    const miss = await attempt(escaping, "stored XSS", opts());
    expect(miss.ok).toBe(false);

    const jsonEcho = new StubSession((req) => {
      const u = new URL(req.url);
      return {
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ q: u.searchParams.get("q") }),
      };
    });
    const notHtml = await attempt(jsonEcho, "XSS", opts());
    expect(notHtml.ok).toBe(false);
  });

  it("confirms path traversal only when host-file contents leak", async () => {
    const leaky = new StubSession((req) =>
      req.url.includes("etc%2Fpasswd") || req.url.includes("/etc/passwd")
        ? { body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin" }
        : { body: "" },
    );
    const ok = await attempt(leaky, "Path Traversal / LFI", opts());
    expect(ok.ok).toBe(true);

    const safe = new StubSession(() => ({ body: "file not found" }));
    const miss = await attempt(safe, "directory traversal", opts());
    expect(miss.ok).toBe(false);
  });

  it("flags CSRF only when a session cookie lacks SameSite and no token is present", async () => {
    const exposed = new StubSession(() => ({
      headers: { "set-cookie": "connect.sid=abc; Path=/; HttpOnly" },
      body: "<form><input name=email></form>",
    }));
    const ok = await attempt(exposed, "Cross-Site Request Forgery", opts());
    expect(ok.ok).toBe(true);

    const defended = new StubSession(() => ({
      headers: { "set-cookie": "connect.sid=abc; Path=/; SameSite=Strict" },
      body: "",
    }));
    const miss = await attempt(defended, "CSRF", opts());
    expect(miss.ok).toBe(false);
  });

  it("falls back to the access probe for broken-access-control and unrecognized techniques", async () => {
    const adminUrl = "http://localhost:3000/rest/admin/application-configuration";
    const admin = new StubSession(() => ({ status: 200, body: "admin application-configuration" }));
    const bac = await attempt(
      admin,
      "Broken Access Control",
      opts({ url: adminUrl, objectiveHint: ["admin"] }),
    );
    expect(bac.ok).toBe(true);

    const unknown = await attempt(
      admin,
      "server-side template injection",
      opts({ url: adminUrl, objectiveHint: ["admin"] }),
    );
    expect(unknown.ok).toBe(true); // unrecognized → same baseline probe, no regression

    const noSignal = await attempt(
      admin,
      "Broken Access Control",
      opts({ url: adminUrl, objectiveHint: ["billing"] }),
    );
    expect(noSignal.ok).toBe(false);
  });

  it("does not report a reachable public page as broken access control (BodgeIt/VAmPI false positive)", async () => {
    // A multi-lab run flooded with false BAC: public catalog/search/contact pages
    // confirmed because they were reachable and echoed an objective word. BAC now
    // requires a privilege-denoting surface — these public pages must not confirm.
    const content = new StubSession(() => ({
      status: 200,
      body: "<html><body>product catalogue — your account basket</body></html>",
    }));
    for (const path of [
      "/bodgeit/product.jsp?typeid=4",
      "/bodgeit/search.jsp",
      "/bodgeit/contact.jsp",
      "/bodgeit/basket.jsp",
      "/user_new.php",
      "/",
    ]) {
      const res = await attempt(
        content,
        "Broken Access Control",
        opts({ url: `http://127.0.0.1:8088${path}`, objectiveHint: ["account", "data", "admin"] }),
      );
      expect(res.ok, `${path} must not confirm`).toBe(false);
    }

    // A genuinely administrative surface still confirms — true BAC is kept.
    const adminArea = new StubSession(() => ({ status: 200, body: "admin console — users" }));
    const real = await attempt(
      adminArea,
      "Broken Access Control",
      opts({ url: "http://127.0.0.1:8088/bodgeit/admin.jsp", objectiveHint: ["admin"] }),
    );
    expect(real.ok).toBe(true);
  });

  it("does not confirm the objective off an auth wall (expired-session false positive)", async () => {
    // A dropped session is redirected to a 200 login page that happens to carry
    // an objective word ("Admin login"). This must NOT read as objective reached.
    const loginPage = new StubSession(() => ({
      status: 200,
      body: '<form action="/login"><h1>Admin login</h1><input type="password" name="password"></form>',
    }));
    const falsePos = await attempt(
      loginPage,
      "Broken Access Control",
      opts({ objectiveHint: ["admin"] }),
    );
    expect(falsePos.ok).toBe(false);
    expect(falsePos.applicable).toBe(false);

    // A bare 401 is an auth wall too, never a finding.
    const unauth = new StubSession(() => ({ status: 401, body: "admin area" }));
    const blocked = await attempt(
      unauth,
      "Broken Access Control",
      opts({ objectiveHint: ["admin"] }),
    );
    expect(blocked.ok).toBe(false);
  });

  it("never reports a public auth-entry page as broken access control (DVNA false positive)", async () => {
    // DVNA's /login, /register, and /forgotpw are public by design. Their body
    // truncates before the login form, leaving only a <title> that echoes a
    // generic objective word ("application") — which falsely confirmed BAC. A page
    // whose URL is a public auth-entry surface must never confirm, whatever its
    // chrome says, and the guard is URL-based so a truncated body can't defeat it.
    const titleOnly = new StubSession(() => ({
      status: 200,
      body: "<title>Damn Vulnerable NodeJS Application</title>",
    }));
    for (const path of ["/login", "/register", "/forgotpw", "/sign-up", "/reset-password"]) {
      const res = await attempt(
        titleOnly,
        "Broken Access Control",
        opts({ url: `http://localhost:8087${path}`, objectiveHint: ["application", "access"] }),
      );
      expect(res.ok, `${path} must not confirm`).toBe(false);
    }

    // A genuinely gated surface that is not an auth-entry page still confirms.
    const admin = new StubSession(() => ({ status: 200, body: "admin application-configuration" }));
    const real = await attempt(
      admin,
      "Broken Access Control",
      opts({ url: "http://localhost:8087/admin", objectiveHint: ["admin"] }),
    );
    expect(real.ok).toBe(true);
  });

  it("does NOT discard a real finding that merely contains a password field (no false negative)", async () => {
    // The mirror risk of the auth-wall guard: an admin page with a change-password
    // widget has a password input but is NOT a login screen. It must still confirm
    // — a lone password field is not enough to classify a page as an auth wall.
    const adminPage = new StubSession(() => ({
      status: 200,
      body: '<h1>Admin Dashboard</h1><p>admin settings</p><form action="/account/password"><input type="password" name="newpass"></form>',
    }));
    const confirmed = await attempt(
      adminPage,
      "Broken Access Control",
      opts({ url: "http://localhost:3000/admin/dashboard", objectiveHint: ["admin"] }),
    );
    expect(confirmed.ok).toBe(true);
  });

  it("at the bare root, steers broken-access to the admin surface but not unrecognized techniques", async () => {
    // A server whose root carries no objective token, but whose admin surface does.
    const perPath = new StubSession((req) => {
      const path = new URL(req.url).pathname;
      return path.includes("/rest/admin/application-configuration")
        ? { status: 200, body: '{"config":{"application":{"name":"OWASP Juice Shop"}}}' }
        : { status: 200, body: "<html><body>spa shell</body></html>" };
    });
    const root = opts({ url: "http://localhost:3005/", objectiveHint: ["admin", "config"] });

    // Broken access control reaches the admin surface (its url carries "admin"/"config").
    const bac = await attempt(perPath, "Broken Access Control", root);
    expect(bac.ok).toBe(true);

    // An unrecognized technique probes only the root → no signal → not confirmed.
    const ssti = await attempt(perPath, "Server-Side Template Injection", root);
    expect(ssti.ok).toBe(false);
    expect(bac.ok).not.toBe(ssti.ok); // the fallback no longer auto-confirms everything
  });

  it("preserves the stable contract: 404/405 not-applicable, 5xx transient, scope block hard-stop", async () => {
    const gone = new StubSession(() => ({ status: 404, body: "" }));
    const na = await attempt(gone, "SQL injection", opts());
    expect(na.applicable).toBe(false);

    const err = new StubSession(() => ({ status: 503, body: "" }));
    const transient = await attempt(err, "Broken Access Control", opts());
    expect(transient.transient).toBe(true);

    const blocked = new StubSession(() => {
      throw new Error("blocked by scope gate: off-scope");
    });
    const hard = await attempt(blocked, "XSS", opts());
    expect(hard.applicable).toBe(false);
    expect(hard.transient).toBeFalsy();
  });

  it("gives different outcomes to different techniques against the same target", async () => {
    // A target that only leaks a SQL error — SQLi confirms, XSS does not.
    const sqlOnly = new StubSession((req) =>
      req.url.includes("q=%27")
        ? { status: 200, body: 'SQLITE_ERROR near "\'"' }
        : { headers: { "content-type": "text/html" }, body: "<div>clean</div>" },
    );
    const sqli = await attempt(sqlOnly, "SQL injection", opts());
    const xss = await attempt(sqlOnly, "XSS", opts());
    expect(sqli.ok).toBe(true);
    expect(xss.ok).toBe(false);
    expect(sqli.ok).not.toBe(xss.ok); // the metric can now tell them apart
  });
});

/** Decode an input (POST body or GET query) to plain text for a stub's branch. */
const inputOf = (req: SessionRequest): string =>
  decodeURIComponent((req.body ?? req.url ?? "").replace(/\+/g, " "));

describe("attempt — widened injection coverage (form- and param-aware)", () => {
  it("confirms reflected XSS injected into a discovered POST form field", async () => {
    const reflect = new StubSession((req) =>
      inputOf(req).includes("nfx7q9<i>")
        ? { headers: { "content-type": "text/html" }, body: "<p>results for nfx7q9<i></p>" }
        : { headers: { "content-type": "text/html" }, body: "<p>no results</p>" },
    );
    const hit = await attempt(
      reflect,
      "Reflected Cross-Site Scripting",
      opts({ url: "http://localhost:9/search", method: "POST", fields: ["query"] }),
    );
    expect(hit.ok).toBe(true);
    expect(hit.note).toMatch(/query/);

    // Escaped reflection does not confirm.
    const escaped = new StubSession(() => ({
      headers: { "content-type": "text/html" },
      body: "<p>results for nfx7q9&lt;i&gt;</p>",
    }));
    const miss = await attempt(
      escaped,
      "XSS",
      opts({ url: "http://localhost:9/search", method: "POST", fields: ["query"] }),
    );
    expect(miss.ok).toBe(false);
  });

  it("confirms command injection and path traversal injected into a GET parameter", async () => {
    const cmd = new StubSession((req) =>
      inputOf(req).includes("; id")
        ? { body: "uid=0(root) gid=0(root) groups=0(root)" }
        : { body: "pinging host..." },
    );
    const cmdHit = await attempt(
      cmd,
      "OS Command Injection",
      opts({ url: "http://localhost:9/ping?host=example" }),
    );
    expect(cmdHit.ok).toBe(true);
    expect(cmdHit.note).toMatch(/host/);

    const lfi = new StubSession((req) =>
      inputOf(req).includes("/etc/passwd")
        ? {
            body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
          }
        : { body: "page not found" },
    );
    const lfiHit = await attempt(
      lfi,
      "Path Traversal",
      opts({ url: "http://localhost:9/view?page=home" }),
    );
    expect(lfiHit.ok).toBe(true);
    expect(lfiHit.note).toMatch(/page/);
  });

  it("never POSTs an injection into a state-changing form (read-only safety)", async () => {
    // A form that WOULD reflect the marker — but its surface is mutating, so the
    // probe must skip it rather than write to the target.
    const reflectingButMutating = new StubSession((req) =>
      inputOf(req).includes("nfx7q9<i>")
        ? { headers: { "content-type": "text/html" }, body: "<p>saved nfx7q9<i></p>" }
        : { headers: { "content-type": "text/html" }, body: "<p>form</p>" },
    );
    for (const url of [
      "http://localhost:9/app/modifyproduct",
      "http://localhost:9/account/create",
      "http://localhost:9/users/update",
    ]) {
      const res = await attempt(
        reflectingButMutating,
        "Reflected Cross-Site Scripting",
        opts({ url, method: "POST", fields: ["name"] }),
      );
      expect(res.ok, `${url} must be skipped`).toBe(false);
      expect(res.applicable, `${url} is not applicable (skipped)`).toBe(false);
      expect(res.note).toMatch(/state-changing form/);
    }

    // A read-oriented POST form (search) with the same reflection DOES confirm.
    const search = await attempt(
      reflectingButMutating,
      "Reflected Cross-Site Scripting",
      opts({ url: "http://localhost:9/usersearch", method: "POST", fields: ["login"] }),
    );
    expect(search.ok).toBe(true);
  });

  it("detects a signal below the 2 KB fold (large nav/framework shell)", async () => {
    // A real app wraps its output in a big nav/framework shell, so the injected
    // signal lands far below the head of the body. Detection must scan the whole
    // response, not a head slice — otherwise a finding is lost purely to page size
    // (the exact gap that hid Mutillidae's command-injection ~49 KB into its page
    // while the identical probe found BodgeIt's XSS in a small page).
    const shell = `<nav>${"<a href='/x'>menu</a>".repeat(3000)}</nav>`; // ~66 KB
    expect(shell.length).toBeGreaterThan(2000);

    const deepCmd = new StubSession((req) =>
      inputOf(req).includes("; id")
        ? { body: `${shell}<pre>uid=33(www-data) gid=33(www-data)</pre>` }
        : { body: `${shell}<pre>lookup...</pre>` },
    );
    const cmdHit = await attempt(
      deepCmd,
      "OS Command Injection",
      opts({ url: "http://localhost:9/dns?host=example" }),
    );
    expect(cmdHit.ok).toBe(true);

    const deepXss = new StubSession((req) =>
      inputOf(req).includes("nfx7q9<i>")
        ? { headers: { "content-type": "text/html" }, body: `${shell}<div>nfx7q9<i></div>` }
        : { headers: { "content-type": "text/html" }, body: `${shell}<div>none</div>` },
    );
    const xssHit = await attempt(
      deepXss,
      "Reflected Cross-Site Scripting",
      opts({ url: "http://localhost:9/search", method: "POST", fields: ["q"] }),
    );
    expect(xssHit.ok).toBe(true);
  });

  it("injects into an OpenAPI path parameter, not as a query string (REST API SQLi)", async () => {
    const seen: string[] = [];
    const pathSqli = new StubSession((req) => {
      seen.push(req.url);
      return inputOf(req).includes("'")
        ? { body: "sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token" }
        : { body: '{"username":"name1"}' };
    });
    const hit = await attempt(
      pathSqli,
      "SQL Injection",
      opts({ url: "http://localhost:9/users/v1/{username}", fields: ["username"] }),
    );
    expect(hit.ok).toBe(true);
    expect(hit.note).toMatch(/username/);
    // The payload must land in the path segment, never appended as ?username=.
    expect(seen.some((u) => u.includes("/users/v1/'"))).toBe(true);
    expect(seen.every((u) => !u.includes("?username="))).toBe(true);
  });

  it("injects into a GraphQL Query-field argument (command injection)", async () => {
    const bodies: string[] = [];
    const gqlCmd = new StubSession((req) => {
      bodies.push(req.body ?? "");
      return inputOf(req).includes("; id")
        ? { body: '{"data":{"systemDebug":"uid=1000(dvga) gid=1000(dvga) groups=1000(dvga)\\n"}}' }
        : { body: '{"data":{"systemDebug":""}}' };
    });
    const hit = await attempt(
      gqlCmd,
      "OS Command Injection",
      opts({
        url: "http://localhost:9/graphql",
        method: "POST",
        graphql: { field: "systemDebug", arg: "arg", selection: "", fixedArgs: "" },
      }),
    );
    expect(hit.ok).toBe(true);
    // The probe POSTed a GraphQL query carrying the field and the payload.
    expect(bodies.some((b) => b.includes("systemDebug(arg:") && b.includes("; id"))).toBe(true);
  });

  it("resubmits a complete GET form (submit button + siblings) when a field gates on it (DVWA)", async () => {
    const seen: string[] = [];
    const dvwaLike = new StubSession((req) => {
      seen.push(req.url);
      const u = new URL(req.url);
      // Mimics DVWA: the query is processed only when the Submit button is present.
      if (
        u.searchParams.get("Submit") === "Submit" &&
        (u.searchParams.get("id") ?? "").includes("'")
      ) {
        return { body: "You have an error in your SQL syntax" };
      }
      return { body: "<form></form>" };
    });
    const hit = await attempt(
      dvwaLike,
      "SQL Injection",
      opts({
        url: "http://localhost:9/vulnerabilities/sqli/",
        method: "GET",
        fields: ["id"],
        formData: { id: "", Submit: "Submit" },
      }),
    );
    expect(hit.ok).toBe(true);
    expect(seen.some((u) => u.includes("Submit=Submit") && u.includes("id="))).toBe(true);
  });

  it("resubmits a complete POST form including the submit button in the body", async () => {
    const bodies: string[] = [];
    const gated = new StubSession((req) => {
      bodies.push(req.body ?? "");
      const sent = new URLSearchParams(req.body ?? "");
      if (sent.get("btnSign") === "Sign" && (sent.get("entry") ?? "").includes("'")) {
        return { body: "error in your SQL syntax near" };
      }
      return { body: "ok" };
    });
    const hit = await attempt(
      gated,
      "SQL Injection",
      opts({
        url: "http://localhost:9/sqli_6.php",
        method: "POST",
        fields: ["entry"],
        formData: { entry: "", btnSign: "Sign" },
      }),
    );
    expect(hit.ok).toBe(true);
    expect(bodies.some((b) => b.includes("btnSign=Sign") && b.includes("entry="))).toBe(true);
  });

  it("confirms SQL injection surfaced in a GraphQL errors array", async () => {
    const gqlSqli = new StubSession((req) =>
      inputOf(req).includes("'")
        ? {
            body: '{"errors":[{"message":"(sqlite3.OperationalError) near \\"x\\": syntax error [SQL: SELECT * FROM pastes WHERE title = ...]"}]}',
          }
        : { body: '{"data":{"pastes":[]}}' },
    );
    const hit = await attempt(
      gqlSqli,
      "SQL Injection",
      opts({
        url: "http://localhost:9/graphql",
        method: "POST",
        graphql: { field: "pastes", arg: "filter", selection: " { id }", fixedArgs: "" },
      }),
    );
    expect(hit.ok).toBe(true);
  });
});
