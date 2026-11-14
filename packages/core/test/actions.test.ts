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
    const admin = new StubSession(() => ({ status: 200, body: "admin application-configuration" }));
    const bac = await attempt(admin, "Broken Access Control", opts({ objectiveHint: ["admin"] }));
    expect(bac.ok).toBe(true);

    const unknown = await attempt(
      admin,
      "server-side template injection",
      opts({ objectiveHint: ["admin"] }),
    );
    expect(unknown.ok).toBe(true); // unrecognized → same baseline probe, no regression

    const noSignal = await attempt(
      admin,
      "Broken Access Control",
      opts({ objectiveHint: ["billing"] }),
    );
    expect(noSignal.ok).toBe(false);
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
