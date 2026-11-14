import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { bus } from "../src/events/bus.js";
import { ScopeGate } from "../src/scope/gate.js";
import { ScopeFile } from "../src/scope/schema.js";
import { HttpSession } from "../src/session/httpSession.js";

let server: Server;
let port: number;
const tokens = new Set<string>();

function loginForm(token: string): string {
  return `<html><body><form action="/login" method="post">
    <input type="hidden" name="user_token" value="${token}" />
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" name="Login" value="Login" />
  </form></body></html>`;
}

beforeAll(async () => {
  server = createServer((req, res) => {
    const cookie = req.headers.cookie ?? "";
    if (req.method === "GET" && req.url === "/login") {
      const token = `tok${tokens.size}`;
      tokens.add(token);
      res.writeHead(200, { "content-type": "text/html", "set-cookie": "sid=s1" });
      res.end(loginForm(token));
      return;
    }
    if (req.method === "POST" && req.url === "/login") {
      let body = "";
      req.on("data", (c) => {
        body += c;
      });
      req.on("end", () => {
        const p = new URLSearchParams(body);
        // DVWA-style: authenticate only when the CSRF token is valid, the submit
        // button is present, and the credentials match.
        const good =
          tokens.has(p.get("user_token") ?? "") &&
          p.get("Login") === "Login" &&
          p.get("username") === "admin" &&
          p.get("password") === "secret";
        if (good) {
          res.writeHead(302, { location: "/home", "set-cookie": "auth=yes" });
          res.end();
        } else {
          res.writeHead(200, { "content-type": "text/html" });
          res.end(loginForm("tok-retry"));
        }
      });
      return;
    }
    if (req.url === "/home") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<html><body>dashboard</body></html>");
      return;
    }
    if (req.url === "/secret") {
      if (/auth=yes/.test(cookie)) {
        res.writeHead(200, { "content-type": "text/html" });
        res.end("<html><body>secret-data</body></html>");
      } else {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(loginForm("tok-gate"));
      }
      return;
    }
    res.writeHead(404);
    res.end("nope");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(() => {
  (server as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
  server.close();
});

afterEach(() => bus.clearListeners());

function session(username: string, password: string): HttpSession {
  const scope = ScopeFile.parse({
    target: `http://127.0.0.1:${port}/`,
    objective: "test",
    allow: { hosts: ["127.0.0.1"], paths: ["/"] },
    deny: { paths: [] },
    credentials: [{ boundary: "", loginUrl: `http://127.0.0.1:${port}/login`, username, password }],
  });
  return new HttpSession(scope, new ScopeGate(scope), "");
}

describe("HttpSession — login (CSRF token + required submit button + verification)", () => {
  it("carries the CSRF token and submit button, and reaches an authenticated page", async () => {
    let event: { ok: boolean } | undefined;
    bus.on("session.login", (e) => {
      event = e;
    });
    const s = session("admin", "secret");
    await s.login();
    expect(event?.ok).toBe(true);
    const res = await s.request({ url: `http://127.0.0.1:${port}/secret` });
    expect(res.body).toContain("secret-data");
  });

  it("detects a failed login (bad credentials) instead of silently claiming success", async () => {
    let event: { ok: boolean } | undefined;
    bus.on("session.login", (e) => {
      event = e;
    });
    const s = session("admin", "wrong");
    await expect(s.login()).rejects.toThrow(/did not authenticate/);
    expect(event?.ok).toBe(false);
    // The session is not authenticated: the protected page returns the login form.
    const res = await s.request({ url: `http://127.0.0.1:${port}/secret` });
    expect(res.body).not.toContain("secret-data");
  });
});
