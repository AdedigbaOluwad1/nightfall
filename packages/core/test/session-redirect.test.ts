import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ScopeGate } from "../src/scope/gate.js";
import { ScopeFile } from "../src/scope/schema.js";
import { HttpSession } from "../src/session/httpSession.js";

let server: Server;
let port: number;

beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === "/inscope-redirect") {
      res.writeHead(302, { location: "/landing" });
      res.end();
      return;
    }
    if (req.url === "/landing") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("landed");
      return;
    }
    if (req.url === "/evil-redirect") {
      res.writeHead(302, { location: `http://127.0.0.1:${port}/pwned` });
      res.end();
      return;
    }
    if (req.url === "/slow") {
      // Never send headers — a stalling/slow-loris target. The client must time
      // out and abort rather than hang. Socket is force-closed in afterAll.
      return;
    }
    res.writeHead(200);
    res.end("ok");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as AddressInfo).port;
});

afterAll(() => {
  (server as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
  server.close();
});

function session(): HttpSession {
  const scope = ScopeFile.parse({
    target: `http://localhost:${port}/`,
    objective: "test",
    allow: { hosts: ["localhost"], paths: ["/"] },
    deny: { paths: [] },
  });
  return new HttpSession(scope, new ScopeGate(scope), "default");
}

describe("HttpSession — redirects are re-gated", () => {
  it("follows an in-scope redirect", async () => {
    const res = await session().request({ url: `http://localhost:${port}/inscope-redirect` });
    expect(res.status).toBe(200);
    expect(res.body).toBe("landed");
  });

  it("fails closed on a redirect that leaves scope (never requests the target)", async () => {
    await expect(
      session().request({ url: `http://localhost:${port}/evil-redirect` }),
    ).rejects.toThrow(/blocked by scope gate/);
  });

  it("times out (aborts) on a stalling target instead of hanging", async () => {
    const prev = process.env.NF_HTTP_TIMEOUT_MS;
    process.env.NF_HTTP_TIMEOUT_MS = "150";
    try {
      await expect(session().request({ url: `http://localhost:${port}/slow` })).rejects.toThrow(
        /timed out/,
      );
    } finally {
      if (prev === undefined) delete process.env.NF_HTTP_TIMEOUT_MS;
      else process.env.NF_HTTP_TIMEOUT_MS = prev;
    }
  });
});
