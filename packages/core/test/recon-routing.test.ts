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
});
