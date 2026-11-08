import makeFetchCookie from "fetch-cookie";
import { CookieJar } from "tough-cookie";
import { bus } from "../events/bus.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";
import type { Session, SessionRequest, SessionResponse } from "./index.js";

/** Tier 1: cookie-aware fetch. Logs in once per boundary, carries the jar. */
export class HttpSession implements Session {
  readonly tier = 1 as const;
  private readonly jar = new CookieJar();
  private readonly fetch = makeFetchCookie(fetch, this.jar);

  constructor(
    private readonly scope: ScopeFile,
    private readonly gate: ScopeGate,
    private readonly boundary: string,
  ) {}

  async login(): Promise<void> {
    const cred = this.scope.credentials.find((c) => c.boundary === this.boundary);
    if (!cred) return; // unauthenticated session is valid
    const decision = this.gate.check(cred.loginUrl);
    if (!decision.allowed) throw new Error(`login URL out of scope: ${decision.reason}`);
    // TODO(R1): submit credentials (form or JSON), capture CSRF token if present.
    await this.fetch(cred.loginUrl, { method: "POST" });
    bus.emit("session.login", { boundary: this.boundary, tier: 1 });
  }

  async request(req: SessionRequest): Promise<SessionResponse> {
    const decision = this.gate.check(req.url);
    if (!decision.allowed) {
      bus.emit("scope.blocked", { url: req.url, reason: decision.reason });
      throw new Error(`blocked by scope gate: ${decision.reason}`);
    }
    const res = await this.fetch(req.url, {
      method: req.method ?? "GET",
      headers: req.headers,
      body: req.body,
    });
    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      body: await res.text(),
    };
  }

  async dispose(): Promise<void> {}
}
