import * as cheerio from "cheerio";
import makeFetchCookie from "fetch-cookie";
import { CookieJar } from "tough-cookie";
import { bus } from "../events/bus.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";
import type { Session, SessionRequest, SessionResponse } from "./index.js";

/** Field names we treat as the username/identity input, in priority order. */
const USER_FIELDS = ["username", "user", "email", "login", "user_name", "name"];
const PASS_FIELDS = ["password", "pass", "passwd", "pwd"];

const MAX_REDIRECTS = 5;
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/** Tier 1: cookie-aware fetch. Logs in once per boundary, carries the jar. */
export class HttpSession implements Session {
  readonly tier = 1 as const;
  private readonly jar = new CookieJar();
  private readonly fetch = makeFetchCookie(fetch, this.jar);
  private loggedIn = false;

  constructor(
    private readonly scope: ScopeFile,
    private readonly gate: ScopeGate,
    private readonly boundary: string,
  ) {}

  /**
   * Route every outbound call through the gate — fail closed on a block. Redirects
   * are followed manually so each hop is re-checked: an in-scope URL that redirects
   * out of scope must not slip past (fetch's default auto-follow would). Honours the
   * method downgrade browsers apply (303, and POST on 301/302 → GET).
   */
  private async fetchGated(url: string, init?: RequestInit): Promise<Response> {
    let currentUrl = url;
    let currentInit: RequestInit = { ...init, redirect: "manual" };
    // Fail safe against a hostile/slow target (slow-loris, honeypot that stalls):
    // bound connect+headers per hop so an automated run can never hang on a
    // single request. A timeout aborts, surfaces as a transient transport error,
    // and the loop recovers (bounded retry → abandon) rather than stalling.
    const timeoutMs = Number(process.env.NF_HTTP_TIMEOUT_MS ?? "20000");

    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const decision = this.gate.check(currentUrl);
      if (!decision.allowed) {
        bus.emit("scope.blocked", { url: currentUrl, reason: decision.reason });
        throw new Error(`blocked by scope gate: ${decision.reason}`);
      }

      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), timeoutMs);
      let res: Response;
      try {
        res = await this.fetch(currentUrl, { ...currentInit, signal: ac.signal });
      } catch (err) {
        if (ac.signal.aborted) throw new Error(`request timed out after ${timeoutMs}ms`);
        throw err;
      } finally {
        clearTimeout(timer);
      }
      const location = res.headers.get("location");
      if (!REDIRECT_STATUS.has(res.status) || !location) return res;

      currentUrl = new URL(location, currentUrl).toString();
      const method = (currentInit.method ?? "GET").toUpperCase();
      const downgrade =
        res.status === 303 || (res.status < 307 && method !== "GET" && method !== "HEAD");
      if (downgrade) {
        currentInit = { ...currentInit, method: "GET", body: undefined, redirect: "manual" };
      }
    }

    throw new Error(`too many redirects (>${MAX_REDIRECTS})`);
  }

  async login(): Promise<void> {
    if (this.loggedIn) return;
    const cred = this.scope.credentials.find((c) => c.boundary === this.boundary);
    if (!cred) return; // unauthenticated session is valid

    // GET the login page first: establishes the session cookie and lets us read
    // any CSRF token / real field names out of the form. Fail closed on block.
    let formHtml = "";
    try {
      const page = await this.fetchGated(cred.loginUrl);
      formHtml = await page.text();
    } catch (err) {
      // A hard scope block must propagate; a soft network hiccup should not stop
      // us from still attempting a blind form post below.
      if (err instanceof Error && err.message.startsWith("blocked by scope gate")) throw err;
    }

    const form = this.parseLoginForm(formHtml, cred.loginUrl);
    const body = new URLSearchParams();
    // Carry hidden tokens (CSRF, etc.) verbatim — capture, do not invent.
    for (const [k, v] of Object.entries(form.hidden)) body.set(k, v);
    body.set(form.userField, cred.username);
    body.set(form.passField, cred.password);

    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    const xsrf = await this.cookieHeaderToken();
    if (xsrf) headers["x-csrf-token"] = xsrf;

    await this.fetchGated(form.action, { method: "POST", headers, body: body.toString() });
    this.loggedIn = true;
    bus.emit("session.login", { boundary: this.boundary, tier: 1 });
  }

  async request(req: SessionRequest): Promise<SessionResponse> {
    const res = await this.fetchGated(req.url, {
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

  /**
   * Pull real field names + hidden inputs out of the login form. Falls back to
   * common field names when the page gives us nothing (blind form post).
   */
  private parseLoginForm(
    html: string,
    loginUrl: string,
  ): { action: string; userField: string; passField: string; hidden: Record<string, string> } {
    const hidden: Record<string, string> = {};
    let action = loginUrl;
    let userField = USER_FIELDS[0] ?? "username";
    let passField = PASS_FIELDS[0] ?? "password";

    if (html.trim()) {
      const $ = cheerio.load(html);
      // Prefer the form that actually contains a password input.
      const form = $("form")
        .filter((_, el) => $(el).find('input[type="password"]').length > 0)
        .first();
      const scope = form.length ? form : $("form").first();

      const rawAction = scope.attr("action");
      if (rawAction) {
        try {
          action = new URL(rawAction, loginUrl).toString();
        } catch {
          /* keep loginUrl */
        }
      }

      scope.find("input").each((_, el) => {
        const name = $(el).attr("name");
        if (!name) return;
        const type = ($(el).attr("type") ?? "text").toLowerCase();
        if (type === "hidden") hidden[name] = $(el).attr("value") ?? "";
        else if (type === "password") passField = name;
      });

      const named = scope
        .find("input")
        .map((_, el) => $(el).attr("name") ?? "")
        .get();
      const foundUser = named.find((n) => USER_FIELDS.includes(n.toLowerCase()));
      if (foundUser) userField = foundUser;
    }

    return { action, userField, passField, hidden };
  }

  /** Common double-submit pattern: XSRF/CSRF value kept in a cookie. */
  private async cookieHeaderToken(): Promise<string | undefined> {
    try {
      const cookies = await this.jar.getCookies(this.scope.target);
      const hit = cookies.find((c) => /csrf|xsrf/i.test(c.key));
      return hit?.value;
    } catch {
      return undefined;
    }
  }
}
