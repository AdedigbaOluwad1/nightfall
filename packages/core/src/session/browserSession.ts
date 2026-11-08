import { type Browser, chromium, type Page } from "playwright";
import { bus } from "../events/bus.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";
import type { Session, SessionRequest, SessionResponse } from "./index.js";

/**
 * Tier 2: real headless browser for JS-driven auth, SPA state, and proving an
 * XSS actually executes (screenshot = report evidence). Same interface as Tier 1.
 * Every navigation is gate-checked first. Isolated so a flaky run degrades gracefully.
 */
export class BrowserSession implements Session {
  readonly tier = 2 as const;
  private browser?: Browser;
  private page?: Page;

  constructor(
    private readonly scope: ScopeFile,
    private readonly gate: ScopeGate,
    private readonly boundary: string,
  ) {}

  private async ensure(): Promise<Page> {
    if (!this.page) {
      this.browser = await chromium.launch();
      this.page = await this.browser.newPage();
      // Enforce the gate at the browser level too: abort any out-of-scope request.
      await this.page.route("**/*", (route) => {
        const d = this.gate.check(route.request().url());
        if (d.allowed) return route.continue();
        bus.emit("scope.blocked", { url: route.request().url(), reason: d.reason });
        return route.abort();
      });
    }
    return this.page;
  }

  async login(): Promise<void> {
    const cred = this.scope.credentials.find((c) => c.boundary === this.boundary);
    if (!cred) return;
    const page = await this.ensure();
    const d = this.gate.check(cred.loginUrl);
    if (!d.allowed) throw new Error(`login URL out of scope: ${d.reason}`);
    await page.goto(cred.loginUrl, { waitUntil: "domcontentloaded" });

    // JS-driven login: fill the first identity + password fields and submit.
    // Heuristic selectors so this generalises past any one lab's markup.
    const pass = page.locator('input[type="password"]').first();
    await pass.waitFor({ state: "visible", timeout: 10_000 });
    const identity = page
      .locator('input[type="email"], input[type="text"], input:not([type])')
      .first();
    await identity.fill(cred.username);
    await pass.fill(cred.password);

    const submit = page
      .locator(
        'button[type="submit"], input[type="submit"], #loginButton, button:has-text("Log in"), button:has-text("Login")',
      )
      .first();
    if (await submit.count()) {
      await submit.click();
    } else {
      await pass.press("Enter");
    }

    // Settle without letting a missing navigation throw.
    await page.waitForLoadState("networkidle", { timeout: 10_000 }).catch(() => undefined);
    bus.emit("session.login", { boundary: this.boundary, tier: 2 });
  }

  async request(req: SessionRequest): Promise<SessionResponse> {
    const page = await this.ensure();
    const res = await page.goto(req.url, { waitUntil: "networkidle" });
    return {
      status: res?.status() ?? 0,
      headers: res ? res.headers() : {},
      body: await page.content(),
    };
  }

  /** Capture the current rendered page — XSS-execution evidence for the report. */
  async screenshot(path: string): Promise<string | undefined> {
    if (!this.page) return undefined;
    await this.page.screenshot({ path, fullPage: true });
    return path;
  }

  async dispose(): Promise<void> {
    await this.browser?.close();
    this.browser = undefined;
    this.page = undefined;
  }
}
