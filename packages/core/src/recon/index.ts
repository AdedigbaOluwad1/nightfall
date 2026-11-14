import * as cheerio from "cheerio";
import { execa } from "execa";
import { bus } from "../events/bus.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";
import type { Session } from "../session/index.js";
import {
  type Fingerprint,
  mergeFingerprints,
  type ProbeResponse,
  parseFingerprints,
} from "./fingerprint.js";

export type { Fingerprint } from "./fingerprint.js";

export interface ReconEndpoint {
  url: string;
  method: "GET" | "POST";
  hasParams: boolean;
  /** Named, injectable form fields (text-like inputs + textareas), if a form. */
  fields?: string[];
}

export interface ReconResult {
  fingerprints: Fingerprint[];
  endpoints: ReconEndpoint[];
}

/** Bounds so a cold run never crawls forever. Deep enough to follow an
 *  authenticated app's menu (e.g. a learn/tutorial hub) to the real surface it
 *  links to, while still terminating. Recon is HTTP-only (no model calls), so a
 *  larger ceiling costs crawl time, not budget. */
const CRAWL_LIMIT = 30;

/** Input types that are NOT a text sink an injection probe would target. */
const NON_INJECTABLE =
  /^(?:submit|button|reset|image|file|checkbox|radio|hidden|password|color|range)$/i;

/** Low-noise discovery paths worth a direct look (all still gate-checked). */
const KNOWN_PATHS = ["/", "/robots.txt", "/login", "/admin", "/sitemap.xml"];

/**
 * A link whose mere GET changes server-side state. Recon is passive and must
 * never fire these: a crawl that logs itself out or toggles a setting corrupts
 * the very session every later probe depends on. (A cold target that enforced
 * SSL per-session via a `?do=toggle-enforce-ssl` link derailed an entire run
 * this way — recon flipped the switch, then every probe hit an unreachable
 * https redirect.) It also keeps recon honest to the read-only contract.
 */
const MUTATING_LINK =
  /\b(?:logout|sign-?out|log-?off)\b|[?&]do=(?:toggle|reset|clear|enable|disable|delete|destroy)|[?&]action=(?:delete|logout|reset)/i;

/**
 * Crawl the in-scope surface through `session` (so a SPA served over the Tier-2
 * browser fingerprints the same way raw HTTP does), fingerprint the stack, and
 * opportunistically enrich with real tools. Every outbound touch is gated: the
 * session gates its own requests, and tool shell-outs are gate-checked here.
 */
export async function recon(
  session: Session,
  gate: ScopeGate,
  scope: ScopeFile,
): Promise<ReconResult> {
  const origin = new URL(scope.target).origin;
  const fingerprints: Fingerprint[] = [];
  const endpoints = new Map<string, ReconEndpoint>();
  const visited = new Set<string>();
  const queue: string[] = [];

  const enqueue = (raw: string) => {
    let url: string;
    try {
      url = new URL(raw, scope.target).toString();
    } catch {
      return;
    }
    if (new URL(url).origin !== origin) return; // stay on-origin; gate is the hard stop
    if (MUTATING_LINK.test(url)) return; // passive recon never fires a state-changing GET
    if (!gate.check(url).allowed) return;
    const key = url.split("#")[0] ?? url;
    if (!visited.has(key) && !queue.includes(key) && queue.length + visited.size < CRAWL_LIMIT) {
      queue.push(key);
    }
  };

  for (const p of KNOWN_PATHS) enqueue(origin + p);
  enqueue(scope.target);

  while (queue.length > 0 && visited.size < CRAWL_LIMIT) {
    const url = queue.shift();
    if (!url || visited.has(url)) continue;
    visited.add(url);

    let res: ProbeResponse;
    try {
      const r = await session.request({ url });
      res = { url, status: r.status, headers: r.headers, body: r.body };
    } catch {
      continue; // gate blocks and transport errors are both "skip this node"
    }

    for (const fp of parseFingerprints(res)) fingerprints.push(fp);
    bus.emit("recon.found", { endpoint: url });

    // Follow links and record forms as attackable endpoints.
    if (/html/i.test(res.headers["content-type"] ?? "") || /<html/i.test(res.body)) {
      const $ = cheerio.load(res.body);
      $("a[href]").each((_, el) => enqueue($(el).attr("href") ?? ""));
      $("script[src]").each((_, el) => enqueue($(el).attr("src") ?? ""));
      // Markdown link targets, e.g. `[User Search](/app/usersearch)`. A docs- or
      // tutorial-style app often renders its real surface from markdown on the
      // client (showdown, marked), so the links exist only as source in the raw
      // HTML — invisible to an <a href> crawl, but a genuine in-scope surface.
      for (const m of res.body.matchAll(/\]\((\/[^)\s"']+)\)/g)) enqueue(m[1] ?? "");
      $("form").each((_, el) => {
        const action = $(el).attr("action") ?? url;
        const method = ($(el).attr("method") ?? "GET").toUpperCase() === "POST" ? "POST" : "GET";
        let abs: string;
        try {
          abs = new URL(action, url).toString();
        } catch {
          return;
        }
        if (!gate.check(abs).allowed) return;
        const fields: string[] = [];
        $(el)
          .find("input,textarea,select")
          .each((_i, input) => {
            const name = $(input).attr("name");
            const type = $(input).attr("type") ?? "text";
            if (name && !NON_INJECTABLE.test(type) && !fields.includes(name)) fields.push(name);
          });
        endpoints.set(`${method} ${abs}`, {
          url: abs,
          method,
          hasParams: true,
          ...(fields.length > 0 ? { fields } : {}),
        });
      });
    }

    const parsed = new URL(url);
    const getKey = `GET ${url}`;
    if (parsed.search && !MUTATING_LINK.test(url) && !endpoints.has(getKey)) {
      endpoints.set(getKey, { url, method: "GET", hasParams: true });
    }
  }

  // Real-tool enrichment — best-effort, never on the critical path.
  for (const fp of await techDetect(origin, gate)) fingerprints.push(fp);

  const merged = mergeFingerprints(fingerprints);
  for (const fp of merged) {
    bus.emit("recon.found", {
      endpoint: scope.target,
      component: fp.component,
      version: fp.version,
    });
  }
  return { fingerprints: merged, endpoints: [...endpoints.values()] };
}

/**
 * Shell out to `httpx` for tech detection when it's installed. Gate-checked and
 * fully optional: a missing binary or any error yields no fingerprints, never a
 * crash. Enable nmap service/version detection with NF_RECON_NMAP=1.
 */
async function techDetect(origin: string, gate: ScopeGate): Promise<Fingerprint[]> {
  if (!gate.check(`${origin}/`).allowed) {
    bus.emit("scope.blocked", { url: `${origin}/`, reason: "tool target out of scope" });
    return [];
  }
  const out: Fingerprint[] = [];

  try {
    const { stdout } = await execa("httpx", ["-silent", "-json", "-tech-detect", "-u", origin], {
      timeout: 20_000,
    });
    for (const line of stdout.split("\n")) {
      if (!line.trim()) continue;
      const tech = (JSON.parse(line) as { tech?: string[] }).tech ?? [];
      for (const t of tech) {
        const [name, version] = t.split(":");
        if (name) out.push({ component: name.trim(), version: version?.trim() ?? "unknown" });
      }
    }
  } catch {
    /* httpx absent or failed — fine */
  }

  if (process.env.NF_RECON_NMAP === "1") {
    try {
      const host = new URL(origin).hostname;
      await execa("nmap", ["-sV", "-Pn", "-T4", host], { timeout: 60_000 });
      // Parsing left intentionally light; presence of the scan is the signal.
    } catch {
      /* nmap absent or failed — fine */
    }
  }

  return out;
}
