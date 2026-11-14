import type { ScopeFile } from "./schema.js";

export interface GateDecision {
  allowed: boolean;
  reason: string;
}

/**
 * Prefix match on path-segment boundaries, NOT raw string prefix. `/app` covers
 * `/app` and `/app/...` but never `/apple` or `/app-secret` — a bare
 * `startsWith` would leak those into scope. Root (`/`) covers everything.
 */
function matchesPrefix(path: string, prefix: string): boolean {
  if (prefix === "" || prefix === "/") return true;
  const base = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return path === base || path.startsWith(`${base}/`);
}

/**
 * Deny-by-default request gate. THE most important file in the repo.
 * - No LLM/model call may ever be added here.
 * - A request is allowed only if its host is in allow.hosts AND its path
 *   matches an allow prefix AND matches no deny prefix.
 * Out-of-scope access is an automatic challenge failure, so this errs closed.
 */
export class ScopeGate {
  constructor(private readonly scope: ScopeFile) {}

  check(rawUrl: string): GateDecision {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch {
      return { allowed: false, reason: "unparseable URL" };
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return { allowed: false, reason: `scheme ${url.protocol} not allowed (http/https only)` };
    }

    const host = url.hostname;
    if (!this.scope.allow.hosts.includes(host)) {
      return { allowed: false, reason: `host ${host} not in allow.hosts` };
    }

    const path = url.pathname;
    for (const denied of this.scope.deny.paths) {
      if (matchesPrefix(path, denied)) {
        return { allowed: false, reason: `path ${path} matches deny ${denied}` };
      }
    }

    const allowed = this.scope.allow.paths.some((p) => matchesPrefix(path, p));
    if (!allowed) {
      return { allowed: false, reason: `path ${path} matches no allow prefix` };
    }

    return { allowed: true, reason: "in scope" };
  }
}
