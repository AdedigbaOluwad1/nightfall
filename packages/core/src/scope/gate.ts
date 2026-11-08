import type { ScopeFile } from "./schema.js";

export interface GateDecision {
  allowed: boolean;
  reason: string;
}

/**
 * Deny-by-default request gate. THE most important file in the repo.
 * - No LLM/model call may ever be added here.
 * - A request is allowed only if its host is in allow.hosts AND its path
 *   matches an allow prefix AND matches no deny prefix.
 * - Encoded path separators are refused outright (see below), because they can
 *   hide traversal from WHATWG normalization and escape the allow prefix.
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

    const host = url.hostname;
    if (!this.scope.allow.hosts.includes(host)) {
      return { allowed: false, reason: `host ${host} not in allow.hosts` };
    }

    const path = url.pathname;

    // Encoded separators defeat WHATWG dot-segment normalization: a server that
    // percent-decodes the path could escape the allow prefix (e.g.
    // `/app/..%2fadmin` -> `/app/../admin` -> `/admin`). Deny-by-default means
    // we refuse any path carrying an encoded `.`, `/`, `\`, or `%` (the
    // double-encoding vector) rather than trying to decode it cleverly.
    if (/%(?:2e|2f|5c|25)/i.test(path)) {
      return { allowed: false, reason: `path ${path} contains an encoded separator` };
    }

    for (const denied of this.scope.deny.paths) {
      if (path.startsWith(denied)) {
        return { allowed: false, reason: `path ${path} matches deny ${denied}` };
      }
    }

    const allowed = this.scope.allow.paths.some((p) => path.startsWith(p));
    if (!allowed) {
      return { allowed: false, reason: `path ${path} matches no allow prefix` };
    }

    return { allowed: true, reason: "in scope" };
  }
}
