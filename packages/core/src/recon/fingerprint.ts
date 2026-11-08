export interface Fingerprint {
  component: string;
  version: string;
}

export interface ProbeResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

const UNKNOWN = "unknown";
const VERSION_RE = /v?(\d+\.\d+(?:\.\d+)?)/;

function header(headers: Record<string, string>, name: string): string | undefined {
  const want = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === want) return v;
  }
  return undefined;
}

/** Split a `Name/1.2.3 (extra)` banner into component + version. */
function parseBanner(raw: string): Fingerprint | undefined {
  const token = raw.split(/[\s(]/)[0] ?? "";
  const [name, version] = token.split("/");
  if (!name) return undefined;
  return { component: name, version: version && VERSION_RE.test(version) ? version : UNKNOWN };
}

/** Session cookie names are a reliable tell for the server-side stack. */
const COOKIE_STACK: Array<[RegExp, string]> = [
  [/PHPSESSID/i, "PHP"],
  [/JSESSIONID/i, "Java Servlet"],
  [/connect\.sid/i, "Express"],
  [/laravel_session/i, "Laravel"],
  [/csrftoken|sessionid/i, "Django"],
  [/ASP\.NET_SessionId/i, "ASP.NET"],
  [/rack\.session/i, "Rack"],
];

/** Distinctive strings in the rendered body — labs and common frameworks. */
const BODY_SIGNATURES: Array<[RegExp, string]> = [
  [/Damn Vulnerable Web Application|DVWA/i, "DVWA"],
  [/OWASP Juice Shop|juice-shop/i, "OWASP Juice Shop"],
  [/WebGoat/i, "WebGoat"],
  [/WordPress/i, "WordPress"],
  [/Drupal/i, "Drupal"],
  [/Joomla/i, "Joomla"],
];

/** Pull every fingerprint we can justify out of a single response. */
export function parseFingerprints(res: ProbeResponse): Fingerprint[] {
  const out: Fingerprint[] = [];
  const push = (component: string, version = UNKNOWN) => {
    if (!component) return;
    const existing = out.find((f) => f.component === component);
    if (!existing) out.push({ component, version });
    else if (existing.version === UNKNOWN && version !== UNKNOWN) existing.version = version;
  };

  for (const h of ["server", "x-powered-by", "x-aspnet-version", "x-generator"]) {
    const v = header(res.headers, h);
    if (!v) continue;
    const fp = parseBanner(v);
    if (fp) push(fp.component, fp.version);
  }

  const setCookie = header(res.headers, "set-cookie") ?? "";
  for (const [re, stack] of COOKIE_STACK) {
    if (re.test(setCookie)) push(stack);
  }

  // <meta name="generator" content="WordPress 6.1">
  const gen = res.body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)?.[1];
  if (gen) {
    const version = gen.match(VERSION_RE)?.[1] ?? UNKNOWN;
    const name = gen.replace(VERSION_RE, "").trim();
    if (name) push(name, version);
  }

  for (const [re, name] of BODY_SIGNATURES) {
    if (re.test(res.body)) push(name);
  }

  return out;
}

/** Merge fingerprints from many responses, de-duped, preferring known versions. */
export function mergeFingerprints(all: Fingerprint[]): Fingerprint[] {
  const byComponent = new Map<string, Fingerprint>();
  for (const fp of all) {
    const prev = byComponent.get(fp.component);
    if (!prev || (prev.version === UNKNOWN && fp.version !== UNKNOWN)) {
      byComponent.set(fp.component, { ...fp });
    }
  }
  return [...byComponent.values()];
}
