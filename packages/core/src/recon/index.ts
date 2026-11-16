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

/**
 * How to drive one injectable argument of a GraphQL Query field. The endpoint is
 * the GraphQL URL (POST); a probe builds `{ <field>(<fixedArgs><arg>: "payload")
 * <selection> }`. Only Query-type fields are ever described here — never a
 * Mutation — so a GraphQL probe is read-only by construction.
 */
export interface GraphQLProbe {
  /** The Query field, e.g. `systemDebug`. */
  field: string;
  /** The String argument the payload is injected into, e.g. `arg`. */
  arg: string;
  /** A selection set the field needs to be valid, e.g. ` { id }`, or "" for a scalar. */
  selection: string;
  /** Other required (NON_NULL) args pre-rendered with benign defaults, e.g. `host: "1", `. */
  fixedArgs: string;
}

/**
 * How to drive one string parameter of a SOAP operation. The endpoint is the
 * service address (POST); a probe builds a SOAP envelope calling `<operation>`
 * with the payload at `<param>` and every sibling parameter at a benign default.
 * Only read-like operations (find/get/search/list/…) are ever described here —
 * never a create/update/delete — so a SOAP probe is read-only by construction.
 */
export interface SoapProbe {
  /** The SOAP operation, e.g. `findUsersByName`. */
  operation: string;
  /** The string parameter the payload is injected into, e.g. `username`. */
  param: string;
  /** The service target namespace, for the envelope's operation element. */
  namespace: string;
  /** The SOAPAction header the binding declares for the operation (may be ""). */
  soapAction: string;
  /** Other string parameters pre-filled with a benign default, to keep the call valid. */
  fixedParams: { name: string; value: string }[];
}

export interface ReconEndpoint {
  url: string;
  method: "GET" | "POST";
  hasParams: boolean;
  /** Named, injectable form fields (text-like inputs + textareas), if a form. */
  fields?: string[];
  /** Every named control with its default value, to resubmit the complete form. */
  formData?: Record<string, string>;
  /** A GraphQL Query-field argument to inject into, when this is a GraphQL endpoint. */
  graphql?: GraphQLProbe;
  /** A SOAP operation parameter to inject into, when this is a SOAP/WSDL endpoint. */
  soap?: SoapProbe;
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

    if (/html/i.test(res.headers["content-type"] ?? "") || /<html/i.test(res.body)) {
      const $ = cheerio.load(res.body);
      $("a[href]").each((_, el) => enqueue($(el).attr("href") ?? ""));
      $("script[src]").each((_, el) => enqueue($(el).attr("src") ?? ""));
      // Markdown link targets, e.g. `[User Search](/app/usersearch)`. A docs- or
      // tutorial-style app often renders its real surface from markdown on the
      // client (showdown, marked), so the links exist only as source in the raw
      // HTML — invisible to an <a href> crawl, but a genuine in-scope surface.
      for (const m of res.body.matchAll(/\]\((\/[^)\s"']+)\)/g)) enqueue(m[1] ?? "");
      // Raw form regions in document order — a fallback for forms the HTML5 parser
      // renders empty. Legacy apps often wrap a form's inputs in `<tr>`/`<td>` with
      // no enclosing `<table>` (WackoPicko's login does); HTML5 foster-parenting then
      // hoists those inputs OUT of the form element, so `$(form).find("input")`
      // returns nothing and the form's entire POST injection surface goes invisible.
      const rawForms = [
        ...res.body.matchAll(/<form\b[^>]*>([\s\S]*?)(?=<\/form\b|<form\b|$)/gi),
      ].map((m) => m[1] ?? "");
      $("form").each((formIdx, el) => {
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
        // Capture every named control with its default value, so a probe can
        // resubmit the COMPLETE form with only the target field changed. Many apps
        // gate processing on a submit button or a sibling field being present (DVWA's
        // SQLi runs only when `Submit` is set), so injecting one field in isolation
        // silently does nothing. `fields` stays the injectable text sinks only.
        const formData: Record<string, string> = {};
        const addControl = (
          name: string | undefined,
          type: string,
          value: string,
          checked: boolean,
        ) => {
          if (!name) return;
          const t = type.toLowerCase();
          if (t === "checkbox" || t === "radio") {
            if (checked) formData[name] = value || "on";
          } else {
            formData[name] = value;
          }
          if (!NON_INJECTABLE.test(t) && !fields.includes(name)) fields.push(name);
        };
        $(el)
          .find("input,textarea,select")
          .each((_i, input) => {
            addControl(
              $(input).attr("name"),
              $(input).attr("type") ?? "text",
              $(input).attr("value") ?? "",
              $(input).attr("checked") !== undefined,
            );
          });
        // Nothing found via the parse tree → recover controls from the raw form
        // region (same document order), so a malformed form still yields its fields.
        if (fields.length === 0 && Object.keys(formData).length === 0) {
          const raw = rawForms[formIdx] ?? "";
          for (const im of raw.matchAll(/<(?:input|textarea|select)\b[^>]*>/gi)) {
            const tag = im[0];
            addControl(
              tag.match(/\bname\s*=\s*["']?([^"'\s>]+)/i)?.[1],
              tag.match(/\btype\s*=\s*["']?([^"'\s>]+)/i)?.[1] ?? "text",
              tag.match(/\bvalue\s*=\s*["']([^"']*)["']/i)?.[1] ?? "",
              /\bchecked\b/i.test(tag),
            );
          }
        }
        endpoints.set(`${method} ${abs}`, {
          url: abs,
          method,
          hasParams: true,
          ...(fields.length > 0 ? { fields } : {}),
          ...(Object.keys(formData).length > 0 ? { formData } : {}),
        });
      });
    }

    const parsed = new URL(url);
    const getKey = `GET ${url}`;
    if (parsed.search && !MUTATING_LINK.test(url) && !endpoints.has(getKey)) {
      endpoints.set(getKey, { url, method: "GET", hasParams: true });
    }
  }

  // API surface: a JSON/REST API publishes no crawlable HTML, so the HTML crawl
  // above finds nothing — its real endpoints live in a machine-readable contract.
  // If the app serves an OpenAPI/Swagger spec, read it to enumerate those routes
  // and the injectable inputs (path and query parameters) the crawl never saw.
  for (const ep of await openApiEndpoints(session, gate, origin)) {
    const key = `${ep.method} ${ep.url}`;
    if (!endpoints.has(key)) endpoints.set(key, ep);
    bus.emit("recon.found", { endpoint: ep.url });
  }

  // GraphQL surface: a single POST endpoint whose schema is read by introspection,
  // not OpenAPI. If one answers, enumerate its Query fields' string arguments as
  // injectable inputs — Query only, never Mutation, so this stays read-only.
  for (const ep of await graphqlEndpoints(session, gate, scope, origin)) {
    const key = `${ep.method} ${ep.url} ${ep.graphql?.field}.${ep.graphql?.arg}`;
    if (!endpoints.has(key)) endpoints.set(key, ep);
    bus.emit("recon.found", { endpoint: `${ep.url} (graphql: ${ep.graphql?.field})` });
  }

  // SOAP surface: a WSDL-first service publishes no crawlable HTML and no JSON
  // contract — its operations and their parameters live in a WSDL document. If one
  // is served, enumerate the read-like operations' string parameters as injectable
  // inputs (never a create/update/delete operation, so this stays read-only).
  for (const ep of await soapEndpoints(session, gate, scope, origin)) {
    const key = `${ep.method} ${ep.url} ${ep.soap?.operation}.${ep.soap?.param}`;
    if (!endpoints.has(key)) endpoints.set(key, ep);
    bus.emit("recon.found", { endpoint: `${ep.url} (soap: ${ep.soap?.operation})` });
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

/** Conventional locations an app serves its OpenAPI/Swagger contract from. */
const SPEC_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/v3/api-docs",
  "/v2/api-docs",
  "/api-docs",
  "/swagger/v1/swagger.json",
  "/api/openapi.json",
];

/** Cap on endpoints ingested from one spec, so a huge contract can't unbound the queue. */
const SPEC_ENDPOINT_LIMIT = 40;

/**
 * Discover a REST API's endpoints from its OpenAPI/Swagger contract. A JSON API
 * publishes no crawlable HTML, so the contract is the only place its surface is
 * visible over plain HTTP. Read-only: only GET operations are emitted (a GET
 * carries read semantics; state-changing bodies are left to a later reviewed
 * increment), each with its injectable path and query parameters. Every spec
 * location and resolved URL is gate-checked. A missing or malformed spec yields
 * nothing, never a throw.
 */
async function openApiEndpoints(
  session: Session,
  gate: ScopeGate,
  origin: string,
): Promise<ReconEndpoint[]> {
  for (const p of SPEC_PATHS) {
    const url = origin + p;
    if (!gate.check(url).allowed) continue;
    let body: string;
    let status: number;
    try {
      const r = await session.request({ url });
      status = r.status;
      body = r.body;
    } catch {
      continue;
    }
    if (status >= 400 || !body.trimStart().startsWith("{")) continue;
    let spec: unknown;
    try {
      spec = JSON.parse(body);
    } catch {
      continue;
    }
    const endpoints = specToEndpoints(spec, origin, gate);
    if (endpoints.length > 0) return endpoints;
  }
  return [];
}

/** The URL prefix a spec mounts its paths under (OpenAPI 3 `servers`, Swagger 2 `basePath`). */
function specBasePath(spec: Record<string, unknown>): string {
  const servers = spec.servers;
  if (Array.isArray(servers) && servers[0] && typeof servers[0] === "object") {
    const u = (servers[0] as { url?: unknown }).url;
    if (typeof u === "string" && u) {
      try {
        const path = u.startsWith("http") ? new URL(u).pathname : u;
        return path === "/" ? "" : path.replace(/\/$/, "");
      } catch {
        return "";
      }
    }
  }
  if (typeof spec.basePath === "string") {
    return spec.basePath === "/" ? "" : spec.basePath.replace(/\/$/, "");
  }
  return "";
}

/** Turn a parsed OpenAPI/Swagger document into gated, GET-only injectable endpoints. */
function specToEndpoints(spec: unknown, origin: string, gate: ScopeGate): ReconEndpoint[] {
  if (!spec || typeof spec !== "object") return [];
  const s = spec as Record<string, unknown>;
  if (!s.paths || typeof s.paths !== "object") return [];
  const base = specBasePath(s);
  const out: ReconEndpoint[] = [];
  for (const [rawPath, item] of Object.entries(s.paths as Record<string, unknown>)) {
    if (out.length >= SPEC_ENDPOINT_LIMIT) break;
    if (!item || typeof item !== "object") continue;
    const pathItem = item as Record<string, unknown>;
    const op = pathItem.get; // read-only: GET operations only
    if (!op || typeof op !== "object") continue;
    const sharedParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
    const opParams = Array.isArray((op as Record<string, unknown>).parameters)
      ? ((op as Record<string, unknown>).parameters as unknown[])
      : [];
    const fields: string[] = [];
    for (const prm of [...sharedParams, ...opParams]) {
      if (!prm || typeof prm !== "object") continue;
      const name = (prm as { name?: unknown }).name;
      const loc = (prm as { in?: unknown }).in;
      if (
        typeof name === "string" &&
        (loc === "path" || loc === "query") &&
        !fields.includes(name)
      ) {
        fields.push(name);
      }
    }
    // An undeclared path template ({id}) is still an injectable input.
    for (const m of rawPath.matchAll(/\{([^}]+)\}/g)) {
      const n = m[1];
      if (n && !fields.includes(n)) fields.push(n);
    }
    if (fields.length === 0) continue;
    const url = origin + base + rawPath;
    if (!gate.check(url.replace(/\{[^}]+\}/g, "1")).allowed) continue;
    out.push({ url, method: "GET", hasParams: true, fields });
  }
  return out;
}

/** Conventional locations a GraphQL endpoint answers on. */
const GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"];

/** Cap on GraphQL (field, arg) probes ingested from one schema. */
const GQL_PROBE_LIMIT = 25;

/** The introspection query: every type with its fields, their args, and return types. */
const INTROSPECTION_QUERY =
  "{ __schema { queryType { name } types { kind name fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }";

interface GqlTypeRef {
  kind?: string;
  name?: string | null;
  ofType?: GqlTypeRef | null;
}
interface GqlArg {
  name?: string;
  type?: GqlTypeRef;
}
interface GqlField {
  name?: string;
  args?: GqlArg[];
  type?: GqlTypeRef;
}
interface GqlType {
  kind?: string;
  name?: string;
  fields?: GqlField[] | null;
}

/** Unwrap NON_NULL/LIST wrappers to the underlying named type. */
function unwrapType(t: GqlTypeRef | undefined): GqlTypeRef | undefined {
  let cur = t;
  for (let i = 0; i < 8 && cur?.ofType; i++) cur = cur.ofType ?? undefined;
  return cur;
}

/** A benign GraphQL literal to satisfy a required non-target argument, by scalar type. */
function benignArg(name: string | undefined): string | undefined {
  switch (name) {
    case "Int":
    case "Float":
      return "1";
    case "Boolean":
      return "true";
    case "String":
    case "ID":
      return '"1"';
    default:
      return undefined;
  }
}

/** A selection set the field's return type needs to be a valid query, e.g. ` { id }`. */
function selectionFor(ret: GqlTypeRef | undefined, byName: Map<string, GqlType>): string {
  const named = unwrapType(ret);
  if (!named?.name) return "";
  const t = byName.get(named.name);
  // A scalar or enum needs no selection; a composite (object/interface/union) does.
  if (!t || (t.kind !== "OBJECT" && t.kind !== "INTERFACE" && t.kind !== "UNION")) return "";
  for (const f of t.fields ?? []) {
    const fk = unwrapType(f.type)?.kind;
    if ((fk === "SCALAR" || fk === "ENUM") && f.name) return ` { ${f.name} }`;
  }
  // No scalar subfield (or a union, which has none): __typename is valid on any composite.
  return " { __typename }";
}

/** Turn an introspected schema into GraphQL (field, string-arg) injection endpoints. */
function schemaToProbes(schema: unknown, url: string): ReconEndpoint[] {
  if (!schema || typeof schema !== "object") return [];
  const s = schema as { queryType?: { name?: string }; types?: GqlType[] };
  const queryName = s.queryType?.name;
  const types = Array.isArray(s.types) ? s.types : [];
  const byName = new Map<string, GqlType>();
  for (const t of types) if (t.name) byName.set(t.name, t);
  const queryType = queryName ? byName.get(queryName) : undefined;
  if (!queryType?.fields) return [];
  const out: ReconEndpoint[] = [];
  for (const field of queryType.fields) {
    if (out.length >= GQL_PROBE_LIMIT) break;
    const args = field.args ?? [];
    const stringArgs = args.filter((a) => unwrapType(a.type)?.name === "String");
    if (stringArgs.length === 0 || !field.name) continue;
    const selection = selectionFor(field.type, byName);
    for (const target of stringArgs) {
      if (out.length >= GQL_PROBE_LIMIT || !target.name) break;
      let fixedArgs = "";
      for (const other of args) {
        if (other.name === target.name || !other.name) continue;
        if (other.type?.kind !== "NON_NULL") continue; // only required args must be filled
        const lit = benignArg(unwrapType(other.type)?.name ?? undefined);
        if (lit) fixedArgs += `${other.name}: ${lit}, `;
      }
      out.push({
        url,
        method: "POST",
        hasParams: true,
        graphql: { field: field.name, arg: target.name, selection, fixedArgs },
      });
    }
  }
  return out;
}

/**
 * Discover a GraphQL API. Probe the conventional endpoints with a read-only
 * `{__typename}` query (a query, never a mutation — so recon stays read-only); if
 * one answers like GraphQL, introspect it and enumerate the Query fields' string
 * arguments as injectable inputs. Every endpoint is gate-checked. Introspection
 * being disabled, or any error, yields nothing rather than a throw.
 */
async function graphqlEndpoints(
  session: Session,
  gate: ScopeGate,
  scope: ScopeFile,
  origin: string,
): Promise<ReconEndpoint[]> {
  const candidates = new Set<string>([scope.target]);
  for (const p of GRAPHQL_PATHS) candidates.add(origin + p);
  for (const url of candidates) {
    if (!gate.check(url).allowed) continue;
    let probe: string;
    try {
      const r = await session.request({
        url,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: "{__typename}" }),
      });
      probe = r.body;
    } catch {
      continue;
    }
    if (!/"__typename"|"data"\s*:|graphql|must provide query/i.test(probe)) continue;
    let schema: unknown;
    try {
      const r = await session.request({
        url,
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: INTROSPECTION_QUERY }),
      });
      const parsed = JSON.parse(r.body) as { data?: { __schema?: unknown } };
      schema = parsed.data?.__schema;
    } catch {
      continue;
    }
    const endpoints = schemaToProbes(schema, url);
    if (endpoints.length > 0) return endpoints;
  }
  return [];
}

/** Conventional locations a SOAP service publishes its WSDL from. */
const WSDL_PATHS = [
  "/?wsdl",
  "/service?wsdl",
  "/services?wsdl",
  "/soap?wsdl",
  "/ws?wsdl",
  "/api/soap?wsdl",
  "/wsdl",
];

/** Cap on SOAP (operation, param) probes ingested from one WSDL. */
const SOAP_PROBE_LIMIT = 25;

/**
 * Operation names we treat as READ-like and will probe. A WSDL carries no
 * type-level read/write distinction (unlike GraphQL's Query vs. Mutation), so we
 * classify by the operation's leading verb and probe only a read-like one — a
 * default-deny allow-list. An operation whose name also carries a state-changing
 * verb anywhere (`getAndDeleteUser`) is excluded even if it starts read-like.
 */
const SOAP_READ_OP =
  /^(?:get|find|search|list|read|query|lookup|retrieve|fetch|show|view|load|count|check|describe|resolve|select)/i;
const SOAP_WRITE_OP =
  /(?:create|update|delete|destroy|insert|remove|save|\badd\b|\bset\b|modify|edit|drop|upload|register|cancel|reset|disable|enable|execute|transfer|\bpay\b|order|send|submit|login|logout|authenticate|change|write)/i;

/** The string parameters of one operation's request wrapper, in WSDL schema order. */
function soapStringParams(wsdl: string, op: string): string[] {
  const safe = op.replace(/[^A-Za-z0-9_]/g, "");
  if (!safe) return [];
  // document/literal-wrapped services name the request wrapper after the operation:
  // a named complexType, or an element with an inline complexType.
  const byType = new RegExp(
    `<\\w+:complexType[^>]*name="${safe}"[^>]*>([\\s\\S]*?)</\\w+:complexType>`,
  );
  const byElem = new RegExp(`<\\w+:element[^>]*name="${safe}"[^>]*>([\\s\\S]*?)</\\w+:element>`);
  const block = wsdl.match(byType)?.[1] ?? wsdl.match(byElem)?.[1];
  if (!block) return [];
  const params: string[] = [];
  for (const m of block.matchAll(
    /<\w+:element[^>]*name="([A-Za-z0-9_]+)"[^>]*type="[^"]*[Ss]tring"/g,
  )) {
    if (m[1] && !params.includes(m[1])) params.push(m[1]);
  }
  return params;
}

/** Turn a WSDL document into SOAP (operation, string-param) injection endpoints. */
function wsdlToProbes(
  wsdl: string,
  wsdlUrl: string,
  origin: string,
  gate: ScopeGate,
): ReconEndpoint[] {
  const namespace = wsdl.match(/targetNamespace="([^"]+)"/)?.[1];
  if (!namespace) return [];
  // The service address the binding advertises, if it is on our origin and in
  // scope; otherwise the WSDL URL stripped of its query (where a `?wsdl` service
  // answers its SOAP calls). This keeps the POST target reachable and gated.
  let address = wsdlUrl.split("?")[0] ?? wsdlUrl;
  const located = wsdl.match(/<\w*:?address[^>]*location="([^"]+)"/)?.[1];
  if (located) {
    try {
      if (new URL(located).origin === origin) address = located;
    } catch {
      /* keep the WSDL-derived address */
    }
  }
  if (!gate.check(address).allowed) return [];
  // Each operation's SOAPAction, from its binding entry (child soap:operation).
  const actions = new Map<string, string>();
  for (const m of wsdl.matchAll(
    /<\w*:?operation[^>]*name="([A-Za-z0-9_]+)"[^>]*>\s*<\w+:operation[^>]*soapAction="([^"]*)"/g,
  )) {
    if (m[1] && !actions.has(m[1])) actions.set(m[1], m[2] ?? "");
  }
  const operations: string[] = [];
  for (const m of wsdl.matchAll(/<\w*:?operation[^>]*name="([A-Za-z0-9_]+)"/g)) {
    if (m[1] && !operations.includes(m[1])) operations.push(m[1]);
  }
  const out: ReconEndpoint[] = [];
  for (const op of operations) {
    if (out.length >= SOAP_PROBE_LIMIT) break;
    if (!SOAP_READ_OP.test(op) || SOAP_WRITE_OP.test(op)) continue; // read-only: allow-list
    const params = soapStringParams(wsdl, op);
    if (params.length === 0) continue;
    const soapAction = actions.get(op) ?? "";
    for (const target of params) {
      if (out.length >= SOAP_PROBE_LIMIT) break;
      const fixedParams = params.filter((p) => p !== target).map((p) => ({ name: p, value: "1" }));
      out.push({
        url: address,
        method: "POST",
        hasParams: true,
        soap: { operation: op, param: target, namespace, soapAction, fixedParams },
      });
    }
  }
  return out;
}

/**
 * Discover a SOAP service. Probe the conventional WSDL locations; if one returns a
 * WSDL document, parse its read-like operations' string parameters into injectable
 * inputs. Every candidate URL and the resolved service address are gate-checked. A
 * missing or malformed WSDL yields nothing rather than a throw.
 */
async function soapEndpoints(
  session: Session,
  gate: ScopeGate,
  scope: ScopeFile,
  origin: string,
): Promise<ReconEndpoint[]> {
  const candidates = new Set<string>();
  try {
    const t = new URL(scope.target);
    t.search = "wsdl";
    candidates.add(t.toString());
  } catch {
    /* target not a URL — rely on the origin paths below */
  }
  for (const p of WSDL_PATHS) candidates.add(origin + p);
  for (const url of candidates) {
    if (!gate.check(url).allowed) continue;
    let body: string;
    try {
      const r = await session.request({ url });
      if (r.status >= 400) continue;
      body = r.body;
    } catch {
      continue;
    }
    if (!/<(?:\w+:)?definitions[\s>]/i.test(body) || !/wsdl/i.test(body)) continue;
    const endpoints = wsdlToProbes(body, url, origin, gate);
    if (endpoints.length > 0) return endpoints;
  }
  return [];
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
