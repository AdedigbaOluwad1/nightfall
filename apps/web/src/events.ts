export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type HaltReason = "objective" | "budget" | "steps" | "exhausted";

export interface Payloads {
  "run.start": { runId: string; target: string; objective: string };
  "scope.loaded": { hosts: number; paths: number };
  "scope.blocked": { url: string; reason: string };
  "recon.found": { endpoint: string; component?: string; version?: string };
  "tavily.cve": {
    component: string;
    version: string;
    cve: string;
    url: string;
    freshAfterCutoff?: boolean;
  };
  "hypothesis.ranked": { candidates: number; grounded: boolean };
  "hypothesis.failed": { component: string; version: string; reason: string };
  "exploit.attempt": { technique: string; target: string; n: number };
  "exploit.interpret": { decision: string; note: string };
  "gateway.call": {
    step: string;
    model: string;
    costUsd: number;
    cacheHit: boolean;
    priceSource?: string;
  };
  "budget.exceeded": { capUsd: number; spentUsd: number; stage: string };
  "finding.confirmed": { id: string; title: string; severity: Severity };
  "objective.reached": { via: string; steps: number; costUsd: number };
  "run.end": {
    runId: string;
    findings: number;
    blocked: number;
    costUsd: number;
    haltedBy?: HaltReason;
  };
}

export type EventName = keyof Payloads;

export interface WsMessage {
  type: EventName;
  payload: Payloads[EventName];
}

export interface TraceItem {
  seq: number;
  type: EventName;
  payload: Payloads[EventName];
}

export interface Receipts {
  scope: { armed: boolean; hosts: number; paths: number; blocked: number };
  bifrost: {
    calls: number;
    costUsd: number;
    cacheHits: number;
    model?: string;
    priceSource?: string;
  };
  tavily: { cves: number; fresh: number };
  run: {
    runId?: string;
    target?: string;
    objective?: string;
    findings: number;
    steps: number;
    objectiveReached: boolean;
    haltedBy?: HaltReason;
    status: "idle" | "running" | "done";
  };
}

export const emptyReceipts = (): Receipts => ({
  scope: { armed: false, hosts: 0, paths: 0, blocked: 0 },
  bifrost: { calls: 0, costUsd: 0, cacheHits: 0 },
  tavily: { cves: 0, fresh: 0 },
  run: { findings: 0, steps: 0, objectiveReached: false, status: "idle" },
});

export function reduceReceipts(prev: Receipts, item: TraceItem): Receipts {
  const next: Receipts = {
    scope: { ...prev.scope },
    bifrost: { ...prev.bifrost },
    tavily: { ...prev.tavily },
    run: { ...prev.run },
  };
  switch (item.type) {
    case "run.start": {
      const p = item.payload as Payloads["run.start"];
      next.run.runId = p.runId;
      next.run.target = p.target;
      next.run.objective = p.objective;
      next.run.status = "running";
      break;
    }
    case "scope.loaded": {
      const p = item.payload as Payloads["scope.loaded"];
      next.scope.armed = true;
      next.scope.hosts = p.hosts;
      next.scope.paths = p.paths;
      break;
    }
    case "scope.blocked":
      next.scope.blocked += 1;
      break;
    case "tavily.cve": {
      const p = item.payload as Payloads["tavily.cve"];
      next.tavily.cves += 1;
      if (p.freshAfterCutoff) next.tavily.fresh += 1;
      break;
    }
    case "gateway.call": {
      const p = item.payload as Payloads["gateway.call"];
      next.bifrost.calls += 1;
      next.bifrost.costUsd += p.costUsd;
      if (p.cacheHit) next.bifrost.cacheHits += 1;
      next.bifrost.model = p.model;
      next.bifrost.priceSource = p.priceSource;
      break;
    }
    case "exploit.attempt":
      next.run.steps = (item.payload as Payloads["exploit.attempt"]).n;
      break;
    case "finding.confirmed":
      next.run.findings += 1;
      break;
    case "objective.reached":
      next.run.objectiveReached = true;
      break;
    case "run.end": {
      const p = item.payload as Payloads["run.end"];
      next.run.status = "done";
      next.run.haltedBy = p.haltedBy;
      next.run.findings = p.findings;
      break;
    }
    default:
      break;
  }
  return next;
}

export interface TraceLine {
  tag: string;
  tone: string;
  text: string;
}

export function formatTrace(item: TraceItem): TraceLine {
  const p = item.payload as Record<string, unknown>;
  switch (item.type) {
    case "run.start":
      return { tag: "run", tone: "bold", text: `run ${String(p.runId).slice(0, 8)} → ${p.target}` };
    case "scope.loaded":
      return {
        tag: "scope",
        tone: "scope",
        text: `${p.hosts} host(s), ${p.paths} path(s) · deny-by-default armed`,
      };
    case "scope.blocked":
      return { tag: "scope", tone: "block", text: `blocked ${p.url} — ${p.reason}` };
    case "recon.found":
      return {
        tag: "recon",
        tone: "recon",
        text: `${p.endpoint}${p.component ? ` · ${p.component} ${p.version ?? ""}` : ""}`,
      };
    case "tavily.cve":
      return { tag: "tavily", tone: "tavily", text: `${p.component} ${p.version} → ${p.cve}` };
    case "hypothesis.failed":
      return {
        tag: "grounding",
        tone: "warn",
        text: `${p.component} ${p.version} — degraded: ${p.reason}`,
      };
    case "hypothesis.ranked":
      return {
        tag: "hypo",
        tone: "recon",
        text: `${p.candidates} candidate(s) · ${p.grounded ? "grounded" : "ungrounded"}`,
      };
    case "exploit.attempt":
      return { tag: "exploit", tone: "exploit", text: `#${p.n} ${p.technique}` };
    case "exploit.interpret":
      return {
        tag: "decide",
        tone: "dim",
        text: `${String(p.decision).toUpperCase()} · ${p.note}`,
      };
    case "gateway.call":
      return {
        tag: "bifrost",
        tone: "bifrost",
        text: `${p.step} → ${p.model} · $${Number(p.costUsd).toFixed(4)} · ${p.cacheHit ? "cache HIT" : "miss"}`,
      };
    case "budget.exceeded":
      return {
        tag: "budget",
        tone: "block",
        text: `cap $${Number(p.capUsd).toFixed(2)} reached (spent $${Number(p.spentUsd).toFixed(4)}) · halting ${p.stage}`,
      };
    case "finding.confirmed":
      return { tag: "finding", tone: "finding", text: `${p.title} · ${p.severity}` };
    case "objective.reached":
      return { tag: "objective", tone: "ok", text: `reached via ${p.via} · ${p.steps} steps` };
    case "run.end":
      return {
        tag: "done",
        tone: "bold",
        text: `${p.findings} finding(s) · ${p.blocked} blocked · $${Number(p.costUsd).toFixed(2)}${p.haltedBy ? ` · halted: ${p.haltedBy}` : ""}`,
      };
    default:
      return { tag: item.type, tone: "dim", text: JSON.stringify(p) };
  }
}
