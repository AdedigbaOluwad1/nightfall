import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { bus } from "../events/bus.js";
import type { Finding } from "../evidence/models.js";
import { EvidenceStore } from "../evidence/store.js";
import type { Gateway } from "../gateway/bifrostClient.js";
import { BudgetExceededError } from "../gateway/budget.js";
import { type Candidate, groundedLookup } from "../hypothesis/tavilyClient.js";
import type { Fingerprint } from "../recon/fingerprint.js";
import { type ReconResult, recon } from "../recon/index.js";
import type { ScopeGate } from "../scope/gate.js";
import type { ScopeFile } from "../scope/schema.js";
import { BrowserSession } from "../session/browserSession.js";
import { HttpSession } from "../session/httpSession.js";
import type { Session } from "../session/index.js";
import {
  type AttemptOpts,
  type AttemptResult,
  attempt,
  findingProfile,
  T_AUTH_BYPASS,
  T_SQLI_DISCLOSURE,
} from "./actions.js";
import { type AttackContext, newContext } from "./context.js";
import { interpret } from "./interpret.js";
import { makeGatewayPlanner, type Planner } from "./planner.js";
import { initialState, type RunState } from "./state.js";

interface WorkItem {
  technique: string;
  url: string;
  tier: 1 | 2;
  retries: number;
  cve?: string;
  /** Finding id of the step that seeded this one — the attack-graph edge. */
  parentId?: string;
  /** 1-based position in the chain. */
  step: number;
}

/** Everything the loop needs, injectable so the north-star is testable offline. */
export interface LoopDeps {
  session: Session;
  recon: (session: Session) => Promise<ReconResult>;
  hypothesize: (fp: Fingerprint) => Promise<Candidate[]>;
  attempt: (session: Session, technique: string, opts: AttemptOpts) => Promise<AttemptResult>;
  /** Build a higher-capability (Tier-2) session on demand; undefined = none. */
  escalate?: () => Promise<Session | undefined>;
  /** Model-driven next-action selector; undefined = pure deterministic order. */
  plan?: Planner;
  record: (finding: Finding) => void;
  budgetUsd: number;
  maxRetries: number;
}

const STOP = new Set([
  "the",
  "and",
  "for",
  "reach",
  "access",
  "get",
  "gain",
  "via",
  "with",
  "into",
  "from",
  "that",
  "this",
  "page",
]);

function objectiveTokens(objective: string): string[] {
  return objective
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 2 && !STOP.has(t));
}

function toFinding(item: WorkItem, result: AttemptResult, scopeId: string): Finding {
  const profile = findingProfile(item.technique, item.cve);
  const cveTag = item.cve ? ` (${item.cve})` : "";
  const produced = result.discovered?.map((a) => a.label);
  return {
    id: crypto.randomUUID(),
    title: `${profile.name} at ${item.url}${cveTag}`,
    foundAt: new Date().toISOString(),
    scopeId,
    technique: item.technique,
    severity: profile.severity,
    cvss: profile.cvss,
    cvssScore: profile.cvssScore,
    evidence: result.evidence
      ? [{ ...result.evidence, note: result.evidence.note ?? result.note }]
      : [{ request: `GET ${item.url}`, response: "", note: result.note }],
    remediation: profile.remediation,
    step: item.step,
    parentId: item.parentId,
    consumed: result.consumed,
    produced: produced && produced.length > 0 ? produced : undefined,
  };
}

/**
 * The decide/recover loop: recon -> hypothesis -> attempt -> interpret ->
 * evidence, repeating until the objective is reached OR the step/budget cap
 * is hit. Recovery (retry | escalate | abandon | pivot) is deterministic, so
 * a cold target behaves like the rehearsed one.
 */
/**
 * Content hash of the authorizing scope, short form. Stamped on every finding so
 * the audit trail proves which authorization governed which result — the scope
 * can't be edited after the fact without the hash no longer matching.
 */
export function scopeId(scope: ScopeFile): string {
  return createHash("sha256").update(JSON.stringify(scope)).digest("hex").slice(0, 12);
}

async function drive(scope: ScopeFile, state: RunState, deps: LoopDeps): Promise<void> {
  const sid = scopeId(scope);
  const primary = deps.session;
  await primary.login().catch(() => undefined); // an unauthenticated session is still valid

  let budgetAnnounced = false;
  const announceBudget = (stage: "hypothesis" | "attempt"): void => {
    if (budgetAnnounced) return;
    budgetAnnounced = true;
    state.haltedBy = "budget";
    bus.emit("budget.exceeded", {
      capUsd: deps.budgetUsd,
      spentUsd: state.costUsd,
      stage,
    });
  };
  const overBudget = (stage: "hypothesis" | "attempt"): boolean => {
    if (state.costUsd < deps.budgetUsd) return false;
    announceBudget(stage);
    return true;
  };

  let reconResult: ReconResult;
  try {
    reconResult = await deps.recon(primary);
  } catch {
    reconResult = { fingerprints: [], endpoints: [] };
  }

  const hint = objectiveTokens(scope.objective);
  const probeUrl = reconResult.endpoints[0]?.url ?? scope.target;
  const context: AttackContext = newContext(scope.objective, hint);
  const queue: WorkItem[] = [];
  // Fingerprints already grounded, so a banner is re-grounded at most once.
  const grounded = new Set<string>();

  // Grounded hypotheses per fingerprint — best-effort; a budget stop here just
  // means we proceed with the generic access probes below.
  for (const fp of reconResult.fingerprints) {
    grounded.add(`${fp.component}@${fp.version}`);
    if (overBudget("hypothesis")) break;
    let candidates: Candidate[] = [];
    try {
      candidates = await deps.hypothesize(fp);
    } catch (err) {
      if (err instanceof BudgetExceededError) {
        announceBudget("hypothesis");
        break;
      }
      const reason = err instanceof Error ? err.message : String(err);
      bus.emit("hypothesis.failed", { component: fp.component, version: fp.version, reason });
    }
    for (const c of candidates) {
      queue.push({
        technique: c.technique,
        url: probeUrl,
        tier: 1,
        retries: 0,
        cve: c.cve,
        step: 1,
      });
    }
  }

  // Deterministic chain seed: an authentication-bypass attempt that runs even
  // when grounding is unavailable, so the flagship chain never depends on the
  // model proposing it. A confirmation here seeds the authenticated follow-up.
  queue.push({ technique: T_AUTH_BYPASS, url: scope.target, tier: 1, retries: 0, step: 1 });

  // Always probe the discovered surface + the target itself for broken access.
  for (const ep of reconResult.endpoints) {
    queue.push({ technique: "access-probe", url: ep.url, tier: 1, retries: 0, step: 1 });
  }
  queue.push({ technique: "access-probe", url: scope.target, tier: 1, retries: 0, step: 1 });

  // Active fingerprinting runs FIRST (unshifted to the front, exempt from the
  // planner): a quote probe trips an error page that discloses the framework
  // and version, which the loop re-grounds live — so the surface is expanded
  // before exploitation, not only at passive recon.
  queue.unshift({ technique: T_SQLI_DISCLOSURE, url: scope.target, tier: 1, retries: 0, step: 1 });

  let tier2: Session | undefined;
  let escalated = false;
  const confirmed: { title: string; severity: string }[] = [];

  try {
    while (queue.length > 0 && !state.objectiveReached) {
      if (state.steps >= state.maxSteps) {
        if (!state.haltedBy) state.haltedBy = "steps";
        break;
      }
      if (overBudget("attempt")) break;

      // Plan: let the model choose the next action from the pending queue,
      // reasoning over the world-model. Front-of-queue is the deterministic
      // floor — a failed, invalid, or budget-stopped plan never stalls the run.
      // The first step is exempt: it is a deterministic active-fingerprint probe
      // (front of queue) that forces the stack to disclose its framework so the
      // surface is re-grounded before planner-driven exploitation begins.
      if (deps.plan && queue.length > 1 && state.steps > 0) {
        let decision: Awaited<ReturnType<NonNullable<LoopDeps["plan"]>>> | undefined;
        try {
          decision = await deps.plan({
            objective: scope.objective,
            artifacts: context.artifacts.map((a) => ({ kind: a.kind, label: a.label })),
            findings: confirmed,
            pending: queue.map((q) => ({ technique: q.technique, url: q.url })),
          });
        } catch (err) {
          if (err instanceof BudgetExceededError) {
            announceBudget("attempt");
            break;
          }
          decision = undefined;
        }
        if (decision && decision.pick > 0 && decision.pick < queue.length) {
          const [chosen] = queue.splice(decision.pick, 1);
          if (chosen) queue.unshift(chosen);
        }
        bus.emit("plan.decision", {
          chose: queue[0]?.technique ?? "(none)",
          reason: decision?.reason ?? "next queued action",
          fallback: !decision,
        });
      }

      const item = queue.shift();
      if (!item) break;
      state.steps++;
      // Mark this (technique, url) attempted — used to stop a later step from
      // re-seeding one already run (the chain's cycle guard). Retries re-queue
      // the same item directly and are bounded by maxRetries, so they are
      // unaffected by this.
      context.visited.add(`${item.technique}|${item.url}`);

      const session = item.tier === 2 && tier2 ? tier2 : primary;
      bus.emit("exploit.attempt", { technique: item.technique, target: item.url, n: state.steps });

      let result: AttemptResult;
      try {
        result = await deps.attempt(session, item.technique, {
          useSession: true,
          url: item.url,
          objectiveHint: hint,
          context,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        result = { ok: false, note: msg, transient: !msg.startsWith("blocked"), applicable: true };
      }

      if (result.ok) {
        const finding = toFinding(item, result, sid);
        deps.record(finding);
        state.findings++;
        bus.emit("finding.confirmed", {
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
        });
        confirmed.push({ title: finding.title, severity: finding.severity });

        // Publish discovered artifacts to the world-model so later steps use them.
        if (result.discovered) {
          context.artifacts.push(...result.discovered);
          // Mid-chain re-grounding: when a step forces the stack to leak a
          // fresh component/version (an injection error page naming the
          // framework), ground that newly-exposed surface against live
          // advisories. Tavily keeps opening steps as the attack expands, not
          // only at recon. Budget-guarded; each banner is grounded once. The
          // new candidates queue behind the in-flight chain so the objective is
          // never delayed — the live re-query itself is the expansion.
          for (const art of result.discovered) {
            if (art.kind !== "fingerprint" || grounded.has(art.value)) continue;
            grounded.add(art.value);
            if (overBudget("hypothesis")) break;
            const [component = "unknown", version = "unknown"] = art.value.split("@");
            let more: Candidate[] = [];
            try {
              more = await deps.hypothesize({ component, version });
            } catch (err) {
              if (err instanceof BudgetExceededError) {
                announceBudget("hypothesis");
                break;
              }
              bus.emit("hypothesis.failed", {
                component,
                version,
                reason: err instanceof Error ? err.message : String(err),
              });
              continue;
            }
            for (const c of more) {
              if (context.visited.has(`${c.technique}|${probeUrl}`)) continue;
              queue.push({
                technique: c.technique,
                url: probeUrl,
                tier: item.tier,
                retries: 0,
                cve: c.cve,
                parentId: finding.id,
                step: item.step + 1,
              });
            }
            if (more.length > 0) {
              bus.emit("chain.step", {
                step: item.step,
                via: item.technique,
                produced: `re-grounded ${component} ${version} → ${more.length} candidate(s)`,
                note: "mid-chain Tavily re-grounding — attack surface expanded",
              });
            }
          }
        }

        // Seed follow-ups at the FRONT so the chain is pursued depth-first,
        // before the loop drains unrelated probes. Skip a seed already
        // attempted (cycle guard).
        const seeds = (result.next ?? []).filter(
          (s) => !context.visited.has(`${s.technique}|${s.url ?? item.url}`),
        );
        if (seeds.length > 0) {
          for (const seed of [...seeds].reverse()) {
            queue.unshift({
              technique: seed.technique,
              url: seed.url ?? item.url,
              tier: item.tier,
              retries: 0,
              cve: seed.cve,
              parentId: finding.id,
              step: item.step + 1,
            });
          }
          bus.emit("chain.step", {
            step: item.step,
            via: item.technique,
            produced: finding.produced?.join(", "),
            consumed: finding.consumed,
            note: result.note,
          });
        }

        // A finding is NOT automatically the objective. Only an attempt that
        // demonstrably reached the goal ends the run.
        if (result.reachesObjective) {
          if (item.step > 1 || result.consumed) {
            bus.emit("chain.step", {
              step: item.step,
              via: item.technique,
              consumed: finding.consumed,
              note: result.note,
            });
          }
          state.objectiveReached = true;
          state.haltedBy = "objective";
          bus.emit("objective.reached", {
            via: item.technique,
            steps: state.steps,
            costUsd: state.costUsd,
          });
        } else {
          bus.emit("exploit.interpret", { decision: "pivot", note: "confirmed; continuing" });
        }
        continue;
      }

      const canEscalate = Boolean(deps.escalate) && !escalated;
      const { decision, note } = interpret(result, {
        retries: item.retries,
        maxRetries: deps.maxRetries,
        tier: item.tier,
        canEscalate,
      });
      bus.emit("exploit.interpret", { decision, note });

      switch (decision) {
        case "retry":
          queue.unshift({ ...item, retries: item.retries + 1 });
          break;
        case "escalate": {
          escalated = true;
          if (deps.escalate && !tier2) {
            try {
              tier2 = await deps.escalate();
              await tier2?.login().catch(() => undefined);
            } catch {
              tier2 = undefined;
            }
          }
          if (tier2) queue.unshift({ ...item, tier: 2 });
          break; // Tier-2 unavailable degrades to "move on", never a crash
        }
        default:
          break; // pivot | abandon: drop this technique, continue
      }
    }
    if (!state.haltedBy) state.haltedBy = "exhausted";
  } finally {
    await tier2?.dispose().catch(() => undefined);
  }
}

function buildDeps(
  scope: ScopeFile,
  gate: ScopeGate,
  gateway: Gateway,
  override?: Partial<LoopDeps>,
): LoopDeps {
  const boundary = scope.credentials[0]?.boundary ?? "";
  const store = new EvidenceStore(
    process.env.NF_EVIDENCE_PATH ??
      resolve(process.env.INIT_CWD ?? process.cwd(), "nightfall-findings.jsonl"),
  );
  return {
    session: override?.session ?? new HttpSession(scope, gate, boundary),
    recon: override?.recon ?? ((s) => recon(s, gate, scope)),
    hypothesize: override?.hypothesize ?? ((fp) => groundedLookup(fp.component, fp.version)),
    attempt: override?.attempt ?? attempt,
    escalate: override?.escalate ?? (async () => new BrowserSession(scope, gate, boundary)),
    plan: override?.plan ?? makeGatewayPlanner(gateway),
    record: override?.record ?? ((f) => store.record(f)),
    budgetUsd: override?.budgetUsd ?? scope.budgetUsd,
    maxRetries: override?.maxRetries ?? 2,
  };
}

/**
 * Entry point. The CLI calls `runLoop(scope, gate, gateway)`; tests pass
 * `override` to inject deterministic deps. Returns the final run state.
 */
export async function runLoop(
  scope: ScopeFile,
  gate: ScopeGate,
  gateway: Gateway,
  override?: Partial<LoopDeps>,
): Promise<RunState> {
  const runId = crypto.randomUUID();
  const state = initialState(runId, scope.maxSteps);

  const onBlocked = () => {
    state.blocked++;
  };
  const onCost = (e: { costUsd: number }) => {
    state.costUsd += e.costUsd;
  };
  bus.on("scope.blocked", onBlocked);
  bus.on("gateway.call", onCost);

  bus.emit("run.start", {
    runId,
    target: scope.target,
    objective: scope.objective,
    scopeId: scopeId(scope),
  });

  const deps = buildDeps(scope, gate, gateway, override);
  try {
    await drive(scope, state, deps);
  } finally {
    await deps.session.dispose().catch(() => undefined);
    bus.off("scope.blocked", onBlocked);
    bus.off("gateway.call", onCost);
  }

  bus.emit("run.end", {
    runId,
    findings: state.findings,
    blocked: state.blocked,
    costUsd: state.costUsd,
    haltedBy: state.haltedBy,
  });
  return state;
}
