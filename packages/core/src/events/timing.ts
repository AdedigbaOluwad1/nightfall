import type { Bus } from "./bus.js";
import type { NightfallEventName } from "./types.js";

export type Phase = "recon" | "hypothesis" | "exploit" | "report";

/**
 * Which phase an event marks the start of. Unmapped events (gateway.call,
 * scope.blocked, budget.exceeded) are phase-neutral: they accrue to whatever
 * phase is already active, so a model call made during hypothesis counts as
 * hypothesis time rather than inventing a phase transition.
 */
const PHASE_OF: Partial<Record<NightfallEventName, Phase>> = {
  "run.start": "recon",
  "scope.loaded": "recon",
  "recon.found": "recon",
  "session.login": "recon",
  "tavily.cve": "hypothesis",
  "hypothesis.ranked": "hypothesis",
  "hypothesis.failed": "hypothesis",
  "plan.decision": "exploit",
  "exploit.attempt": "exploit",
  "exploit.interpret": "exploit",
  "chain.step": "exploit",
  "finding.confirmed": "exploit",
  "objective.reached": "report",
  "run.end": "report",
};

const PHASES: Phase[] = ["recon", "hypothesis", "exploit", "report"];

export interface PhaseTiming {
  phase: Phase;
  ms: number;
  pct: number;
}

export interface TimingBreakdown {
  totalMs: number;
  phases: PhaseTiming[];
}

/**
 * A wall-clock timing recorder. Subscribes to every event and stamps its arrival
 * time, so a run's cost in time — not just dollars — is reconstructable and
 * chartable. The breakdown attributes each inter-event interval to the phase that
 * was active when the interval opened; the sum of phase times is the run's total
 * wall clock, so the numbers are auditable, not estimated. This proves a run
 * actually happened and shows where the time really went.
 */
export class RunTimeline {
  private readonly marks: { name: NightfallEventName; t: number }[] = [];
  private readonly unsubscribe: () => void;

  constructor(bus: Bus, now: () => number = Date.now) {
    this.unsubscribe = bus.onAny((name) => {
      this.marks.push({ name: name as NightfallEventName, t: now() });
    });
  }

  /** Stop recording. Safe to call more than once. */
  stop(): void {
    this.unsubscribe();
  }

  /** Raw timeline, for a caller that wants to render it differently. */
  timeline(): { name: NightfallEventName; t: number }[] {
    return [...this.marks];
  }

  breakdown(): TimingBreakdown {
    const totals: Record<Phase, number> = { recon: 0, hypothesis: 0, exploit: 0, report: 0 };
    if (this.marks.length < 2) {
      return { totalMs: 0, phases: PHASES.map((phase) => ({ phase, ms: 0, pct: 0 })) };
    }
    let current: Phase = "recon";
    for (let i = 0; i < this.marks.length - 1; i++) {
      const here = this.marks[i];
      const next = this.marks[i + 1];
      if (!here || !next) continue;
      current = PHASE_OF[here.name] ?? current;
      totals[current] += Math.max(0, next.t - here.t);
    }
    const totalMs = PHASES.reduce((sum, p) => sum + totals[p], 0);
    const phases = PHASES.map((phase) => ({
      phase,
      ms: totals[phase],
      pct: totalMs > 0 ? (totals[phase] / totalMs) * 100 : 0,
    }));
    return { totalMs, phases };
  }
}

/** Render a timing breakdown as a terminal bar chart — one row per phase. */
export function formatTiming(b: TimingBreakdown): string {
  const secs = (ms: number) => `${(ms / 1000).toFixed(1)}s`;
  const barWidth = 28;
  const rows = b.phases.map((p) => {
    const filled = b.totalMs > 0 ? Math.round((p.ms / b.totalMs) * barWidth) : 0;
    const bar = "█".repeat(filled) + "·".repeat(barWidth - filled);
    const label = p.phase.padEnd(11);
    const pct = `${p.pct.toFixed(0)}%`.padStart(4);
    return `${label} ${bar} ${pct}  ${secs(p.ms)}`;
  });
  return [
    `wall-clock breakdown — total ${secs(b.totalMs)}`,
    ...rows,
    `(each interval attributed to the phase active when it opened; sums to total)`,
  ].join("\n");
}
