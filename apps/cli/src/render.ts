import { bus } from "@nightfall/core";
import pc from "picocolors";

/** Nightfall trace colours — the CLI's brand surface. */
const tag = {
  scope: (s: string) => pc.yellow(s),
  recon: (s: string) => pc.cyan(s),
  tavily: (s: string) => pc.green(s),
  exploit: (s: string) => pc.magenta(s),
  gateway: (s: string) => pc.blue(s),
  finding: (s: string) => pc.bold(pc.red(s)),
  ok: (s: string) => pc.bold(pc.green(s)),
};

export function attachRenderer(): void {
  bus.on("run.start", (e) => console.log(`${pc.bold("nightfall ▸")} run ${e.runId} → ${e.target}`));
  bus.on("scope.loaded", (e) =>
    console.log(
      "  " +
        tag.scope(`▸ scope`) +
        `  ${e.hosts} host(s), ${e.paths} path(s) · deny-by-default armed`,
    ),
  );
  bus.on("scope.blocked", (e) =>
    console.log(`  ${tag.scope(`⚠ scope`)}  blocked ${e.url} — ${e.reason}`),
  );
  bus.on("recon.found", (e) =>
    console.log(
      "  " +
        tag.recon(`▸ recon`) +
        `  ${e.endpoint}` +
        (e.component ? ` · ${e.component} ${e.version ?? ""}` : ""),
    ),
  );
  bus.on("tavily.cve", (e) =>
    console.log(`  ${tag.tavily(`▸ tavily`)}  ${e.component} ${e.version} → ${e.cve}`),
  );
  bus.on("hypothesis.failed", (e) =>
    console.log(
      "  " +
        pc.yellow("⚠ grounding") +
        `  ${e.component} ${e.version} — degraded, running ungrounded · ${e.reason}`,
    ),
  );
  bus.on("plan.decision", (e) =>
    console.log(
      "  " +
        pc.blue(`▸ plan`) +
        `  ${e.chose}${e.fallback ? pc.dim(" (deterministic)") : ""}\n    ${pc.dim(`└ ${e.reason}`)}`,
    ),
  );
  bus.on("exploit.attempt", (e) =>
    console.log(`  ${tag.exploit(`▸ exploit`)}  #${e.n} ${e.technique}`),
  );
  bus.on("exploit.interpret", (e) => console.log(`    └ ${e.decision.toUpperCase()} · ${e.note}`));
  bus.on("gateway.call", (e) =>
    console.log(
      "  " +
        tag.gateway(`▸ bifrost`) +
        `  ${e.step} → ${e.model} · $${e.costUsd.toFixed(4)} · ${e.cacheHit ? "cache HIT" : "miss"}`,
    ),
  );
  bus.on("budget.exceeded", (e) =>
    console.log(
      "  " +
        pc.bold(pc.red("⛔ budget")) +
        `  cap $${e.capUsd.toFixed(2)} reached (spent $${e.spentUsd.toFixed(4)}) · halting the ${e.stage} loop`,
    ),
  );
  bus.on("finding.confirmed", (e) =>
    console.log(`  ${tag.finding(`✓ finding`)}  ${e.title} · ${e.severity}`),
  );
  bus.on("chain.step", (e) => {
    const flow = [
      e.consumed ? `uses ${e.consumed}` : undefined,
      e.produced ? `yields ${e.produced}` : undefined,
    ]
      .filter(Boolean)
      .join(" · ");
    console.log(
      `    ${pc.bold(pc.magenta(`⛓ chain`))}  step ${e.step} · ${e.via}${flow ? ` · ${flow}` : ""}`,
    );
  });
  bus.on("objective.reached", (e) =>
    console.log(
      "  " +
        tag.ok(`▸ objective`) +
        `  reached via ${e.via} · ${e.steps} steps · $${e.costUsd.toFixed(2)}`,
    ),
  );
  bus.on("run.end", (e) =>
    console.log(
      pc.bold("nightfall ▸") +
        ` done · ${e.findings} finding(s) · ${e.blocked} blocked · $${e.costUsd.toFixed(2)}` +
        (e.haltedBy ? ` · halted: ${e.haltedBy}` : ""),
    ),
  );
}
