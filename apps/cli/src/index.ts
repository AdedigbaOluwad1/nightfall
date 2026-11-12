import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  Budget,
  bus,
  EvidenceStore,
  type Finding,
  type FrozenTarget,
  formatAblationTable,
  Gateway,
  groundedLookup,
  loadScope,
  type PrecisionScore,
  precisionAtK,
  readFindings,
  runAblation,
  runLoop,
  ScopeGate,
  type StepType,
  setHypothesisGateway,
  toMarkdown,
  ungroundedLookup,
} from "@nightfall/core";
import { Command } from "commander";
import { loadEnv } from "./env.js";
import { attachRenderer } from "./render.js";

loadEnv();

function fromCwd(path: string): string {
  return resolve(process.env.INIT_CWD ?? process.cwd(), path);
}

const program = new Command();
program.name("nightfall").description("Autonomous web-app pentest agent");

program
  .command("run", { isDefault: true })
  .description("run the autonomous pentest loop against a scope")
  .requiredOption("--scope <path>", "path to scope.yaml")
  .option("--target <url>", "override target")
  .option("--objective <text>", "override objective")
  .action(async (opts) => {
    attachRenderer();
    const scope = loadScope(fromCwd(opts.scope));
    const gate = new ScopeGate(scope);
    const gateway = new Gateway(new Budget(scope.budgetUsd));
    setHypothesisGateway(gateway);
    bus.emit("scope.loaded", { hosts: scope.allow.hosts.length, paths: scope.allow.paths.length });

    const evidencePath = process.env.NF_EVIDENCE_PATH ?? fromCwd("nightfall-findings.jsonl");
    const store = new EvidenceStore(evidencePath);
    const findings: Finding[] = [];
    const state = await runLoop(scope, gate, gateway, {
      record: (f) => {
        store.record(f);
        findings.push(f);
      },
    });

    const report = toMarkdown(findings, {
      target: scope.target,
      objective: scope.objective,
      runId: state.runId,
      haltedBy: state.haltedBy,
      costUsd: state.costUsd,
    });
    const reportPath = `${evidencePath.replace(/\.jsonl$/, "")}.report.md`;
    writeFileSync(reportPath, report);
    console.log(`\nreport → ${reportPath}`);
  });

program
  .command("report")
  .description("render a client-ready Markdown report from a run's evidence JSONL")
  .option("--in <path>", "evidence JSONL file", "nightfall-findings.jsonl")
  .requiredOption("--target <url>", "target the findings are for")
  .option("--objective <text>", "engagement objective")
  .option("--out <path>", "write the report (default: print to stdout)")
  .action((opts) => {
    const findings = readFindings(fromCwd(opts.in));
    const md = toMarkdown(findings, { target: opts.target, objective: opts.objective });
    if (opts.out) {
      const out = fromCwd(opts.out);
      writeFileSync(out, md);
      console.log(`report → ${out} · ${findings.length} finding(s)`);
    } else {
      console.log(md);
    }
  });

program
  .command("ablate")
  .description("Tavily grounded-vs-ungrounded ablation over a frozen target list")
  .requiredOption("--targets <path>", "path to frozen targets JSON")
  .option("--out <path>", "write scored rows + raw candidate logs as JSON")
  .action(async (opts) => {
    attachRenderer();
    const gateway = new Gateway(new Budget(Number(process.env.NF_BUDGET_USD ?? "5")));
    setHypothesisGateway(gateway);
    const frozen = JSON.parse(readFileSync(fromCwd(opts.targets), "utf8")) as FrozenTarget[];
    const rows = await runAblation(frozen);
    console.log(`\n${formatAblationTable(rows)}\n`);
    if (opts.out) {
      const out = fromCwd(opts.out);
      writeFileSync(out, JSON.stringify(rows, null, 2));
      console.log(`raw logs → ${out}`);
    }
  });

program
  .command("precision")
  .description(
    "precision@k: do grounded vs ungrounded candidates reach confirmed findings (supporting)",
  )
  .requiredOption("--scope <path>", "path to scope.yaml for the live lab")
  .requiredOption("--component <name>", "fingerprinted component")
  .requiredOption("--version <ver>", "fingerprinted version")
  .option("--k <n>", "top-k candidates to score", "3")
  .option("--repeats <n>", "repeats per candidate for variance control", "3")
  .action(async (opts) => {
    attachRenderer();
    if (!process.env.NF_SEED) {
      console.warn(
        "warning: NF_SEED unset — precision@k is run-to-run noisy without a pinned seed",
      );
    }
    const scope = loadScope(fromCwd(opts.scope));
    const gate = new ScopeGate(scope);
    const gateway = new Gateway(new Budget(scope.budgetUsd));
    setHypothesisGateway(gateway);
    const k = Number(opts.k);
    const repeats = Number(opts.repeats);

    const grounded = await groundedLookup(opts.component, opts.version);
    const ungrounded = await ungroundedLookup(opts.component, opts.version);
    const pg = await precisionAtK(scope, gate, gateway, grounded, { k, repeats });
    const pu = await precisionAtK(scope, gate, gateway, ungrounded, { k, repeats });

    const row = (label: string, s: PrecisionScore) =>
      label.padEnd(12) +
      String(s.attributed).padEnd(11) +
      String(s.trials).padEnd(8) +
      `${(s.precisionAtK * 100).toFixed(0)}%`;
    console.log(`\ncond        attributed trials  p@${k}`);
    console.log(row("grounded", pg));
    console.log(row("ungrounded", pu));
    console.log(
      "\nsupporting metric (noisy) — headline is citation-validity + freshness via ablate\n",
    );
  });

program
  .command("cache-demo")
  .description(
    "prove the Bifrost cache is load-bearing: identical prompt twice → 2nd is a hit at $0",
  )
  .option(
    "--prompt <text>",
    "prompt sent twice",
    "List three common web application vulnerabilities as a JSON array of strings.",
  )
  .option("--step <step>", "routing step: classify | exploit_reason | report_write", "classify")
  .action(async (opts) => {
    attachRenderer();
    const step = opts.step as StepType;
    const gateway = new Gateway(new Budget(Number(process.env.NF_BUDGET_USD ?? "1")));
    const calls: { costUsd: number; cacheHit: boolean }[] = [];
    bus.on("gateway.call", (e) => {
      calls.push({ costUsd: e.costUsd, cacheHit: e.cacheHit });
    });

    console.log("\ncall 1 — identical prompt, cold:");
    await gateway.complete(step, opts.prompt);
    console.log("call 2 — identical prompt, warm:");
    await gateway.complete(step, opts.prompt);

    const first = calls[0];
    const second = calls[1];
    if (!first || !second) {
      console.log("\nwarning: expected two gateway.call events — cache demo inconclusive");
      return;
    }
    console.log(
      `\ncache: call1 $${first.costUsd.toFixed(4)} (${first.cacheHit ? "HIT" : "miss"})` +
        ` → call2 $${second.costUsd.toFixed(4)} (${second.cacheHit ? "HIT" : "miss"})`,
    );
    if (second.cacheHit) {
      console.log(
        `cache is load-bearing: 2nd identical call served from cache at $0 (saved $${first.costUsd.toFixed(4)})`,
      );
    } else {
      console.log(
        "no cache hit — enable the Bifrost cache plugin and keep NF_CACHE_ENABLED unset/true (see tracker).",
      );
    }
  });

program.parseAsync(process.argv.filter((arg) => arg !== "--"));
