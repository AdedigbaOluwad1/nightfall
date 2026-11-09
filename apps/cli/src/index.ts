import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  Budget,
  bus,
  type FrozenTarget,
  formatAblationTable,
  Gateway,
  groundedLookup,
  loadScope,
  type PrecisionScore,
  precisionAtK,
  runAblation,
  runLoop,
  ScopeGate,
  setHypothesisGateway,
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
    await runLoop(scope, gate, gateway);
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

program.parseAsync(process.argv.filter((arg) => arg !== "--"));
