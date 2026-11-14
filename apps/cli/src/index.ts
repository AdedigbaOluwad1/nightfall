import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  Budget,
  bus,
  EvidenceStore,
  type Finding,
  type FrozenTarget,
  formatAblationTable,
  formatRegrounding,
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
  scopeId,
  setHypothesisGateway,
  toMarkdown,
  ungroundedLookup,
} from "@nightfall/core";
import { Command } from "commander";
import pc from "picocolors";
import { WebSocketServer } from "ws";
import { loadEnv } from "./env.js";
import { attachRenderer } from "./render.js";

loadEnv();

function fromCwd(path: string): string {
  return resolve(process.env.INIT_CWD ?? process.cwd(), path);
}

interface GateProbe {
  label?: string;
  url: string;
  expect?: "allow" | "block";
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
      scopeId: scopeId(scope),
      haltedBy: state.haltedBy,
      costUsd: state.costUsd,
    });
    const reportPath = `${evidencePath.replace(/\.jsonl$/, "")}.report.md`;
    writeFileSync(reportPath, report);
    console.log(`\nreport → ${reportPath}`);
  });

program
  .command("serve")
  .description("run the loop and stream the event bus over a WebSocket for the web view")
  .requiredOption("--scope <path>", "path to scope.yaml")
  .option("--port <n>", "WebSocket port", "4317")
  .action(async (opts) => {
    attachRenderer();
    const port = Number(opts.port);
    const wss = new WebSocketServer({ port });
    const backlog: string[] = [];
    const send = (type: string, payload: unknown) => {
      const msg = JSON.stringify({ type, payload });
      backlog.push(msg);
      for (const client of wss.clients) {
        if (client.readyState === client.OPEN) client.send(msg);
      }
    };
    bus.onAny((type, payload) => send(type as string, payload));
    wss.on("connection", (socket) => {
      for (const msg of backlog) socket.send(msg);
    });
    console.log(
      `\n${pc.bold("nightfall ▸")} serve → ws://localhost:${port}` +
        `  · start the web view with: pnpm --filter @nightfall/web dev\n`,
    );

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
      scopeId: scopeId(scope),
      haltedBy: state.haltedBy,
      costUsd: state.costUsd,
    });
    writeFileSync(`${evidencePath.replace(/\.jsonl$/, "")}.report.md`, report);
    console.log(`\nrun complete — socket stays open on :${port}. Ctrl+C to stop.`);
  });

program
  .command("scope-check")
  .description("prove the deny-by-default scope gate refuses adversarial out-of-scope requests")
  .requiredOption("--scope <path>", "path to scope.yaml")
  .option("--probes <path>", "JSON array of { label?, url, expect? } probes")
  .option(
    "--url <u>",
    "extra URL to probe (repeatable)",
    (u: string, acc: string[]) => {
      acc.push(u);
      return acc;
    },
    [] as string[],
  )
  .action((opts) => {
    const scope = loadScope(fromCwd(opts.scope));
    const gate = new ScopeGate(scope);
    const probes: GateProbe[] = [];
    if (opts.probes) {
      probes.push(...(JSON.parse(readFileSync(fromCwd(opts.probes), "utf8")) as GateProbe[]));
    }
    for (const u of opts.url as string[]) probes.push({ url: u });
    if (probes.length === 0) {
      console.error("no probes — pass --probes <json> and/or --url <u>");
      process.exitCode = 1;
      return;
    }

    console.log(
      `\nscope gate — deny-by-default · host(s): ${scope.allow.hosts.join(", ")}` +
        ` · allow: ${scope.allow.paths.join(", ")} · deny: ${scope.deny.paths.join(", ") || "(none)"}\n`,
    );
    let mismatches = 0;
    let checked = 0;
    for (const p of probes) {
      const d = gate.check(p.url);
      let mark = " ";
      if (p.expect) {
        checked += 1;
        const ok = (p.expect === "allow") === d.allowed;
        if (!ok) mismatches += 1;
        mark = ok ? pc.green("✓") : pc.red("✗");
      }
      const verdict = d.allowed ? pc.green("ALLOW") : pc.yellow("BLOCK");
      console.log(`${mark} ${verdict}  ${(p.label ?? "").padEnd(40)} ${p.url}  — ${d.reason}`);
    }
    if (checked > 0 && mismatches === 0) {
      console.log(
        `\n${pc.green(`${checked}/${checked}`)} probes behaved as scoped — deny-by-default holds.\n`,
      );
    } else if (checked > 0) {
      console.log(
        `\n${pc.red(`${mismatches} of ${checked}`)} probes did NOT behave as scoped — gate regression.\n`,
      );
      process.exitCode = 1;
    }
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
    const md = toMarkdown(findings, {
      target: opts.target,
      objective: opts.objective,
      scopeId: findings.find((f) => f.scopeId)?.scopeId,
    });
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
    const regrounding = formatRegrounding(rows);
    if (regrounding) console.log(`${regrounding}\n`);
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
