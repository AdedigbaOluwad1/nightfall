import { resolve } from "node:path";
import { Budget, bus, Gateway, loadScope, runLoop, ScopeGate } from "@nightfall/core";
import { Command } from "commander";
import { loadEnv } from "./env.js";
import { attachRenderer } from "./render.js";

loadEnv();

const program = new Command();
program
  .name("nightfall")
  .description("Autonomous web-app pentest agent")
  .requiredOption("--scope <path>", "path to scope.yaml")
  .option("--target <url>", "override target")
  .option("--objective <text>", "override objective")
  .action(async (opts) => {
    attachRenderer();
    const scope = loadScope(resolve(process.env.INIT_CWD ?? process.cwd(), opts.scope));
    const gate = new ScopeGate(scope);
    const gateway = new Gateway(new Budget(scope.budgetUsd));
    bus.emit("scope.loaded", { hosts: scope.allow.hosts.length, paths: scope.allow.paths.length });
    await runLoop(scope, gate, gateway);
  });

program.parseAsync(process.argv.filter((arg) => arg !== "--"));
