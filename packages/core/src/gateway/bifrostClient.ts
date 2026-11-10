import { createHash } from "node:crypto";
import OpenAI from "openai";
import { bus } from "../events/bus.js";
import type { StepType } from "../events/types.js";
import type { Budget } from "./budget.js";
import { computeCostLive } from "./pricing.js";
import { modelForStep } from "./routing.js";

function cacheHeaders(model: string, prompt: string): Record<string, string> {
  if (process.env.NF_CACHE_ENABLED === "false") return {};
  const key = createHash("sha256").update(`${model}\n${prompt}`).digest("hex");
  const headers: Record<string, string> = { "x-bf-cache-key": key };
  if (process.env.NF_CACHE_TTL) headers["x-bf-cache-ttl"] = process.env.NF_CACHE_TTL;
  if (process.env.NF_CACHE_THRESHOLD)
    headers["x-bf-cache-threshold"] = process.env.NF_CACHE_THRESHOLD;
  return headers;
}

function sampling(): { temperature: number; seed?: number; max_tokens: number } {
  const temperature = Number(process.env.NF_TEMPERATURE ?? "0");
  const maxTokens = Number(process.env.NF_MAX_TOKENS ?? "1024");
  const max_tokens = Number.isFinite(maxTokens) && maxTokens > 0 ? maxTokens : 1024;
  const seedRaw = process.env.NF_SEED;
  const seed = seedRaw !== undefined ? Number(seedRaw) : undefined;
  return seed !== undefined && Number.isFinite(seed)
    ? { temperature, seed, max_tokens }
    : { temperature, max_tokens };
}

export class Gateway {
  private readonly client: OpenAI;
  constructor(private readonly budget: Budget) {
    this.client = new OpenAI({
      baseURL: process.env.BIFROST_BASE_URL,
      apiKey: process.env.BIFROST_API_KEY,
    });
  }

  async complete(step: StepType, prompt: string): Promise<string> {
    this.budget.assertUnder();
    const model = modelForStep(step);
    const { data, response } = await this.client.chat.completions
      .create(
        {
          model,
          messages: [{ role: "user", content: prompt }],
          ...sampling(),
        },
        { headers: cacheHeaders(model, prompt) },
      )
      .withResponse();

    const cacheHit = response.headers.get("x-bifrost-cache-hit") === "true";
    const { costUsd, source } = cacheHit
      ? { costUsd: 0, source: "catalog" as const }
      : await computeCostLive(model, data.usage);
    this.budget.add(costUsd);
    bus.emit("gateway.call", { step, model, costUsd, cacheHit, priceSource: source });
    return data.choices[0]?.message?.content ?? "";
  }
}
