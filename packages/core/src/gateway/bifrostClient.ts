import { createHash } from "node:crypto";
import OpenAI from "openai";
import { bus } from "../events/bus.js";
import type { StepType } from "../events/types.js";
import type { Budget } from "./budget.js";
import { computeCost } from "./pricing.js";
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

function sampling(): { temperature: number; seed?: number } {
  const temperature = Number(process.env.NF_TEMPERATURE ?? "0");
  const seedRaw = process.env.NF_SEED;
  const seed = seedRaw !== undefined ? Number(seedRaw) : undefined;
  return seed !== undefined && Number.isFinite(seed) ? { temperature, seed } : { temperature };
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
    const costUsd = cacheHit ? 0 : computeCost(model, data.usage);
    this.budget.add(costUsd);
    bus.emit("gateway.call", { step, model, costUsd, cacheHit });
    return data.choices[0]?.message?.content ?? "";
  }
}
