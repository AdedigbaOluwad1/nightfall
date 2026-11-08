import OpenAI from "openai";
import { bus } from "../events/bus.js";
import type { StepType } from "../events/types.js";
import type { Budget } from "./budget.js";
import { modelForStep } from "./routing.js";

/** Every LLM call in Nightfall goes through Bifrost via this client. */
export class Gateway {
  private readonly client: OpenAI;
  constructor(private readonly budget: Budget) {
    this.client = new OpenAI({
      baseURL: process.env.BIFROST_BASE_URL,
      apiKey: process.env.BIFROST_API_KEY,
    });
  }

  async complete(step: StepType, prompt: string): Promise<string> {
    this.budget.assertUnder(); // throws if the per-run cap is hit — the demo moment
    const model = modelForStep(step);
    const res = await this.client.chat.completions.create({
      model,
      messages: [{ role: "user", content: prompt }],
    });
    // TODO(R2): read real cost + cache-hit from Bifrost response headers/usage.
    const costUsd = 0;
    const cacheHit = false;
    this.budget.add(costUsd);
    bus.emit("gateway.call", { step, model, costUsd, cacheHit });
    return res.choices[0]?.message?.content ?? "";
  }
}
