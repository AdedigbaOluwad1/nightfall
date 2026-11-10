import { catalogPriceFor } from "./catalog.js";

export interface ModelPrice {
  inPerMillion: number;
  outPerMillion: number;
}

export interface TokenUsage {
  prompt_tokens?: number;
  completion_tokens?: number;
}

export type PriceSource = "override" | "catalog" | "table" | "estimate";

export interface CostResult {
  costUsd: number;
  source: PriceSource;
}

const DEFAULT_PRICES: Record<string, ModelPrice> = {
  "gpt-4o-mini": { inPerMillion: 0.15, outPerMillion: 0.6 },
  "gpt-4o": { inPerMillion: 2.5, outPerMillion: 10.0 },
  "gpt-4.1-mini": { inPerMillion: 0.4, outPerMillion: 1.6 },
  "gpt-4.1": { inPerMillion: 2.0, outPerMillion: 8.0 },
};

function overrides(): Record<string, ModelPrice> {
  const raw = process.env.NF_PRICING;
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Record<string, ModelPrice>;
  } catch {
    return {};
  }
}

function fallbackPrice(): ModelPrice {
  const inPerMillion = Number(process.env.NF_PRICING_DEFAULT_IN);
  const outPerMillion = Number(process.env.NF_PRICING_DEFAULT_OUT);
  if (Number.isFinite(inPerMillion) && Number.isFinite(outPerMillion)) {
    return { inPerMillion, outPerMillion };
  }
  return { inPerMillion: 2.5, outPerMillion: 10.0 };
}

export function priceFor(model: string): ModelPrice {
  return overrides()[model] ?? DEFAULT_PRICES[model] ?? fallbackPrice();
}

function costOf(price: ModelPrice, usage: TokenUsage | undefined): number {
  const inTokens = usage?.prompt_tokens ?? 0;
  const outTokens = usage?.completion_tokens ?? 0;
  return (inTokens / 1e6) * price.inPerMillion + (outTokens / 1e6) * price.outPerMillion;
}

export function computeCost(model: string, usage: TokenUsage | undefined): number {
  return costOf(priceFor(model), usage);
}

export async function resolvePrice(
  model: string,
): Promise<{ price: ModelPrice; source: PriceSource }> {
  const override = overrides()[model];
  if (override) return { price: override, source: "override" };
  const catalog = await catalogPriceFor(model);
  if (catalog) return { price: catalog, source: "catalog" };
  const table = DEFAULT_PRICES[model];
  if (table) return { price: table, source: "table" };
  return { price: fallbackPrice(), source: "estimate" };
}

export async function computeCostLive(
  model: string,
  usage: TokenUsage | undefined,
): Promise<CostResult> {
  const { price, source } = await resolvePrice(model);
  return { costUsd: costOf(price, usage), source };
}
