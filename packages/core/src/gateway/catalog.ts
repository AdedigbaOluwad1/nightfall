import type { ModelPrice } from "./pricing.js";

interface CatalogEntry {
  id: string;
  pricing?: { prompt?: string; completion?: string };
}

function normalize(id: string): string {
  const slash = id.indexOf("/");
  return slash >= 0 ? id.slice(slash + 1) : id;
}

let cache: Promise<Map<string, ModelPrice>> | undefined;

async function load(): Promise<Map<string, ModelPrice>> {
  const map = new Map<string, ModelPrice>();
  const base = process.env.BIFROST_BASE_URL;
  if (!base) return map;
  const key = process.env.BIFROST_API_KEY;
  try {
    const res = await fetch(`${base.replace(/\/$/, "")}/models`, {
      headers: key ? { Authorization: `Bearer ${key}` } : {},
    });
    if (!res.ok) return map;
    const body = (await res.json()) as { data?: CatalogEntry[] };
    for (const entry of body.data ?? []) {
      const prompt = Number(entry.pricing?.prompt);
      const completion = Number(entry.pricing?.completion);
      if (!Number.isFinite(prompt) || !Number.isFinite(completion)) continue;
      const price: ModelPrice = {
        inPerMillion: prompt * 1e6,
        outPerMillion: completion * 1e6,
      };
      map.set(entry.id, price);
      map.set(normalize(entry.id), price);
    }
  } catch {
    return map;
  }
  return map;
}

export function resetCatalog(): void {
  cache = undefined;
}

export async function catalogPriceFor(model: string): Promise<ModelPrice | undefined> {
  if (!cache) cache = load();
  const map = await cache;
  return map.get(model) ?? map.get(normalize(model));
}
