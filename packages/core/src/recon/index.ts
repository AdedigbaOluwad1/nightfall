import type { Session } from "../session/index.js";

export interface Fingerprint {
  component: string;
  version: string;
}

/** TODO(R1): crawl in-scope surface via `session`, fingerprint stack. */
export async function recon(_session: Session): Promise<Fingerprint[]> {
  return [];
}
