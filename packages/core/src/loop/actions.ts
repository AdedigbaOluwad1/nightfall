import type { Session } from "../session/index.js";

export interface AttemptResult {
  ok: boolean;
  note: string;
}

/**
 * TODO(R1): a single exploit attempt. `useSession` routes through the stateful
 * client instead of a raw tool call. DO NOT add real payloads during scaffolding
 * — built by hand against the authorized lab only.
 */
export async function attempt(
  _session: Session,
  _technique: string,
  _opts: { useSession: boolean },
): Promise<AttemptResult> {
  return { ok: false, note: "stub" };
}
