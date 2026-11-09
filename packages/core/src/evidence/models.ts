import { z } from "zod";
import { Severity } from "../events/types.js";

/**
 * One captured request/response pair that supports a finding. Captured as it
 * happens (never reconstructed after the run) and written to the append-only
 * evidence log. `screenshot` is an optional path to a Tier-2 (browser) capture
 * — e.g. proof that an XSS payload actually executed.
 */
export const Evidence = z.object({
  request: z.string(),
  response: z.string(),
  note: z.string().default(""),
  screenshot: z.string().optional(),
});
export type Evidence = z.infer<typeof Evidence>;

/**
 * Optional CVSS v3.1 detail for a finding. `severity` on the finding is always
 * present (the qualitative band); `cvss` adds the numeric score/vector when the
 * loop or a human has computed one.
 */
export const Cvss = z.object({
  score: z.number().min(0).max(10),
  vector: z.string().optional(),
});
export type Cvss = z.infer<typeof Cvss>;

export const Finding = z.object({
  id: z.string(),
  title: z.string(),
  severity: Severity,
  cvss: Cvss.optional(),
  description: z.string().default(""),
  evidence: z.array(Evidence).default([]),
  remediation: z.string().default(""),
});
export type Finding = z.infer<typeof Finding>;
