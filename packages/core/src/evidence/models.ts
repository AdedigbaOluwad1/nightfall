import { z } from "zod";
import { Severity } from "../events/types.js";

export const Evidence = z.object({
  request: z.string(),
  response: z.string(),
  note: z.string().default(""),
});

export const Finding = z.object({
  id: z.string(),
  title: z.string(),
  severity: Severity,
  cvss: z.string().default(""),
  cvssScore: z.number().optional(),
  evidence: z.array(Evidence),
  remediation: z.string().default(""),
});
export type Finding = z.infer<typeof Finding>;
