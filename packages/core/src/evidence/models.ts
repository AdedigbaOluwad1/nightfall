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
  /** ISO timestamp the finding was recorded — chain-of-custody. */
  foundAt: z.string().default(""),
  /** Content hash of the authorizing scope file — binds a finding to the
   *  specific authorization that governed the request that produced it. */
  scopeId: z.string().default(""),
  /** The originating technique — the stable attribution key for precision@k. */
  technique: z.string().default(""),
  severity: Severity,
  cvss: z.string().default(""),
  cvssScore: z.number().optional(),
  evidence: z.array(Evidence),
  remediation: z.string().default(""),
  /** Position in the attack chain (1-based); absent for standalone findings. */
  step: z.number().optional(),
  /** Id of the finding this one chained from — the attack-graph edge. */
  parentId: z.string().optional(),
  /** Label of the artifact this step consumed from its parent. */
  consumed: z.string().optional(),
  /** Labels of the artifacts this step produced for later steps. */
  produced: z.array(z.string()).optional(),
});
export type Finding = z.infer<typeof Finding>;
