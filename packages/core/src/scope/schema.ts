import { z } from "zod";

/** Credentials authenticate an authorized test. They do NOT widen scope. */
const Credentials = z
  .object({
    boundary: z.string(), // logical auth boundary name
    loginUrl: z.string().url(),
    username: z.string(),
    password: z.string(),
  })
  .strict();

export const ScopeFile = z
  .object({
    target: z.string().url(),
    objective: z.string(),
    allow: z.object({
      hosts: z.array(z.string()).min(1),
      paths: z.array(z.string()).default(["/"]), // path prefixes
    }),
    deny: z
      .object({
        paths: z.array(z.string()).default([]),
      })
      .default({ paths: [] }),
    budgetUsd: z.number().positive().default(5),
    maxSteps: z.number().int().positive().default(40),
    credentials: z.array(Credentials).default([]),
  })
  .strict();

export type ScopeFile = z.infer<typeof ScopeFile>;
