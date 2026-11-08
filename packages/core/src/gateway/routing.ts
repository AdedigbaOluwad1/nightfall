import type { StepType } from "../events/types.js";

/** Map each step type to a model. Cheap for classify, strong for reasoning. */
export function modelForStep(step: StepType): string {
  switch (step) {
    case "classify":
      return process.env.NF_MODEL_CHEAP ?? "gpt-4o-mini";
    case "exploit_reason":
      return process.env.NF_MODEL_STRONG ?? "gpt-4o";
    case "report_write":
      return process.env.NF_MODEL_WRITE ?? "gpt-4o";
  }
}
