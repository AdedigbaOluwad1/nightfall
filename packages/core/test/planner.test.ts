import { describe, expect, it } from "vitest";
import { parsePayloadPairs } from "../src/loop/planner.js";

describe("parsePayloadPairs — model bypass output", () => {
  it("extracts well-formed pairs even when wrapped in prose", () => {
    const raw =
      'Sure, here are bypasses:\n[{"t":"0 oorr 1=1","f":"0 oorr 1=2"},{"t":"0 || 1=1","f":"0 || 1=2"}]\nHope this helps.';
    expect(parsePayloadPairs(raw)).toEqual([
      { t: "0 oorr 1=1", f: "0 oorr 1=2" },
      { t: "0 || 1=1", f: "0 || 1=2" },
    ]);
  });

  it("drops malformed entries and never throws on junk", () => {
    expect(parsePayloadPairs("no json here")).toEqual([]);
    expect(parsePayloadPairs("[not valid json")).toEqual([]);
    expect(parsePayloadPairs('[{"t":"x"},{"f":"y"},{"t":"a","f":"b"},{"t":1,"f":2}]')).toEqual([
      { t: "a", f: "b" },
    ]);
  });
});
