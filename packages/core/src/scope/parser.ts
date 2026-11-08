import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { ScopeFile } from "./schema.js";

/** Parse + validate a scope file. Throws on anything malformed — fail closed. */
export function loadScope(path: string): ScopeFile {
  const raw = parse(readFileSync(path, "utf8"));
  return ScopeFile.parse(raw);
}
