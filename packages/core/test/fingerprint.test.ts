import { describe, expect, it } from "vitest";
import {
  mergeFingerprints,
  type ProbeResponse,
  parseFingerprints,
} from "../src/recon/fingerprint.js";

function res(partial: Partial<ProbeResponse>): ProbeResponse {
  return { url: "http://localhost/", status: 200, headers: {}, body: "", ...partial };
}

describe("parseFingerprints", () => {
  it("parses a Server banner into component + version", () => {
    const fps = parseFingerprints(res({ headers: { server: "Apache/2.4.49 (Unix)" } }));
    expect(fps).toContainEqual({ component: "Apache", version: "2.4.49" });
  });

  it("maps a session cookie to a server-side stack", () => {
    const fps = parseFingerprints(res({ headers: { "set-cookie": "PHPSESSID=abc; path=/" } }));
    expect(fps).toContainEqual({ component: "PHP", version: "unknown" });
  });

  it("reads a generator meta tag", () => {
    const fps = parseFingerprints(res({ body: '<meta name="generator" content="WordPress 6.1">' }));
    expect(fps).toContainEqual({ component: "WordPress", version: "6.1" });
  });

  it("recognises known lab signatures from the body", () => {
    expect(parseFingerprints(res({ body: "<title>OWASP Juice Shop</title>" }))).toContainEqual({
      component: "OWASP Juice Shop",
      version: "unknown",
    });
    expect(
      parseFingerprints(res({ body: "Damn Vulnerable Web Application (DVWA)" })),
    ).toContainEqual({ component: "DVWA", version: "unknown" });
  });

  it("merges duplicates and prefers a known version", () => {
    const merged = mergeFingerprints([
      { component: "nginx", version: "unknown" },
      { component: "nginx", version: "1.21.0" },
    ]);
    expect(merged).toEqual([{ component: "nginx", version: "1.21.0" }]);
  });
});
