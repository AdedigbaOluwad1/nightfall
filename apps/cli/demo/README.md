# Grounding demo pair (Task 5)

The locked grounded-vs-ungrounded before/after for the demo. Both rows are real
live ablation output (`grounding-pair.json`, captured 2026-11-11 against
Cloudflare Workers AI `llama-3.3-70b-instruct`, model cutoff `2024-06`). They
show the two independent ways Tavily grounding is load-bearing: **freshness** and
**citation validity**.

## Headline — freshness (WebGoat 2026.5)

The bare model's training stops at `2024-06`, so it cannot know 2026 advisories.

| condition    | CVEs cited                                               | fresh (post-cutoff) |
| ------------ | -------------------------------------------------------- | ------------------- |
| **grounded** | **5** — CVE-2026-109618, -109619, -33066, -13070, -13078 | **100%**            |
| ungrounded   | 0                                                        | 0%                  |

Grounded, retrieval surfaces 5 real post-cutoff CVEs; ungrounded, the model
produces none. Zero → five is the single clearest before/after.

## Supporting — citation validity (Apache Log4j 2.14.1)

Independent Tavily re-verification of each cited CVE (searches the CVE alone and
checks the component appears in its advisories).

| condition    | CVEs cited                                     | valid | validity |
| ------------ | ---------------------------------------------- | ----- | -------- |
| **grounded** | **4** — CVE-2021-44228, -45046, -45105, -44832 | 4/4   | **100%** |
| ungrounded   | 2 — CVE-2021-44228, -45046                     | 2/2   | 100%     |

Both cite only real CVEs, but grounding recovers the **full Log4Shell chain**
(including the follow-up bypasses -45046/-45105/-44832 that matter for patching);
the bare model recalls only two.

## Honesty note

On the intentionally-vulnerable labs (Juice Shop, DVWA, WebGoat) citation
**validity is 0% for both** conditions — those apps have no component-specific
CVEs, so the model emits real CVE IDs misattributed to the wrong product, and the
verifier correctly rejects them. Grounding wins on freshness there, not validity.

## Reproduce

```bash
# freshness pair (labs)
pnpm --filter @nightfall/cli dev -- ablate --targets apps/cli/example.targets.json --out labs.json
# validity pair (real-CVE reference targets)
pnpm --filter @nightfall/cli dev -- ablate --targets apps/cli/reference.targets.json --out ref.json
```

Live CVE sets may drift as new advisories are published; `grounding-pair.json` is
the frozen snapshot used for the demo.
