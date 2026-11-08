# Contributing to Nightfall

These rules are mandatory for everyone working on this repository. Read
[NIGHTFALL.md](./NIGHTFALL.md) first for what we're building and why.

## Branching model

- `main` is the integration branch and the base for every pull request. It is
  always green: nothing unformatted, broken, or untested lands on it.
- There is **no direct pushing to `main`.** All work reaches `main` through a
  pull request.
- Each role works on its own long-lived branch and opens PRs from it to `main`:
  - `r1-agent-core` — recon, loop, session logins & screenshot, Tier-2 hardening.
  - `r2-integrations` — gateway cost/cache, hypothesis grounded/ungrounded,
    the ablation harness, `.env` loading.
  - `r3-evidence-report-docs` — evidence, report/PDF, adversarial gate tests, docs.
- Branch off `main` for a unit of work, keep PRs focused, and rebase on `main`
  before requesting review.

## Pull requests

- Open every PR against `main`.
- **No one merges their own PR, and no one merges anyone else's.** The repository
  owner reviews and merges all PRs. Open the PR, make CI green, and wait.
- Keep a PR scoped to one coherent change. A smaller PR that always works beats a
  large one that sometimes stalls.
- A PR cannot be merged while CI is failing.

## Commits

- Follow [Conventional Commits](https://www.conventionalcommits.org/): a
  `type: subject` summary line, where `type` is one of `feat`, `fix`, `chore`,
  `docs`, `refactor`, `test`, `perf`, `build`, or `ci`.
- Imperative mood, concise, focused purely on the technical change
  (`feat: add CSRF capture to HttpSession`, not `added some login stuff`).
- **Never add co-authorship or attribution footers.** No `Co-Authored-By` lines,
  no "Generated with" footers, no session or tool links, under any circumstance.

## Format and lint before you push

- Formatting and linting are done with [Biome](https://biomejs.dev/), not Prettier.
- Run the formatter over the whole repo before every push:

  ```bash
  pnpm format        # biome format --write .
  ```

- Linting must pass with no errors:

  ```bash
  pnpm lint          # biome check .
  ```

- **Do not push unformatted code.** CI runs `biome ci .` and fails on any
  formatting or lint error.

## Don't push broken code

Before pushing, the build and tests must be green locally:

```bash
pnpm build
pnpm test
```

The scope-gate tests in `packages/core/test/gate.test.ts` must always pass.

## CI

Every push to a role branch and every PR to `main` runs `.github/workflows/ci.yml`:
install → `biome ci .` (format + lint) → `pnpm build` → `pnpm test`. A red check
blocks the merge. Fix it on your branch; never work around it.

## Non-negotiables

- **The scope gate is sacred.** `packages/core/src/scope/gate.ts` is
  deny-by-default and must stay that way. Never make it more permissive, add an
  exception, or put a model/LLM call inside it.
- **Leave `TODO(Rn)` markers in place** until the owning role implements them.
  Don't silently fill another role's stub.
- **Never commit secrets.** `.env` is git-ignored; real credentials are provided
  at runtime and never committed. Commit only `.env.example`.
- No public, real-world, or non-consenting targets, ever. See
  [AUTHORIZATION.md](./AUTHORIZATION.md).
