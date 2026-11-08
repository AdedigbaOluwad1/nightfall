# Authorization & Safety

Nightfall runs ONLY against authorized, isolated targets defined in a scope file.
No public, real-world, or non-consenting target is ever in scope — that is the
explicit rule of the challenge, and it is enforced in code, not by convention.

## The scope gate (`packages/core/src/scope/gate.ts`)

Deny-by-default. A request is allowed **only if** its host is in `allow.hosts`
**and** its path matches an allow prefix **and** matches no deny prefix.
Everything else is denied. Properties that make this trustworthy:

- **No LLM/model call lives inside the gate.** It is pure, deterministic logic —
  scope adherence is pass/fail and must never depend on a model choosing to behave.
- **It errs closed.** An unparseable URL is denied. An ambiguous case is denied.
- **It refuses encoded path-traversal.** Percent-encoded separators (`%2e`, `%2f`,
  `%5c`) and double-encoding (`%25`) can hide `..` from URL normalization and
  escape the allow prefix (e.g. `/app/..%2fadmin` → `/app/../admin` → `/admin`).
  The gate rejects any path carrying them rather than trying to decode cleverly.
- **It is enforced at both layers** — the HTTP client and the browser `route`
  handler — so a browser navigation cannot slip around it.
- **A blocked request is logged (`scope.blocked`)** and the loop is told — never
  silently dropped.
- **It is the most-tested file in the repo.** `test/gate.test.ts` attacks it with
  out-of-scope hosts, path and case tricks, plain and encoded traversal,
  `userinfo@host` confusion, trailing-dot hosts, IP/IPv6 substitution, and
  non-HTTP schemes. Every case is proven to be denied.

## Credentials

- The scope schema has an optional `credentials` block for authenticated testing.
- Credentials only **authenticate**; they never **widen** scope. The gate still
  governs every request.
- Test credentials are provided at runtime and are **never committed** (`.env` is
  git-ignored; only `.env.example` is tracked).

## Out of scope = hard failure

Any out-of-scope access is treated as a hard failure, not a warning. The design
goal is that Nightfall can *prove* it stays in bounds.
