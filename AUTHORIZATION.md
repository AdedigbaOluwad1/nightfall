# Authorization & Safety

Nightfall runs ONLY against authorized, isolated targets defined in a scope file.

- Deny-by-default: `scope/gate.ts` blocks any request outside allow.hosts/paths.
- No public, real-world, or non-consenting targets, ever.
- Credentials in the scope file authenticate; they never widen scope.
- Test credentials are provided at runtime and never committed.
- Out-of-scope access is treated as a hard failure.
