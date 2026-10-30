# Repository Change Instructions

These are standing rules for agents and contributors making changes in OWASP Agentic AI GOAT.
They supplement `CLAUDE.md`; the security-lab do-not-fix rules there still
apply.

## Required workflow

1. **Keep the change minimal.** Use the smallest coherent diff that meets the
   requirement. Do not mix in unrelated refactors, formatting sweeps, dependency
   upgrades, database resets/reseeds, or destructive cleanup.
2. **Work in logical chunks.** Each chunk should have one clear behavior and be
   independently reviewable and verifiable.
3. **Use test-driven development for code changes.** Add or update a regression
   test, run it and observe the expected failure, implement the minimum fix,
   then rerun it to green. Refactor only with the tests still passing. Pure
   documentation-only changes do not need a contrived failing test.
4. **Update documentation in every chunk.** Keep the relevant module document
   and `docs/code-map/` index/catalog current with behavior, relationships,
   operational effects, tests, and known limitations. A code chunk is not done
   until its documentation is updated.
5. **Use a devil's-advocate review before implementation.** For non-trivial
   work, challenge the plan for regressions, scope errors, concurrency and
   multi-user behavior, persistence/restart behavior, and backward
   compatibility before writing production code.
6. **Use a fresh devil's-advocate review after implementation.** Run relevant
   tests and builds first, then adversarially inspect the actual diff. Convert
   accepted findings into failing tests and minimal fixes, rerun verification,
   and recheck the remediated findings before completion.

## Completion standard

- Report exactly which relevant tests and builds passed.
- Record unrelated baseline failures separately; do not broaden scope merely to
  make an unrelated suite green.
- Do not claim completion while an accepted in-scope adversarial finding is
  unresolved.
- Preserve user work and intentional challenge vulnerabilities. Never use a
  destructive reset or mass deletion as a shortcut.
