# XSS stored-LLM profile origin foundation

Status: promoted as XSS migration 0006 and integrated with the PostgreSQL XSS
profile write/reset and grading paths. The original draft remains design history.

## Problem and contract

The audited stored-LLM g3 path proved that a profile value was returned and
that its exact bytes caused an attributed browser event. The shared profile row
did not say who last wrote those bytes. A learner could retain historical g2
progress, overwrite the field through `stored_user`, and then read that manual
value through `stored_llm`. Rewriting the same bytes was indistinguishable from
leaving the model write untouched.

The promoted migration adds an independent revision to each raw profile field and one private
current-origin row per profile field. The repository provides four operations:

- `writeModelField` increments that field's revision and records the exact UTF-8
  value digest with the authenticated platform user, workshop generation, XSS
  run owner and generation, real model metadata, raw decision digest, and
  observation index. It also receives the original server-owned learner message.
  When that message contains the exact stored value, the raw vulnerable write
  still succeeds but the transaction clears qualifying model origin.
- `writeManualField` increments the same revision and removes model origin,
  including when the written bytes are identical.
- `resetProfile` restores existing default raw values, advances all three
  revisions, and removes every origin for the owner.
- `readCurrent` returns a server-only value, revision, digest, and origin. The
  existing public profile DTO still selects only `name`, `bio`, and `website`.

The write receipt and `readCurrent().origin` use the same shape:

```text
version, userKey, platformUserId, field, revision, valueSha256,
workshopGeneration, runId, ownerKey, durableGeneration, decisionSource,
provider, model, rawDecisionSha256, observationIndex, writtenAt
```

The repository requires `userKey === String(platformUserId)`, the exact
`["XSS", userId]` run owner, a current-execution check, a successful model
decision, and non-mock provider/model metadata. It hashes values and raw model
responses itself. No plaintext value is duplicated in the origin row.

## Promotion and runtime boundary

The registered migration is SQL-equivalent to the reviewed draft except for its
status comment. The active PostgreSQL store routes ordinary profile writes and
reset through the repository, while the stored-LLM graph passes its private
model-decision context to the model-origin write. The native qualification now
relies on the registered migration; it no longer applies the draft a second
time.

The XSS data store and the platform run/progress authority are separate
PostgreSQL databases. The repository calls the supplied execution check before
work and again before committing its XSS transaction, but this alone is not a
distributed transaction. The active path runs the write inside the existing XSS
owner lease/effect fence, then rechecks the current owner and workshop generation
before publishing credit. Reset acquires the same owner boundary.

For g2, active grading requires a current private origin whose writer run is the
evaluated run. For g3, it requires canonical g2 completion and a current
origin matching owner, workshop generation, field, revision, and exact value
digest; its attributed browser source must be that exact current value. A local
`xss.progress` row is not a canonical prerequisite.

## Native evidence

The owned PostgreSQL 18 test applies the ordinary XSS migrations, including
migration 0006. It proves exact multibyte UTF-8 hashing, receipt/snapshot shape,
no public DTO metadata, identical-byte manual invalidation, reset invalidation,
foreign-owner rejection, non-model metadata rejection, rollback when the final
execution check is stale, and coherent ordering of twelve concurrent
model/manual writes.

- Passing run: `owasp-ai-goat-xss-profile-origin-cw0a9krs/result.log`, 1 passed, 0
  failed. The exact owned container was removed.
- Promoted-migration rerun: `owasp-ai-goat-xss-profile-origin-8vrgi3sz/result.log`, 1
  passed, 0 failed. The exact owned container was removed.
- Learner-copy rerun: `owasp-ai-goat-xss-profile-origin-jyfp7xkd/result.log`, 1 passed,
  0 failed. It proves that same-byte and new-byte learner copies remain stored
  while clearing prior model origin. The exact owned container was removed.
- An earlier fresh run at `owasp-ai-goat-xss-profile-origin-bngker4c/result.log` failed
  because repository admission rejected `mock` but not `fixture` model labels.
  The repository was aligned with the private validator, and that owned
  container was also removed before the passing rerun.

No learner database, live model, deployment asset, or working service was used
or changed by these native qualifications.

The active grading contract is `xss_model_origin.v2` under shared Judge v18. Focused completion, integrity, and browser/grader checks pass28, including denial before browser qualification for an identical-byte manual rewrite despite old g2 credit. The rendered connected stored-LLM workflow remains under qualification; these checks do not establish real-model success for that workflow.

## Current v19 cross-scenario regression

The current stored-user rendered workflow passes deterministic run `y6g47czs` and actual llama3.1:8b actor/Judge run `0isauh_o` (29.70 seconds test, 34.67 seconds total). It verifies exact raw-value storage, later browser execution, no-save negative control, owner isolation and both reset paths. Owned containers were removed. The expanded stored-LLM actual8B snapshot `cj_6xzkv` matches the current route, origin repository, graph, grader, Judge and rendered test source bytes.

Canonical completion-list native qualification `e4hijtit` passes owner separation, retention of disabled historical prerequisites and reset generation rejection; this is separate from visibility-filtered dashboard display. The v19 native dispatch suite `7hbmvfct` rejects unavailable retry packets from v18 and earlier without creating child judgments or completions. These are bounded XSS results; they do not qualify every workshop or close dashboard/admin parity.
