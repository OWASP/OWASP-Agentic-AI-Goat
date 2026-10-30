# Sensitive Information reset-only promotion plan

## Scope and immutable inputs

The reset capability needs two forward migrations. The five phase-two Legacy
Sensitive objectives are a separate curriculum change and remain unregistered.
The machine-readable companion is
`sensitive-info-reset-promotion-manifest-2026-09-14.json`.

| Store | Current head | Candidate name | Candidate SHA-256 | Resulting file count |
| --- | --- | --- | --- | --- |
| identity | `0043_dpi_evidence_guidance.sql` | `0044_sensitive_info_aggregate_reset.sql` | `1485e878466a6a52b598f176832af45d8f5a7fc3ae5ec13e008abaea2c8ad186` | 43 |
| finflow | `0008_student_deletion.sql` | `0009_sensitive_info_aggregate_reset.sql` | `87ee181873584976096ec94a4f57987e60ecce8433220e76be60b2d68a7925be` | 9 |

Identity `0044` depends on the existing identity users, workshop-platform
generation/progress tables, and graph-runtime run/effect tables. FinFlow `0009`
depends on the existing `finflow` and `legacy_sensitive` schemas through
FinFlow `0008`. Both candidate hashes must be checked again immediately before
copying. Existing ledger rows must exactly match the local migration sequence;
the loader must reject a changed prefix.

`legacy-sensitive-canonical-catalog.sql` has no reserved migration number and is
not a reset prerequisite. Identity `0045` is reserved for the qualified SecureShop
persona-inbox release. The separately excluded legacy catalog draft would insert
five objectives with `is_enabled=false` and `catalog_active=false`. Neither reset repository
readiness nor either cleanup function reads those rows. Leaving this separate catalog draft out
keeps the existing 18-objective FinFlow workshop and every instructor setting
unchanged while allowing its current canonical state and legacy store to reset
together. Catalog registration and eventual visibility remain a later teaching
release with their own review and qualification.

## Pre-promotion recovery proof

1. Load local database configuration programmatically without printing URLs,
   passwords, JWT material, or private environment values. Verify the configured
   identity and FinFlow runtime/migration role pairs point to distinct stores and
   that their ledgers exactly match the current 42-file and 8-file directories.
2. Create an owned private recovery directory with mode `0700`. Stop HTTP work
   before backup: identify the current nodemon watcher and child, pause the
   watcher, drain and stop the backend child, and verify that it cannot accept
   new writes. A two-store backup is coherent only while both stores are quiet.
3. Dump the exact identity and FinFlow stores without exposing connection
   strings. Store dumps and manifests with mode `0600`. Record SHA-256, sizes,
   table row counts, stable row-content digests, migration ledgers, roles needed
   for restore, and an inventory of files. Reset promotion has no owned file
   payload to back up.
4. Restore both dumps as a pair into fresh owned PostgreSQL 18 databases with
   equivalent migration/runtime roles. Verify every table count and stable
   digest, the complete ledger prefixes, identity/FinFlow store separation, and
   runtime access. Remove the owned restore container and record its exact-name
   absence. A failed restore blocks promotion; preserve its diagnostics and the
   original backups.

## Forward application

Keep the watcher paused and backend stopped. Copy only the two exact candidate
bytes into their migration directories under the names above. Run the normal
16-store application initializer so production uses the same migration loader,
role, lock, and ledger behavior as startup. Require identity to report only
`0044_sensitive_info_aggregate_reset.sql`, FinFlow to report only
`0009_sensitive_info_aggregate_reset.sql`, and all other stores to report no
new migration. Run the complete initializer a second time and require an empty
replay for every store plus exact ledger name/checksum equality.

Before HTTP resumes, run reset readiness through the production composition.
It must verify the exact runtime and migration roles, same-store role pairing,
identity/FinFlow database separation, full local ledgers, journal and cleanup
relations/functions/triggers, runtime `EXECUTE`, and absence of effective
`PUBLIC EXECUTE`. Any failure keeps the backend stopped. If one store applies
and the other fails, do not start against the partial state; repair forward or
restore both quiet-store backups together.

Migrations are forward-only after success. Disabling the feature does not
remove schema or receipts. Restoring pre-promotion dumps is safe only before
new application writes resume. After a reset journal or cleanup receipt exists,
database rollback can destroy fencing history and is not an acceptable runtime
rollback.

## Activation without private configuration edits

The current flag is explicitly enabled only by
`SENSITIVE_INFO_AGGREGATE_RESET_ENABLED=true`. After both migrations and the
production readiness check pass, wire the currently unreferenced
`sensitiveInfoResetActivationPolicy.js` into the composition in the same paused
release so PostgreSQL requests reset by default when the variable is absent or `true`;
retain `false` as the documented maintenance opt-out and reject every other
value. Require both platform and workshop engines to be PostgreSQL.

`server/index.js` must use that shared policy and await the retained reset
composition after normal initialization and before `listen()`. Both reset
routes already resolve the same retained composition, so requested-but-unready
must remain `503`/startup failure and must never fall back to a single-store
reset. Deploy this source while the watcher is paused, then resume the watcher,
signal a fresh child, and verify startup readiness and the health endpoint. No
private `.env`, catalog, AWS asset, or learner data edit is part of activation.

The reviewed promotion entrypoint is
`tests/postgres/run-sensitive-info-reset-recovery.py --promote-reset`. It first
creates a new coherent backup and proves an owned restore; the earlier retained
backup is evidence, not the promotion snapshot. It checks the exact baseline
and activated composition hashes from the manifest, copies migrations with
same-directory atomic renames, runs the normal 16-store initializer, verifies
all 16 ledgers, invokes the actual loader again and requires an empty applied
set, and probes retained reset readiness before installing the default-on
source candidate. If anything fails after the first promotion byte is
installed, it records the failure and leaves the watcher paused for forward
repair or paired restore. It never resumes a partially qualified application.

Focused startup tests must cover unset PostgreSQL default-on, explicit `true`,
explicit `false`, malformed values, missing `0044`, missing `0009`, checksum
mismatch, wrong roles/databases, missing runtime grants, and no HTTP listen on
failure. Explicit `false` may start for maintenance, but PostgreSQL reset routes return
`503`; they must never fall back to a partial single-store reset.

## Acceptance evidence and remaining qualifier work

The owned mounted HTTP proof
`/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-sensitive-info-reset-wfgokn82`
passed with actual PostgreSQL authentication. It proved failed cleanup recovery,
cross-route exact replay, wrong-owner and malformed operation rejection, stale
run fencing, sibling preservation, inactive catalog independence, and canonical
FinFlow total/label/disabled-row projection before reset. The real coordinator
callback-result contract is separately covered by a focused regression using
`createRunCoordinator`.

The reset-only mounted HTTP03 qualification passed with zero skips in
`owasp-ai-goat-sensitive-info-reset-fz0epvm2` (result SHA-256
`823007bff6675046da945fe60a4624ee449388b045ea541ee5d6003f3b7153ee`).
It staged only identity0044 and FinFlow0009, without the separate legacy catalog.
After reset/replay it verified zero canonical completions, unchanged total17,
custom labels, disabled-objective exclusion, and empty owner legacy stats/access
logs. Root independently verified terminal results and exact container absence.
This closes that owned qualification gate. The coherent live paired
backup/owned restore also passed in `owasp-ai-goat-sensitive-reset-recovery-qsn6uy0s`:
its private manifest SHA-256 is
`d138209abfa1eb0cf5c84651eb9e5c7f67abb60f6fd4b91fb7397d8cb7718bce`
and comparison SHA-256 is
`c62f401ed2fe9dfff372d7954222316c85f6d237893a86160e8bfa6779e81f3b`.
All gating data, sequence, ledger, schema, ownership, database/default/object
privilege, and role records matched. Raw ACL serialization differed and was
retained as non-gating diagnostic evidence. Exact container cleanup, watcher
resume, and HTTP health were independently verified. A fresh snapshot remains
required inside promotion because application writes resumed afterward.
Forward application, startup readiness, and activation remain required. No
model call is needed to prove reset persistence semantics.
