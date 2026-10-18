# Reviewed platform archive apply

`node db/postgres/apply-platform-archive.js --archive ARCHIVE --review REVIEW.json`
performs a native PostgreSQL constraint dry run and rolls back. Add `--apply` to
commit. The destination must already have migrations applied but no imported or
application business state; existing registrations cause refusal. The CLI does
not initialize, reset, merge, or overwrite an existing deployment.

Use `IDENTITY_MIGRATION_DATABASE_URL` in the environment, or choose another
migration URL variable with `--database-env NAME_MIGRATION_DATABASE_URL`. Never
put a URL/password in CLI arguments. Remote connections require the existing
verified TLS configuration. Output contains counts/digests only; failures emit
bounded error codes without SQL details, stack traces, or source values.

The review JSON has exactly these fields:

```json
{
  "version": 1,
  "archiveDigest": "<SHA256 from the verified archive plan>",
  "identityMap": {"71": 71},
  "naiveTimestamps": "UTC",
  "resolutions": {},
  "identityNormalizations": [],
  "platformDefaults": {},
  "retainedPlatformTables": []
}
```

Use `reject` instead of `UTC` when every timestamp has an explicit zone. Supply
NOVA per-field decisions in `resolutions` using the existing archive-bound
solution mapper contract. `identityNormalizations` must contain the exact
normalization records from the identity report, with `requiresReview` replaced
by `policy: "apply_native_metadata_policy_retain_source_archive"`. Even zero
normalizations require the explicit empty array. These decisions acknowledge
native metadata filtering while retaining original values in the source archive.

`platformDefaults` contains exactly the missing categories reported by the
platform mapper (`exercises`, `objectiveVisibility`, `hintVisibility`), each with
`catalog_visibility_defaults_without_content`. No missing category is approved
automatically. `retainedPlatformTables` contains every unmapped users_auth table,
including empty tables, as `{ "table": "NAME", "policy": "retain_archive_only" }`.
Retired CSRF tab content remains archive-only; its canonical objective content is
imported independently. Stale, missing, duplicate, or extra decisions fail.

The archive is verified once per invocation. All private DTOs derive from those
verified bytes. The batch hash binds private source identity rows, normalization
approvals, the identity map, content, and other reviewed decisions. The database
batch record holds counts and policy identifiers, never original credentials or
content. The low-level coordinator still accepts explicit scoped DTOs without
claiming archive coverage; this CLI additionally enforces source coverage and
always invokes the identity normalization review gate.

Scope is platform identity (including four auxiliary identity tables), canonical
workshop state, and the supported solution collections. Other challenge database
tables are counted separately and **are not imported**. This command is not a
whole-archive migration. Keep the original archive for every retained table.

Verification: `node --test tests/platformArchiveApply.test.js`. An opt-in native
branch uses `PG_TEST_DISPOSABLE=yes` and
`PG_PLATFORM_APPLY_TEST_MIGRATION_URL` pointing at a uniquely created empty test
database; it exercises dry-run rollback, apply, and refusal of a second import.
