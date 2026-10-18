# Workshop archive apply command

`npm run db:legacy:apply-workshop` exposes the existing bounded MCP, CSRF, XSS, CTF, FinFlow and Supply Chain import libraries. It reads a verified export, validates its exact family review and mapping before opening a connection, and runs a database dry run by default. It does not discover assets, activate a running installation or provide cross-database atomicity.

```sh
npm run db:legacy:apply-workshop -- --archive /private/export --family mcp --review /private/mcp-review.json
```

Add `--apply` only for the reviewed staging target. Each importer retains its existing empty/default-target requirements. The CTF helper runs inside the command's outer transaction; other family helpers own their transaction. Failure rolls back that target and always closes its pool. The command does not migrate or seed a target automatically.

| Family | Migration connection variable | Required keys inside `review` |
| --- | --- | --- |
| `mcp` | `MCP_WORKSHOP_MIGRATION_DATABASE_URL` | `archiveDigest`, `retainedTables` |
| `csrf` | `CSRF_WORKSHOP_MIGRATION_DATABASE_URL` | `archiveDigest`, `missingVictimState`, `retainedTables` |
| `xss` | `XSS_WORKSHOP_MIGRATION_DATABASE_URL` | `archiveDigest`, `missingTables`, `retainedTables`, `workshopSource` |
| `ctf` | `CTF_MIGRATION_DATABASE_URL` | `archiveDigest`, `identityMap`, `resolutions` |
| `finflow` | `FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL` | `archiveDigest`, `tables` |
| `supply_chain` | `SUPPLY_CHAIN_WORKSHOP_MIGRATION_DATABASE_URL` | `archiveDigest`, `tables` |

The JSON envelope contains exactly `family`, `naiveTimestamps`, `review`, `ownerBinding` and `opaqueOwnerResolutions`. The timestamp policy is `reject` or explicitly reviewed `UTC`. Review structures are the existing contracts in the corresponding `db/postgres/map-*-archive.js` modules; this wrapper does not relax their retained-table, source-choice, missing-state or identity decisions. Review files are bounded to1MiB and cannot be symlinks. Unknown flags, extra fields, stale digests, invalid source columns and unresolved CTF review requirements fail before pool creation.

Keep migration connection credentials in private environment configuration, never in the review file. The result and errors omit raw source rows and connection strings. Sensitive row content remains in the verified archive and applicable migration-role provenance tables.

The combined platform import records an immutable `identity.archive_owner_bindings` record. Apply that reviewed platform import first, then set `IDENTITY_MIGRATION_DATABASE_URL` for workshop commands. Before opening the workshop target, the command verifies that `ownerBinding` exactly matches the persisted archive and identity map and that target identities still exist. This is a point-in-time check across separate databases, not a distributed transaction; keep the staging installation quiescent throughout import. Older platform imports without this record require a newly reviewed staging import; the command never infers a map from coincidentally equal IDs.

`ownerBinding` contains `{"archiveDigest":"<64 lowercase hex characters>","identityMap":{"7":71}}`. It must carry the entire same map used by the platform import, including for an empty workshop. CTF's review `identityMap` must match it. MCP, CSRF, XSS, FinFlow and Supply Chain remap attendee ownership and store the map digest in their import batch. Raw provenance, tool arguments, victim IDs and teaching payloads retain their original values. Historical workshop projections do not mint current Judge receipts.

Use `opaqueOwnerResolutions: []` for canonical numeric owners. An ambiguous historical key such as `0007` requires `{"sourceKey":"0007","disposition":"map_source_identity","sourceId":"7"}`; it then maps through the verified platform map. A genuinely nonnumeric legacy key can be explicitly retained using `preserve_opaque`. Numeric aliases cannot use that disposition. XSS anonymous `anon_*` namespaces remain separate from authenticated owners. Post-mapping key collisions fail instead of merging histories.

For active generic-demo, legacy sensitive-info and SecureShop plan/apply commands and staged asset proofs, see [active-store operator workflow](active-archive-operator.md). Platform and ARIA/NOVA have their own reviewed command paths. Together these are per-store operator tools; [remaining release gates](release-status-2026-09-11.md) still govern complete installation cutover, assets and recovery.
