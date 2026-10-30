# Remaining archive coverage

Bounded source audit, 2026-09-11. This companion compares the SQLite files exported by [`db/postgres/export-legacy.js`](../../db/postgres/export-legacy.js) with checked-in archive maps/import libraries, native PostgreSQL schemas, and route branches. It reads source-controlled code only; no working `.db`, `.env`, MySQL store, deployment asset, or live archive was opened.

“Archive-connected” means a verified archive can reach a bounded mapper/import library. It does not mean the normal application has completed cutover, that filesystem assets were transferred, or that a standalone operator command exists.

## Current archive-connected families

| Source | Checked-in mapping/import | Native proof and current boundary |
| --- | --- | --- |
| `owasp-ai-goat.db` | [`map-legacy-challenge-archive.js`](../../db/postgres/map-legacy-challenge-archive.js), [`import-legacy-challenge-archive.js`](../../db/postgres/import-legacy-challenge-archive.js) map the ten `legacy_challenge` table families and preserve raw teaching values through provenance. | [`tests/postgres/legacyChallengeArchive.integration.test.js`](../../tests/postgres/legacyChallengeArchive.integration.test.js) covers dry-run/rollback, constraints, IDs and immutable provenance in a disposable database. File paths and product image references remain metadata-only. The active-store plan/apply CLI now supports this target and has a real native command test. |
| `sensitive_info.db` | [`map-legacy-sensitive-archive.js`](../../db/postgres/map-legacy-sensitive-archive.js), [`import-legacy-sensitive-archive.js`](../../db/postgres/import-legacy-sensitive-archive.js), and FinFlow migration `0005_legacy_sensitive_archive.sql` map documents/access logs with strict owner mapping and preserved IDs/content. | [`tests/postgres/legacySensitiveArchive.integration.test.js`](../../tests/postgres/legacySensitiveArchive.integration.test.js) covers native dry-run rollback, runtime provenance denial, sequence continuation, null owners, and zero imported Judge receipts. `challenge_progress`, `ssi_templates`, historical sessions/resets, and file assets remain explicit archive-only dispositions. |
| `secureshop.db` + `secureshop_agents.db` | [`map-secureshop-archive.js`](../../db/postgres/map-secureshop-archive.js) and [`import-secureshop-archive.js`](../../db/postgres/import-secureshop-archive.js) cover commerce/agent rows, provenance, vector metadata and explicit asset review. Migration `secureshop_agents/0004_embedding_identity.sql` records the required provider/model/algorithm/dimension identity for compatible vector use. | [`tests/postgres/secureshopArchive.integration.test.js`](../../tests/postgres/secureshopArchive.integration.test.js) covers dry-run/late rollback, permissions, raw content, sequences, vector metadata, and asset-review gating. [`secureshopEmbeddingIdentity.integration.test.js`](../../tests/postgres/secureshopEmbeddingIdentity.integration.test.js) covers incompatible/unverified vector identities. Cross-schema application remains non-atomic. The active-store CLI can bind and restore explicitly mapped assets into new private staging roots; activation and vector sidecars remain separate. |

The checked-in readers and imports for FinFlow/CodeBot, MCP, CSRF, XSS and CTF now have the workshop operator CLI; ARIA/NOVA retain their dedicated command, described in [`data-migration-inventory.md`](data-migration-inventory.md). The platform identity/additional-solution imports are separate from challenge archive continuity. None of these statements authorizes importing a working database into a live destination without the family’s empty-target, review, identity, and timestamp checks.

## Remaining gaps

### `platform_secure.db`

The SQLite schema contains platform users, admin permissions, progress, challenge configuration, audit logs, system configuration, reset/verification tokens, notifications and sessions ([`server/database/platformDb.js`](../../server/database/platformDb.js)). The normal PostgreSQL startup path uses the identity/platform branches in [`server/index.js`](../../server/index.js), while [`server/secureServer.js`](../../server/secureServer.js) now rejects execution before any imports. Its historical source remains, but it cannot initialize the legacy stores.

No `platform_secure.db` archive mapper/importer is checked in. A future import must make explicit decisions for platform identity, audit/configuration, tokens, sessions and legacy challenge relationships; numeric IDs and session semantics cannot be equated with `users_auth.db` by name. These sources are retained archive-only under the explicit [legacy entrypoint retirement](legacy-entrypoint-retirement.md); the supported entrypoint is server/index.js.

### `owasp-ai-goat.db` residual tables and classic challenge sources

The `owasp-ai-goat.db` importer covers the ten generic demo families represented by the native `legacy_challenge` schema. It does not claim workshop progress, admin/session/configuration tables outside that mapping, or transfer of `files.file_path` and `products.image_url` targets. Those rows are preserved in verified source provenance and reported as metadata-only references.

The classic `sqli_challenge.db`, vulnerable `xss_challenge.db`, and `ctf_ai_challenge.db` tables are separate from the generic `legacy_challenge` importer. [`import-xss-archive.js`](../../db/postgres/import-xss-archive.js) covers the bounded XSS workshop/email/config rows; it intentionally does not claim the vulnerable classic XSS tables. No SQLi or CTF-AI archive importer is checked in. The alternate server is now retired before imports. Its classic APIs and separate historical stores are documented in the retirement record and retained archive-only; they are not merged into current `legacy_challenge` or `ctf` by filename similarity.

### `sensitive_info.db` residual semantics and assets

The native sensitive-info import deliberately maps only `documents` and `file_access_logs`. `challenge_progress` is retained archive-only and never becomes a native Judge receipt; `ssi_templates` has no native equivalent in the checked-in route path; historical reset/session semantics are not replayed. Owner IDs are mapped only where a reviewed identity map exists, and nullable historical owners remain null.

The document `file_path` values are references. The importer does not copy or verify their filesystem targets. [`db/postgres/asset-bundle.js`](../../db/postgres/asset-bundle.js) now supplies an offline, bounded capture/verification primitive, but it is not wired into this importer and does not restore files into working paths.

### SecureShop assets, vectors and operator path

SecureShop import requires an explicit asset review when local references exist and records `unverified_external_files` when no transfer proof is supplied. The importer now accepts a branded archive/reference-bound proof from freshly verified staged restoration. It records `verified_staging_at_capture_no_activation`, with bundle/reference/restore digests. The CLI connects this path through an explicit assetBundle review and --restore-assets-to option. It does not rewrite application paths or claim exhaustive attachment discovery. Historical vector rows retain their values even when identity is unknown, but search requires compatible identity or explicit rebuild; `.hnsw` files under `server/database/vector-indexes/` remain separate sidecars and must be rebuilt or captured under a versioned policy.

The commerce and agent schemas are imported separately, so the checked-in proof explicitly reports `crossDatabaseAtomic: false`. The [active-store operator workflow](active-archive-operator.md) now documents the plan/apply commands, commerce-before-agents ordering, separate commits, and staging recovery. Whole-installation orchestration remains manual. Explicit SecureShop runtime asset-root configuration and live cutover verification now exist; neither rewrites opaque references nor proves exhaustive asset coverage. See [the local upgrade runbook](local-existing-installation-upgrade.md).

### `excessive_agency.db`

The SQLite schema declares lab users, notes, orders, refunds, audit and progress, but the active lab uses process memory or the native attendee store ([`server/services/excessiveAgencyAttendeeLabStore.js`](../../server/services/excessiveAgencyAttendeeLabStore.js)). Native PostgreSQL tables exist under `excessive_agency`, but no SQLite-file importer exists. Continuity would require a quiesced process-memory snapshot and an archive-bound mapper; a database export must not be presented as the active in-memory lab snapshot.

## Explicit unknowns and boundaries

- Archive manifests may contain runtime-created tables or columns absent from initialization SQL. Unknown rows remain retained for review; a filename or familiar table name does not authorize discard.
- Route grep is not reachability proof. PostgreSQL engine branches and feature gates determine active consumers; secureServer.js is now explicitly retired.
- Filesystem assets, vector index sidecars, process-memory state, MySQL sensitive lookup data, `.env`/deployment configuration and cloud resources are outside the SQLite row import boundary.
- The asset-bundle primitive verifies explicitly listed, quiesced files into a new private bundle. It does not discover files, claim full symlink-race immunity, or restore assets into application paths.
- Operator commands now cover platform, ARIA/NOVA, legacy challenge/sensitive and both SecureShop stores. Other family libraries, per-family asset activation and whole-installation cutover still need the remaining operator integration.

## Next implementation priorities

1. Complete reviewed asset activation and required legacy challenge/sensitive file bindings; staged SecureShop proofs alone do not make application URLs resolve.
2. Connect remaining active family import libraries to the operator workflow and verify whole-installation cutover/recovery.
3. Keep the explicit secureServer retirement and source-only platform/classic challenge dispositions in release documentation.
4. Resolve Excessive Agency's process-memory continuity policy without presenting its historical SQLite file as a live snapshot.
