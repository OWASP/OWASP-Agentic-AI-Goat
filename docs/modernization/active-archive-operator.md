# Reviewed active-store imports

Use these commands for a verified SQLite export and **new staging PostgreSQL databases**. They do not modify the source export, replace a running installation, activate files, or merge histories into populated targets. Keep the original installation stopped and preserve its verified archive throughout cutover and rollback.

The normal fresh installer seeds demo data. These import targets instead require the schema migrations first, without normal demo seeding. SecureShop permits only its migration-created empty vector corpus defaults; the legacy sensitive-info importer requires its three native default documents. Importers refuse other populated targets. Use separate migration and runtime roles as created by the application provisioner.

| Target | Migration connection environment variable | Imported source |
| --- | --- | --- |
| `legacy_challenge` | `LEGACY_CHALLENGE_MIGRATION_DATABASE_URL` | Ten mounted generic demo table families from `dvaia.db` |
| `legacy_sensitive` | `FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL` | Documents and access logs from `sensitive_info.db` |
| `secureshop` | `SECURESHOP_MIGRATION_DATABASE_URL` | Commerce data from `secureshop.db` |
| `secureshop_agents` | `SECURESHOP_AGENTS_MIGRATION_DATABASE_URL` | Agent history, registry and vector data from `secureshop_agents.db` |

Both SecureShop commands verify both source envelopes so their relationship review is bound to the same archive digest. Platform identity migration and ARIA/NOVA have separate commands; this command does not replace them. Sensitive-info owner mappings must refer to reviewed platform identities, never guessed matches between numeric IDs.

### Legacy Sensitive owner binding

Import platform identity before planning a committed Legacy Sensitive import. The Legacy Sensitive review envelope must include both mappings below:

- `identityMap` records the disposition of each owner found in `sensitive_info.db`. A positive target ID must equal the corresponding platform mapping. A `null` target is an explicit reviewed orphan and is accepted only when that source ID is absent from the platform mapping.
- `ownerBinding` is the complete `{archiveDigest, identityMap}` that the platform identity import persisted. It is not a subset containing only owners used by this challenge.

The planner deliberately emits `ownerBinding: null`, `requiresPersistedOwnerBinding: true`, and unresolved `null` owner targets. These are prompts for operator review, not apply-ready defaults. Do not infer an owner from a matching current PostgreSQL ID. Before it opens the Legacy Sensitive target, the active apply command verifies the binding receipt in the identity database and checks that every mapped target exists. That proof is a point-in-time cross-database check; it is not a distributed transaction. Keep identity and challenge writes quiesced throughout the reviewed cutover.

## Plan, inspect, then dry run

Generate a proposal with the plan command. It reads the verified export and opens no PostgreSQL connection:

```sh
npm run db:legacy:plan-active -- --archive /private/export --target legacy_challenge
```

The result contains `report` and `reviewEnvelope`. Save the output privately, inspect the proposed retained-table, missing-table, timestamp and asset dispositions, then save the reviewed `reviewEnvelope` as a separate JSON file. These are operator decisions: the plan does not prove that retaining historical rows outside the live application meets your workshop requirements. Unknown columns or invalid relationships remain errors rather than being silently discarded. An explicit `--naive-timestamps UTC` policy is available only when the historical timezone is known to be UTC.

The apply command expects the review envelope's target to match the command target. It verifies archive hashes and mapping before connecting. Export only the appropriate migration connection variable from your private staging configuration, or use Node's `--env-file` option with that configuration. Never put a connection URL in shell history or the review JSON.

```sh
npm run db:legacy:apply-active -- --archive /private/export --target legacy_challenge --review /private/review.json
npm run db:legacy:apply-active -- --archive /private/export --target legacy_challenge --review /private/review.json --apply
```

The first command checks native constraints and rolls back rows, provenance and sequence changes. The second commits one target transaction. Keep the JSON reports with the archive. Output contains mapping/count metadata, not raw teaching content or connection credentials. Errors expose a bounded error code.

## SecureShop assets

The baseline `assetReview` explicitly acknowledges metadata-only references; it does **not** verify files. For staged file proof, replace that field with `assetBundle` containing `bundleRoot`, `manifestDigest` and `mappings`. Each mapping names the exact `source`, `table`, `key`, `column`, SHA256 of the original path as `referenceSha256`, and explicit bundle `sourcePath` and restored `targetPath`.

Capture only explicitly listed, quiesced files using `captureAssetBundle()` from `db/postgres/asset-bundle.js`. It creates a new private directory and deterministic manifest. It never follows a database path automatically. The bundle supports up to10,000 files,64MiB per file and512MiB total. Relative paths cannot traverse parents or follow symlinks.

With the reviewed `assetBundle`, add `--restore-assets-to /private/new-staging-directory` to the apply command. Even a database dry run creates this new file staging directory; use a distinct destination for each invocation. Every mapped reference must match its original archive value, and every bundled file must be accounted for. Shared references may point to one file. Verification and copying use bounded reads and exact hashes.

The database import receipt records bundle, reference and restore digests. Its status is `verified_staging_at_capture_no_activation`: proof describes bytes at capture time. Neither that status nor a successful database commit claims that application URLs resolve to the staged files. Attachment JSON and other opaque content are preserved but are not an exhaustive asset-discovery manifest. Activation requires a separately reviewed path mapping and application verification.

## Ordering and recovery

Run the platform identity import before stores requiring its owner mapping. Dry-run both SecureShop targets against their separate staging databases, using the same reviewed archive. Apply commerce, then agents. The two commits are independent: `crossDatabaseAtomic` is always false.

FinFlow and Legacy Sensitive share a PostgreSQL database but have independent import receipts. New Legacy Sensitive imports write `legacy_sensitive.import_batches` and `legacy_sensitive.import_provenance`; FinFlow continues to write its own tables. Migration `finflow/0007_legacy_sensitive_import_provenance.sql` moves exact `sensitive_info.db:` historical provenance and the `legacy-sensitive-v1` receipt out of the old shared FinFlow audit tables while preserving its archive digest, timestamps, decisions, and any historical unbound `NULL` identity-map hash. Other FinFlow provenance remains in place. This separation permits either FinFlow-first or Legacy-Sensitive-first imports without overwriting the sibling receipt. New Legacy Sensitive receipts use importer version `legacy-sensitive-v2` and include the verified owner-binding digest.

If either command fails, stop the cutover. A failed database transaction rolls back its own rows and sequences; an already committed sibling store remains committed. Do not retry a completed target blindly or delete an import marker. Inspect migration-role `import_batches` and the saved reports to identify the completed target. Resolve the failing target in staging and resume only that target, or provision a fresh pair and repeat the reviewed import. Never reset the source installation to recover staging.

An asset failure leaves `INCOMPLETE` in the new owned directory. A later database failure may leave a complete asset staging directory, but it remains inactive. Retain it for diagnosis or remove only that explicitly owned directory, then choose a new destination. Do not overwrite or delete working uploads.

Keep imported SecureShop vectors out of search until their embedding identity is verified or an explicit homogeneous rebuild succeeds. Historical vectors with unknown identity are retained for provenance; HNSW sidecars are not assumed portable. The application rejects mixed/unknown identities instead of silently combining incompatible embeddings.

A successful Legacy Sensitive database import preserves source asset references as metadata only. It does not copy or activate referenced files, create Judge receipts from historical progress, or make retained archive-only tables live. Treat the database receipt, owner proof, asset restoration, and application activation as separate evidence.

The retired `server/secureServer.js` entrypoint and its unique historical platform/classic challenge namespaces are documented in [legacy entrypoint retirement](legacy-entrypoint-retirement.md). The remaining whole-installation boundaries are in [release status](release-status-2026-09-11.md). This workflow provides reviewed per-store imports and staged proofs; it does not advertise an automatic lossless in-place upgrade.

## Select and verify SecureShop's restored asset tree

The backend and agent host share `SECURESHOP_UPLOAD_ROOT`. Its default retains the existing repository location. An explicit value must be an absolute path. This selects the root for both upload writes and download/static reads; the intentional challenge traversal, MIME and inline-rendering behavior is preserved.

For a reviewed local cutover, keep both installations stopped. Preserve the old private environment file, database URLs and upload root. Use the same verified archive and asset mapping for both SecureShop imports. Each mapped legacy reference must retain its runtime-relative layout: for example, `server/uploads/secureshop/product_images/7/image.png` maps to `product_images/7/image.png` in the restored tree. Arbitrary absolute references and renamed target layouts are not automatically rewritten. Other active-store import commands and their owner-binding order remain separate.

Set the candidate's private `SECURESHOP_UPLOAD_ROOT` to the verified restored `assets` directory and select the candidate PostgreSQL URLs. Restart the candidate backend and its agent host together. Then run the check against its loopback origin, using the reviewed commerce envelope and the corresponding restored directory:

```sh
npm run db:legacy:verify-secureshop-assets -- --archive /private/export --review /private/commerce-review.json --restore /private/restored --base-url http://127.0.0.1:8081 --receipt /private/new-cutover-receipt.json
```

The command reads both `SECURESHOP_MIGRATION_DATABASE_URL` and `SECURESHOP_AGENTS_MIGRATION_DATABASE_URL` from the operator's private environment. It verifies each committed archive/import staging receipt, the exact reference bindings and restored bytes, then compares every mapped static URL's bytes with its recorded hash. It verifies the restored tree again afterward and creates a new private receipt exclusively. Missing files, changed bytes, unsupported layouts, redirects, unavailable HTTP routes and incompatible import records fail without a success receipt. Existing receipts are never overwritten. Files restored separately for the two database dry runs/commits must have the same deterministic restore-manifest digest; an arbitrary different tree is rejected.

This is a point-in-time observation of mapped static files at the supplied candidate. It does not edit environment files, restart processes, attest which process owns the URL, rewrite database references, verify every product/manual route, or make database commits atomic. Keep writes quiesced during the check. Verify product images in the UI and download/MCP continuity before admitting attendees. Imported manual vectors still require the documented compatible rebuild; a successful file check does not enable unknown embeddings.

If candidate checks fail, stop its backend and agent host, restore the prior environment/database URLs/upload root, and restart the old installation. Keep the failed candidate and reports separate for diagnosis. Do not overwrite old uploads or delete import receipts to retry. Historic return evidence without mapped database references, opaque attachment JSON and retired source-only data require their explicitly reviewed inventory/disposition; this check does not silently expand asset coverage.
