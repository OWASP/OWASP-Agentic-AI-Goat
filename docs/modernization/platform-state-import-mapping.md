# Canonical platform state import mapping — review draft

The shared archive reader bounds manifests to 4 MiB, each schema to 8 MiB,
each table payload to 128 MiB, and one complete archive read to 512 MiB. It
uses no-follow descriptor reads and rejects declared oversize, size mismatch,
or file identity, size, and timestamp changes observed across a read.

The offline validator/mapper is implemented in `db/postgres/map-platform-snapshot.js`; transactional apply primitives are implemented, while complete archive coverage and the end-to-end import command remain in progress. Inspection used checked-in `01_users_auth.sql`, platform migrations, catalog and seed code only. No working SQLite database was opened. ARIA/NOVA archive imports are independently verified; they do not establish platform import completeness.

The mapper requires explicit identity mappings and an archive SHA256. It rejects ambiguous timestamps by default; the explicit UTC policy adds a timezone without losing microseconds. It reports missing exercise/objective/hint rows and populated unmapped tables as requiring review, rather than silently applying seed defaults. Ten focused tests cover these contracts, conflicting rows, independent hints and historical provenance.

`db/postgres/read-platform-archive.js` now verifies completed export manifests and payload hashes, rejects unsafe paths and incomplete archives, and supplies decoded canonical rows to the mapper. Unknown platform tables retain JSON-safe integer/real/blob tags, while other archive sources are explicitly listed for their separate adapters. Sixteen reader/mapper regressions pass. This is offline validation only: it neither writes a database nor resolves solution precedence, and archive hashes do not independently prove source quiescence.

## Exact first adapter scope

The source is the completed, hash-verified `users_auth.db` archive entry. User IDs must already have a validated identity import mapping; matching usernames or numbers from challenge databases are not sufficient. Use the shared workshop catalog challenge-key mapping; reject unknown keys for active canonical state.

| Legacy table | Native destination and conversion |
| --- | --- |
| users, admin_permissions, user_sessions, activity_logs | Existing identity import contract, preserving verified IDs/hashes. Validate remaining identity columns and session revocation/expiry policy separately; do not pretend four collections cover all account state. |
| challenge_visibility | workshop_platform.exercises: challenge_key resolves workshop_key; preserve name/description/category/difficulty/route, is_visible/show_hints/show_solutions, updated_by/time. Legacy integer flags require exactly 0/1. Native ordinal/catalog_active derive from the current catalog, not archive ordering. |
| workshop_objective_visibility | objectives.is_enabled and update metadata, joined by exact workshop_key/objective_id. Missing rows require an explicit catalog-default policy, not silent omission. |
| workshop_hint_visibility | objectives.hint_enabled independently of solution visibility and exercise show_hints. Preserve update metadata in the import provenance when several sources collapse into one updated_at. |
| workshop_hints | objectives.hint_content = {title,hints}; decode valid hints JSON without changing strings/order. Original raw JSON bytes remain in the archive because JSONB normalizes representation. Invalid JSON blocks that mapped row/import pending explicit remediation. |
| workshop_objectives_progress | completed=1 maps to completions using original completed_at and updated_at; completed=0 is not a completion. Legacy labels/categories/row IDs/created_at remain in provenance because native completion rows lack those fields. Never infer objective passes from workshop-level status. |
| workshop_time_tracking | time_tracking: preserve ID, owner, workshop key, session_start, last_heartbeat, nonnegative integral duration_seconds. Preserve every valid session row; do not sum into a replacement row or use elapsed wall time. Native identity restart follows maximum imported ID. |
| workshop_user_modes | user_modes: require exact decimal platform identity resolution for source text user_id; preserve mode and creation/update timestamps. Keep allowed vulnerable/vuln representation or record explicit normalization. Reject unmapped guest/demo keys instead of coercing them into a platform user. |
| workshop_progress | No one-to-one objective destination. Its challenge_id/status/completed_at cannot establish which objectives passed. Archive it; optionally use validated created_at as a documented started_at candidate, never synthesize completions. |
| workshop_config_revision, app_change_revisions | Existing counters are polling state, not grading evidence. Preserve in archive; initialize a new revision epoch/bump after atomic import so connected clients reload. Do not import stale process revision values as active fences. |

Create user_state rows for imported progress/time/modes with generation 0 as a **new native epoch**, not a claim about historical resets. Prefer the earliest validated activity timestamp for started_at; document which source contributed it. Do not reopen old sessions or award elapsed time since export.

## Editable solution mapping

Target `objectives.solution_content` must match the public solution DTO, while `solution_enabled` is a separate flag. Proposed exact content sources:

- DPI: prompt_injection_solutions, joined through reviewed challenge_id→objective mapping; prompt_injection_solution_visibility controls per-objective visibility.
- IPI: ipi_solutions + ipi_solution_visibility.
- EA: ea_solutions + ea_solution_visibility; review numeric/`objective_N` key representation explicitly.
- MCP: mcp_workshop_solutions + mcp_workshop_solution_visibility.
- ARIA: sql_injection_solutions + sql_injection_solution_visibility.
- NOVA: nosql_injection_solutions + nosql_injection_solution_visibility.
- XSS: xss_workshop_objective_solutions (objective_id/exercise_id/title/hint/example/explanation/solutions_enabled).
- CSRF: csrf_workshop_objective_solutions with the same objective DTO.

For array-style solution tables, preserve title/difficulty/hints/examples/approach/tips exactly after validated JSON decoding. XSS/CSRF use their distinct existing DTO, not an invented conversion to array-style examples. The master challenge show_solutions flag and per-objective solution_enabled remain separate; hint flags/content never change either solution flag.

## Ambiguities requiring an explicit import decision

1. XSS legacy tab solutions and the 12 canonical objective solutions now have separate native destinations. Both are preserved independently; neither takes precedence over the other. Generic challenge_solutions/challenge_config and unknown runtime-created tables still require explicit source review.
2. FinFlow and CodeBot editable solutions primarily live in their native legacy workshop databases. A users_auth-only import cannot reconstruct them. Preserve those archive entries and join only through approved mappings later.
3. NOVA's local nosql_workshop.db solutions duplicate users_auth definitions. ARIA/NOVA importer copies local rows without changing canonical content. Conflict reports must compare both; do not overwrite instructor edits with seed defaults or dialect-converted defaults.
4. Runtime authDb/admin schema can contain tables absent from schema01. Unknown archive tables must remain archived and appear in an unmapped manifest. The above list does not authorize dropping email inbox configuration, sent mail, victim state, user settings, security tokens or system configuration.
5. Historical dvaia.db progress is a separate candidate source. No automatic merging with users_auth or challenge-native green flags; require explicit owner/key/conflict mapping.
6. Unknown/retired objective IDs, missing users, orphan foreign keys, malformed JSON, absent completion timestamps or conflicting duplicate keys block automatic import. Retain archive data. Do not add retired IDs to the active106 catalog or invent dates/users.

## Historical completion provenance

Preserve accepted legacy completion flags as **historical imported completions**, without generating objective_judgments, graph runs, evidence digests, model names, pass criteria or grade packets. Those observations never existed. Before implementing, add an immutable import provenance ledger linking each imported completion to archive hash/source table/source row, original timestamps and importer version. Dashboards can honor the completion while inspection distinguishes imported history from judged completion. A later reset deletes current credit normally but retains provenance/history; a later real attempt creates a new genuine judge receipt. Never call scoring routes or tools to manufacture history.

Inspection must identify the specific completion event, not merely find any historical row for the same owner and objective: imported history survives reset and must not relabel a later genuine Judge award. The apply transaction must write the current completion and its provenance together. The provenance table alone grants no completion. Runtime access is read-only; migration tooling inserts records and ordinary update/delete/truncate operations are rejected. Source row identifiers are stored as a versioned canonical primary-key digest; the original row remains in the verified archive.

## Empty-target ordering and atomicity

1. Provision the dedicated identity database/roles; run schema migrations only. Do not invoke fresh setup administrator bootstrap or normal seeds first.
2. Validate the complete source archive and all mappings/conflicts offline. Require empty identity user/business state; allow only migration-created singleton revision rows. If an administrator already exists, refuse this initial adapter instead of merging.
3. In one destination transaction, lock config then target tables in the established order, recheck emptiness, import identities, seed **catalog structure only**, overlay reviewed visibility/content, then import user state/completions/time/modes/provenance. Standard seeding must not later overwrite imported content/flags. Missing content defaults require explicit recorded approval.
4. Dry run executes validation and native constraints then rolls back. Apply restarts sequences transactionally and publishes one new revision epoch. No new admin is created; validate a preserved administrator login or use a separate explicitly authorized recovery procedure.
5. Verify DB-derived totals/completions/time across all dashboards, decoupled hint/solution visibility, catalog106 parity, owner isolation, restart stability and reset/regrade fencing. This review gate remains open until the adapter and these tests exist.


## Implemented atomic primitives

`preparePlatformImport` reruns the mapper and requires archive-bound decisions for missing catalog defaults and every retained table. `applyPlatformSnapshot` requires an existing transaction and an empty platform/graph/provenance destination. It copies configuration, hints, historical completions, individual time sessions and modes, starts a fresh generation epoch, and records immutable completion provenance without inventing Judge receipts.

`importIdentityInTransaction` composes identity insertion with that apply step. `importPlatformIdentity` owns the combined transaction, checks initial configuration and a preserved active administrator with user-management permission, and defaults to a native constraint dry run that rolls back both identities and platform state. It accepts explicit decoded collections, not an unverified claim of complete archive coverage. Remaining source families and the archive-to-command coordinator must be completed before declaring lossless migration ready.

The pure solution mapper covers52 content rows and52 independent visibility rows across DPI, IPI, EA, MCP, ARIA and NOVA. Matching duplicate NOVA sources retain both origins; disagreements require independent archive-bound content/visibility choices. Static defaults never overwrite instructor edits. The mapper reports legitimate gaps separately from missing source rows.


## Durable batch records

Coordinator `platform-identity-v3` records `identity.import_batches` in the same transaction as identities, canonical state and optional solution application for all ten workshop families. The row stores archive and deterministic plan digests, bounded counts/coverage and approved policy identifiers. It stores no source content, credentials or user names. Unknown retained table names are represented by digest. Timestamp interpretation and retained incomplete rows are explicit metadata. A late batch insertion failure rolls back every prior write and sequence change; successful batches are append-only and survive later application resets.

The combined native test now applies all100 source-backed canonical solutions and four separate legacy XSS content/visibility pairs. It verifies mapped actors, raw legacy text, dry-run and late-batch-failure rollback, and non-overwriting restart seeds (`/tmp/dvaia-combined-v3-native.log`). The additional mapper/apply suite passed8 tests and the focused combined mapping/ledger suite passed22. Six catalog objectives have documented no-source gaps; structural catalog defaults do not invent editable source content.

`additionalSolutions` accepts the XSS/CSRF tables from users_auth.db and FinFlow/CodeBot tables from their own archives. Legacy XSS JSON fields remain raw text to preserve existing preview fallback behavior. Non-null legacy actors require an explicit identity map consistent with the platform import; naive timestamps require an explicit UTC policy. Migration0014 starts the compatibility tables empty, and normal seeding uses non-overwriting inserts only after import. The five legacy admin routes are restored independently of canonical student solution gates. Retired CSRF tab data remains an explicit unresolved retention review, with no new runtime namespace.

The complete archive operator command and remaining source coverage are still open; this tested library accepts explicit decoded collections and does not claim a complete lossless migration.

## Identity metadata review

`reviewIdentityArchive` recomputes normalization records from the private source DTO and requires an exact archive-bound decision for every affected field. Missing, extra, duplicate and stale decisions reject. The explicit policy applies the native metadata allowlist/JSON representation while retaining original values in the verified source archive; it does not claim that the normalized native audit/device fields are lossless copies. `preparePlatformArchive` can validate this review during its single-read projection. The private raw token DTO remains unchanged, and the overall plan remains unready for apply until remaining defaults and source-coverage decisions are implemented. Four focused review/preparation tests pass.
