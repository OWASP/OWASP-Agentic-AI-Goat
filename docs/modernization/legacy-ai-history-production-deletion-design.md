# Private AI history deletion integration

The production successor keeps the existing student-deletion manifest. Adding a
`legacy_ai_history` step would quarantine admitted jobs because recovery checks
the exact ordered manifest. Adding cleanup only to `legacy_challenge` would miss
jobs already beyond that step.

The candidate instead calls private-history cleanup from the database's existing
`identity.finalize_student_deletion`, after authority checks and before content
removal and account tombstoning. Cleanup verifies the live lease, inactive student,
pending/failed identity step, and completed predecessors. Its receipt supports
retry under a current lease. Calling the database finalizer directly cannot omit
private cleanup. Both operations roll back together. The current finalizer body
is otherwise identical to migration 0079, preserving XSS redaction controls.

The historical experiment remains unchanged. The qualified schema is registered
as identity migration 0080 and source migration 0004. These are additive schema
changes: they import no rows and change no mounted route. The installed legacy
history endpoints are not yet protected by the planned route cutover.

Qualification covers current-manifest jobs admitted before the candidate,
including jobs already past legacy cleanup; migration replay; direct finalizer
calls; failure/reclaim; stale leases; explicit transaction rollback; receipt
replay; sibling history; owner archive removal and preservation of unknown and
sibling archive records; invalidation of archive batch receipts; and private
schema privilege readiness. Predecessor acknowledgments are controlled fixture
operations, not proof that every external deletion adapter ran.

Fresh whole-chain migration, no-op replay, and a database-observed import/deletion
blocking race also pass against the candidate; see tasks/legacy-ai-history-fresh-race-2026-09-19.json.

Still required before production cutover: broader concurrent reset qualification,
mounted-route readiness,
operator-attested source ownership, lossless quarantine and source cleanup,
protected route/mutation composition, and synthetic-only vulnerable history.
Already inactive/deleted owners must never regain history through import.

Source cleanup is registered as legacy migration 0004; its qualified candidate
is retained in `drafts/legacy-ai-history-source-cleanup.sql`. The coordinator
binds it to locked target quarantine. It is not autonomous deletion authority;
production operator tooling and route activation remain pending.
The existing legacy owner deletion function trusts mutable platform_owner_id and
cannot serve as import cleanup. The importer receipt proves quarantine only;
there is no implemented transition to source_removed. The next implementation
needs migration-only source batch/row receipts, exact-byte conditional removal,
and a cross-store coordinator that holds/revalidates target archive state through
source commit, then acknowledges or safely replays. Student deletion invalidates
verified batches, so a cached verification receipt cannot authorize removal.

An unmounted operator coordinator now validates exact seven-field archive records
and aggregate under a target batch/row lock, commits exact source cleanup, then
acknowledges source_removed. Native tests force acknowledgement failure after the
real source commit and prove replay from its durable receipt while quarantine is
unchanged. Unexpected archive fields are rejected before source access.

Deletion-during-recovery now reconciles from the committed source journal while
holding the target batch lock and the source writer lock. Original source IDs
must remain absent. A single digest-bound source_cleanup_committed event records
acknowledgement independently of archive state; the archive stays blocked and
no deleted rows are recreated. Missing journal receipts fail closed. Source
sessions use UTC so timestamp JSON hashes survive operator timezone changes.
Native tests exercise canonical student deletion between source commit and retry,
plus timezone replay. Evidence: tasks/legacy-ai-history-deletion-reconciliation-2026-09-19.json.

Actual process interruption is now qualified: an owned Node migration worker is
killed with SIGKILL after source commit and before target acknowledgement. Independent
connections observe the durable source receipt and retained quarantine; a fresh
coordinator recovers. Evidence: tasks/legacy-ai-history-crash-recovery-2026-09-19.json.
A transport fault while the COMMIT response is in flight remains distinct from
this proven boundary. Production route activation is still pending; the
installed application and learner data are unchanged.

Activation file map (source review):
- Registered identity0080 and legacy0004; SourceSnapshot now requires the exact
  reviewed four-migration ledger. Prior migrations are unchanged.
- Compose protected history with canonical postgresIdentityAdapter and real
  legacy experiment inference during awaited server/index.js startup, before listen.
- Replace all four routes/ai.js saveConversation paths; preserve the existing
  checkVulnerabilityAccess gate now required by the detached router/composition.
  Inject the canonical prompt_injection middleware; authentication precedes it.
  Forty-three controlled checks pass (tasks/legacy-ai-history-availability-2026-09-19.json).
- Preserve intentionally vulnerable history GETs against synthetic-only data;
  do not rely only on removing application writes because raw runtime DML persists.
- StudentDeletionProduction readiness now requires private cleanup as well as
  the finalizer; a missing capability rejects readiness.
- Fresh setup may initialize empty private schema plus declared synthetic seeds.
  Existing installations require explicit operator attestation/import/cutover;
  ordinary startup must not perform destructive migration.
- Separate trusted deletion authority from the raw challenge runtime capability.
  Legacy history extraction remains an ungraded synthetic lesson unless its
  canonical exercise inventory is deliberately changed and requalified.

Inference mounting prerequisite: the request service must provide a trusted
per-request execution context to createLegacyAiExperimentProduction.run. It
needs owner/session/generation, request cancellation and a live generation check;
a shared closure or no-op authority check would lose lifecycle fencing. Actor
and Judge configuration are resolved independently from operator environment,
with no mock fallback used as model proof.


Production source integration, 2026-09-19: `server/index.js` now registers the
protected dispatcher before the retained AI teaching router and awaits its
readiness before listening. The four old POST handlers, raw history writes and
offline fallback successes were removed. Real actor/Judge inference uses operator
configuration through the new adapter. Current focused and disposable native
HTTP verification is recorded in `tasks/legacy-ai-history-production-mount-2026-09-19.json`.
Native inference in that cohort is controlled, not actual-model qualification.
The installed process has not been restarted.

This completes the new-request source mount only. Historical source isolation is
still incomplete: the retained intentionally vulnerable SQL GETs can access old
learner rows. Moving the SELECT to another table or filtering owner columns does
not establish isolation against qualified-name/UNION injection. The next cutover
must establish a database privilege boundary while preserving the teaching sink
and retaining all existing data through the attested archive path. Nothing in
ordinary startup automatically imports or deletes historical source rows.


Historical source privilege isolation, 2026-09-19: forward migration
`legacy_challenge/0005_private_history_boundary.sql` now retains the original
source table and bytes while revoking runtime/PUBLIC table, column and sequence
privileges. A separate read-only fictional table serves the intentionally
vulnerable history GETs. Qualified source references and UNION extraction are
denied, while injected predicates still expose the two fictional identities.
The admin teaching GET reads fictional usernames directly rather than joining
imported users. Startup checks actual roles/privileges and the exact reviewed
deletion helper body; the runtime helper no longer reaches historical history.

This supersedes the raw-history exposure limitation above for the current source
and qualified migrated schema. Migration0005 neither copies nor removes source
rows. The migration-only snapshot and exact cleanup retain the original table
name and now require the five-file source ledger. Operator attestation/import
remains necessary to promote known history and apply deletion to proven owners;
mutable historical owner columns alone do not authorize erasure. Canonical new
private history continues to use identity-finalizer cleanup. Native HTTP,
populated/replay, source snapshot/recovery, legacy import and other owner-deletion
checks pass; see `tasks/legacy-ai-history-source-boundary-2026-09-19.json` for exact
coverage and corrected launcher failures. No installed PostgreSQL migration or
application restart was performed.

Configured model qualification: the operator-selected Ollama actor and independent
Judge both ran against the installed `llama3.1:8b` digest for all four baseline
experiment routes. Eight actual transport calls completed, with fourteen trusted
execution checks per route. Each benign request produced a non-completion verdict.
The hash-only report is `tasks/legacy-ai-configured-inference-actual8b-2026-09-19.json`.
This establishes the configured adapter's real-model baseline path, not positive
attack solvability, mounted persistence or installed browser acceptance.


Operator glue is implemented in `scripts/legacy-ai-history-cutover.js` and
`legacyAiHistoryOperator.js`. The separate plan/quarantine/cleanup commands bind
both store endpoints and a stable reviewed-record digest, use owner-private
no-overwrite files, and retain unknown classification. Actual CLI child-process
qualification passes in disposable stores, including changed-plan rejection and
cleanup replay. See `legacy-ai-history-operator.md` and
`tasks/legacy-ai-history-operator-2026-09-19.json`. This closes the archive-only
operator tooling gap; independent row ownership attestation/restoration remains
unavailable, and no installed source data has been moved.
