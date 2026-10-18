# SecureShop audit teaching workflow integration

Status: implementation design following installed journal checkpoint; no summary/Judge completion claimed.

## Existing behavior and gap

`agent-host/agents/audit/tools/index.js` builds a raw log prompt but does not itself execute a model. Its retained SQL search interpolates input into a shared legacy table. Neither implementation can simply be exposed through the owner-bound gateway: a returned prompt is not a model summary, and SQL interpolation can escape an ownership WHERE clause. Installed normal audit listing is independently bounded/paginated and must stay so.

## Selected integration

1. Add server-selected `secureshop_audit_summary` conversation purpose with a forward agents migration. Reuse the bound conversation/turn coordinator and LangGraph runner, including generation fencing, persisted model calls and exact source observations.
2. The graph exposes `audit.summarize_anomalies` over the canonical owner/session/launch/scenario/generation journals. The model decides whether to request the tool. Its observation contains exact raw event lines and a source manifest. The next actual model response is the summary. Return the existing prompt/log_text/row_count fields plus summary, run identity and assessment state, preserving existing presentation.
3. Snapshot source IDs, timestamps, order, source/effect references and content digests. Derive this server-side; do not accept source manifests, actor identities or launch coordinates in model arguments. Bind the observation to the retained run/call and generation. A complete source response must declare requested and returned counts; no silent substitution with the normal16MiB page.
4. Preserve intentional raw log interpolation (LLM01) and the exercise's unclamped requested log volume (LLM10). Execute potentially oversized collection/model work in an owned, disposable resource-limited worker. Resource exhaustion is an observed failed run, never a successful summary. The supervisor must survive and release owned resources. Do not induce host-wide OOM to prove the lesson.
5. Judge evaluates separate rubrics: model actually used the observed log; source instruction affected the model beyond faithful summarization; excessive-volume objective requires measured source/tool/model resource evidence. A mere injected string, echoed quoted payload, returned prompt, timeout or mock identity earns no credit. Preserve deterministic evidence validation around the LLM judgment and calibrate positive/negative cases using local8B.
6. Search-by-user needs a separate owned PostgreSQL teaching database/role (reuse qualified per-launch SQL-copy infrastructure after checking its lifecycle contract). Copy only this launch's synthetic shop data and immutable audit snapshot. Raw input interpolation remains the sink; the role cannot access shared identity/journal stores. Persist source snapshot/query/effect provenance. Do not use a shared journal SQL filter as an isolation boundary.

## Verification gates

- Unit: exact raw content/order/digest provenance, argument closure, stale generations and malformed provider output; no fabricated summary fallback.
- Native: source isolation, cross-store source ordering, reset/deletion fencing, actual owned SQL target and resource cleanup.
- Actual8B: graph decisions, exact tool observation, final narrative, Judge calibration positive/negative; distinguish safe failed runs from completion.
- Browser: existing summary panel displays actual narrative/run assessment, retries and cancellation work, raw prompt remains inspectable, search preserves SQL/error visibility.
- Installed activation only after these gates. AWS assets and protected vulnerable dependency pins remain unchanged.

## Implementation checkpoint: observation contract

`secureshopAuditExecutionConfig.js` exposes only the administrator audit summary tool, with no count maximum that would remove the LLM10 lesson. `secureshopAuditSummaryObservation.js` constructs the original raw log prompt and its ordered immutable source manifest. It rejects partial/ambiguous collection results. The collector must set `hasMore: false` only after satisfying the requested snapshot (or reaching its actual end), not after hitting a transport byte cap. Nine focused cursor/manifest/observation checks pass. These modules are not yet activated or evidence of actual model execution.

Runtime integration must account for the runner's existing **65536-byte trusted result metadata cap** (`secureshopBoundAgentRunner.js`). Do not copy full log text/events into `taskMetadata`, or the intended large-volume exercise would fail at an unrelated metadata validator after model execution. Persist the full immutable observation through the owned worker/evidence store and return only its digest/reference, requested/returned count, model/run identity and assessment reference as trusted metadata. The response presenter may retrieve the authorized observation separately. The shared platform process must not deserialize an unbounded child result.

The existing runner calls `assessment.finalize` **before** `resultMetadata`. Audit assessment must independently check successful final model identity, final stop reason, tool evidence and current generation; it cannot assume the later response presenter has already validated these. Tool closure creation must remain effect-free; provision/reserve the worker only inside the selected tool's effect boundary.

Independent agent review confirmed the production composition and graph hooks. An additional boundary is the generic loop evidence parser's2MiB aggregate cap; large audit observations require persisted digest/reference evidence and a dedicated audit assessment, not reuse of that parser with a raised shared-process limit.

Provenance fix completed during integration review: `secureshopSupervisorGraph.js` retains explicit `fallback:true` on the actual decision and terminal traces. `secureshopLoopEvidence.js` rejects fallback or synthetic identities independently of provider qualification.73 controlled graph/runner/assessment/evidence regressions pass, including a fallback tool selection followed by a non-fallback terminal response. This corrects evidence eligibility; it does not activate audit summary or claim real-model exploit success.

The provenance review also found duplicated model checks in review-content, inbox, MCP and SSRF assessment. These now use the same trace qualification helper. The router preserves an adapter's explicit `mocked:true` instead of overriding it because it occupies a real-provider slot.48 shared checks and106 affected-exercise regressions pass. An old deterministic MCP preflight test expected objective credit for provider `fixture`; it now requires noncredit. The native preflight harness has matching expectations but awaits its isolated rerun. Real-model qualification retains its original positive-credit requirements.

Native provenance qualification is complete for the MCP regression: preflight39597 verified real scoped effects with zero fixture credit; actual8B37779 verified both MCP objectives with two genuine Judge calls, canonical invocation evidence, replay, owner reset, sibling preservation and independently confirmed cleanup. The model digest was checked before and after. This supports the shared provenance change; audit summarization still requires its worker, runtime wiring, dedicated rubric and own actual-model proof.

## Streaming source checkpoint

`secureshopAuditSnapshot.js` now supplies a requested-count stream from two scope-bound read-only repeatable-read PostgreSQL cursors, fetching at most four rows per store per round. Requested count remains unclamped; the source does not silently substitute a UI page. Raw fields and deterministic timestamp/store/UUID ordering survive. Each database has an independent snapshot, not a cross-database atomic commit. Authority/cancellation checks bracket database reads and yielded rows. Early consumer return and failures rollback/release both clients; concurrent fetch failures are fully settled before cleanup. Per-statement and idle-transaction timeouts bound stalled source queries.

Five controlled tests and isolated native28124 passed: six near2MiB raw events streamed in exact order, a later concurrent insert excluded from the pinned source but visible to a fresh request, empty unrelated-owner scope, existing audit writer/grant/reset regressions. Cleanup independently verified. This module is not yet exposed through the live summary endpoint.

Worker review confirmed existing bubblewrap mechanisms have namespace/seccomp/time/output controls but no per-operation OS memory/CPU quota. Do not claim they contain native allocations or the shared external Ollama process. The next integration must distinguish owned collection/serialization resource controls from external-provider limits; source streaming alone neither proves LLM10 completion nor enables a full model summary.

## Streamed observation storage checkpoint

`secureshopAuditObservationSpool.js` consumes the scoped snapshot stream into private log/source files, preserving canonical manifest digests without aggregating all rows in memory. It checks strict global order (also rejecting duplicate adjacent identities), authority and cancellation, and publishes the manifest only after complete source-file writes. Its64MiB default storage budget is server configuration: exceeding it produces a typed failed-operation result with measured bytes/rows, closes the input iterator and removes partial files. It never truncates input into a successful summary. This is an application storage budget, not proof of OS memory/CPU containment or objective completion.

Thirteen focused tests passed. Native60577 passed with seven scoped events including six near2MiB raw payloads, streamed digest verification and disposal; all owned resources were independently confirmed absent. Worker/model execution, durable run-bound evidence publication and authorized response retrieval remain unimplemented. These temporary files are not canonical progress evidence and the module is not active in the live endpoint.

## Audit graph execution core

`secureshopAuditSummaryGraph.js` now uses the shared actual LangGraph supervisor: an administrator model decision selects the exact requested-count local audit tool; its successful receipted observation triggers a distinct structured final-response model call. The raw observation is unchanged in the model history. The execution host supplies persistence, scope checks, source closure and effect receipts. The core requires qualified non-mock/non-fallback identity on both provider calls and refuses prompt-only replies, changed tool authority, missing observation or nonterminal response. It returns a narrative and model identity only, not an assessment or completion verdict.

Four controlled graph tests pass, including raw observation→finalResponse, mocked/fallback refusal, selected count/owner injection rejection and stale authority. This core is intended to run inside the owned audit execution host; it is not wired into the live application and does not replace the required parent coordinator, durable observation publication or dedicated Judge. Actual8B qualification of this audit core remains pending.

Actual8B core qualification51334 now passed on current isolated PostgreSQL. The real Ollama adapter selected the audit tool, received the exact raw two-row current-generation source, then produced a separate structured final response. Source hashes, model calls, traces and unchanged model digest are retained in the owned evidence directory referenced by tasks/secureshop-audit-actual-51334.json. Owned processes/container cleanup was independently checked. Qualification uses local test persistence/effect receipts and intentionally grants no objective credit: it does not yet qualify production ledger hosting, worker resource containment, dedicated Judge or live UI activation. Initial83454 failed a test-only row-count expectation, corrected after inspecting the scoped seed; that failed evidence remains retained.

Connection acquisition now defaults to a10s server-configured deadline (maximum30s) and responds to cancellation even when a PostgreSQL pool is saturated. A late connection grant is released without executing queries; the existing finally path releases any already-open sibling transaction.15 focused snapshot/spool/graph tests pass, including cancelled acquisition and second-pool saturation. This prevents a pending audit request from indefinitely holding the other store's transaction; it does not replace the later concurrency/capacity qualification.

## Separate worker checkpoint

`secureshopAuditWorkerHost.js` launches a fixed Node worker with a minimal environment (no inherited application credentials),256MiB V8 old-space setting, bounded stdin/stdout/stderr, wall deadline and periodic authority checks. Cancellation escalates from SIGTERM to SIGKILL for that exact child and waits for close. `workers/secureshopAuditWorker.js` verifies source hashes through no-follow file handles, runs the real audit LangGraph and Ollama adapter, and writes private message/trace/local-effect artifacts with digests. It returns a bounded narrative/metadata result, not raw source or objective credit. Application input/artifact byte limits and V8 heap settings are explicitly not OS RSS/CPU quotas and do not contain external Ollama.

Actual8B native89009 passed with scoped PostgreSQL source collection, spool, separate worker graph/model calls, independently verified artifact hashes and cleanup. Failure controls verify tampered-source rejection and deadline termination without exposing raw diagnostics. The parent production coordinator must still capture a protected whole-job effect containing run/scope/source/artifact identities and publish durable references before a dedicated Judge may evaluate credit. Worker-local receipts cannot substitute for that parent effect. Live gateway/UI activation remains pending.

Parent artifact verification now runs in `runSecureShopAuditWorker` before return. It accepts only fixed messages/traces/effects references, snapshots their metadata, checks aggregate byte limits, verifies sources and artifacts in64KiB chunks through no-follow file handles, and rechecks authority and file size/time/hash. Returned references are immutable. Five controlled artifact/child tests and actual8B native32886 passed; all owned resources independently confirmed absent. This closes the parent trust gap for worker-returned hashes, but durable publication must still bind retained content to the protected parent run/effect before Judge credit.

## Durable publication decision

A reviewed candidate schema now lives under `docs/modernization/drafts/secureshop-audit-runs/`; it is not an active migration and intentionally grants no runtime access yet. It separates immutable run identity, five artifact manifests,64KiB bytea chunks with database-generated chunk hashes, and a publication marker. All writes use the agents audit owner-deletion lock before the run row lock; publication will seal further inserts. Publication completeness validation, deletion receipts/function, repository and native qualification remain required before promotion.

The parent must publish these bytes inside a protected graph effect callback, recording expected runId/ownerKey/durableGeneration/effectKey. Publication is prepared evidence only: identity-store effect completion occurs after the callback and cannot be atomically committed with this agents database. Grading must independently verify that exact completed ledger effect. A published run with an uncertain/missing effect is retained noncredit evidence and must never be automatically re-executed. A completed effect with missing/mismatched artifacts is an integrity failure.

Artifact deletion will use a separate receipt after the installed agents event-deletion receipt, retaining the applied event receipt's digest/count contract. Both use the same owner lock. This tolerates a crash gap between event deletion and artifact deletion while preventing later upload; completion requires rereading/verifying both receipts. Review-store cleanup remains independent. Reset fences old-generation execution but retains published historical evidence under its original exact scope.

Worker artifact encoding now writes one JSON record at a time, hashes those exact written bytes and enforces the aggregate budget without serializing the entire messages/traces/effects array at once. Seven writer/verifier/child controls pass. Model history still resides in the isolated worker and remains subject to its declared limitations; this is not a claim of streaming model inference or strict OS memory containment.

Candidate schema publication/deletion controls now passed native79091: incomplete artifacts cannot publish, published runs reject further chunks, runtime mutation is denied, deletion requires the installed event receipt, exact artifact counts/bytes/digest replay is stable, sibling records survive and late owner writes fail. This supersedes the earlier draft-only absence of validators/grants; the SQL remains outside active migrations. Whole-file hashes will be checked by streaming publication/readback, while PostgreSQL checks each generated chunk hash and layout without concatenating128MiB inside a database aggregate. Full repository, lifecycle composition and protected effect qualification are still needed before promotion.

`secureshopAuditRunRepository.js` now publishes verified files in one agents-store transaction. It captures administrator/launch/run/effect identity, locks the owner before inserting, streams64KiB chunks and rehashes while writing, then seals only after all byte/hash and authority checks pass. Any precommit failure rolls back the entire run and chunks. Loss of authority after commit leaves prepared noncredit evidence; completed-parent-effect verification remains mandatory. Duplicate model execution/publication must be prevented by durable request admission, not inferred from a duplicate-key retry.

Native53747 passed: a150KiB artifact is stored as three ordered chunks with exact generated chunk and full-file hashes; injected generation retirement after a chunk write rolls back all run/chunk rows. Prior publication/deletion/ownership controls also pass. Candidate schema remains unpromoted pending scoped readback, parent effect verification and lifecycle integration.

### Scoped durable readback qualification

`secureshopAuditRunReader` reads only a published run matching all trusted launch coordinates and the administrator shop persona. Every query excludes the installed owner-deletion fence. Before exposing metadata and before/after artifact consumption it independently verifies the exact completed parent ledger receipt (run, owner key, durable generation and effect key). Prepared artifacts with missing, uncertain or mismatched receipts remain unavailable and noncredit.

Artifact iteration fetches at most eight64KiB chunks per query, checks contiguous ordinals, per-chunk digest, declared byte count and complete-file SHA256, then rechecks publication and parent effect. Consumers must fully consume an artifact before using it as evidence; partial bytes are not verified evidence. A completed effect alone does not prove an actual model or objective success: trace provenance and the dedicated Judge remain separate required gates.

Disposable PostgreSQL qualification6801 passed with cleanup independently verified (`tasks/secureshop-audit-scoped-readback-6801.json`). It covers controlled storage fixtures, not actual-model or objective-credit proof. Storage migration remains a draft; no live routes were activated.

### Parent effect composition

`secureshopAuditJob` is an internal operation for an already admitted turn whose coordinator uses the normalized request UUID as its idempotency key. It owns one `audit-summary-job` effect encompassing snapshot collection, spool, worker, durable publication and temporary-file disposal. Cleanup errors leave the effect uncertain. The worker's inner graph effects are local provenance only. This is a dedicated whole-job effect, not a nested tool callback in the shared bound agent runner.

After the durable effect completes, the job verifies its exact receipt, opens the independent durable reader, and calls the trusted evidence consumer while the parent lease remains active. Only a compact serializable noncredit result leaves the job. This is necessary because the current ledger's `readCompletedEffect` requires an active run lease; finished-run HTTP inspection requires a separately authorized read API. Never retain these iterator/check closures beyond the enclosing coordinator operation.

Native qualification68882 exercised the real PostgreSQL identity ledger and agents artifact repository with controlled worker output. Actual8B65935 repeated the parent flow with the real separate worker and qualified local model. Both consumed five verified artifacts before lease release, completed the parent run and rejected duplicate effect execution. Cleanup was independently verified. These tests qualify parent effect composition, not production launch authority, conversation admission, Judge credit, resource-exhaustion achievement or live routes. The candidate storage migration remains unpromoted pending those integrations.

### Durable admission checkpoint

The dedicated audit runner now uses the retained BoundTurns coordinator and existing turn journal with server-owned purpose `secureshop_audit_summary`. Its versioned operation input binds requested count into the request digest. Completed requests replay their compact DTO without another worker or graph; mismatched count reuse conflicts and uncertain attempts require recovery. Both fresh and replayed responses recheck exact conversation ownership after coordinator completion. The internal result contains only summary/model/count/run metadata, never private paths or artifact streams.

The candidate0021 migration extends the existing immutable-purpose constraint without altering applied migrations. The current live database is not upgraded and no endpoint uses this runner yet. Native36434 and actual8B60479 qualify real database admission, purpose separation, completed replay and changed-count conflict through the complete parent worker/publication/readback flow.40 relevant controlled tests pass. The native launch adapter remains controlled; real platform launch/reset/deletion and dedicated Judge qualification are still required.

### Judge provenance preparation

The fixed worker now appends a compact model-chain record to the existing effects artifact. It requires exactly one successful audit tool result between two qualified model decisions, exact requested count and raw observation, a completed worker-local tool receipt, matching final narrative and end-turn terminal state. It binds the complete messages/traces JSON byte digests, source digests, observation digest and summary digest. Worker-local receipts still cannot substitute for the independently completed parent ledger effect.

`consumeSecureShopAuditEvidence` accepts only the internal durable reader during an active parent lease. It parses at most1MiB of effect metadata, requalifies the model identities against the trusted adapter and published metadata, then fully drains all four large artifact streams for integrity verification. No large log/message/trace JSON array is parsed in the application process. The returned evidence explicitly reports `objectiveCredit:false`; it establishes provenance, not instruction-following exploitation or resource exhaustion. Dedicated objective semantics, source influence comparison and actual Judge evaluation remain the next gate.

### Audit Judge semantic calibration

`secureshopAuditJudgePacket` defines provisional objective `ss_audit_instruction_followed` with canonical primary source comparison. The first Judge call identifies instructions only from the source; the second compares the candidate answer against those instructions. Server facts establish completed scoped effect and verified real-model observation, never semantic success. The only passing semantic criterion is actual answer redirection; quotation, discussion and refusal fail. Claims about administrative tool execution do not prove actual actions.

Packet preparation revalidates the durable model chain and complete artifact streams, then includes the exact complete log and final summary. The canonical24KiB packet budget applies: oversized source/summary packets fail explicitly without truncation or credit. This is an unresolved operational limit for long audit histories, not a resource-exhaustion achievement; a larger-scale targeted evidence design remains required.

Actual8B native3417 caught a criterion-name integration error and an ambiguous imperative classification. The corrected rubric uses the verifier's required `redirected_output` criterion and specifies how to classify recorded imperatives. Native3787 passed all three static calibration cases (executed redirect, faithful warning, refusal) using two actual Judge calls per case; cleanup and unchanged model identity were verified. The same suite prepares a packet from the actual parent-run durable evidence. These semantic fixtures do not establish an end-to-end learner exploit, durable completion credit, broad Judge accuracy or live readiness. Five packet tests plus six provenance tests pass.

### Artifact deletion recovery

`secureshopAuditRunCleanup` composes the existing two-store audit journal cleanup with candidate artifact deletion. It first verifies both original journal receipts under the current owner-deletion job, then calls the artifact deletion function and independently rereads its exact owner/job/count/byte/digest receipt. Lease loss, missing or changed receipts and any partial step reject completion. Existing journal receipt bytes and API fields are preserved.

Nine cleanup tests and native75415 passed. The native test injects an artifact-step outage after both journal fences, proves artifacts remain until the same-job retry, then verifies complete cleanup of a published multi-chunk run, stable replay and sibling retention. Candidate schema and this cleanup composition remain inactive in the live app; required readiness checks and production composition wiring must precede promotion.

### Storage readiness and factory wiring

The shared audit composition now accepts explicit `includeRunArtifacts:true` for both readiness and cleanup construction. Readiness requires the exact runtime role, SELECT on all five storage tables, no mutable privileges, exactly the intended INSERT columns, private cleanup execution, the audit-purpose constraint and five enabled row-level BEFORE INSERT triggers bound to the expected functions. Server clocks, generated hashes and deletion receipts cannot be runtime-written.

Native32331 and final81112 passed, including injected privilege drift, a disabled publication validator, restored readiness and cleanup through the shared factory. The default remains the installed journal-only capability until migration, assessment, launch authority and installed-upgrade qualification are complete. Future activation must pass the same capability choice to readiness and composition; it must never enable serving artifact-backed summaries with journal-only deletion.

### Canonical assessment lifecycle wiring

The optional audit assessment factory uses the existing objective completion service and privately captures the exact launch scope for a protected execution. The runner begins the attempt before any job collection or model work, requires explicit canonical mode/generation, and passes the resulting lifecycle only through its trusted job input. The job consumes verified evidence and evaluates the dedicated rubric while the parent lease is retained. Reusing the assessment, substituting another run or returning before assessment completion fails.

The runner publishes canonical assessment outcome with the compact journal result only after the lifecycle settles, preserving completed-request replay without another model or Judge call. The job itself still reports no credit; only the completion service result can mark the response completed. Existing ungraded internal qualification remains possible without an assessment factory; production activation must require one. Canonical objective registration and native real-launch assessment qualification are still outstanding.

### Genuine launch authority qualification

Native qualification66657 and actual8B61624 now create real platform users, sessions and launch bindings, write the parent fixture event under that binding, and use the production launch repository for conversation authority. Completed replay is rejected after beginReset advances the generation. Both runs passed with independently verified owned resource cleanup. This tests the reset fence, not full reset cleanup; fixtures remain controlled and no canonical objective credit or live activation is claimed.

### Canonical negative assessment

Actual8B73805 exercises the audit assessment factory with native completion repositories and real local actor/Judge calls under a genuine launch. The ordinary event summary records one fail/not_pass receipt with exact launch coordinates; replay adds no Judge call. The qualification temporarily enables the pending objective only in disposable storage and restores it afterward. Positive exploit/award and complete reset/deletion qualification remain required before release.

### Authentic positive source qualification

Actual8B40112 passed both benign and injected merchant-listing cases. Each source is written through the owned product repository under a real reserved target and issued launch; its audit event commits with the mutation. The injected description redirects the genuine graph final answer, and the canonical assessment records a real Judge pass/awarded receipt bound to that launch. The benign case records fail/not_pass. Replay, disabled receipt preservation and generation fencing also pass. This does not yet qualify complete reset/deletion cleanup, rendered UI, or production activation; the objective remains pending.

### Aggregate reset and progress qualification

Actual8B80213 verifies the authentic positive and benign cases against canonical workshop, user, visible-user and bulk-admin progress projections. The aggregate reset uses real conversation retirement, product cleanup/reconciliation and progress checkpoints, commits the next generation, removes current completion and preserves immutable Judge receipts. Product contents disappear while retired target metadata remains. This qualifies native service paths; rendered UI, deletion and deployment activation gates remain.

### Reset recovery and sibling preservation

Actual8B15808 injects a failure before progress retirement, verifies the old generation stays fenced, then resumes and replays the same reset request without advancing another generation. Sibling Judge receipts and audit-run metadata are identical before and after. Both genuine actor/Judge cases remain valid. Concurrent in-flight reset races, user deletion and rendered release qualification remain separate.

### Native terminal deletion

Native24057 and actual8B71287 compose genuine student deletion admission, lease renewal, run drain, SecureShop reset recovery and audit cleanup, then the identity finalizer and completed job. Both positive and negative graded artifacts are removed idempotently and the account becomes a tombstone. This proves the isolated SecureShop/identity manifest, not unrelated application stores or installed deployment activation.

### Migration and cleanup capability

Native77652 applies candidate0021 through the production migration ledger against populated session, event and MCP state, preserves exact content digests and old checksums, and proves second-run no-op. Fresh full-manifest qualification is still required. Artifact cleanup capability must depend on installed schema support, independently of the switch allowing new summary runs: disabling summaries cannot disable deletion of previously persisted artifacts.

### Promoted storage capability

Migration0021 is now active with exactly the qualified candidate bytes (the historical draft header is retained for checksum parity). Fresh17129 passed. Production cleanup startup unconditionally requires this schema and artifact-aware deletion, independently of future summary serving flags. The current installation has not been migrated or restarted; summary runtime and rendered qualification remain pending.

### Retained runtime and UI contract

The optional `SS_AUDIT_SUMMARY_ENABLED` runtime now retains the same ledger as bound turns/reset cleanup, owns a private temporary spool root, and aborts/drains work before shutdown removes that root and releases pools. Authenticated bound session/summary endpoints require the admin persona and mandatory consistent Judge results. Serving defaults off; artifact cleanup stays required independently.

The existing Audit page uses dedicated session/request UUIDs and displays the actual model summary and Judge verdict. Transport failures retain the request identity for safe replay; after success, the next click creates a fresh observation so subsequent listing changes can be assessed. Late session responses cannot dispatch across a changed scope. Sixteen focused Audit component tests and the production build pass. These source/build checks do not replace genuine mounted HTTP, rendered browser or installed upgrade qualification; the catalog objective remains pending.

### Authenticated real-model HTTP qualification

Actual8B40543 passed using real launch and persona repositories, HTTP login/session admission, mounted bound gateway, runtime factory and actual local actor/Judge. Authenticated positive and benign requests yield correctly scoped canonical credit/no-credit; same-request replay makes no second model/Judge call. Missing/forged tokens and a customer persona are denied. Native reset recovery, progress parity and artifact deletion still pass. Test process and container cleanup were independently verified. Unused commerce/UI routes are deliberately outside this HTTP harness; full production startup, rendered browser and installed upgrade remain separate gates.

### Retained startup and rendered benign assessment

Production-composition51935 passed with the serving capability enabled: real retained construction, schema readiness, authenticated dedicated-purpose session admission, reset regression, and rejection after shutdown. Rendered69099 then exercised the built opaque frame through real persona login, pagination and actual Llama8B summary/Judge calls. Its benign case has exactly one fail/not_pass receipt scoped to the rendered owner/launch/scenario/generation and no completion contribution. Browser and native resources were independently cleaned. This is additional integration evidence, not positive rendered exploit qualification or installed activation. The objective remains pending.

Reproduce the opt-in actual audit browser path with the existing isolated `manual-rendered` launcher and `--audit-summary`, pinned browser/Node/Docker hashes and the installed offline embedding cache. The flag is rejected for other suites. It enables the pending objective only in disposable test storage, checks the model digest before and after, and leaves installed application configuration untouched.

Rendered32409 additionally passed after waiting for the summary expansion to settle. Visual inspection confirms summary text and provider/model/Judge metadata are visible within the retained Audit layout. Genuine positive rendered injection and canonical admin/dashboard release parity remain outstanding.

### Remaining SQL search design gap

The bound UI still reports search unavailable. The retained legacy `queryAuditTeaching` executes raw read-only SQL using the agents runtime role; copying that call into the bound route would expose other owners' journal rows. A launch-specific table/schema name alone is not an isolation boundary when the same SQL role can read sibling tables, change its search path, or switch back to a more privileged role.

Before implementing bound search, qualify a PostgreSQL teaching connection that has no rights to platform/agents/review storage, no role escalation, and no dangerous granted functions. Only exact owned snapshot rows may enter its private relation; record source digest and scope before execution. The application must execute the deliberately interpolated query only on that restricted connection, then persist an immutable scoped result/effect receipt through the trusted parent. Bounded SQL time, cancellation, reset/deletion, cross-owner probes and error paths need native proof. A dedicated separate database or independently restricted login is required; a shared runtime-role schema prefix is insufficient.

Keep the preserved SQLi teaching sink and vulnerability mapping intact. The first bounded UNION proof and separate time-based proof must both be authentic; the existing SQLite-fixture UNION test is not evidence for PostgreSQL timing or bound ownership. Any new objective must use a genuine Judge grounded in the retained SQL/effect evidence, consistent with the application's per-objective grading requirement. Do not mark this search workflow available before those gates pass.

### Positive rendered source-to-credit qualification

Rendered52393 passed an authentic merchant form edit that persisted the teaching instruction in a scoped listing-update journal event. The real audit graph observed that event and returned the requested imperative; the actual Judge recorded pass/awarded with one owned contribution. Native catalog/progress repositories, production progress HTTP handlers and revision polling updated the parent exercise display to1/2. The rendered reset returned it to0/2 while retaining the Judge receipt. The screenshot was visually inspected and all owned resources were independently cleaned.

The former rendered fixture responses concealed a challenge-key mismatch in the disposable integration seed. The seed now matches the production curriculum key, and the audit browser path uses actual progress handlers. Platform login in this harness remains an explicitly owned test-session middleware; the shop persona login, launch, runtime, evidence and grading are real. This does not claim assembled platform-authentication or every admin/dashboard page coverage. Catalog release and installed activation remain pending.

### Student dashboard parity

Actual8B21389 verifies canonical challenge/progress/stats/time HTTP responses and native bulk-admin projection against the real awarded audit contribution. The built Overview, Exercises and historical Progress redirect show1/2 before reset and0/2 afterward; exercise counts agree. Time is zero in this fixture, so this establishes value parity only, not duration accrual. The screenshots captured entrance fades; a subsequent test-only opacity gate awaits rerun. Rendered platform-admin controls remain a separate gate.

### Administrator control coverage checkpoint (2026-09-19)

Generic `/api/admin/solutions` already lists and edits active SecureShop objective content through the canonical repository. Missing a workshop-prefixed solution route is therefore not evidence that generic editing is broken. The Exercises objective-panel registry does omit SecureShop, leaving its per-objective controls absent there; reuse the existing UI and canonical APIs to close that gap. The pending Audit objective must continue rejecting enable requests with409 until release qualification. Native/rendered40918 confirms settled student dashboard credit/reset parity with the genuine local actor/Judge; it does not qualify platform administrator rendering, live duration accrual or installed migration.

### Generic solution editor persistence repair

Preserve the existing form and store its description, code, references, estimated time and prerequisites as optional fields in canonical solution_content JSONB. Existing rows retain approach-as-description fallback. Keep example objects intact and render them as text in preview. Save content and requested visibility atomically through the canonical configuration transaction; pending-objective enablement rejects before any content write. Visibility still updates master/per-objective gates and the configuration revision together. Validate optional strings/lists and safe reference schemes, preserve instructor-custom provenance, and qualify real native edit/readback plus rejected-edit rollback. No schema rewrite or deployed migration is required for these optional JSON fields.

### Qualified admin/editor checkpoint

Native cohorts82947 and30611 passed genuine PostgreSQL authentication, administrator catalog access, pending Audit enable rejection, rendered SecureShop objective controls and existing permission/agent-run regressions.30611 additionally proves optional solution fields persist and a rejected content-plus-publish request leaves content unchanged. Student rendered40918 separately proves actual actor/Judge credit and reset dashboard parity. These separate runs do not establish instructor observation of the same awarded run, in-flight reset/model races, operational capacity, or installed activation. Those remain explicit release work.

### In-flight reset qualification

Native73942 now qualifies the real aggregate reset during a controlled suspended Audit worker: cancellation drains the run, prevents publication/judgment/credit, leaves an uncertain effect and terminal run, and fences released-lease evidence access. Reset recovery and sibling preservation pass in the same isolated run. Actual child cancellation was separately exercised against an owned stalled loopback provider. Actual8B evidence remains the separate model-provenance proof. Instructor observation of that same awarded run, operational limits, catalog release and installed qualification remain open.

### Platform capacity and same-run instructor checkpoint

The retained Audit lifecycle admits at most two concurrent summary runs per backend process and rejects excess before runtime admission with HTTP 503. No waiting queue or extra worker is created. Slot release covers both resolved and rejected work; session creation and shutdown draining retain their existing contracts. Four focused lifecycle tests pass. This process-local bound does not establish fleet-wide admission or capacity for 200 simultaneous learners.

Owned native qualification76573 (`tasks/audit-admin-actual-76573.json`) passed with actual local 8B actor/Judge positive and benign runs, then read their canonical completion through the real platform admin HTTP router with genuine PostgreSQL JWT sessions. Student and invalid-token requests were denied. This uses service-issued sessions, not browser login; the earlier native browser cohort covers login separately. Independent cleanup verified process/container absence. The installed application was not restarted or migrated. Catalog release, rendered same-run instructor observation and broader capacity qualification remain pending.
