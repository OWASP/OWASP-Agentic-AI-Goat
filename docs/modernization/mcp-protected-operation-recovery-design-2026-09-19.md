# Protected-operation receipt recovery

Proposed protocol, September19. Current protected calls remain uncertain on lost acknowledgement and never retry automatically. No installed activation or migration is part of this step.

## Existing patterns and boundary

`sidecars/sandbox-runner/mcpTargets.js::observeCommand` derives an immutable request identity, persists started/completed state under the target lock, and returns retained command receipts without executing again. Package/ticket operations also journal operation UUIDs. `owned-http/operationStore.js` separates execute from readReceipt and refuses pending replay. Protected operations currently carry only runId and return a private result; a run can invoke the same tool more than once, so runId is not an operation ID.

Use a dedicated reusable protected-operation journal under `<target>/protected-operations`, called inside the existing `targetStore.withTarget` lock. All scope comes from that lock's binding. Executor and filesystem root are trusted composition dependencies. Request fields are exactly operationId, runId, operation, arguments. Only validated tool arguments are learner-selected; labRole and policy remain derived from server invocation. No learner owner/session/target claim is accepted.

The future client derives operationId as a domain-separated UUID from canonical `(runId,effectKey,"protected-operation.v1")`, not ephemeral SDK invocationId and not runId alone. The request digest includes operation ID, run ID, operation, exact arguments, and target/owner/platform-session/generation binding. Same ID with changed arguments/run/scope is conflict. Different graph steps in one run have different effect keys. A replay may retrieve only its original run's receipt; never attach it to a new run.

Persist a durable immutable pending envelope before execution. Persist completed envelope containing exact original protected receipt plus canonical receipt digest after execution, before releasing target lock. Completed replay/readback validates exact request and receipt hashes and never invokes the executor. Unknown pending or interrupted publication remains uncertain; never infer success from current key version and never repeat the operation. A successfully published completion whose network acknowledgement or return-authority fence fails can later be read only after current authority is re-established. An absent readback is distinct from pending and is not permission to repeat an uncertain centrally admitted effect.

## Bounded foundation in this step

New `sidecars/sandbox-runner/protected-operations/operationStore.js` and focused filesystem tests only. Immutable bounded JSON snapshots, exact schemas, no symlink/hardlink journal reads, private directories, exclusive publication, fsync, target lock held through completion, private trusted executor, exact replay/conflicts and explicit pending uncertainty. Deliberately no automatic staged-file recovery: interrupted writes fail closed pending further recovery design. It is not imported by production routes or advertised as readiness.

## Coordinated follow-on files (not implemented here)

- `mcpTargets.js`, `ownedTargetApi.js`: mount execute/readback with explicit new request schema; require same lock and current authority for both; target retirement already removes the containing target directory. Verify pending/completed deletion and sibling preservation through real retirement.
- `ownedTargetClient.js`: stable effect-based operationId; typed receipt/readback validators and WeakSet enrollment only after exact trusted validation. Retain existing uncertain-error propagation.
- `sandboxShell.js`, SDK/protocol and `ownedResourceApplication.js`: adopt private original result after acknowledged recovery, without synthesizing actor decision provenance. Private witness must match original model invocation/run. Manual inspector actions never become model completions.
- `ownedQualification.js`, composition readiness: new capability `mcp-owned-protected-operation-journal.v1` in addition to existing state-transitionv2; do not reinterpret v2 as receipt recovery. Legacy runner stays unavailable for recovery.
- `sidecars/sandbox-runner/Dockerfile`: explicitly COPY new directory; pinned-image build manifest/readiness hashes and local installer runner upgrade required. No AWS changes and no global AppArmor change; trusted filesystem journaling adds no untrusted-process authority.
- Central reconciliation requires a forward identity migration only after the actual repository contract is agreed: immutable original graph effect/request identity + target receipt digest, checked current owner/generation/session authority, reconciliation of an uncertain effect without reexecuting or creating a new model decision. Do not overwrite graph completed/uncertain status with a guessed outcome. Reserve no migration number yet. MCP target inventory schema need not change for target-contained filesystem receipts.

## Acceptance before wiring or release

Real target + socket + SDK + PostgreSQL: lost ack after completion returns exact receipt on authorized readback; same operation conflict; two operations in one run; pending lost publication does not execute again; return-phase revocation refuses publication/readback until reauthorized; reset/deletion fences late output, deletes target journal and preserves siblings; no caller JSON can create trusted witness. Reconstruct private provenance only from original durable decision/effect linkage. Fresh/populated/no-op migration and native installer image qualification follow central design. No model rerun is necessary for this storage foundation.

## Connected source candidate qualified

`tasks/mcp-protected-journal-connected-native-2026-09-19.json` records2 native tests and51 focused checks. The actual target store, API, client and explicit private runner readback are now connected in source with `protectedJournalCapability`. New capable clients derive domain-separated operation IDs from private run/effect identity. Existing clients without the capability retain the previous uncertain/no-retry contract. The Dockerfile copies the new module; no image was built or installed in this cohort. Completed readback leaves historical PostgreSQL graph effects uncertain. Durable central reconciliation and original model provenance are deliberately not inferred from a sidecar receipt. Controlled macOS readiness in the native fixture is not an AppArmor or Linux image proof.
