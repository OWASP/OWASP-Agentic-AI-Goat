# MCP conversation storage design and first qualification

## Actual actor/Judge composition

The existing MCP route's actor, observation grading and progress projection now live in one shared `performMcpConversationTurn` function. The legacy chat handler calls it directly; `createConversationRouter` composes the same function with qualified request/history repositories and the same owner coordinator. The actor accepts the internal bound-history capability separately from ignored client history. The factory is available for installation but is not mounted automatically.

An assembled isolated test passed with real PostgreSQL sessions, the actual MCP actor and local8B Judge: recon produced one awarded native receipt, replay returned the saved response without another receipt, authenticated history restored the answer, a no-tool negative stayed incomplete, and full-progress reset removed credit. Evidence: `/tmp/dvaia-mcp-conversation-actor-live.log` (1 aggregate test, no skips, approximately18.5 seconds). The scope is recon; the other ten exploit objectives are not qualified by this run. The dedicated PostgreSQL18 container was removed.

The frozen backend suite passed1,342 tests with34 gated skips at `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-regression-IpFHlq/tests.log`. A subsequent audit correction records failed/refused MCP tools with success=false instead of always true. The final targeted snapshot passed8 tests, including15 HTTP smoke checks and the persisted failure flag, at `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-mcp-actor-smoke-b_4t6jn3/result.log`; sidecar exploit checks inside that smoke suite were explicitly skipped.

Remaining activation gates: production migration promotion with reload coordinated, frontend request IDs/reload/clear handling, independent-process retry/cancellation qualification, and browser parity. Full-progress reset currently fences old conversation data by graph generation; wire old-payload cleanup into its activated lifecycle as well as conversation-only clear.

## Authenticated HTTP adapter qualification

`mcpConversationRoutes` now provides an unmounted router factory for chat, history and conversation clear. It derives the owner from authenticated request state, accepts only a UUIDv4 request ID and bounded message for chat, rejects owner/history/query overrides, marks responses no-store, propagates disconnect cancellation into coordinated runs, and returns stable redacted conflict/unavailable errors. Clear calls the service's reset path directly; nesting reset inside an active run would deadlock. The actor runs in the existing owner execution AsyncLocalStorage context.

Seven focused HTTP/service/history tests pass. The native integration additionally uses actual PostgreSQL identity sessions and `createPostgresAdminAuth` middleware: unauthenticated history is rejected, history is restored for the authenticated owner, another learner sees only their own rows, completed HTTP retry returns the saved JSON with one counted actor callback, and clear removes history while an old request returns 409/`STALE_REQUEST`. Evidence: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-mcp-http-bzmisl8y/result.log` (1 aggregate native test, no skips). The actor is an injected counted callback, not a real MCP exploit/model/Judge. The owned PostgreSQL18 container was removed.

The adapter is still not mounted into `mcpWorkshop`, and no running-user migration or frontend switch-over has occurred. Required next integration is the actual MCP actor/grader response pipeline, client request IDs/restoration/clear handling, migration promotion with coordinated reload, and assembled browser/native qualification.

## Conversation-only clear semantics

The internal service now clears conversation through the actual owner coordinator reset boundary. It increments the graph generation to invalidate in-flight work, then transactionally deletes old history rows and removes the user text/response JSON from old request records. Minimal request identities remain so an old client retry is rejected rather than rerunning an effect. Current-generation data is not deleted by the cleanup query. Objective progress, tool/audit records and challenge state are not part of conversation-only clear.

The native PostgreSQL18 suite passed with the actual coordinator: old payloads were removed, another learner's conversation survived, seeded objective completion survived, and stale request reuse still failed. Evidence: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-mcp-clear-211f1_wv/result.log` (1 aggregate test, no skips). Six focused history/service tests also pass, including rejecting invalid clear owners before coordinator mutation. The owned container was removed. This verifies internal semantics; authenticated HTTP and UI controls are still not switched over.

Clear is logically fenced before payload cleanup. If cleanup fails, previous generations remain inaccessible, but raw payload deletion requires retry/reconciliation. Request identity retention is intentional replay protection; an eventual retention policy must not silently permit expired old IDs to rerun without a separate conversation identity check.

## Bound model-history follow-up

The internal conversation service now turns stored rows into an opaque current-execution history capability. The decision graph accepts that capability separately from current-run tool observations. The capability binds owner, run and durable generation; serialized copies and caller-supplied role arrays are rejected. Prior dialogue becomes only user/assistant messages, never a current tool result or grading fact. It retains a chronological suffix of at most 12 whole turns within 16KiB of serialized messages and reports omitted turns. An oversized newest turn omits the whole history rather than silently cutting it or substituting unrelated older turns.

Thirteen focused decision/history/loop tests and two additional service tests pass. A real local8B test selected a random filename mentioned only in bound previous dialogue, and the test then read the matching owned temporary file successfully (`/tmp/dvaia-mcp-bound-history-live.log`). That test injects stored dialogue/execution identity; it does not prove database-to-browser restoration. HTTP/UI activation and native requalification of the assembled path remain required.

## Request admission follow-up

The unmounted `mcpRequestRepository` now admits a client request UUID before work, scoped to server-derived user/owner/run/generation. The request key deliberately excludes generation: reuse after reset is rejected as `STALE_REQUEST`, rather than being interpreted as permission to repeat an old effect. Exact user text is retained for conflict detection; no lossy normalization is used. An admitted request without a completed original run is uncertain and cannot automatically repeat work. Once its original run completes, a retry receives the saved JSON response, including objective/Judge fields, without calling the work function.

Response JSON and the user/assistant history row commit in one transaction under the generation row lock. The internal `conversationService` composes admission, history loading, work and completion while retaining execution checks around awaits. It remains unmounted, and the schema remains a non-discovered draft.

Native qualification now includes the actual PostgreSQL run ledger/coordinator and internal service: completed retries skip the callback, changed messages/responses conflict, pre-completion retries refuse, reset prevents stale request reuse, and a callback that throws after its counted action is never called again by retry. The fake action is an injected counter, not an actual exploit or model call. Same-process coordinator/native leases are proven; independent process/HTTP/browser qualification is not. Evidence: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-mcp-requests-4snyqf4g/uncertain-result.log` (1 aggregate native test passed, no skips). The dedicated PostgreSQL18 container was removed.

The remaining activation work below still applies: wire client IDs and authenticated routes, define clear/retention semantics, bound model history, qualify independent processes and browser restoration, then coordinate migration promotion. Existing users do not yet receive persistent MCP chat or HTTP replay.

The client retains chat only in React component state and sends only the new message. The service ignores optional history. MCP's native workshop database contains progress and tool activity but no conversations. Therefore neither follow-up references nor reload restoration currently have authoritative conversation context.

## Storage boundary

The new, unmounted `mcpConversationRepository` stores bounded user/assistant text separately from metadata-only graph traces. Its qualification draft uses a `workshop_conversations` schema in the identity database, where the authoritative graph owner generation and run status already live. This permits a conversation append and reset generation update to share a PostgreSQL row-lock boundary. Keeping conversations in the separate MCP database instead would require an additional cross-database publication/reconciliation protocol; this draft avoids that particular boundary without claiming the existing overall workshop reset is atomic.

Each row belongs to a server-derived MCP owner, user, generation and run. Append locks the owner then validates the active run; identical writes within the run are idempotent and changed content conflicts. Reads require the current owner generation and a completed run. Failed/in-flight responses and previous generations are not restored. Raw proof capabilities and tool responses are not stored by this initial API. Limits are 16KiB user text, 32KiB assistant text and 200 turns per generation. Retention/clear-chat policy is still required before activation.

The SQL stays under `docs/modernization/drafts/` and is **not loaded by startup migration discovery**. No runtime route imports the repository, no schema has been applied to learner databases, and the UI history gap is not yet fixed.

## Native evidence

`tests/postgres/mcpConversations.integration.test.js` passed against disposable PostgreSQL18, with no skips. It proves owner isolation, same-run duplicate/conflict behavior, completed-run restoration through a fresh repository, failed-run suppression, reset generation visibility, and stale-write rejection. Its race case observes an actual blocked PostgreSQL lock, commits the reset generation, then verifies that the pending append fails with `STALE_GENERATION` and writes no row.

Evidence: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-mcp-history-l28pvqbx/race2-result.log`. An earlier race fixture incorrectly tried to monitor locks through the single-connection migration pool while holding that connection; its connection-timeout log is retained as `race-result.log`. Monitoring was moved to a spare runtime connection. The test injects execution metadata and creates actual run rows; it does not prove integration with live coordinator leases or authenticated HTTP. The owned container was removed.

## Required work before activation

1. Integrate the implemented pre-execution request admission with client request UUID and exact request-text comparison into authenticated HTTP. Persist uncertain outcomes and never auto-reexecute them.
2. Connect the implemented saved-response replay and atomic history completion to the real route response, including Judge receipts. Qualify lost-response retries through HTTP; repository/service evidence alone is insufficient.
3. Integrate reads/appends with the actual owner coordinator, authenticated route, and generation check before publishing history. Qualify reset/lease-loss races across independent processes.
4. Define separate conversation-clear and full-workshop-reset semantics. The current UI clear button is local-only. Persisted history must not reappear after a server-acknowledged clear. Define retention and quotas before enforcing a user-visible 200-turn limit.
5. Feed only bounded server-loaded prior user/assistant messages to decisions. Keep client-supplied tool roles/results out of current-run evidence. Preserve the existing UI while restoring ordered history on load.
6. Qualify the complete native HTTP/model/reload/reset path, then promote the draft to the next migration number with live reload coordinated. Do not alter already applied migrations or AWS/deployment assets.
