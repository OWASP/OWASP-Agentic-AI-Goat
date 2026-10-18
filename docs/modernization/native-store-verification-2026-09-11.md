# Native PostgreSQL verification checkpoint

The latest checkpoint includes fourteen initialized PostgreSQL repositories, including SecureShop commerce/agent state/vectors, legacy generic challenges and sensitive lookup. This is a verified intermediate checkpoint, not a completed PostgreSQL-only application release. Legacy engine branches remain for staged verification; the normal installer has not switched engines. No AWS/deployment assets were changed.

## Verified behavior

- FinFlow preserves all18 objectives and native tool-log/reset behavior. Its PostgreSQL progress view uses authoritative canonical completion receipts.
- Excessive Agency persists attendee state, sessions and conversations. Vulnerable-mode cross-persona actions remain possible inside one attendee's lab; composite ownership prevents crossing platform attendees. Reset reseeds only that lab and retains its active session.
- CTF uses native named operations, atomic accepted-attempt/progress/leaderboard writes, immutable receipt tombstones, progress identity/stage-digest checks, and a short shared write lock. Models run outside the transaction. Explicit imports read source SQLite without modifying it and require an empty PostgreSQL destination.
- The email builder shares the existing XSS pool/database. HTML remains unsanitized for teaching. Profile/template/preview ownership is enforced by composite keys; receipt insertion validates the template owner. Runtime roles cannot update/delete grading receipts. Reset transactionally removes generated content/progress and preserves profiles and historical receipt metadata, including unavailable judgments.
- PostgreSQL monitoring checks the live session repository for admin HTML access and never loads SQLite at route construction. Operational logs, stress tests and model configuration require an active administrator bearer session. Invalid stress limits are rejected, preventing a zero-concurrency infinite loop. Public JSON health/liveness endpoints are preserved.
- `npm run db:postgres:initialize -- --plan` lists configuration without connecting or printing credentials. The execution form initialized all ten converted repositories in a disposable PostgreSQL cluster. It does not migrate existing data or provision cluster roles.

## Evidence

The isolated root suite completed666 checks:647 passed,19 skipped,0 failed. The previous run exposed stale FinFlow reset fixtures after named-store migration; corrected fixtures retain the ordering and mode-preservation assertions. The final monitoring guard test was also rerun separately after the operational endpoint changes.

The real PostgreSQL matrix passed26 tests, including the latest CTF result feedback/import/concurrent-reset cases, followed by all ten repository initializers and the existing ARIA105/NOVA137 service checks. Their explicitly server-dependent sections remain skipped; this is not full application browser qualification.

The200-attendee regression uses injected storage and deterministic model responses (551ms total,494ms p95, maximum model concurrency4). It proves scheduling behavior in that harness, not200 simultaneous real-model throughput. Existing real local8B Judge qualification is documented separately in `judge-verification-2026-09-11.md`.

Learning dependency preservation passed, with four investigation/frozen entries. All62 currently mapped intentional SecureShop vulnerability IDs retain code/test annotations; this coverage check does not replace executable exploit tests after the future SecureShop migration.

Local diagnostic logs: `/tmp/dvaia-native-stores-regression-final.log`, `/tmp/dvaia-final-ctf-ea-snapshot.log`. Disposable PostgreSQL clusters were stopped; application databases were not reset or imported.

## Remaining work

Remove hidden legacy imports in DPI/RAG/rate-limit paths; migrate legacy sensitive-info and other challenge persistence; migrate SecureShop and its separate agent-host synchronous stores; implement PostgreSQL administrative initialization/export/reset and final installation. Preserve the separate platform/challenge trust boundary and re-prove dialect-sensitive teaching behavior. The published legacy email-builder script-element objective still lacks a reachable browser rendering workflow and must remain uncredited until that mismatch is resolved.

## Latest startup closure checkpoint

The fresh disposable PostgreSQL suite passed36/36 tests after adding generic legacy challenges and sensitive lookup, with all14 initializer repositories, ARIA105 and NOVA137 checks passing. Logs: `/tmp/dvaia-legacy-native-pg.log`. Both new stores use separate runtime/migration roles and databases; no platform data is placed in raw-SQL teaching stores. Compatibility sensitive-info URLs remain available, with PostgreSQL dialect explicitly reported.

SecureShop startup now gates application readiness. Its supervisor uses the current Node executable, verifies its own child instance in health responses, destroys stalled health requests, and bounds child shutdown. The agent host closes SSE transports before awaiting HTTP drain. Focused lifecycle6/6 tests pass; a separate disposable full-process boot passed, with legacy drivers forbidden in parent and child, all17 agents, native catalog HTTP, and clean shutdown.
