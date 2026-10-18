# Student Dashboard Reset Ownership

## Scope

This document covers the attendee reset button on `WorkshopDashboard` and the
`POST /api/workshop/progress/reset/:workshopKey` API. A successful response means
the selected workshop's authoritative attendee progress owners were reset; it is
not merely a deletion of the central dashboard projection.

## Dispatch contract

Direct Prompt Injection retains its dedicated middleware and atomic progress
service. Every other workshop key is delegated to the shared
`createAdminWorkshopResetService` implementation, using the authenticated
platform user ID and the canonical workshop-key mapping.

The shared service owns the following targeted reset boundaries:

| Workshop | Targeted reset owners |
|---|---|
| XSS | `xss_workshop_progress` plus central objectives, summary, and time |
| CSRF | local progress and tool log, wallet baseline, plus central progress |
| Indirect Prompt Injection | RAG and email progress, central progress, and the selected attendee's current in-memory RAG document session |
| MCP | `mcp_workshop_progress`, per-user tool activity, central progress, and the `mcp_<userId>` sandbox/listener owner |
| Sensitive Information | FinFlow progress, per-user tool log and auxiliary rows, central progress, and process-local simulator state |
| Supply Chain | `sc_progress` plus central progress |
| SQL / NoSQL | central authoritative progress |

The multi-database reset service preflights required tables before deletion and
uses its existing transaction chain. Sensitive Information holds the user's
simulator queue across durable deletion and post-commit state invalidation. A
post-commit simulator failure is returned as an explicit committed/partial
error; it is never reported as success.

MCP follows the same truthful ownership rule. The tool-log table and sandbox
adapter are preflighted before deletion. Local progress and tool activity are
deleted in the MCP database transaction, central progress is deleted through
the shared transaction chain, and only then is `resetSandbox("mcp_<userId>")`
invoked. Bulk admin reset semantics remain unchanged; sandbox invalidation is a
targeted attendee-reset responsibility.

Indirect Prompt Injection preflights the RAG session adapter before durable
deletion. After RAG/email and central progress commit, it clears only the
authenticated attendee's current `ragVectorStore` session. A failure is
returned as an explicit committed/partial reset instead of false success.

## Explicit in-lab reset exception

Excessive Agency now partitions its mutable five-persona graph by platform
attendee, and its in-lab **Reset Progress** action reseeds only that attendee's
graph while preserving their active lab session. The generic dashboard reset
continues to return HTTP `409` with `code: TARGETED_RESET_UNSUPPORTED` and
`manualResetRequired: true`; this recoverable path deliberately directs the
attendee to the authoritative in-lab reset instead of partially resetting only
the central projection.

## Verification

The reset suite uses only in-memory SQLite fixtures and covers dashboard
delegation through authoritative local and central owners, Sensitive tool-log
and simulator cleanup, MCP tool-log and sandbox cleanup, the CSRF wallet/tool-log
compatibility behavior, and the Excessive Agency manual-reset response:

```bash
node --test tests/adminWorkshopResetService.test.js
node --test tests/progressSyncReset.test.js tests/promptInjectionProgress.test.js tests/workshopProgressService.test.js
node --test tests/sensitiveInfoResetRace.test.js tests/sensitiveInfoStateIsolation.test.js
```
