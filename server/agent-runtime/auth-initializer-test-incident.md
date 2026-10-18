# Test isolation incident — 2026-09-11 04:10:40 UTC

Command: `node --test tests/sensitiveInfoResetRace.test.js tests/sensitiveInfoUserReset.test.js`.
The reset-race test imported adminAuth, which loaded the live authDb initializer.
The companion user-reset test uses an in-memory store.

Captured output confirmed database connection, mode 600, foreign-key/WAL setup,
table creation/verification, CSRF seeding, solution reconciliation, and existing
account detection. Source references in `server/database/authDb.js` identify the
potential operations:

- Startup initialization, chmod and PRAGMAs: lines 362–420.
- Schema creation and initial tables: lines 427–630.
- Deprecated-row cleanup and visibility updates: lines 670–752.
- Configuration/solution seeds and progress deduplication: lines 757–1149.
- Objective visibility, stale-row cleanup and hint reconciliation: lines 1201–1367.
- Remaining workshop solution seeds/reconciliation: lines 1376 onward.

There was no before-image. Individual row changes or counts cannot be attributed
to this command; modified Git status does not establish causation. No database
rows were inspected or restored. Root took 19 read-only snapshots afterward.

The test now stubs adminAuth and throws on any attempted authDb import. All broad
tests must run in a disposable copy. Working-repository tests require verified
injected dependencies and a guard against implicit live database imports.
