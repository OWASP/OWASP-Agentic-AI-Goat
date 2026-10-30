# Archive integration verification — September 11, 2026

The native aggregate passed after the legacy challenge, legacy sensitive-info and SecureShop archive import libraries were added. It ran in a disposable source copy against a newly created, empty PostgreSQL18 container bound only to loopback. No working application database or upload directory was used. The owned container was removed after the run.

Results:

- 67 native tests passed, with no failures or skips. These include importer rollback, provenance, sequence continuation, seed preservation and embedding identity checks.
- All14 application repositories initialized. Two application/agent-host startup checks passed without loading legacy database drivers.
- The200-attendee HTTP test passed with explicit mock inference: all200 requests returned200, median2162ms and p953689ms. It also checked210 completed run records,10 unavailable Judge receipts and10 resets. Those unavailable mock judgments did not award credit. Rate limiting was disabled for this scoped load fixture. This is application/storage qualification, not live-model or AWS capacity proof.
- ARIA service checks passed105, with7 explicitly skipped HTTP checks. NOVA passed137, with7 explicitly skipped HTTP checks.
- The separate disposable-copy SecureShop suite passed284 checks with one gated skip and no failures. Source checks found code/test annotations for all62 enforced vulnerability IDs and retained all4 frozen dependency investigations. Log: `/tmp/owasp-ai-goat-secureshop-migration-regression.log`.
- The final disposable-copy backend regression passed888 tests, with23 gated skips and zero failures (911total). Log: `/tmp/owasp-ai-goat-migration-final-unit.log`. This uses isolated fixtures and mock inference; it is separate from the frozen250-case real8B Judge qualification.

The first aggregate exposed an obsolete RAG test authentication fixture. The test now creates a durable identity session and sends its issued Bearer token. Production authentication was not relaxed. The entire aggregate was then repeated on a fresh empty cluster.

Run summary: `/tmp/owasp-ai-goat-native-auth-aggregate.log`. Full log: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-regression-mcQYSp/tests.log`.

`npm run test:postgres` now uses `scripts/test-isolated.js postgres`. This matters because an existing SecureShop upload fixture writes relative to its checkout; the disposable copy contains those writes. The underlying Python harness still requires an empty disposable cluster and refuses an external cluster containing application databases.

The import libraries remain bounded migration components. File references alone do not verify file continuity; SecureShop imports are transactional per database, not across both databases. Imported vectors retain their original values but require an explicit rebuild when their embedding identity is unknown. Operator orchestration, asset activation and remaining legacy source dispositions are still tracked in [remaining archive coverage](remaining-archive-coverage.md). These checks do not declare the broader modernization goal complete.
