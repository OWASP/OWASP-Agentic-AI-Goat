# SecureShop commerce PostgreSQL storage

`secureshop/0001_schema.sql` reproduces commerce tables from legacy schemas 03, 17, 19 and 20. `secureshopSeed.js` loads the checked-in JSON snapshot with parameterized inserts and preserves existing IDs and instructor edits. The snapshot was captured by executing seeds 03, 17, 19, 20, 21 and 22 in a disposable copied directory; no application database was opened. Randomized seed timestamps, hashes and message IDs are fixed in this snapshot. Manual document bodies are separately captured in `secureshopManuals.json`; the original seed wrote these as files and left `product_manuals` empty. Database initialization itself does not write those files.

`getSecureShopCommerceDb()` uses the shared commerce pool. Named asynchronous methods back the PostgreSQL-selected commerce tools; the legacy branch remains available only during the staged migration. Tool MCP handlers await the result before encoding JSON. Product, review, policy and manual source loaders are asynchronous.

The SQL injection lessons execute actual PostgreSQL SQL, including typed UNION, Boolean and error payloads. Read-only query tools use one extended-protocol statement inside a read-only transaction with a challenge-local search path. There is no SQLite SQL translation layer. The intentional HTML, template, SSRF, XXE, IDOR, credential disclosure and unchecked role mutation behavior remains in the tools.

User-management writes its commerce mutation and an audit outbox event in one commerce transaction. Delivery to the separate agents database uses the stable event UUID and idempotent `appendAudit`. A failed delivery leaves the event pending and does not repeat the mutation. `flushAuditOutbox(appendAudit)` processes at most 100 pending events. This is eventual audit delivery across databases, not a cross-database atomic transaction.

The disposable integration test is `tests/postgres/secureshopCommerce.integration.test.js`. It requires `PG_TEST_DISPOSABLE=yes` and its own `PG_SECURESHOP_TOOLS_TEST_RUNTIME_URL` / `PG_SECURESHOP_TOOLS_TEST_MIGRATION_URL` pair. It must not target an existing application database.
