# PostgreSQL startup reachability audit

Static audit of `server/index.js`, 2026-09-11. No application startup or working database connection was used. This is a scoped source audit, not proof of complete transitive import closure; concurrent migrations can supersede entries.

The originally identified startup paths below are now resolved in PostgreSQL selection. A disposable full application boot forbidding sqlite3, better-sqlite3 and mysql2 in both backend and child passed: all17 MCP agents started, the native catalog served HTTP, and SIGTERM exited cleanly. This verifies the selected runtime path, not final removal of legacy branches or the installation/data-import cutover.

## Identified paths

| Selected entry | Reachable legacy operation | Required follow-up |
| --- | --- | --- |
| index → `sqliteTuning.installSqliteTuning()` | Imports and patches sqlite3; does not itself open a DB | Skip driver tuning in PostgreSQL mode |
| index → `retireLegacyWebSocketConfigFile(dvaia.db)` | Opens an existing working SQLite file read/write and updates historical websocket configuration even in PostgreSQL mode | Gate legacy file maintenance by selected engine; preserve PostgreSQL retirement independently |
| mounted `/api/ai`, `/api/ecommerce`, vulnerability routes → `database/init.js` | Unconditional SQLite `dvaia.db` construction and initialization | Resolved: native isolated legacy_challenge repository preserves SQL/HTML teaching semantics |
| AI route → `middleware/workshopMode.js` | Same unconditional init import and callback query for vulnerability settings | Resolved: native named legacy_challenge configuration access |
| auth/admin/solutions/hints and middleware → `database/authDb.js` | Independent review found no reachable import under full PostgreSQL selection; these modules branch before SQLite bodies | Resolved inventory correction. Startup now makes PLATFORM postgres imply WORKSHOP postgres, including CSRF sandbox selection |
| index → `mysqlSensitiveInfoDb.initialize()`; mounted `/api/sensitive-info/mysql` | Actual mysql2 pool and MySQL query methods | Resolved: isolated sensitive_lookup repository with explicit PostgreSQL dialect; compatibility endpoints retained |

`server/routes/workshop.js`, sensitiveInfoDb, XSS email route, SecureShop auth/customer/admin, and SecureShop runtime stores have PostgreSQL selection branches. Their unselected SQLite bodies are not counted as reachable PostgreSQL operations. SecureShop merchant is being migrated by a separate worker. Unmounted secureAuth/secureChallenges were not counted merely because their files contain legacy imports.

## Classic challenge configuration migrated in this slice

`routes/challenges.js` now calls the named asynchronous `legacyChallengeConfigStore`. PostgreSQL selection delegates to the existing XSS pool/factory, using `xss.legacy_challenge_config` from migration `xss/0003_legacy_challenge_config.sql`. No identity tables are used. The empty initial state means solutions disabled, matching the previous absence-of-row behavior; initialization never overwrites a toggle. Runtime permissions are explicit.

The intentionally unauthenticated demo toggle and raw reflected HTML remain unchanged. Read/write failures produce HTTP 500 rather than silently opening SQLite. The staged legacy branch retains `challenge.db` and its existing table; `LEGACY_CHALLENGE_DB_PATH` supports disposable fixtures. Existing legacy configuration is not automatically imported into PostgreSQL.

Guarded `tests/legacyChallengeConfig.test.js` passes 2/2: route contracts/raw reflection and no SQLite import in PG selection. The existing disposable `tests/postgres/xss.integration.test.js` includes configuration persistence across recreated factories; its updated native check passed in the fresh36-test PostgreSQL run. Full PostgreSQL boot is now separately covered by tests/postgres/applicationBoot.integration.test.js.
