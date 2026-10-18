# Existing-data migration inventory

Source-controlled code review, 2026-09-11. This inventory describes the checked-in PostgreSQL migration surface without opening working SQLite databases, `.env` files, MySQL, or deployment assets. Native schemas and fresh seeds establish a destination shape; they do not establish existing-data continuity.

The SQLite exporter allowlists the 19 source filenames in [`db/postgres/export-legacy.js`](../../db/postgres/export-legacy.js:4-20). It writes a verified, typed archive and rejects WAL/journal sidecars and changed sources. The exporter is per-file; operators must quiesce writers and separately account for MySQL, process memory, filesystem assets, vector sidecars, and environment configuration.

## Implemented archive and import surface

| Surface | Current status | Operator entry point |
|---|---|---|
| Platform identity, workshop state and solution records | Archive reader, mappers, validation and transactional native apply are implemented. The combined path covers identity/platform/auxiliary state, 100 canonical solution records and legacy XSS solution pairs. Retained or unresolved source tables still require review. | `node db/postgres/apply-platform-archive.js --archive <dir> --review <file> --database-env <migration-variable-name> [--apply]` |
| ARIA / NOVA | Verified archive read, map, constraint dry run and apply are implemented. | `node db/postgres/import-workshop-archive.js --archive <dir> --family aria|nova --review <file> --database-env <migration-variable-name> [--apply]` |
| FinFlow / CodeBot | Archive readers and verified map/apply libraries cover progress and tool logs; solution content is handled by the platform solution apply. | `npm run db:legacy:apply-workshop -- --family finflow|supply_chain …` |
| MCP | Archive reader and map/apply library cover progress and tool logs. | `npm run db:legacy:apply-workshop -- --family mcp …` |
| CSRF | Archive reader and map/apply library cover progress, tool logs, wallets and victim-state input. | `npm run db:legacy:apply-workshop -- --family csrf …` |
| XSS | Archive reader and map/apply library cover XSS workshop/email rows and `challenge.db.admin_config`; unknown or vulnerable legacy rows remain retained for review. | `npm run db:legacy:apply-workshop -- --family xss …` |
| CTF | Archive reader and map/apply library cover the documented 12-table `ctf.db` snapshot. A separate older direct SQLite importer also exists. | `npm run db:legacy:apply-workshop -- --family ctf …`; older direct helper remains separate |
| Native-only destinations | PostgreSQL schemas and runtime branches exist, but active-store imports now cover SecureShop, generic legacy challenge and legacy-sensitive records; platform_secure and the SQLite excessive-agency file remain outside supported continuity. | See [`remaining-archive-coverage.md`](remaining-archive-coverage.md) |

“Archive-connected” means a verified archive can reach a bounded mapper/apply library. Platform, ARIA/NOVA, workshop-family and active-store operator commands now exist. Their per-target transactions do not constitute a whole-installation orchestrator. Follow [the local upgrade runbook](local-existing-installation-upgrade.md).

## Source-file coverage

| Source file | Current disposition |
|---|---|
| `users_auth.db` | Partially archive-connected through the platform path: identity, platform/auxiliary state and solution inputs have mappers. Tokens, edited config, overlapping progress and unknown tables require an explicit policy. |
| `sql_workshop.db`, `nosql_workshop.db` | Archive-connected and CLI-backed. |
| `xss_email_challenge.db`, `xss_challenge.db`, `challenge.db` | XSS archive library covers supported workshop/email/config rows; vulnerable/unknown rows remain archive-only until a route-backed disposition is approved. |
| `csrf_workshop.db`, `mcp_workshop.db` | Archive-connected through the workshop operator CLI. |
| `supply_chain_workshop.db`, `sensitive_info_workshop.db` | FinFlow/CodeBot progress/tool-log libraries; solution tables are platform solution inputs; other source tables require review. |
| `ctf.db` | Archive-connected through the workshop operator CLI; older direct-source helper remains separate. |
| `platform_secure.db`, `sqli_challenge.db`, `ctf_ai_challenge.db` | No verified-archive importer. Reachability and required disposition are documented in the companion. |
| `dvaia.db` | Active-store CLI maps ten native generic demo table families; unsupported tables and unresolved file references retain explicit dispositions. |
| `excessive_agency.db` | SQLite schema exists, but the active lab authority is process memory or PostgreSQL attendee state; a file-only import would not be lossless. |
| `secureshop.db`, `secureshop_agents.db` | Active-store verified archive import and explicit asset staging/cutover verification exist; imported vectors require verified compatibility or re-embedding. |
| `sensitive_info.db` | Main routes consume documents/access logs through the PostgreSQL `legacy_sensitive` adapter, with an active-store mapper/importer for documents and access logs; residual tables remain archive-only. |

## Native destination and cutover boundary

The native initializer provisions 16 PostgreSQL destinations in [`db/postgres/initialize-application.js`](../../db/postgres/initialize-application.js:5-21). The main server selects PostgreSQL branches when both `PLATFORM_DATABASE_ENGINE=postgres` and `WORKSHOP_DATABASE_ENGINE=postgres` and mounts the route families described in [`server/index.js`](../../server/index.js:161-223,227-313). That branch evidence is the basis for distinguishing active consumers from legacy SQLite entry points.

The focused gaps, route evidence, source table families, native targets, and explicit unknowns are maintained in [`remaining-archive-coverage.md`](remaining-archive-coverage.md). It also lists the next implementation priorities. No runtime or database files were changed for this inventory.
