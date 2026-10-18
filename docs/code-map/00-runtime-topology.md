# Runtime Topology and Startup

This page describes the supported PostgreSQL application. Legacy SQLite fixtures and alternate servers are not the local installation path.

## Entry points

| Command | Purpose |
|---|---|
| `npm run setup` | Install application dependencies, verify local components, provision fresh PostgreSQL configuration |
| `./start_all.sh` | Validate configuration and launch the application using `scripts/start-application.js` |
| `./stop_all.sh` | Stop this workspace's owned launcher through `scripts/launcher-control.js` |
| `npm run dev` | Developer-only nodemon/Vite watching; bypasses launcher preflight and controller |
| `npm start` | Run `server/index.js` directly |
| `npm run client` | Vite frontend, normally port 3000 |

The macOS/Linux installers prepare missing system prerequisites before setup. Startup does not install tools, rewrite private configuration, reset databases, start Ollama, or kill unrelated listeners. Keep the configured services available before launching. See [Quick Start](../QUICK_START.md).

## Configuration and initialization

`scripts/start-application.js` validates the Node runtime, private environment, PostgreSQL URL pairs and platform signing configuration. `--plan` reports configuration presence without connecting. `--init-db` invokes explicit idempotent initialization; `--reset` is rejected.

`db/postgres/initialize-application.js` exports `requiredStoreManifest`, the authoritative list of isolated stores and runtime/migration URL pairs. Initialization runs sequentially and does not import legacy learner data. Existing-installation migration is a separate reviewed process.

The backend entry point is `server/index.js`; startup-required database initialization must succeed before it listens. The frontend communicates with the Express backend, which uses the configured PostgreSQL stores and local or optional cloud model providers. LangGraph owns agent decision workflows and LangChain supplies model integration. Exercise-specific sidecars and the SecureShop agent host have separate readiness requirements.

## Ownership and verification

The process entry in `server/index.js` acquires the application maintenance lease before `server/applicationServer.js` constructs middleware and mounts routes. For the detailed mappings, see [backend authority and revisions](02-backend-core-auth-admin.md), [workshops and CTF](03-workshops-and-ctf.md), [SecureShop agents and MCP](05-secureshop-agents-and-mcp.md), [file catalog](09-file-catalog.md), and [polling safeguards](16-polling-load-safeguards.md). Development proxy routes and timeouts are defined in `client/vite.config.mjs`.

The launcher control record belongs to this workspace. Shutdown targets its owned child processes rather than arbitrary port listeners. PostgreSQL persistence and shared Ollama lifetime are separate from the application process lifetime.

The supported launcher starts the backend directly and requires a token/PID/port-bound readiness message before starting Vite on its strict configured port. Startup has a bounded deadline. Unexpected exits stop owned sibling processes and return failure. Windows uses an owned guardian to retain a process-tree root.

Check both the frontend and `/api/monitoring/health`; a served frontend alone does not prove backend readiness. Full exercise acceptance additionally requires actual tool effects, Judge evidence, ownership/reset checks and dashboard parity. See [current release status](../modernization/current-release-status.md) for the verified scope and remaining gaps.
