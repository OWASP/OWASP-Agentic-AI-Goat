# Deployment and Operations

## Local modes

| Mode | Command | Components |
|---|---|---|
| full local dev | `./start_all.sh` | validated configuration, Express 8081, frontend 3000, optional agent host and owned sidecars |
| manual dev | `npm run dev` | Express + frontend; assumes dependencies/env/DB/AI are ready |
| backend only | `npm start` | Express; serves built React bundle if present |
| MCP sidecars | `docker compose up -d mcp-sandbox mailpit ssrf-target rogue-mcp` | execution backends only |

`npm run setup` is the supported fresh-install path. `./start_all.sh --plan`
reports required PostgreSQL URL pairs without starting the application.

## Docker sidecars

| Service | Port | Source | Purpose |
|---|---:|---|---|
| `mcp-sandbox` | 8090 | `sidecars/sandbox-runner` | constrained execution and fake lab filesystem |
| Mailpit | 1025/8025 | upstream image | SMTP sink and inbox API/UI |
| `ssrf-target` | 9099 | `sidecars/ssrf-target` | controlled internal metadata/URL target |
| `rogue-mcp` | 8091 | `sidecars/rogue-mcp` | malicious/changed MCP server behavior |

The teaching sidecars remain local Docker services. The owner-scoped runner
uses its separately provisioned private profile and readiness checks.

## Installation scripts

- macOS/Linux: installer wrappers provision local prerequisites and delegate
  application setup to `npm run setup`.
- Windows: the PowerShell preview reports the unqualified native path before
  installation or startup changes; see `docs/install/windows.md`.
- `docs/install/*` and `docs/QUICK_START.md` are operator instructions, not
  executable sources.

## Database administration scripts

| Script | Function |
|---|---|
| `db/postgres/initialize-application.js` | additive migrations and idempotent seeds for configured stores |
| `scripts/deploy-fresh.js` | compatibility aliases for additive PostgreSQL initialization; reset forms fail closed |
| `scripts/admin/reset-auth-defaults.js` | restore auth/config defaults |
| `scripts/admin/unlock-accounts.js` | clear account locks |
| `scripts/seed-bulk-data.js` | SecureShop bulk seed |
| `scripts/seed-vectors.js` | SecureShop vector corpora |
| `scripts/sync-pi-solutions-to-db.js` | Retired SQLite writer; use `/admin/exercises` for current content or forward PostgreSQL migrations for defaults |

## GitHub Actions and CI/CD

Tracked workflows under `.github/workflows` cover:

- a manually triggered DB schema check;
- SecureShop parity and intentional-vulnerability checks.

## Operational boundaries

- Health: `/api/monitoring/ping` is lightweight; `/health` can include deeper
  DB/AI status and HTML output.
- Logs: application, access, error, and LLM request logs feed both admin UI and
  teaching tools; log format changes have UI/lab consumers.
- Persistence: supported startup requires the configured isolated PostgreSQL
  stores and preserves learner data on additive migrations.
- Live-event gate: shared event password applies before routes but whitelists
  health checks required for local operation.
