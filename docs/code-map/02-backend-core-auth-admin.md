# Backend Core, Authentication, and Administration

## Core request context

The default server combines an intentionally weak Express session with a
separate workshop JWT/session system. These are distinct mechanisms:

- `express-session` creates a weak, client-readable, SameSite=Lax cookie for
  teaching purposes.
- `middleware/sessionManager.js` resolves bearer/cookie/session identity,
  checks `users_auth.db`, refreshes activity, and exposes session helpers.
- `utils/requestContext.js` stores user/IP/request data in AsyncLocalStorage so
  deep AI/tool layers can log without threading parameters through every call.
- `middleware/adminAuth.js` performs token authentication, role/admin-level and
  permission checks, lockout verification, and activity logging.

Changing JWT secrets, token fields, session expiry, or user role fields affects
`auth.js`, `sessionManager.js`, `adminAuth.js`, monitoring, both AuthContexts,
and SecureShop's separate JWT code.

## Authentication API

`server/routes/auth.js` is the default `/api/auth` implementation.

| Endpoint group | Behavior |
|---|---|
| captcha/config | math captcha, registration flags, public feature flags |
| `POST /login` | rate limiting, lockout, password check, JWT, DB session, permissions, activity log |
| `POST /secure-login` | parameterized comparison endpoint for teaching |
| registration | validation, optional captcha, bcrypt, verification token, progress initialization |
| verification/reset | verify/resend email and generic-response password reset |
| profile/password | own-profile/admin checks, profile update, password rotation |
| logout/status | deactivate session, clear state; JWT verification with DB-session fallback/sliding refresh |
| activity | recent workshop/login activity formatted for the profile UI |

`database/authDb.js` supplies the connection plus validation, hashing,
lockout, integrity recovery, and security logging. It also performs extensive
schema creation/migrations and default metadata reconciliation at startup.

## Authorization model

Workshop users have overlapping fields (`role`, `is_admin`, `admin_level`) for
historical compatibility. Admin permissions are rows in `admin_permissions`.
Route middleware uses combinations of:

- authenticated token/session;
- `is_admin`/role/admin level;
- named permission;
- account active/lock state;
- optional verified email.

The React admin guard is UX only. Every sensitive backend mutation must retain
server authorization.

## Admin API domains

`server/routes/admin.js` is the platform integration hub. Its endpoints are
grouped as follows:

| Domain | Representative paths | Dependencies |
|---|---|---|
| students/users | `/students`, `/users`, locked/lock/unlock, password/profile | auth DB, admin middleware |
| dashboard/stats | `/dashboard`, `/dashboard/stats`, `/activity-stats` | users, progress, logs |
| exercises | `/challenges`, toggle, bulk-toggle | challenge config/visibility, persisted global revision |
| objectives/hints | `/workshops/:key/objectives|hints/*` | visibility tables, canonical objective IDs |
| generic solutions | `/solutions`, `/solutions/:id` | challenge solution metadata |
| per-lab solutions | `/pi-workshop`, `/xss-workshop`, `/csrf-workshop`, `/finflow-workshop`, `/supply-chain-workshop`, `/ea-workshop`, `/ipi-workshop`, `/mcp-workshop`, SQL/NoSQL | each lab's content/visibility table or data module |
| student progress | `/students/:id/progress`, per-workshop reset, all-student resets | central progress helpers plus lab tables |
| activity/logs | `/activity-logs`, `/logs/app`, `/logs/llm`, `/logs/stats` | DB activity, Winston/plain logs, LLM request log |
| analytics | `/analytics/progress`, platform stats | normalized progress and activity |
| security/config | `/security/settings`, `/config`, permissions | security/system config, rate limiter |
| monitoring | `/system/monitoring`, `/llm/health`, `/llm/stats`, `/llm/test` | performance and provider services |
| provider management | `/ai/providers/*`, `/ai/stats` | multi-provider service and `.env` rewrite |
| database operations | `/database/reset`, `/database/initialize` plus typo alias | backups, run-all initializer, lab resets |

Because this router touches many independently owned tables, treat each domain
section as a future sub-router boundary. Its local helpers normalize callback
DB calls, log formats, action descriptions, and provider inference.

## Canonical workshop catalog and progress

`server/routes/workshop.js` is the student-facing normalization layer. It owns:

- `WORKSHOP_OBJECTIVES`, the canonical objective labels for catalog/progress;
- workshop-key to challenge-key translation;
- visible challenge retrieval;
- enabled-objective intersection;
- merging legacy and central completion records;
- master and per-objective solution visibility;
- student/instructor progress and reset endpoints;
- central objective completion and user activity;
- heartbeat/time summaries.

`utils/progressSync.js` is the shared write path used by individual workshops:

- mark a workshop started;
- idempotently mark an objective complete;
- calculate/mark workshop completion;
- fetch normalized progress;
- reset central records.

The source lab may also keep a lab-specific progress/audit table. Completion
there and in `workshop_objectives_progress` must remain synchronized.

## Visibility, hints, and solutions

Visibility is layered, not a single boolean:

1. `challenge_visibility` controls whether the challenge is listed and includes
   master `show_solutions` / `show_hints` flags.
2. `workshop_objective_visibility` enables individual objective IDs.
3. `workshop_hint_visibility` controls per-objective hints.
4. each lab may have a per-objective solution visibility table.
5. `routes/solutions.js` resolves the correct lab registry/table and enforces
   master plus objective visibility before returning content.
6. `routes/hints.js` resolves workshop aliases and applies the same layered
   checks for hints.

The database remains authoritative for every visibility/content value. The
former visibility WebSocket has been replaced by persisted change revisions:

- `changeRevisionStore.js` owns global, workshop, and user revision scopes in
  `users_auth.db`;
- `changeRevisionService.js` initializes the runtime store, while
  `changeRevisionServiceFactory.js` records a global `server_restart` revision
  before serving snapshots;
- authenticated `GET /api/changes/revisions` returns only the signed-in user's
  revision plus explicitly requested workshop revisions and the global
  revision;
- a caller-supplied user ID is never accepted for private revision state.

Admin mutation points now record global revisions for exercise/catalog changes
and workshop revisions for objective, hint, and solution changes. Aggregate
dashboards can subscribe to every workshop revision while the store still
filters private user revisions by authenticated identity.
Individual and bulk per-lab solution mutations use the same workshop signal;
this includes the dedicated FinFlow and Supply Chain “all solutions” routes.
Transient revision-write failures are coalesced by scope and retried with
bounded backoff, while the already-persisted admin mutation remains successful.
The restart marker uses the same bounded retry behavior. It closes the
process-crash window by forcing connected pollers to reconcile authoritative
data after a replacement server becomes available.

Interactive vulnerable/fixed mode is also database-backed. `workshopModeStore`
keys each setting by authenticated user and workshop, and changes the private
`mode` revision through a trigger in the same atomic SQLite statement. The chat routes read that
stored value server-side; request bodies cannot select a security mode or
another attendee's mode.

## Middleware inventory

| File | Functionality |
|---|---|
| `adminAuth.js` | authentication/authorization, permissions, lockout, activity |
| `eventGate.js` | HMAC-signed shared-password gate with health/static allowlist |
| `llmLogger.js` | structured provider call log enriched from request context |
| `performanceMonitor.js` | latency/request/error/concurrency metrics and alerts |
| `rateLimiter.js` | DB-configured general/login/register/reset limiters |
| `requestLogger.js` | UUID request ID and Morgan-to-Winston HTTP record |
| `sessionManager.js` | token/session cache, DB persistence, activity, cleanup |
| `workshopMode.js` | reads legacy vulnerability settings and blocks disabled labs |

## Logging and monitoring

- `utils/logger.js` configures Winston; JSON in production/AWS, readable in dev.
- `requestLogger.js` adds request IDs and structured HTTP entries.
- `server/index.js` also writes simple access/error logs used by a teaching lab.
- `llmLogger.js` writes the provider request ledger consumed by admin statistics.
- `monitoring.js` exposes unauthenticated ping/health and protected detailed
  performance/LLM/log views, including an HTML health page.
- `contextLogger.js` attaches request/user context to deep log calls.

## Alternate secure server path

`server/secureServer.js` mounts `secureAuth.js` and `secureChallenges.js` backed
by `platformDb.js`, `challengeDb.js`, and `secureDbManager.js`. It adds Helmet,
strict sessions, a fixed limiter, isolation audit, and a separate health API.
It does not boot SecureShop. No current npm script starts it, so changes there
do not affect the default application unless the entry point is deliberately
reintroduced.

## High-coupling contracts

- `JWT_SECRET` must be loaded before session/auth singleton construction.
- The user/session table column names are repeated across DB schema, auth,
  session manager, admin routes, and frontend user checks.
- `admin.js` can rewrite provider settings in `.env` and hot-reload the service;
  filesystem/runtime config must remain coherent.
- Database initialize/reset APIs are destructive administrative operations and
  coordinate backups plus several in-memory lab resets.
- Multiple historical progress tables exist; deleting one based only on an
  apparent duplicate can silently break an admin or legacy view.
