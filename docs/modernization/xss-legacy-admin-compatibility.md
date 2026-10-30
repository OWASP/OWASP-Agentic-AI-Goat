# Legacy XSS admin compatibility contract

## Decision and boundary

The four exercise-level XSS solution APIs are a supported compatibility surface. They remain reachable in the SQLite application even though the current admin UI and student page use the newer 12-objective API. PostgreSQL selection must therefore preserve the four legacy records and all five routes. An archive-only record is insufficient because an authenticated client can still call these routes directly.

This contract is separate from the canonical `xss_r1` through `xss_e3` objective content. The legacy keys are `reflected`, `stored_user`, `stored_llm`, and `email`; they are not aliases for individual objective IDs. Restoring these routes must not replace or collapse the 12 objective rows.

The retired CSRF tab tables have no corresponding requirement. They may remain archive-only because the mounted student and admin routers use only the canonical CSRF objective rows.

## Pre-fix compatibility defect and implementation status

`server/index.js` mounts the selected admin router at `/api/admin`. In SQLite mode, `server/routes/admin.js` registers the five routes described below. In PostgreSQL mode, `server/routes/admin.js` immediately selects `server/routes/postgresAdmin.js`.

Before migration 0014, the PostgreSQL router's only XSS solution prefix was `xss-workshop/objective-solutions`. Its generated routes began at `/xss-workshop/objective-solutions`; it never registered `/xss-workshop/solutions`. Consequently all five legacy paths fell through to the application's not-found response when `PLATFORM_DATABASE_ENGINE=postgres`:

- `GET /api/admin/xss-workshop/solutions`
- `POST /api/admin/xss-workshop/solutions/toggle`
- `POST /api/admin/xss-workshop/solutions/bulk`
- `GET /api/admin/xss-workshop/solutions/preview/:challengeId`
- `POST /api/admin/xss-workshop/solutions/:challengeId`

Evidence:

- Mount: `server/index.js:306`
- SQLite selection and global authentication: `server/routes/admin.js:1-3`, `server/routes/admin.js:112-113`
- SQLite implementations: `server/routes/admin.js:2420-2547`
- PostgreSQL route registry and generated routes: `server/routes/postgresAdmin.js:7-18`, `server/routes/postgresAdmin.js:490-528`
- Current UI uses the objective routes instead: `client/src/pages/ComprehensiveAdminDashboard.js:2555-2631`, `client/src/pages/ComprehensiveAdminDashboard.js:4493`

The lack of a current first-party UI caller does not make an authenticated HTTP route safe to remove. Scripts, bookmarks, and older admin clients can still depend on it.

The compatibility implementation now consists of:

- Empty native table creation in `db/postgres/identity-migrations/0014_xss_legacy_admin.sql`.
- Non-overwriting four-row defaults in `server/database/postgres/workshopPlatformSeed.js`.
- Explicit named PostgreSQL operations in `server/database/postgres/xssLegacyAdminRepository.js`.
- All five routes and the atomic generic XSS master cascade in `server/routes/postgresAdmin.js`.
- Injected HTTP contract coverage in `tests/xssLegacyAdminCompatibility.test.js` and native PostgreSQL coverage in `tests/postgres/adminHttp.integration.test.js`.

The focused tests pass against a fresh disposable PostgreSQL 18 database: two tests passed, with no failures or skips. The native test proves the direct legacy toggle leaves canonical flags unchanged, restart seeding preserves an instructor edit, and an injected legacy-write failure rolls back the master gate and all canonical objective changes. The verification log is `/tmp/owasp-ai-goat-xss-legacy-native.log`.

## Authentication and audit contract

All five routes inherit the admin router's bearer-token authentication and require admin level 1 or higher.

Under the selected PostgreSQL authentication middleware:

- A missing bearer token returns `401` with `{ "error": "Authentication required", "message": "Access token is missing" }`.
- An invalid token or expired token returns `401` with `{ "error": "Invalid token", "message": "Token verification failed" }`.
- A missing or expired stored session returns `401` with `{ "error": "Session expired", "message": "Please login again" }`.
- An authenticated user below admin level 1 returns `403` with `{ "error": "Insufficient privileges", "userLevel": <number> }`.
- An unavailable authentication store returns `503` with `{ "error": "Authentication error", "message": "Session store unavailable" }`.

The three mutating operations retain their existing audit action names:

| Operation | Audit action |
|---|---|
| Toggle one exercise | `admin_xss_solution_toggle` |
| Toggle all exercises | `admin_xss_solution_bulk` |
| Update exercise content | `admin_xss_solution_update` |

The PostgreSQL `logActivity` middleware is fail-closed: if the audit record cannot be stored, it returns `503 { "error": "Audit store unavailable" }` before the mutation. The implementation should also publish the same scoped config-change records used by the SQLite handlers after a successful commit. It must not report a change before the native transaction commits.

## HTTP and DTO contract

Route ordering is part of the implementation requirement. Register `/toggle`, `/bulk`, and `/preview/:challengeId` before `/:challengeId` so a literal route is never interpreted as an update ID.

### List the four exercises

`GET /api/admin/xss-workshop/solutions`

The list is driven by visibility rows and left-joins optional content. Sort by `challenge_id` ascending, matching SQLite. With all seed rows present this produces `email`, `reflected`, `stored_llm`, `stored_user`.

Success is `200`:

```json
{
  "success": true,
  "challenges": [
    {
      "challengeId": "reflected",
      "solutionsEnabled": false,
      "enabledBy": null,
      "enabledAt": null,
      "updatedAt": "2026-09-11 12:34:56",
      "title": "Reflected XSS",
      "difficulty": "Beginner"
    }
  ]
}
```

`enabledBy`, `enabledAt`, `updatedAt`, `title`, and `difficulty` are nullable. Timestamps remain JSON strings. PostgreSQL reads should format UTC timestamps consistently rather than exposing driver-specific `Date` objects. A repository failure returns `500 { "error": "Failed to fetch XSS workshop solutions" }`.

### Toggle one exercise

`POST /api/admin/xss-workshop/solutions/toggle`

Request body:

```json
{ "challengeId": "reflected", "enabled": true }
```

`challengeId` must be one of the four legacy keys. A missing or unknown key returns `400 { "error": "Valid challengeId is required" }`. The legacy handler coerces `enabled` with JavaScript truthiness; the compatibility implementation must retain that behavior for this route even though newer PostgreSQL objective routes require a Boolean.

The update sets the Boolean flag and the authenticated actor. Enabling sets `enabled_at` to the current time. Disabling preserves the previous `enabled_at`. Every successful update changes `updated_at`. The seed guarantees the row exists; preserve the legacy success shape:

```json
{ "success": true, "challengeId": "reflected", "enabled": true }
```

The change notification is `{ type: "solutionVisibility", workshopKey: "xss_workshop", objectiveId: challengeId }`. A repository failure returns `500 { "error": "Failed to update visibility" }`.

### Toggle all four exercises

`POST /api/admin/xss-workshop/solutions/bulk`

Request body is `{ "enabled": <truthy-or-falsy-value> }`; it uses the same legacy truthiness coercion. It updates all visibility rows and uses the same actor and timestamp rules as the single toggle.

Success is `200`:

```json
{ "success": true, "enabled": false, "updated": 4 }
```

`updated` is the number of rows affected, including rows whose flag already had the requested value, because the SQLite statement has no change predicate. The change notification is `{ type: "solutionVisibility", workshopKey: "xss_workshop", bulk: true }`. A repository failure returns `500 { "error": "Failed to update visibility" }`.

### Preview exercise content

`GET /api/admin/xss-workshop/solutions/preview/:challengeId`

Preview is admin-only and does not check the exercise visibility flag. An unknown ID returns `404 { "error": "Solution not found" }`; there is no four-key allowlist check on this read.

Success is `200`:

```json
{
  "success": true,
  "solution": {
    "title": "Reflected XSS",
    "difficulty": "Beginner",
    "hints": ["First hint"],
    "examples": [{ "payload": "<b>test</b>", "explanation": "HTML is preserved" }],
    "approach": "Start with harmless HTML.",
    "tips": ["Observe the rendered output"]
  }
}
```

The SQLite columns `hints`, `examples`, and `tips` contain JSON text. The legacy parser processes those fields sequentially in one `try` block and swallows the first parse error. Exact compatibility therefore requires text storage and the same observable fallback: fields parsed before an invalid field are arrays/objects, while that field and subsequent fields remain raw strings. A repository failure returns `500 { "error": "Failed to fetch solution" }`.

### Update exercise content

`POST /api/admin/xss-workshop/solutions/:challengeId`

Body fields are `title`, `difficulty`, `hints`, `examples`, `approach`, and `tips`. A truthy `title` is the only validation requirement; otherwise return `400 { "error": "Title is required" }`. This route does not validate `challengeId` against the four seed IDs and does not treat a zero-row update as missing. An unknown ID with a title therefore retains the legacy `200` response:

```json
{ "success": true, "message": "Solution updated successfully" }
```

Array values for `hints`, `examples`, and `tips` are JSON-stringified. A non-array `hints` value is stored verbatim, with any falsy value becoming the text `[]`. Non-array `examples` and `tips` are stored verbatim; omitted values become SQL `NULL`. `difficulty` and `approach` are also passed through, and `updated_at` changes on a matching row. The change notification is `{ type: "solutionContent", workshopKey: "xss_workshop", objectiveId: challengeId }`. A repository failure returns `500 { "error": "Failed to update solution content" }`.

## Visibility and cascade semantics

The four exercise flags are an independent compatibility namespace:

- Calling a legacy single or bulk toggle changes only the legacy exercise rows.
- It does not change `challenge_visibility.show_solutions`.
- It does not change any of the 12 canonical `xss_workshop` objective flags.
- It does not change hint visibility.

This isolation matches the handlers at `server/routes/admin.js:2452-2495`. Do not add a new cascade to these routes during migration.

The broader legacy endpoint `PATCH /api/admin/solutions/:solutionId/visibility` has different behavior when its resolved challenge key is `reflected_xss_llm`: it updates both all four legacy exercise flags and all 12 canonical objective flags (`server/routes/admin.js:4314-4342`). If that generic endpoint remains supported in PostgreSQL, its native transaction must preserve that dual write. This is separate from the five routes in this document and must be covered by an integration test rather than implemented as a side effect of their repository methods.

The current admin page explicitly uses the canonical objective API and the student API gates content with the master and canonical objective state. A direct legacy toggle therefore must not be described as publishing a student-visible objective solution.

## Minimum native PostgreSQL storage

Add dedicated native tables in the platform workshop schema. Suggested names are `workshop_platform.xss_legacy_solution_visibility` and `workshop_platform.xss_legacy_solutions`; final names may follow the established migration naming convention, but they must remain distinct from canonical solution tables.

Minimum visibility columns:

| Column | Requirement |
|---|---|
| `challenge_id` | Text primary key, constrained to the four legacy keys |
| `solutions_enabled` | Non-null Boolean, default false |
| `enabled_by` | Nullable identity user ID with the same foreign-key policy as other platform config rows |
| `enabled_at` | Nullable `timestamptz` |
| `updated_at` | Non-null `timestamptz`, default current time |

Minimum content columns:

| Column | Requirement |
|---|---|
| `challenge_id` | Text primary key, constrained to the four legacy keys |
| `title` | Non-null text |
| `difficulty` | Nullable text |
| `hints` | Nullable text containing the archived JSON representation |
| `examples` | Nullable text containing the archived JSON representation |
| `approach` | Nullable text |
| `tips` | Nullable text containing the archived JSON representation |
| `updated_at` | Non-null `timestamptz`, default current time |

Use text for the three encoded fields. Converting them to `jsonb` would reject instructor-edited legacy strings and would change the preview endpoint's documented fallback behavior. Native SQL must use explicit named queries and PostgreSQL placeholders; no SQLite SQL translator or runtime fallback is permitted.

## Seed and import contract

The native initializer seeds exactly four visibility rows, disabled by default, and the four content objects from `server/data/xssWorkshopSolutions.js`'s `solutions` export. Seed insertion must use `ON CONFLICT DO NOTHING`. Unlike the old `db/initialize-db/seeds/01_users_auth.js:177-195` behavior, ordinary PostgreSQL initialization must not overwrite instructor-edited content on restart.

Archive import preserves both legacy tables as live native data, independently of the canonical objective import:

| SQLite source | Native destination | Mapping |
|---|---|---|
| `xss_workshop_solution_visibility` | Legacy visibility table | `challenge_id` unchanged; `0/1` to Boolean; actor mapped through the identity import map; timestamps parsed as SQLite UTC timestamps |
| `xss_workshop_solutions` | Legacy content table | `challenge_id`, all content text, and `updated_at` preserved; JSON text is not rewritten |
| `xss_workshop_objective_solutions` | Existing canonical solution/config tables | Continue the separate 12-objective mapping |

A non-null `enabled_by` that cannot be resolved through the identity map blocks import for that row and appears in the review report. Duplicate IDs, unknown challenge IDs, malformed row shapes, or content without a matching visibility seed row also block the native apply. Import runs in the same atomic platform migration transaction as the surrounding snapshot apply so a partial legacy import cannot be published.

`db/postgres/map-platform-additional-solutions.js:205-250` currently validates these legacy rows but emits only digests in `snapshot.retainedLegacy`. The implementation phase must extend the reviewed snapshot with the full validated native legacy rows, or consume the original archive again under the same immutable archive digest. A digest-only retention record cannot populate these APIs. Once dedicated destinations exist, canonical objective rows and legacy tab rows no longer compete for one slot: both must be imported. Existing source-choice records may continue to govern canonical projection, but they must never discard the live legacy copy.

## Required verification

Add focused injected-router tests and disposable PostgreSQL integration tests. At minimum they must prove:

1. PostgreSQL selection registers all five exact methods and paths, while the 12-objective routes remain available.
2. Missing authentication returns 401, a student returns 403, and admin level 1 can use every route.
3. A fresh seed lists four rows in SQLite-compatible ordering and preserves nullable left-join fields.
4. Single toggle validates the key, uses legacy truthiness, records the actor, refreshes `updated_at`, sets `enabled_at` only on enable, and preserves `enabled_at` on disable.
5. Bulk toggle reports four affected rows even when values already match and does not alter master, objective, or hint flags.
6. Preview returns decoded arrays/objects for valid JSON and preserves the sequential raw-string fallback when a stored field is malformed.
7. Update preserves the exact array/string/null serialization rules, rejects a missing title, and retains the legacy success response for an unknown ID.
8. Mutation audit failures prevent writes; repository failures return the endpoint-specific status and error DTOs above; successful mutations publish their scoped change only after commit.
9. The generic `reflected_xss_llm` visibility operation, if mounted, changes legacy and canonical flags atomically without changing hints.
10. Archive import preserves instructor-edited content, flags, actors, and timestamps in both legacy and canonical namespaces. Restart seeding does not overwrite imported edits.
11. A guarded PostgreSQL application boot can call these endpoints without loading SQLite. A separate selection test confirms the SQLite handlers still retain their current behavior.
12. No CSRF legacy table or route is introduced; retired CSRF rows remain explicitly reported as archive-only.

The implementation is complete only when these tests run against a disposable PostgreSQL schema and the existing canonical XSS admin and student tests remain green.
