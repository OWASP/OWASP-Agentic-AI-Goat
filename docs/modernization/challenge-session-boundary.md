# Challenge session boundary

Status: the MCP/XSS route-local authority correction has focused and full-backend native checks. The existing upstream PostgreSQL workshop gate already blocked cookie-only requests; no full-application stale-cookie bypass was demonstrated. A minimal allocation/metadata phase is qualified in source; the broader scoped persistent-store redesign below is not implemented.

The supported PostgreSQL platform validates bearer sessions through `postgresSessionManager` and canonical authentication middleware. Separately, `server/index.js` mounts a deliberately readable, weakly signed Express challenge cookie globally with `saveUninitialized: false` and the default memory store. Untouched anonymous requests no longer persist sessions or receive the challenge cookie. `postgresAuth` retains userId, username and platform owner/session IDs in that server-side challenge session. The owner/session IDs are required by the legacy mutation lifecycle fence; removing them would downgrade cookie-backed writes into unowned legacy work. New login sessions no longer copy role/adminLevel, and the PostgreSQL session manager no longer copies session metadata on bearer requests. The cookie contains an opaque signed identifier, not those fields or a JWT. Knowing its signing secret does not create an existing server-side session.

Two route-local consumers retained unsafe fallback behavior under alternate mounting: MCP accepted cookie owner/role fields without current platform-session validation, and XSS could derive a platform owner from the same cookie. The correction requires canonical PostgreSQL authority for MCP and uses optional canonical authentication for XSS. An omitted bearer can still use explicitly anonymous synthetic XSS behavior; a supplied invalid bearer cannot regain authority through the challenge cookie. CSRF's deliberate managed-browser victim-cookie effect remains unchanged. The full application already authenticates the upstream `/api/workshop` router: its cookie-only denial precedes these route-local checks. The graded CSRF UI uses a bearer-authenticated managed-browser entry and bound internal dispatch, so the retained public cookie-only `/csrf/agent-action` endpoint returning401 does not prove the graded exercise is broken. Full-application XSS also requires login; anonymous behavior is limited to standalone/legacy mounting. See [native evidence](../../tasks/workshop-cookie-authority-2026-09-19.json).

The global memory store is a separate application design gap. Untouched anonymous health/static/event-gate traffic no longer persists challenge sessions. Initialized teaching sessions still occupy this process-local store. Expired records are removed when read rather than by an active sweep, and mappings disappear on restart and are not shared across replicas. These properties should not be treated as PostgreSQL platform-session guarantees.

## Remaining implementation

1. Inventory every mounted cookie consumer, including retained e-commerce and vulnerability routes. Classify platform authority, deliberately vulnerable effect, and anonymous synthetic state. Keep every intentional sink and its existing UI/workflow.
2. The minimal phase stops copying unused platform roles and session records. Removing usernames and owner/session IDs requires migrating the identified legacy consumers and mutation lifecycle fence first. Platform administration, progress and owned resources always validate current canonical authority.
3. Replace the global anonymous session allocator with middleware scoped to explicit cookie-based lab routes. Use a distinct cookie name/path and `saveUninitialized: false`. Preserve readable SameSite behavior where the CSRF lesson requires it.
4. Store an opaque CSRF victim binding in the existing isolated PostgreSQL CSRF store using a forward migration. Retain only the required owner/session/generation mapping, bounded expiry and lifecycle state. Resolve it through trusted server code; the learner cookie supplies no role or owner authority. Validate the underlying session/lifecycle without adding a CSRF defense that would remove the vulnerable-mode exercise.
5. Integrate reset, session revocation and student deletion. Reject stale bindings while preserving siblings and immutable effect/Judge evidence. Do not silently reinterpret old memory cookies as new bindings.

## Acceptance

- Health/static/event-gate requests allocate no challenge cookie or session row.
- Valid bearer authentication works; revoked/expired/malformed bearer plus an old cookie cannot access platform-owned MCP/XSS state or administration.
- Anonymous XSS stays isolated from platform owners. Synthetic session-disclosure exercises remain synthetic and separately gated.
- The existing genuine CSRF forged effect still succeeds in vulnerable mode and fails under its fixed defense; actor/Judge provenance and objective credit retain their current requirements.
- Restart and two backend processes resolve the same active lab binding through PostgreSQL. Bounded expiry cleanup, reset/deletion races and sibling preservation have native tests.
- Rendered login, workshop navigation, reset and instructor views retain the existing baseline.

AWS assets remain unchanged. Multi-process application qualification does not establish compatibility or capacity of the frozen deployment.

## Minimal allocation phase

`tests/challengeSessionAllocation.test.js` uses the actual production session configuration and an actual MemoryStore to verify zero entries/no Set-Cookie on untouched anonymous and bearer-only requests. Login rotation retains the four required teaching/lifecycle fields; legacy mutation and durable MCP resolver checks remain. The native copied-backend fixture additionally probes health, static/404, valid owner reads, and revoked/expired sessions. This phase changes no cookie name/path/security flags, route order, CSRF sink, session-disclosure store, or lifecycle ownership semantics. It does not provide bounded initialized-session cleanup, durable cookie mappings, or multi-replica support.

## Current mounted-consumer inventory — 2026-09-19

Source review confirms these distinct consumers; middleware scoping must preserve their contracts before replacing MemoryStore:

| Consumer | Required state and boundary |
|---|---|
| `postgresAuth.js` login/logout | Rotates the lab SID, retains userId/username plus platformOwnerId/platformSessionId for legacy mutation fencing, destroys the cookie session on logout. Canonical bearer authority remains separate. |
| `csrfWorkshop.js` | Rebinds userId after authenticated entry and retains an anonymous lab key when used in standalone teaching fixtures. Preserve the managed-browser vulnerable/fixed effect contract; a cookie field alone cannot establish platform authority. |
| `mcpWorkshop.js`, `xssWorkshop.js` | Supported PostgreSQL paths use canonical platform authority. Cookie fallback belongs to explicit legacy/standalone modes; do not migrate it into the supported authority resolver. |
| `ecommerce.js` | Retained intentionally weak userId fallback and attacker-selectable account examples. Their execution must stay in isolated challenge data; removing these checks would alter teaching semantics. |
| `vulnerabilities.js` | Retains teaching username/userId access, with canonical lifecycle-selected owner for the protected application path. Preserve the lifecycle check when changing cookie storage. |
| `secureChallenges.js` | The remaining cookie check gates a retired caller-supplied progress endpoint, which returns409 rather than credit. It is not a supported completion mechanism. |
| `auth.js`, `secureAuth.js`, legacy `sessionManager.js` | Retained legacy session writers are not evidence of supported PostgreSQL auth behavior. Test/import mode and actual route mounting must be established before treating these writes as active platform authority. |

This inventory is source evidence, not a restart, cross-process, expiry or browser qualification. The broader persistent binding migration remains open. The historical work-queue statement that anonymous traffic still allocates sessions and PostgreSQL bearer middleware still copies metadata is superseded by the implemented minimal allocation phase above.
