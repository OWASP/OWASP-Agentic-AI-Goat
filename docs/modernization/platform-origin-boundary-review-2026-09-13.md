# Platform origin-boundary review

**Status:** read-only source review and implementation/test plan. No route, middleware, database, browser, model, or AWS behavior is changed by this document.

## Current checkpoint

The baseline problem was a global `cors({origin: true, credentials: true})` mounted before every route and before SecureShop's narrower CORS middleware. The `cors` package ends an `OPTIONS` request by default, so that global middleware could answer a preflight before a later prefix policy ran. On an actual request it also installed reflective credentialed headers before later authentication or origin checks.

The shared working tree now contains the SecureShop ordering correction: `server/index.js:88-93` selects one `createApplicationCors` policy before body parsing and route mounts. `server/middleware/applicationCors.js:12-30` rejects disallowed and `null` origins for the exact `/api/secureshop` boundary before invoking CORS; all other paths still receive the reflective legacy policy. `tests/applicationCors.test.js:17-67` covers SecureShop null/disallowed preflight and actual requests, configured/Origin-free clients, and preservation of reflective behavior on unrelated challenge routes. The focused suite and direct backend checks reported at this checkpoint observed allowed preflight as 204 and disallowed or null requests as 403 without ACAO; this is SecureShop-only qualification, not connected platform-boundary qualification.

That fixes the ordering defect for SecureShop at this checkpoint. It does **not** create a platform origin boundary: `/api/auth`, `/api/admin`, progress, Judge/retry, revision, and platform observability paths still enter the reflective legacy branch. The next policy should classify all protected prefixes before calling `cors`; stacking another middleware after `createApplicationCors` would recreate the preflight defect.

CORS is a browser response policy, not authentication or CSRF protection. Origin checks must happen before protected route effects, while platform JWT/session validation, launch binding, CSRF tokens, and authorization remain independently mandatory.

## Platform prefixes mounted by `server/index.js`

These mounts are platform identity/control-plane or platform-owned student state. They should use a hardened platform policy with exact configured origins, unconditional `Origin: null` rejection, and no reflective fallback.

| Mounted or exact path prefix | Why it is platform-only | Current source evidence |
| --- | --- | --- |
| `/api/auth` | Platform registration, login, durable session status/logout, profile, password and activity. Public login/register still belong to the identity origin and should not be callable from an opaque challenge frame. | Mounted at `server/index.js:276`; PostgreSQL endpoints at `server/routes/postgresAuth.js:39-328`; authenticated middleware binds the durable session at `server/middleware/postgresAdminAuth.js:11-37`. |
| `/api/admin` | Instructor users, permissions, visibility/content, provider config, logs, reset, analytics and other control-plane operations. This includes the more-specific `/api/admin/exercises` and `/api/admin/agent-runs` mounts. | Mounted in specificity order at `server/index.js:281,283-284`; both admin routers apply platform authentication (`server/routes/admin.js:113`; `server/routes/postgresAdmin.js:49`). |
| `/api/agent-runs` | Learner-owned model decisions, events, judgments and retry requests. These are platform evidence/Judge records, not a challenge sink. | Mounted at `server/index.js:282`; the router applies `authenticateToken` before all endpoints (`server/routes/agentRuns.js:45-46,57-114`). |
| `/api/changes` | Authenticated configuration revision snapshots used by the platform polling layer. | Mounted at `server/index.js:277-280`; route authentication at `server/routes/changeRevisions.js:31`. |
| `/api/workshop/config` | Shared exercise/objective visibility and content revision/snapshot. It is read-only to students but controls what the platform presents. | Mounted before the general workshop router at `server/index.js:263`; endpoints at `server/routes/workshopConfig.js:6-10`. |
| `/api/workshop/student`, `/api/workshop/progress`, `/api/workshop/challenges`, `/api/workshop/instructor`, `/api/workshop/objective`, `/api/workshop/user-activity`, `/api/workshop/time` | Canonical progress, time, objective completion/reset, learner activity and instructor state. Use these exact sub-prefixes rather than all of `/api/workshop`, because challenge routers share that parent. | General router mounted at `server/index.js:264`; PostgreSQL router authenticates all requests and defines these paths at `server/routes/postgresWorkshop.js:18-204`. SQLite has the same platform route families, though some handlers check `req.user` individually (`server/routes/workshop.js:167-632`). |
| `/api/solutions` and `/api/hints` | Instructor-gated teaching content. Some reads are intentionally unauthenticated after visibility checks, but they are platform publication surfaces and should not be readable from an opaque SecureShop frame. | Mounted at `server/index.js:288-289`; PostgreSQL content routes at `server/routes/postgresWorkshopContent.js:11-38`. |
| `/api/ctf/admin` | CTF instructor analytics, solutions, configuration, stage mutation, participant reset/ban and blocklist reset. Harden only the admin sub-prefix in this review; participant CTF paths remain in the challenge policy pending their own boundary decision. | Parent mounted at `server/index.js:287`; admin endpoints and `requireAdmin` at `server/routes/ctf.js:509-758`. |
| `/api/monitoring` | Health, performance, provider control, stress, metrics and logs. The whole prefix can use the platform origin policy: ALB/server health calls normally omit `Origin`, while browser admin calls come from an allowed origin. Hardening CORS does not stop the intentional server-side SSRF probe because it is not a browser CORS client. | Mounted at `server/index.js:286`; public and admin endpoints at `server/routes/monitoring.js:14-366`. |
| `/event-gate/login` | Creates the live-event gate session and sits outside `/api`; it must be classified explicitly. | Mounted before the gate at `server/index.js:131-132` in the current checkpoint. |

Future platform launch/status/reset and opaque-frame bridge endpoints should receive a distinct prefix such as `/api/secureshop-platform`, covered by the hardened platform policy from its first commit. Do not place them under a generic reflective challenge mount. The `/api/secureshop` application itself is not platform-only, but its current stricter policy must remain selected before preflight; the opaque iframe design additionally rejects direct `Origin: null` access and uses the trusted parent/BFF bridge.

### Prefix matching requirements

Match a prefix only when the path equals it or the next character is `/`, after Express has exposed a normalized path. `/api/administer`, `/api/authentic-demo`, `/api/workshop/configuration-attack`, `/api/ctf/administrator`, and `/api/secureshop-example` must not inherit a protected policy accidentally. Apply the same decision to any case variants the server would route, or reject noncanonical API case consistently. Query strings do not participate in policy selection.

More-specific entries must win where policies differ. A simple ordered classification is:

1. platform exact prefixes;
2. SecureShop exact prefix and configured origins;
3. explicitly registered intentional challenge CORS prefixes;
4. conservative default with no credentialed reflection for unknown `/api` paths.

The current middleware instead gives every non-SecureShop path the reflective policy (`server/middleware/applicationCors.js:15-19`). That means a typo or a newly added platform route silently inherits challenge behavior. Make intentional reflection opt-in, not the default for unknown routes.

## Intentional challenge behavior to preserve

Do not infer that every route containing a vulnerability or every workshop needs permissive CORS. Preserve reflective credentialed behavior only for an endpoint/prefix with an explicit teaching contract and regression. At this checkpoint, the source provides a broad comment about intentional legacy lab policy and a regression using `/api/vulnerabilities/xxe`, but no complete per-endpoint CORS vulnerability registry. The SecureShop comment about cross-origin token signing describes a deleted dangerous endpoint, not a requirement to keep broad SecureShop CORS (`server/routes/secureshop/postgres/admin.js:418-428`).

The minimum explicit preservation set evidenced by current tests/design is:

- `/api/vulnerabilities/*`, including the classic CSRF target and deliberately vulnerable browser routes. The existing CORS regression uses `/api/vulnerabilities/xxe` (`tests/applicationCors.test.js:58-67`).
- Any specific `/api/workshop/csrf/*` route whose canonical objective requires a cross-origin browser request. Preserve only the route/method/header behavior proven by that objective; simple form/image CSRF does not require readable CORS responses.
- Any additional path added to an `INTENTIONAL_REFLECTIVE_CORS_PREFIXES` registry only with an `@intentional-vulnerability` identifier, named objective/mechanism, allowed methods/headers, and positive plus containment tests.

Leave other challenge mounts unchanged during this bounded platform-policy change until their individual CORS contracts are audited: `/api/ai`, `/api/ecommerce`, `/api/workshop/sql`, `/api/workshop/nosql`, `/api/workshop/prompt-injection`, `/api/workshop/rag-injection`, `/api/workshop/sensitive-info`, `/api/email-agent`, `/api/challenges`, `/api/sensitive-info`, `/api/sensitive-info/mysql`, `/api/xss-email`, `/api/workshop/xss`, `/api/workshop/mcp`, `/api/excessive-agency`, `/api/workshop/supply-chain`, and participant `/api/ctf` paths (`server/index.js:257-273,265-270,272-273,287`). This is sequencing, not a claim that reflective credentialed CORS is pedagogically required or safe on every listed route.

## Hardened request contract

For every platform prefix:

- Reject the literal `Origin: null` with a bounded 403 before CORS headers, authentication, parsing-intensive work, or route effects. Never allow it through an environment allowlist.
- When `Origin` is present, require an exact normalized string from a deployment-controlled `PLATFORM_ALLOWED_ORIGINS`; do not use suffix, substring, reflected regex, forwarded host, or request Host matching. Return the exact allowed origin, `Access-Control-Allow-Credentials: true` only where a hardened cookie is needed, and `Vary: Origin`.
- Allow an absent `Origin` for ALB health checks and authenticated server/CLI clients. Absence is not proof of same-origin and does not replace authentication or CSRF checks. Browser unsafe mutations still require the planned trusted Origin/fetch-metadata/session-bound CSRF contract.
- Answer allowed preflight in this policy, with an explicit method set and explicit headers needed by the current clients: `Authorization`, `Content-Type`, `Accept`, and the future CSRF/request-correlation headers actually adopted. Do not reflect arbitrary `Access-Control-Request-Headers`. Return no ACAO/ACAC on rejection.
- Apply least privilege by prefix. Public platform GETs do not need credentialed CORS merely because authenticated admin routes do. Expose only required response headers such as a request ID or bounded download metadata.
- Perform policy selection before any generic CORS middleware can set headers or terminate `OPTIONS`. Do not call the reflective challenge middleware first and attempt to overwrite its result later.

The same-origin hosted build serves the React bundle and APIs from one Express origin, so normal browser requests often have no cross-origin CORS exchange. Local development commonly uses `http://localhost:3000` or `http://127.0.0.1:3000` against port 8081; the exact frontend origin must be allowlisted, and Authorization/JSON requests will preflight. Keep `localhost` and `127.0.0.1` as distinct explicit origins. AWS should configure the exact public HTTPS origin; do not derive it from ALB forwarding headers. Origin-free ALB health checks remain usable.

## Focused tests

Extend the pure Express fixture in `tests/applicationCors.test.js`; no database or full server is needed.

- Table-drive every platform prefix above through `OPTIONS`, `GET`, and an unsafe method with `Origin: null` and an untrusted HTTPS origin. Assert 403, no ACAO/ACAC, `Vary: Origin`, and zero downstream effects.
- For each boundary, prove lookalikes such as `/api/administer` and `/api/secureshop-example` do not match. Assert the intended fallback explicitly rather than accepting accidental reflection.
- For local allowed origins, verify preflight status, exact ACAO, credentials only where configured, explicit methods/headers, and actual request continuation once. Add the configured hosted HTTPS origin and an Origin-free health/server call.
- Prove the current frontend header shapes: platform bearer plus JSON for auth/admin/progress/Judge retry, simple GET for config/hints/solutions, and monitoring health without Origin. A disallowed preflight must not reach auth or route handlers.
- Keep positive intentional regressions for `/api/vulnerabilities/xxe` and each registered CSRF/CORS teaching route. Assert only its declared methods/headers/origins and verify that a nearby platform path remains blocked.
- Add a registration test that enumerates protected mounts from a checked-in policy list. A new `/api/admin`, `/api/auth`, progress/Judge, launch, bridge, reset, or observability mount must fail review tests until classified.
- At the application level, send a real `OPTIONS /api/secureshop/...` and a platform `OPTIONS /api/auth/status` through the actual middleware order. This catches a future earlier middleware that ends preflight before policy selection.

The current SecureShop-focused tests are valuable but do not support a claim that platform null-origin access is closed. That claim requires the complete platform-prefix matrix, CSRF/identity checks, and the opaque-frame adversarial browser tests described in the launch integration plan.

## Next bounded implementation checkpoint

Extend the existing `createApplicationCors` selector rather than introducing a second CORS layer. Add an exported, exact-boundary platform-prefix list containing the rows above, then choose the hardened platform policy before the SecureShop and legacy branches. Keep the current reflective legacy branch unchanged for challenge paths in this checkpoint; narrowing that fallback belongs to the separate per-challenge CORS audit.

This checkpoint does not need an AWS asset or deployment change. Pass the same already resolved, operator-controlled origin list that currently protects SecureShop into the platform policy as its initial allowlist. The middleware may accept a separately named `platformOrigins` option for future configuration, but its default in `server/index.js` should be the existing configured `ssV2AllowedOrigins`, not a value inferred from `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Referer`, or request URL. If the deployed public frontend origin is absent from that configured list, fail closed and stage the source change until the operator supplies an exact origin; do not guess it from an incoming request. A later deployment can split `PLATFORM_ALLOWED_ORIGINS` from `SS_ALLOWED_ORIGINS` when operationally useful without changing the request contract.

The initial implementation should:

1. classify `/event-gate/login` and every exact platform prefix in the table with the equals-or-slash rule;
2. reject literal `Origin: null` and unallowlisted origins before CORS, authentication, or route execution;
3. allow absent-Origin server/health traffic to continue to the existing authentication and route checks;
4. answer allowed preflight once from `createApplicationCors`, with the current frontend's explicit methods and headers;
5. retain the existing `/api/secureshop` behavior and reflective challenge fallback byte-for-byte except for shared helper extraction; and
6. add the table-driven pure middleware matrix before any connected-browser qualification.

This is the smallest source slice that closes the known browser-origin gap on platform APIs without changing challenge semantics, frontend appearance, ingress, DNS, or AWS assets. It still does not make Origin an identity credential and does not complete SecureShop owner-capability or CSRF integration.

## Implemented checkpoint review

The source checkpoint after this plan implements the bounded platform boundary. This section supersedes the earlier statements that only SecureShop was protected and that the platform extension was still proposed.

`server/middleware/applicationCors.js:10-16` exports the complete reviewed platform prefix list. Its equals-or-slash matcher and case-normalized `req.path` classification are applied before either CORS branch (`server/middleware/applicationCors.js:17,27-33`), so the list covers the mounted platform routes while leaving `/api/workshop/csrf`, participant `/api/ctf`, other challenge paths, and prefix lookalikes in the preserved legacy branch. The implemented list matches the inventory in this document; no mounted platform prefix identified in this review is missing.

The platform policy defaults to the same resolved SecureShop origin list (`server/middleware/applicationCors.js:21-24`; `server/index.js:91-94`). It compares the supplied Origin exactly, rejects literal `null` even if configured, and makes no decision from `Host`, forwarding headers, Referer, or request URL (`server/middleware/applicationCors.js:33-41`). Policy selection remains before body parsing, cookies, sessions, event-gate effects, and routes (`server/index.js:88-101`). Missing-Origin server and health traffic continues, as designed.

The seven focused middleware tests now cover the platform path matrix, null and hostile preflight plus actual requests before effects, configured origins, absent Origin, spoofed Host/forwarding headers, case behavior, boundary lookalikes, and preserved challenge reflection (`tests/applicationCors.test.js:19-120`). Reported direct-backend qualification additionally observed allowed platform preflight as 204; null and hostile platform requests as 403 without ACAO; an allowed credentialed admin login; a null-Origin logout rejected while the authenticated session remained active; and an allowed cookie-bearing logout that invalidated the session. Those checks demonstrate the current CORS ordering and session-effect containment. They are not the connected opaque-frame, launch-capability, CSRF, or deployment-origin qualification described in the companion plans.

One hardening item remains from the request contract: the trusted branch currently uses `cors({ origin: true, credentials: true })` without explicit `methods` or `allowedHeaders` (`server/middleware/applicationCors.js:26`). The installed CORS middleware therefore advertises its broad default method set and reflects `Access-Control-Request-Headers` for an already allowlisted origin (`node_modules/cors/lib/index.js:8-12,94-110`). This does not let a rejected origin through and is not a regression in the newly closed boundary. A later bounded least-privilege change should declare the platform and SecureShop method/header sets from their real clients and add negative preflight tests for an undeclared method and header. It should be staged separately because SecureShop challenge requests and platform APIs may need different sets.

The longer-term recommendation to replace the reflective catch-all with an explicit intentional-challenge registry also remains open. The implemented checkpoint correctly preserves that fallback to avoid changing unaudited teaching behavior.
