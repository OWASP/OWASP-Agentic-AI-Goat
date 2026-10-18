# SecureShop launch and platform-session integration

> Superseded implementation details: [the durable authority checkpoint](secureshop-launch-authority-checkpoint-2026-09-13.md) records the implemented PostgreSQL repository and migration 0025. In particular, the original cascade-delete schema and automatic missing-cookie rotation below are not the implementation: lifecycle tombstones survive session deletion, and renewal requires the current handle. The remaining browser/target integration requirements still apply.

**Status:** bounded architecture review and implementation plan only. This document makes no migration, database, browser, model, runner, or AWS change.

## Concrete session anchor

Use PostgreSQL `identity.user_sessions.id` as the server-side platform-session identity for a SecureShop launch. It is an integer primary key tied to `identity.users(id)`; only a SHA-256 digest of the platform JWT is stored, with active, expiry, and revocation state (`db/postgres/identity-migrations/0001_identity.sql:27-38`). PostgreSQL authentication verifies the signed JWT, finds that exact active durable row, assigns the durable row to `req.identitySession`, and assigns its user to `req.user` (`server/services/postgresIdentityAdapter.js:74-89`; `server/middleware/postgresAdminAuth.js:11-37`).

Never put `identity.user_sessions.id`, the platform JWT, its digest, a user ID, or the existing Express session ID in a browser launch claim. The integer row ID is a database join key, not a bearer credential. The current `connect.sid` session is also unsuitable: the application deliberately configures a weak shared secret, JavaScript-readable cookie, and process-local default session storage (`server/index.js:123-141`). It may continue serving intentionally vulnerable workshops, but it cannot prove SecureShop platform ownership.

Issue a separate random launch handle of at least 256 bits. Store only its SHA-256 digest. In deployed HTTPS, use a host-only cookie such as:

```text
Set-Cookie: __Host-dvaia-ss-launch=<random>; Path=/; HttpOnly; Secure; SameSite=Strict
```

`__Host-` deliberately requires `Path=/` and no `Domain`. This lets the existing authenticated `/api/auth/status` endpoint inspect and repair the binding without frontend work. Other routes must ignore the cookie and request logging must redact it. For the supported offline HTTP installation, use a separately named host-only development cookie with `HttpOnly; SameSite=Strict; Path=/` and no `Domain`; select this from trusted deployment configuration, not an untrusted forwarded header. Qualify localhost, `127.0.0.1`, the CRA proxy, and the deployed HTTPS origin in real browsers. Never accept the development cookie in the deployed HTTPS configuration.

This handle is still a bearer secret. A stolen live cookie can act as that launch until expiry or revocation; binding its database row to a platform session does not provide independent possession proof on each SecureShop request. The design prevents caller-selected owner IDs and causes platform logout/revocation to invalidate the handle. It does not claim to defeat full browser or cookie theft.

### Same-origin XSS blocks a complete claim

The current platform and SecureShop SPAs share an origin. The platform bearer is stored in `localStorage` and installed in Axios (`client/src/context/AuthContext.js:36-43,126-133`); the SecureShop bearer is also stored in `localStorage` (`client/src/pages/secureshop/context/AuthContext.jsx:20-22,100-105`). A SecureShop XSS exercise executing on that origin can therefore read the platform token. Even if the launch handle itself is HttpOnly, a stolen platform bearer can call the authenticated status/issuance path from another browser and obtain a new launch unless issuance has an independent credential or browser binding. Same-origin XSS can also make credentialed requests as the victim even when it cannot read HttpOnly cookies.

The no-UI-change cookie flow below is feasible for request plumbing and prevents shop claims from selecting a different database owner. By itself it is **not** a robust immutable-learner boundary against the platform token theft that the same-origin XSS lab can cause. Do not enable connected SecureShop grading or real owned host sinks on the strength of this cookie alone.

Production qualification requires one of these reviewed credential boundaries while preserving the existing visual UI:

1. Serve the vulnerable SecureShop application from a dedicated origin that cannot read platform storage or receive platform cookies. Keep platform login/status/launch issuance on the platform origin, restrict its CORS and fetch metadata policy, and transfer only a one-time, audience-bound launch code through a server-mediated navigation handshake. Exchange it on the SecureShop origin for a host-only HttpOnly launch cookie, then invalidate the code. Do not put a reusable platform token or launch bearer in a URL.
2. Run the entire SecureShop application in the opaque-origin sandboxed iframe described below. The trusted parent retains platform state and exposes a deny-by-default SecureShop-only API bridge. This is application-only and needs no DNS or ingress change, but it requires router, storage, streaming, file, download, and curriculum adapters.
3. Migrate the platform credential out of JavaScript storage into a hardened HttpOnly host cookie, add CSRF/origin protection to identity and launch issuance, and isolate intentionally vulnerable content so it cannot issue platform requests as the victim. Moving the token to HttpOnly without isolating the vulnerable script is insufficient because XSS can still send same-origin requests.

The dedicated-origin option gives the clearest boundary and best native browser fidelity. It requires routing/origin and credential-handshake work, so it is a deployment design item under the current AWS freeze. The iframe is feasible under that freeze but is not complete until its bridge and affected lessons are browser-qualified. Until one boundary is qualified, the launch flow remains design/transitional and must fail closed for grading and host effects.

## Transitional request flow without a UI code change

The platform client already logs in with `POST /api/auth/login`, stores the returned platform token, installs it as Axios's default Authorization header, and checks `/api/auth/status` on startup (`client/src/context/AuthContext.js:36-43,126-137`). SecureShop separately stores its shop token and sends it explicitly in `fetch` Authorization headers (`client/src/pages/secureshop/context/AuthContext.jsx:20-48,107-123`). Its relative URLs are same-origin, so browser cookies accompany them without taking the one Authorization slot.

Use this flow to establish the backend/session plumbing without changing current UI components or response DTOs. It does not resolve the same-origin XSS limitation above:

1. During platform login, generate the raw launch handle in the identity adapter. Insert the durable platform session and launch in one PostgreSQL transaction, return the platform token in the existing JSON shape, and set the launch cookie. `createSession` already receives the newly inserted session row internally (`server/services/postgresIdentityAdapter.js:40-72`; `server/database/postgres/identityRepository.js:81-92`), so no ID needs to enter a DTO.
2. On a successful `GET /api/auth/status`, after the existing bearer validation has produced `req.user` and `req.identitySession`, reconcile the cookie. If it resolves to the same active platform session, leave it in place. If it is absent, malformed, expired, revoked, or bound to another session, revoke that session's previous launch, create a fresh handle, and set it in the response. The existing client already makes this request, covering sessions active before rollout without new UI code (`server/routes/postgresAuth.js:232-253`). Serialize renewal per platform-session row so concurrent tabs cannot leave two active handles. In the current shared-origin deployment this repair endpoint accepts the JavaScript-readable platform bearer and therefore must not authorize graded/host effects.
3. The learner opens SecureShop and logs into a deliberately vulnerable shop persona. That response and all later SecureShop requests keep their current JSON and Authorization behavior. The browser also sends the HttpOnly launch cookie.
4. Launch middleware hashes the cookie and performs one PostgreSQL lookup joining launch, platform session, and user. It requires matching digest, launch status `active`, both expiries in the future, session `is_active=1`, and an active/unlocked platform user. It freezes `{launchId, platformSessionId, platformOwnerId, scenarioId, generation, expiresAt}` as `req.ssLaunch`. It never reads ownership from the shop JWT, body, query, `_ss_caller`, Express session, or agent session UUID.
5. SecureShop middleware separately validates the shop token and attaches `req.ssUser`. Graded agent/effect/Judge routes require both `req.ssLaunch` and `req.ssUser`; public catalog and explicitly ungraded demo routes may omit the launch. The graph records platform owner from the launch and shop actor from the persona.
6. SecureShop shop logout and role switching clear only the shop token. The launch persists across the intended customer/merchant/admin persona changes. Platform logout clears the launch cookie and durably revokes its launch before acknowledging success.

This zero-UI-code-change path assumes the current supported relative, same-origin API URLs or CRA same-origin proxy. It is useful for compatibility tests, not a security release gate. A dedicated origin needs a server-mediated navigation/code exchange and reviewed cookie, CORS, CSP, and fetch-metadata policy. The application-only iframe alternative needs the parent bridge described below. The current broad CORS configuration provides neither boundary and is not evidence that browsers will send cookies (`server/index.js:88-117`).

## PostgreSQL design

Add the launch state to the identity PostgreSQL database, beside the session authority. Do not create an SQLite runtime authority or duplicate it in the vulnerable SecureShop commerce database. A migration should create an app-generated UUID row similar to:

```sql
CREATE TABLE identity.secureshop_launches (
  launch_id uuid PRIMARY KEY,
  platform_session_id integer NOT NULL UNIQUE
    REFERENCES identity.user_sessions(id) ON DELETE CASCADE,
  handle_hash text NOT NULL UNIQUE
    CHECK (handle_hash ~ '^[a-f0-9]{64}$'),
  scenario_id uuid NOT NULL UNIQUE,
  generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
  status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'resetting', 'revoked', 'expired')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revoked_at timestamptz,
  revoke_reason text,
  CHECK (expires_at > created_at),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX secureshop_launch_cleanup
  ON identity.secureshop_launches (expires_at)
  WHERE status IN ('active', 'resetting');
```

The unique `platform_session_id` gives one current scenario per platform login and supplies its lookup index. The unique handle digest supports the cookie lookup; the unique scenario UUID prevents accidental scenario sharing. Do not duplicate `user_id` in the launch row: derive it through the foreign-keyed platform session so a mismatched owner cannot be persisted. `expires_at` must be no later than the referenced platform session expiry; enforce this in the locked issuance transaction because a row check cannot reference another table.

If reset orchestration is durable, add a second table:

```sql
CREATE TABLE identity.secureshop_reset_operations (
  reset_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL
    REFERENCES identity.secureshop_launches(launch_id) ON DELETE CASCADE,
  from_generation bigint NOT NULL CHECK (from_generation >= 1),
  to_generation bigint NOT NULL CHECK (to_generation = from_generation + 1),
  status text NOT NULL
    CHECK (status IN ('fencing', 'draining', 'resetting_target',
                     'committed', 'failed')),
  idempotency_key text NOT NULL,
  target_receipt jsonb,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (launch_id, to_generation),
  UNIQUE (launch_id, idempotency_key)
);

CREATE INDEX secureshop_reset_pending
  ON identity.secureshop_reset_operations (updated_at)
  WHERE status NOT IN ('committed', 'failed');
```

Grant only the identity runtime role the needed operations. The SecureShop Agent Host, browser, model, and vulnerable commerce role must never query these tables directly. There is no PostgreSQL foreign key across separate identity and SecureShop databases; signed internal envelopes and receipt checks carry the launch/scenario/generation boundary across that process/database seam.

## Logout, revocation, and expiry

Every resolution query must join the platform session instead of trusting the launch row alone. This makes the handle immediately unusable when `identity.user_sessions.is_active` becomes false or expires, even if launch cleanup has not run. The current repository supports single-session logout, all-session account changes, password rotation, administrative mass revocation, and expiry cleanup (`server/database/postgres/identityRepository.js:103-121,138-140`).

Keep lifecycle state consistent as well:

- Single-session logout locks or identifies the session by the verified JWT digest, sets that session inactive, marks its launch revoked, and records the reason in one transaction. Only then clear the cookie and acknowledge logout. The current route revokes the platform session before returning (`server/routes/postgresAuth.js:254-265`); extend that repository transaction rather than adding a best-effort route update.
- Password rotation, user-wide revocation, administrative revocation, account deactivation, and session pruning must mark associated launches revoked or delete them in the same transaction. A database trigger on transition from active to inactive can enforce this for all current and future callers; resolution must still join the session as defense in depth.
- Physical deletion of an expired/revoked platform session cascades to its launch. Before deletion, any asynchronous graph/runner work is fenced by launch generation/status and its leases are cancelled. Do not let cleanup silently remove the only reset/reconciliation record while external work is active.
- Cookie clearing must use the exact issuance name, `Path=/`, host-only scope, SameSite, and Secure variant. Clear both known development and production names during a controlled environment transition. SecureShop persona logout must not revoke the platform launch.

## Reset transaction and external-effect boundary

Identity PostgreSQL, SecureShop commerce PostgreSQL, the Agent Host, and the sandbox runner cannot share one database transaction. Use a durable, idempotent reset state machine rather than holding a PostgreSQL transaction open across network calls.

1. **Fence transaction:** lock the launch and its platform-session row `FOR UPDATE`; require the current active session, launch status, current generation, and idempotency key. Insert the reset operation, change the launch to `resetting`, and advance generation atomically before committing. From this commit onward, old graph, MCP, filesystem, evidence, and Judge work must fail generation checks.
2. **Drain and reset:** cancel/drain the prior generation, then reset each owned commerce/runner target with the reset ID and target generation. Each target records or returns an idempotent receipt. Never hold the identity row lock while awaiting these effects. A retry reads the reset-operation row and resumes missing steps without applying a completed target twice.
3. **Commit transaction:** lock the same launch/reset rows, require the expected resetting generation, verify all target receipts, reset canonical SecureShop progress for the platform owner/generation, store safe receipt digests, set the operation `committed`, and return the launch to `active` in one identity transaction. Publish success only after commit.
4. **Failure:** retain `resetting` and a safe error code when target state is uncertain. Do not clear progress or advertise a clean lab. A reconciler may resume or complete rollback only from durable receipts. Logout/revocation wins over reset activation: the final transaction must not reactivate a launch whose platform session became inactive.

Every graph/tool/runner call captures launch generation before dispatch and checks status/session/generation again after its await and before trace publication, evidence, Judge, or another effect. The process-local filesystem generation is an additional target fence; it never replaces the durable launch generation.

## Focused qualification seams

- Platform login returns the unchanged JSON DTO and a correctly attributed launch cookie; the database contains only its digest tied to the exact `identity.user_sessions.id`.
- The existing `/api/auth/status` call preserves a valid same-session handle, repairs a missing/foreign handle under a row lock, and cannot create two active launches during concurrent tab requests.
- A SecureShop request carries shop Authorization plus the launch cookie. Switching shop personas preserves launch/owner/scenario/generation, while copied shop JWTs and caller-provided owner/session fields cannot change them.
- Missing, malformed, expired, revoked, wrong-environment, or unknown handles fail closed. A test explicitly records that possession of a valid live cookie is sufficient bearer access; it must not falsely claim independent theft resistance.
- A real browser proof shows SecureShop-origin script cannot read the platform token/cookie, call platform status or launch issuance with victim credentials, or exchange a launch code twice. Before origin isolation exists, an adversarial regression proves the current same-origin XSS can read the local-storage platform token; this expected failure blocks grading/host-effect enablement rather than being waived.
- Single logout, password rotation, revoke-all, account disable, expiry cleanup, and session pruning all make the launch lookup fail immediately and prevent late effects or credit. SecureShop shop logout leaves the launch active.
- Reset races at the model, MCP, commerce, runner, Judge, and final-commit boundaries reject the old generation. Target failure leaves the launch unavailable and canonical progress unchanged; an idempotent retry resumes safely.
- AWS/multi-instance tests resolve the same handle through PostgreSQL from two backend tasks and observe revocation immediately. They do not depend on Express MemoryStore affinity, local maps, or a local filesystem registration surviving restart.

## Application-only opaque iframe alternative

### Feasibility and boundary

A sandboxed iframe can create the missing browser-origin boundary without new DNS, ingress, or AWS infrastructure. Render a small trusted parent page at the existing `/secureshop/*` URL and load a separate SecureShop-only entry document in:

```html
<iframe sandbox="allow-scripts allow-forms allow-modals allow-downloads">
```

Do **not** add `allow-same-origin`, `allow-top-navigation`, or `allow-popups-to-escape-sandbox`. Without `allow-same-origin`, the frame receives a unique opaque origin even though its document and assets came from the application host. SecureShop script cannot read the parent DOM, the parent's platform `localStorage`, or host cookies. The rendered React components and styling can retain the current visible UI dimensions and strings.

This is feasible, but it is not a wrapper around the current application bundle. `SecureShopApp` currently lives inside the top-level `BrowserRouter` and shared application composition (`client/src/App.js:2,640-747`). Its auth and guest cart directly use `localStorage` (`client/src/pages/secureshop/context/AuthContext.jsx:20-22,100-105`; `client/src/pages/secureshop/context/CartContext.jsx:28-71`). Opaque-origin storage access is unavailable/unreliable by design, relative API fetches come from origin `null`, and direct streaming/download behavior needs adaptation. Build a separate frame entry and a narrow parent bridge before treating the option as contained.

The iframe contains the deliberately vulnerable shop application, so injected XSS can control the whole frame and use every operation exposed by its bridge. That is acceptable only because the bridge derives immutable learner/scenario ownership in the trusted parent/backend and limits the attacker to the current learner's SecureShop exercise surface. The frame cannot choose a platform owner or invoke platform identity, admin, progress, launch, reset, or arbitrary network APIs.

### Parent bridge contract

The trusted parent owns the platform session/launch cookie and never sends a platform JWT, platform cookie, raw launch handle, internal capability, or PostgreSQL identifier into the frame. It creates one iframe element, one cryptographically random per-load nonce, and one bounded bridge state record tied to the current launch/scenario/generation.

Handshake and message checks must include all of these properties:

- The child accepts initialization only when `event.source === window.parent`, `event.origin` equals the configured trusted parent origin, and the message has the expected version and nonce. The parent must use `targetOrigin="*"` when sending into an opaque-origin child, so the child-side source/origin validation matters.
- The parent accepts child messages only when `event.source === iframe.contentWindow`, `event.origin === "null"`, the nonce and protocol version match, the sequence/request ID is fresh, and the iframe has not navigated or been replaced. Rotate and invalidate the nonce on load, navigation, logout, reset, and generation change.
- The nonce distinguishes this WindowProxy/load from other opaque frames; it is not a defense against XSS already executing inside the SecureShop frame. Such XSS can use the same bridge as the legitimate UI, so method/path and ownership restrictions are the security boundary.
- Accept structured operations, not URLs or generic fetch options. Allowlist exact SecureShop method/path templates, headers, body types, response fields, maximum sizes, timeouts, redirect behavior, and whether an operation is public, shop-authenticated, or graded. Reject `/api/auth`, `/api/workshop`, `/admin`, absolute URLs, protocol-relative URLs, encoded path confusion, arbitrary headers, `credentials`, redirects outside the allowlist, and model-supplied bridge metadata.
- The child may send its deliberately vulnerable shop bearer for allowlisted shop authentication. The parent attaches it only to the selected SecureShop request. The backend independently resolves the parent's launch cookie and ignores all frame owner/scenario claims. A shop token stolen by inner XSS therefore authorizes the vulnerable persona but cannot create a graded launch outside the owner's browser.
- Bound cloned strings, JSON, `File`/`Blob`, and `ArrayBuffer` before allocation/forwarding. Never relay raw Set-Cookie, Cookie, Authorization, launch/capability, native path, or unrestricted response headers. Return a small status/body/header schema and opaque effect/download receipts.
- Streaming uses a distinct start/frame/end/cancel protocol with monotonic sequence numbers, bounded buffered bytes, and one active stream budget per frame. Parent cancellation propagates to the backend AbortSignal. The current agent UI parses a POST response body incrementally (`client/src/pages/secureshop/hooks/useAgentStream.js:45-92`); a one-shot `postMessage` response would silently destroy that teaching trace.

The parent should call a backend-for-frontend bridge route rather than reflect arbitrary frame requests directly from browser JavaScript. That route requires the launch cookie, CSRF token, trusted parent origin/fetch metadata, exact operation ID, current generation, and an allowlisted shop bearer where needed. It mints internal capabilities server-side. Keeping the operation catalog on both parent and server prevents DOM modification or a compromised parent callback from broadening the bridge accidentally.

### Platform null-origin and CSRF policy

Direct iframe requests to application APIs carry an opaque/null origin and must fail. Remove `null` from all identity/workshop CORS handling and reject it before platform authentication, launch/status, progress, Judge, reset, admin, and mutation routes. For browser-facing platform operations require an exact trusted parent `Origin`, appropriate `Sec-Fetch-Site`/`Sec-Fetch-Dest`, and a session-bound CSRF token on unsafe methods. Cookies remain host-only, HttpOnly, Secure in HTTPS, and SameSite; SameSite alone is not the CSRF boundary.

The broad application CORS middleware currently reflects origins with credentials before the narrower SecureShop middleware (`server/index.js:88-117`). An iframe design must prove effective headers for `Origin: null` and ensure the global middleware cannot grant it credentialed platform access. Static frame assets may need narrowly scoped delivery that does not confer API CORS. Add `Content-Security-Policy: frame-ancestors 'self'` to the trusted parent and allow the frame entry to be embedded only by that parent. The frame itself receives a CSP appropriate to the lessons; do not weaken the parent's CSP to make an inner exploit visible.

### Behavior that must be adapted or intentionally qualified

| Current behavior | Opaque-frame impact | Required adaptation or curriculum decision |
| --- | --- | --- |
| Top-level `BrowserRouter`, nested `/secureshop` routes, redirects, and deep links (`client/src/App.js:640-735`) | Opaque documents cannot safely rely on the host history/origin contract, and direct deep links would bypass the trusted parent. | Use a SecureShop-only `MemoryRouter` or reviewed hash router. Parent translates the visible path to an allowlisted initial route and receives route-change messages so refresh/back/forward retain the visible URL without letting the frame navigate the top level. |
| Shop authentication and guest cart in `localStorage` | Opaque-origin storage is unavailable; refresh loses state. | Keep the shop token and guest cart in frame memory, or ask the bridge for scenario-scoped opaque state. Never fall back to parent platform storage. Role-switch logout/login remains visually identical. |
| Shop token theft lesson | Existing `localStorage.getItem('secureshop_v2_token')` payloads stop working. | Expose only the intentionally vulnerable **shop** token through an explicit sandbox-local JavaScript session object or equivalent real in-frame sink, update hints/proofs accordingly, and confirm the stolen token works for shop-persona actions inside the same scenario. It must not expose platform or launch credentials. |
| Numerous direct `fetch('/api/secureshop/...')` calls | They originate as `null`, lack the launch cookie by default, and must be rejected by direct API policy. | Replace calls behind one typed SecureShop API client implemented over the bridge. Preserve exact vulnerable payload bytes, query strings, filenames, and tool arguments after the bridge validates the outer operation. |
| POST SSE agent trace | `ReadableStream` cannot cross `postMessage` directly. | Parent/BFF consumes the real stream and relays ordered bounded frames and cancellation without inventing tool observations or final effects. |
| File upload and editable filename (`client/src/pages/secureshop/components/UploadZone.jsx:35-57`) | `File` cloning is possible, but multipart fetch is no longer direct. | Clone bounded file bytes plus the exact learner filename through the bridge, rebuild multipart server-side, and preserve the intentional inner filename/path sink within the owner sandbox. |
| Audit CSV/blob downloads (`client/src/pages/secureshop/pages/admin/Audit.jsx:105-116`) and uploaded asset links | Direct authenticated download navigation lacks the bridge context. | Return an opaque one-use download receipt and have the trusted parent create a forced-download blob, or enable sandboxed `allow-downloads` for an uncredentialed receipt URL. Never render active HTML/SVG in the parent origin. |
| Alerts, forms, drag/drop, popups, clipboard, and external links | Sandbox flags and Permissions Policy alter browser semantics. `alert` needs `allow-modals`; native forms need `allow-forms`; popups are blocked unless enabled; popup opener/origin behavior changes. | Qualify each canonical XSS/browser objective. Enable only required flags. If popups are needed, use `allow-popups` while retaining inherited sandboxing and never `allow-popups-to-escape-sandbox`; otherwise update the proof to an in-frame DOM/effect receipt. Keep top navigation blocked. |
| Browser cookies and `document.cookie` | Opaque frame cannot demonstrate host cookie theft. | Use synthetic scenario cookies/data or the sandbox-local shop token and label the mechanism accurately. A platform-cookie theft objective cannot run inside this boundary unchanged. |
| Service workers, IndexedDB, cross-tab storage events, reload persistence | Opaque origin removes or changes them. | Do not depend on them. Put durable learner state behind the scenario-bound bridge and treat a frame reload as a UI rehydrate, not a new owner. |
| Client-side calls to arbitrary competitors/URLs | Direct CORS/network behavior differs and could become an exfiltration channel. | Keep SSRF authenticity server-side: pass the exact attacker URL through an allowlisted SecureShop tool endpoint, then observe the real isolated server-side effect. Block generic parent fetch. |

`allow-scripts` preserves inner DOM XSS, prompt injection, poisoned-content rendering, agent decisions, tool observations, SSRF tool inputs, excessive agency, and isolated server/runner effects. It does not preserve every original browser sink automatically. Each objective needs an explicit mechanism/effect/proof review; opaque-frame restrictions must be reflected in hints rather than simulated away.

### Comparison with a dedicated origin

| Property | Opaque iframe on current host | Dedicated SecureShop origin |
| --- | --- | --- |
| AWS/DNS/ingress change | None; application bundle, parent route, BFF, and headers only. | Requires approved DNS/TLS/ingress/CORS/cookie deployment work. |
| Visible UI | Can remain visually the same in a full-size frame. | Remains naturally the same. |
| Engineering change | Separate entry, router/storage/API bridge, stream/file/download adapters, CSP/CSRF, and per-objective browser qualification. | Mostly deployment/auth handshake and origin-safe API configuration; existing native routing/storage/fetch semantics can remain. |
| Security boundary | Strong only if `allow-same-origin` stays absent and the bridge remains a tiny deny-by-default capability surface. XSS can perform all allowlisted current-scenario actions. | Cleaner native browser boundary; SecureShop XSS cannot read platform-origin state, while direct SecureShop behavior needs fewer adapters. |
| Lesson fidelity | Server-side SSRF/agent/runner lessons remain authentic; cookie/storage/router/popup/download XSS details require changes and precise wording. | Better preservation of normal browser auth, navigation, storage, download, and popup behavior. |
| Failure mode | One generic-fetch bridge, platform endpoint accepting `Origin: null`, leaked nonce/capability, or accidental `allow-same-origin` collapses containment. | Misconfigured CORS/cookies or shared parent-domain credentials can collapse containment, but the browser boundary is easier to reason about. |

The dedicated origin remains the cleaner long-term design. The opaque iframe is a viable application-only path under the current deployment freeze and must no longer be described as categorically blocked by the absence of new ingress. It can qualify connected grading and isolated host effects after its bridge, null-origin platform rejection, reset/generation propagation, and every affected browser objective pass real-browser adversarial tests. Until then, both alternatives remain design work and current same-origin direct rendering remains unqualified.

### Opaque-frame qualification gates

- A payload running inside the frame cannot read parent DOM, platform `localStorage`, any host cookie, launch state, or platform response; attempts report an opaque origin.
- Direct `Origin: null` GET/POST requests to platform status, launch, progress, Judge, reset, and admin APIs fail without state changes, including simple form/image/navigation variants.
- Another opaque frame, a reloaded prior frame, a forged nonce, a replayed request ID, and a WindowProxy from a navigated frame cannot use the parent bridge.
- A compromised SecureShop frame can use every allowlisted shop operation for its own active scenario, including intentional vulnerable effects, but cannot call an unlisted path, add credentials, follow an external redirect, change owner/generation, or access another learner.
- Platform logout/reset invalidates the bridge generation immediately; streamed or file operations returning afterward cannot publish evidence, Judge credit, downloads, or a second effect.
- Real browser tests cover back/forward/refresh, login/role switching, guest cart, drag/drop filename preservation, streaming order/cancel, alerts/forms, any enabled sandboxed popup, external links, CSV/asset downloads, and responsive full-frame layout.
- Every canonical XSS/browser objective records whether its original mechanism is preserved or its curriculum/proof changed. An alert or scripted fixture alone is not evidence that cookie/token theft, navigation, or exfiltration still works.
