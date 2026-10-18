# CSRF teaching authority: narrow integration review

Design only; no production code, installed changes or model calls.

## Current seams

- `server/index.js` mounts `/api/workshop` before `/api/workshop/csrf`. The umbrella router's authentication intercepts a cookie-only forged request before the intended `/agent-action` sink. Moving the whole CSRF router earlier would also change protection of state, reset, mail, RAG and administrative-like controls.
- `csrfWorkshop.js` currently copies `req.user.id` into `req.session.userId`. This does not create the owner/session binding required by the new PostgreSQL teaching store. `getUserId` also accepts that lone cookie field. Replace this only on the supported PostgreSQL path with canonical runtime authority; retain explicit legacy fixtures separately.
- `teachingSessionRuntime.bindBearer(req)` already validates the actual bearer, regenerates a mismatched/anonymous session, saves canonical owner/session fields, checks durable binding and returns a captured revalidation guard. Reuse it; do not invent a second cookie issuer or assign fields directly.
- `teachingSessionRuntime.resolveAuthority(req,{allowCookie:true})` already gives an explicit bearer precedence and denies malformed/revoked supplied authorization without cookie fallback.
- `ownerWorkflowRoutes` already supports `withAdmission`, wraps execution.check and buffers publication. CSRF's local wrapper must compose this option while retaining its grading context. A guard alone is not a mutation lease.
- `csrfAgentGraph` performs actual decision/classification, then `applyCsrfSelectedEffect` calls `sandbox.forge` and `flush`, then a separate phrase node calls the model. This is the narrow effect seam. Recon/defense nodes also mutate sandbox state and currently rely on eventual flush; they need the same short mutation wrapper if admitted via cookie authority.

## Proposed mount and binding

Configure the existing CSRF router with the initialized teaching runtime before listen. Export a dedicated sink router/factory containing only GET and POST `/agent-action` and the same handler/owner-workflow chain. Mount it at the exact `/api/workshop/csrf/agent-action` path immediately before the umbrella mount. Do not dispatch the entire CSRF router there. Unknown methods, subpaths and non-sink routes must retain their current platform gate; explicitly deny HEAD on this mutating GET sink rather than accidentally inheriting Express's GET handler. Test case-insensitivity/trailing-slash behavior consistent with Express's existing route settings.

For normal bearer-authenticated CSRF UI requests, call `bindBearer` after express-session and canonical bearer authentication. Capture its returned authority and actual sessionID in server-owned request context (symbol/WeakMap), never body/query fields. This rotates/saves the durable teaching cookie before the next image/form request. All non-sink endpoints remain bearer-only on supported PostgreSQL startup.

For the early sink, resolve captured authority with `allowCookie:true`. A bearer request first binds its cookie through bindBearer; a cookie-only request must already have a valid durable canonical binding. Derive owner exclusively from this authority and verify it matches any existing canonical principal. Do not promote cookie authentication into platform role/admin fields. Hydrate the owner sandbox only after authority validation. Normalize authority failures to their typed401/423/503 without exposing database details.

Use `withAdmission` solely to pass `{check:authority.check}` around coordinator admission/execution/publication; never place the entire `coordinated()` callback inside `store.withAuthority`. Existing effect/checkpoint wrappers may surround slow work and are not suitable SQL-lock scopes. The CSRF local grading wrapper should install a separate `withTeachingEffect(work)` capability on its guarded execution, captured from runtime + sessionID + frozen binding. Reject a missing capability for the supported manual teaching sink.

## Short effect lease

Pass the captured capability as an explicit trusted dependency to `applyCsrfSelectedEffect` (or read only from the captured execution, never model-selected args). Validate selected action/vector first. Execute the current tab-state read, defense decision, exact forge chain, flush and post-flush snapshot within one `withTeachingEffect` callback. Return an immutable observation to objective resolution/phrasing afterward. Include refusal evaluation inside the lease so defenses cannot change between the decision and mutation. Use the same wrapper for defense toggles/recon counters; do not merely wrap a final beforePublish flush after RAM mutation already occurred.

The capability performs run/current-authority checks before acquisition, calls `store.withAuthority(sessionID,binding,shortWork)`, and checks execution after release. The store already acquires canonical authority plus a teaching-session row share lock using a separate effect pool, then revalidates before commit. No classifier, language model, response phrasing, browser navigation, email network operation or Judge call may occur inside the callback. Avoid nested withAuthority calls and avoid cookie save/regenerate/destroy while its row lock is held. Test lock ordering with canonical revoke/reset, rather than assuming independent check queries cannot deadlock under pending exclusive locks.

This is an authority fence across stores, **not** a distributed transaction: CSRF flush commits in a different database. If flush fails after RAM mutation, invalidate/reload that sandbox instance or retain explicit unavailable/uncertain state; do not let a later unrelated request persist dirty unauthorised leftovers. If identity lease completion becomes uncertain after successful CSRF flush, report uncertainty and never automatically execute the action again. Existing graph effect receipts/idempotency should describe the observed effect; no claim of cross-database rollback.

`beforePublish` remains a defensive final check but should not be the only persistence boundary. Any residual dirty mutation outside the protected effect is a defect to identify in tests, not permission to lease the entire route.

## Managed browser and credit

`csrfBrowserWorkflow` copies the captured parent execution into its child, and managed dispatch calls the internal handler directly. Propagate the same effect capability through that captured execution, with the existing browser child.check/run scope, without pretending the synthetic observed request carries the real platform cookie. Its browser victim cookie remains part of the owned browser observation protocol. The externally mounted manual sink does not mint or adopt private browser receipts.

Preserve `beginGrading`, child identity, browser dispatch/activity receipt, and `finalGrade` exactly. Manual GET/POST can demonstrate the teaching side effect but cannot earn objectives requiring managed-browser private evidence. A forged request body, cookie field, result JSON or copied receipt cannot substitute. Runtime authority protects ownership/revocation; it does not replace the private observation proof.

## Exact files and gates

Implementation seams: `server/index.js` (one exact early mount/configuration), `server/routes/csrfWorkshop.js` (authority capture and shared sink chain), `server/agent-runtime/csrfAgentGraph.js` (trusted effect dependency and short non-model mutations), `server/agent-runtime/csrfSelectedEffect.js` (forge+flush envelope). Reuse teaching runtime/bearer-binding/authority/store unchanged unless qualification identifies a concrete defect. Extend `ownerWorkflowRoutes` only if its current withAdmission cannot convey the separate capability safely; no global request-authority policy change.

1. Mounted full-order regression reproduces umbrella interception, then proves only exact GET/POST sink can use valid cookie authority. Bearer-only state/RAG/reset/mail and umbrella/admin routes still reject cookie-only requests. Wrong methods/subpaths/HEAD cannot mutate.
2. Native binding: first bearer creates durable session, repeated same binding stable, owner/account switch rotates; restart preserves cookie. Unknown/tampered/stale/revoked cookies and invalid supplied bearer denied. No username/role/request-owner inference.
3. Controlled graph instrumentation proves decision and phrase/Judge execute with no authority lease held; forge+flush occur exactly inside one lease. Document, chained-XSS, refused action, recon and defense branches covered.
4. Disposable two-store races: revoke/reset before mutation means no mutation; revoke waits only for short active mutation, not a deliberately paused classifier/phrase; late publication/credit rejected. Flush failure does not leak dirty RAM state into later persistence. Sibling unaffected; deterministic replay/uncertainty handling tested.
5. Existing managed browser controlled/native tests continue proving real browser private receipt earns credit and direct manual requests cannot. Actual model/browser qualification follows integration; it is not replaced by controlled adapter tests.
6. Source startup orders identity+teaching readiness before route admission/listen, with no memory fallback. Installed app remains untouched until separate preservation/activation gate.
