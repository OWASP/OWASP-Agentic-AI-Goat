# CSRF managed-browser cutover — September 13, 2026

## Implemented application behaviour

The existing GET/POST payload editor now submits its exact HTML to bearer-authenticated `POST /api/workshop/csrf/browser-attempt`. Templates target `http://victim.csrf.invalid`; the trusted Chrome executor serves the unchanged attacker page at a distinct same-site origin, observes the outgoing synthetic cookie, dispatches the shared application action handler under the captured learner run, and confirms the response before grading. Exported HTML is explicitly ungraded and those intercepted origins do not resolve outside managed execution. Existing styling and page layout are retained; execution labels explain the actual workflow.

`csrf_g2`, `csrf_g3`, `csrf_p1`, `csrf_p2` and `csrf_p3` now use rubric `csrf-observed-v8`. Grading requires a private receipt whose identity is bound to the exact execution, activity, owner, run, generation and objective. A copied/serialized receipt or an ordinary GET/form/JSON request cannot establish browser provenance. Manual action routes retain their deliberate teaching effects. Defense credit requires actual token enforcement, not synthetic SameSite=Strict metadata.

Admission rejects caller-supplied identity, cookies, observations, receipts and target configuration. It enforces current visibility/prerequisites, a 64 KiB decoded HTML limit and a 400 KiB encoded JSON limit. The route has protected platform CORS and validated bearer sessions, while the sibling intentional action sink retains its challenge policy. Resource limits are 12 attempts/minute/learner and four concurrent browsers/process; these are bounds, not measured 200-student capacity.

The graph flushes an admitted victim mutation before post-effect narration. Browser failure still cannot award completion, but the client refreshes canonical state because the action may already have happened. There is no automatic payload retry; learners must inspect state or reset before intentionally repeating a mutation. Browser failures throw bounded HTTP errors so the owner coordinator records failed runs instead of successful ones, and private launch/configuration errors are redacted.

Executor shutdown is terminal and drains admitted callbacks. Browser cancellation reaches the workflow child signal, including narration. The application gives cleanup 60 seconds instead of 10; an uncooperative callback can still force a nonzero timeout exit. This is not a promise of arbitrary callback termination or rollback.

## Verification and precise limits

- Real Chrome composition covers image GET, form POST and JSON fetch, with success and token-defense controls (all five browser objectives). Local llama3.1:8b Judge evaluation passes these cases.
- A separate real Chrome + actual CSRF LangGraph actor + llama3.1:8b Judge test passes a real transfer and a no-action control. Its catalogue and storage callbacks are controlled fixtures, not a native application deployment.
- `tests/postgres/csrfBrowserCompletion.integration.test.js` passed against an owned PostgreSQL 18 instance with native owner ledger, v8 receipt and canonical completion. It proves failed-browser no-credit, sibling isolation and reset rejection. The Judge is an explicit deterministic fixture, and the victim sandbox is not the full mounted native route. Evidence: `/tmp/dvaia-csrf-browser-completion-proof-3nDZRE/result.log`.
- The source-copy smoke includes the mounted router, production bearer authentication and actual Chrome, with explicit deterministic actor/Judge fixtures and legacy test storage. Manual action effects do not award browser objectives. The source-copy boundary is required; direct checkout execution is now refused.
- HTTP controller tests cover exact payload/identity binding, malformed/oversized input, cookie-only rejection, origin policy, hidden/prerequisite admission, redacted failures and matching coordinator failure status. The status assertions use an injected ledger recorder; a native mounted-route status assertion remains open.
- A real Chrome cancellation test verifies persistence precedes delayed narration and that shutdown awards no credit. It uses an owned file persistence adapter, not native PostgreSQL victim storage.
- Frontend tests cover exact submission, double-click suppression, error/no-credit, reset, hidden objective, tab switch, mismatched response and post-error state reconciliation. Complete rendered native application/admin parity remains open.

The full mounted PostgreSQL + actual-model + browser + UI route has not yet been qualified as one connected path. XSS/email and RAG variants still use the explicitly labelled server gadget interpreter. Existing stored/customized solutions were not migrated by the source text corrections. AWS files remain unchanged; their Node18 images and browser packaging are incompatible with this new path. The original broader exercise/SecureShop goal remains active.

See [test-isolation incident](test-isolation-incident-2026-09-13.md) for the working legacy-store exposure. No pre-incident baseline exists, so learner/instructor state preservation and restoration cannot be claimed.


## Final regression checkpoint for this cutover

The final source-copy backend run passed **1,438 tests, 36 skipped** (1,474 total). Log: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-regression-Q31rmu/tests.log`. All 15 changed runtime/frontend source files checked against that executed snapshot match. The direct-checkout smoke guard was added afterward and was verified to reject with exit 2 before imports; no production code changed after the snapshot.

The frontend passed **286 tests across 32 suites**, and the production build passed (existing large-chunk advisory remains). The two live-model aggregate tests passed: six browser transport/defense cases with the actual local Judge, and actual 8B actor/Judge positive/no-action controls. These counts retain the qualification boundaries above; they do not certify all workshop exercises, native deployment or 200 simultaneous real-model users.
