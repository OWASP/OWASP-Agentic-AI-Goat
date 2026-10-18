# Opaque-frame browser feasibility qualification

The application-only iframe design has a real Chromium feasibility proof in
`tests/secureshopOpaqueFrame.test.js`. Root independently ran it with the current
CORS suite: **10 tests passed** (nine HTTP tests and one real-browser test).
Chromium used its sandbox defaults and a fresh temporary profile. Requests were
restricted to the fixture's owned ephemeral loopback server. No live app session,
learner credential, model, database or deployment asset was used.

Observed browser behavior:

- The target frame had exactly `sandbox="allow-scripts"`. Its actual script ran
  and its browser origin was opaque (`null`).
- Access to the parent's DOM and synthetic localStorage bearer raised
  `SecurityError`. The parent marker and synthetic bearer remained unchanged.
- A simple POST from the frame reached the production `createApplicationCors`
  middleware with `Origin: null`. The server recorded 403 and zero protected
  effects; the browser could not read the response.
- A synthetic bridge accepted one exact `asset.read`/`GET`/fixture-path operation
  from the expected window, opaque origin and nonce. It rejected a sibling
  window, wrong nonce, platform path, literal traversal, encoded traversal and
  unexpected method. The accepted operation only records an event; it does not
  read a live asset or grant a capability.

Root review tightened the initial fixture's path-prefix check to an exact
operation/method/path allowlist. A prefix check alone would not reject paths
that normalize out of that prefix. Production bridge routing must retain this
explicit operation boundary rather than accepting arbitrary URLs.

## Acceptance limits and next integration

This is browser-primitive qualification, not the current SecureShop SPA. It does
not prove router/history, uploads, streams/cancellation, popup/download behavior,
role changes, reset races, durable sessions, replay handling or Judge credit.
Those remain required before the visible application can use this boundary.

The live application's legacy host file/shell/network sinks remain reachable
outside this fixture and are not contained by a frame. Their real contained
substitutes and owner checks must be integrated too. Do not enable connected
grading or claim whole-app safety on this test alone.

The next implementation is the typed parent API bridge and isolated SecureShop
entry described in `secureshop-launch-session-integration-2026-09-13.md`, coupled
to durable platform launch/run/generation state and signed operation capabilities.
The bridge must never forward platform tokens, cookies, raw capabilities or
unrestricted request URLs to the vulnerable frame. Preserve the existing visual
baseline and qualify each affected exercise's actual mechanism in the integrated
browser flow.
