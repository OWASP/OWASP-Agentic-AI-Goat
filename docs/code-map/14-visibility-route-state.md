# Workshop Visibility Route State

## Purpose

`VisibilityProtectedRoute` is the client-side gate used by authenticated Workshop routes whose availability is controlled by the instructor. It distinguishes a confirmed hidden exercise from a failure to determine visibility, so transient or malformed responses do not silently send an attendee to the dashboard.

## State contract

The gate has four explicit states, each bound to the current `challengeId`:

- `loading` renders the existing `VulnerabilityTemplate` loading view and never renders protected children.
- `visible` renders protected children after an authoritative response contains the exact challenge ID.
- `hidden` redirects to the configured fallback route with history replacement.
- `error` renders an in-place message and Retry button without rendering children or navigating.

A decision for an earlier `challengeId` is treated as loading. Each request receives a generation number; only the newest mounted request may update state. The outer guard also supplies an `AbortController` signal to Axios. Changing challenges, retrying, or unmounting invalidates older responses and best-effort aborts the superseded request.

## Authoritative response rules

The `/api/workshop/challenges` response is accepted only when its body is a non-array object with `success: true`, a `challenges` array, and a non-empty string `id` on every challenge entry. Extra response and challenge fields are allowed.

Once validated:

- An exact ID match confirms the exercise is visible.
- An empty list or a list without the requested ID confirms the exercise is hidden.
- Request failures, unsuccessful bodies, and malformed payloads enter the error state. They never imply that an exercise is hidden.

## Retry and compatibility

Retry starts one fresh visibility request and returns to the same `VulnerabilityTemplate` loading state. The guard passes `visibilityManagedExternally` only to this loading placeholder, which suppresses the template's initial check, 30-second visibility interval, and objective-completion refresh listener. This prevents duplicate requests and a transient inner access-denied decision while the outer guard owns availability. The template's standalone loading, polling, and access-denied behavior are unchanged when the prop is absent.

After the outer request confirms visibility, the guard provides the matching
challenge through a local React context. A nested `VulnerabilityTemplate`
initializes its visible state, challenge metadata, and hint availability from
that confirmation and skips only its immediate duplicate request. Its existing
30-second visibility interval and objective-completion refresh listener remain
active. Errors from those silent background checks preserve the last confirmed
visible state; a later successful response that omits the challenge still
blocks the exercise. Initial, interval, and objective-triggered template checks
share latest-request ownership: a newer check best-effort aborts the previous
request, and only the newest generation may commit visibility state. Cleanup and
challenge changes invalidate and abort outstanding ownership, so an older
visible response cannot restore content after a newer hidden confirmation.
Templates outside the guard receive no context and retain their original
initial visibility request and fail-closed behavior.

A successful retry may render the exercise or perform the existing confirmed-hidden redirect; another failure returns to the in-place error state.

This gate does not replace server-side authorization. It preserves the existing authenticated App gate, fallback-route behavior, and `VulnerabilityTemplate` loading presentation, and adds no dependency.

## Guarded workshop routes

The authenticated workshop aliases `/workshop/sql`, `/workshop/nosql`, and
`/workshop/sensitive-info` are guarded with the canonical challenge IDs
`sql_injection_workshop`, `nosql_injection_workshop`, and
`sensitive_info_disclosure`, respectively. A confirmed admin disable therefore
redirects an attendee from any of these routes to the workshop dashboard, while
the navbar and workshop page mount only after visibility is confirmed.

## Regression coverage

- `client/src/components/VisibilityProtectedRoute.test.js` covers loading, confirmed visible and hidden responses, request failures, malformed payload variants, retry recovery, child suppression, redirect replacement, stale-response protection, and abort signals across challenge changes and retries.
- `client/src/components/VisibilityProtectedRoute.integration.test.js` uses the real `VulnerabilityTemplate` to prove that outer loading, retry, and confirmed-visible child mounting issue no immediate inner duplicate request; silent background errors retain confirmed content; later confirmed-hidden responses block it; an older overlapping visibility response cannot undo that block; and standalone template behavior remains unchanged.
- `tests/workshopRouteVisibilityWiring.test.js` locks the three workshop aliases to
  their canonical `VisibilityProtectedRoute` challenge IDs and preserves their
  navbar/page children inside the guard.
