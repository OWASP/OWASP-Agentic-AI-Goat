# Workshop Polling Load Safeguards

## Client timeout recovery

The shared revision poller retains its normal randomized 12–15 second visible-tab schedule, pauses while the tab is hidden, and permits only one poll attempt at a time. Fetch failures and ordinary reconciliation failures retain the existing bounded failure cadence.

`RECONCILIATION_TIMEOUT` has a separate consecutive-failure counter. The first timeout still retries within the existing cadence. From the second consecutive timeout onward, the default delay uses exponential backoff with a 30-second base, a 120-second cap, and ±20 percent jitter. The threshold, base, cap, jitter ratio, and existing random source are injectable, so tests can assert exact schedules.

A successful reconciliation, ordinary error, network error, stale reconciliation, or abort clears the timeout streak. An ordinary failure after a timeout starts its own existing failure sequence. Timed-out snapshots do not advance the comparison baseline, so the same change remains eligible for eventual reconciliation.

The poller aborts timed-out work and prevents overlapping poll attempts. Cancellation of consumer work remains cooperative: reconcilers must honor the supplied abort signal.

## Server snapshot construction

`workshopConfigService.getSnapshot` performs a fresh configuration build for
every request. It does not cache or coalesce in-flight results. This preserves
the existing public response contract (`revision` and `exercises`) and ensures
a request that begins after a direct configuration-table mutation cannot join
an older build whose revision signal has not advanced yet.

Only repeated reconciliation-timeout backoff is implemented as a new load
safeguard. Initial and recurring request pressure remains governed by the
existing hidden-tab deferral, one in-flight poll per client, and randomized
12–15 second repeat cadence. Simultaneous initial mounts can still create a
burst; production measurement is required before introducing another server
optimization or changing client cadence.

## Regression coverage

- `tests/revisionPoller.test.js` covers healthy scheduling, first and repeated timeout delays, deterministic jitter configuration, baseline retention, counter resets, non-overlap, visibility pause, abort, and unchanged ordinary failure behavior.
- `tests/workshopConfigService.test.js` covers fresh post-mutation snapshots, effective visibility, public/raw behavior, targeted status checks, and unchanged route response shapes.
