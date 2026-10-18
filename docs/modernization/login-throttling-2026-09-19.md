# Workshop login throttling

The enabled login limiter has two in-memory layers shared by `/login` and
`/secure-login`: 1,000 total attempts per IP network per 15 minutes, followed by
20 failed or in-flight attempts per exact username and IP network. The aggregate
budget counts successes and account-level rejections. Its policy allowance is
200 attendees times five attempts; this is not a bcrypt concurrency benchmark.

The account layer reserves a slot before authentication and releases it only
after a finished HTTP200. Failed, interrupted and outstanding requests count.
Consequently 21 simultaneous requests for one account do not bypass the bound
even when the first 20 eventually succeed. Sequential successes release their
account slots but still consume the aggregate budget. Existing account lockout
policy and the administrator's enable/disable setting remain unchanged.

PostgreSQL identity lookup preserves case and whitespace. The limiter hashes
exact 1–50-character usernames with a type tag; missing, non-string, empty and
oversized usernames share a distinct invalid bucket. It performs no account
existence lookup and logs neither usernames nor credentials. IP normalization
uses express-rate-limit's IPv6 /56 helper, preventing address rotation inside
that subnet from escaping a bucket. Separate middleware request properties keep
the audit's limit and counter accurate; the last applicable layer supplies the
standard response headers. Both rejections use the same generic response.

A shared attacker can still exhaust the aggregate NAT budget, and existing
account-specific authentication responses are outside this patch's enumeration
scope. There is intentionally no new cross-IP account bucket that could let a
remote actor lock a victim out through this middleware alone. Counters remain
per process, reset on restart, and require a shared store for multi-instance
coordination. Correct trusted-proxy configuration remains necessary.

Policy evidence: `tasks/login-layered-rate-limit-2026-09-19.json` runs copied-source HTTP
middleware with controlled response handlers, no application databases. Tests
cover 200 concurrent distinct successful learners, repeated success release,
20 held same-account requests plus rejected overflow, failed aliases, exact
username distinction, IPv6 subnet rotation, malformed input, aggregate spraying,
and disabled toggle. The existing PostgreSQL storage-selection check separately
proves the rejection audit avoids SQLite. Real bcrypt admission is qualified in
the bounded single-process scope below; distributed enforcement remains open.

## Platform login response boundary

Source review of `server/routes/postgresAuth.js` finds a separate account
discovery oracle: an unknown username returns401 with `attemptsRemaining:0`,
whereas the first wrong password for an existing account returns401 with a
positive remaining count. Locked accounts return423 and can expose a lock
expiry before password verification. Unknown and inactive accounts also skip
bcrypt entirely, creating a timing distinction. These are platform behaviors,
not annotated teaching sinks. The frontend does not consume these fields.

Implemented after freezing the real200-login baseline: use the same failed-login status and body for unknown,
inactive, locked and incorrect-password submissions; retain lockout enforcement
and private audit data. Perform one bounded password comparison for every
well-formed login, using the stored digest when present and a fixed non-authenticating cost12
dummy hash otherwise. Never turn a dummy comparison into account
authority. Preserve valid-login/session-rotation contracts and authenticated
account-status handling. Qualify unknown/existing/inactive/locked responses,
comparison admission and absence of new sessions; avoid claiming constant-time
network behavior from these functional tests. The frozen real200-login baseline predates this separate change. Eleven isolated
HTTP/session checks pass, including both login aliases and retained failing
baseline responses; see `tasks/login-account-discovery-fix-2026-09-19.json`.
The frozen real200-login baseline failed with38 successes and162 service errors.
The later diagnostic mapped its current-source reproduction to control-pool
acquisition timeouts; both failed receipts remain preserved alongside the
bounded correction and qualification below.

## Bounded login execution — qualified local scope

The owned diagnostic mapped all147 service failures to five-second control-pool
acquisition timeouts at the identity repository boundary. Main-thread event-loop
delay peaked near1.9seconds. Pool and request timeouts remain unchanged.

The selected application design admits at most four complete login pipelines
(and no more than available CPU parallelism), with256 waiting requests.
Credential lookup occurs after admission. A matching bounded worker pool runs
bcrypt comparisons outside the HTTP event loop; both login aliases use the same
router-owned runtime. Unknown credentials still take the dummy comparison path.
Queue overflow returns a generic503. Worker failure must reject the affected
request without replay or discarding ownership of a live worker.

The route now carries disconnect cancellation through admission and each
publication step. If session creation already occurred, existing token/cookie
cleanup runs before the admission slot is released. Application shutdown closes
login admission before draining HTTP and closing the session store/database.

Focused runtime and HTTP checks pass, including queue bounds, worker failure and
termination ownership, disconnect cancellation, identical invalid-account
responses and graceful close. The owned current-source qualification then ran
two consecutive bursts of200 distinct valid logins from one IP. Both returned
200/200 HTTP200 responses within the unchanged thirty-second per-request
deadline (max13.58s and13.42s), with no429,503 or client timeout. Admission
peaked at4 active/196 queued, the worker pool at4, the identity pool at8
connections/0 waiters, event-loop delay at16.68ms and RSS at188,628,992 bytes.

The cohort produced400 unique JWTs,400 durable platform sessions/cookies and400
login audit rows. Revoking one current token left399 active platform sessions;
that bearer and its retained teaching cookie were denied, while an older token
for the same user and a sibling token remained valid. Raw teaching rows remain
unrevoked history;399 rows retained canonical bindings to active platform
sessions. Shutdown joined all workers/admission, released all pool reservations,
and the owned process group/container were absent. See
`tasks/login-shared-nat-capacity-2026-09-19.json`.

This qualifies bounded route-level local admission on the recorded macOS ARM
host. It does not qualify a distributed/multi-instance limiter, proxy/TLS/NAT
infrastructure, Linux/AWS, installed state, sustained soak, browser login or200
concurrent model inferences.
