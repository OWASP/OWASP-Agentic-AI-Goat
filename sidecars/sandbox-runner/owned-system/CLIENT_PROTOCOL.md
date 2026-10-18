# Owned System private transport

`server/services/secureshopSystemConfigClient.js` is a server-only adapter.
The standalone listener serves the endpoints below. Application mounting is
explicitly opt-in; installed service and deployment activation are separate.
These private routes are distinct from the UI bridge's legacy
`/api/secureshop/admin/system/read-config` route.
No existing sandbox health response may imply this capability.

Constructor: `createSecureShopSystemConfigClient({baseURL, token, fetchImpl?, timeoutMs?})`.
The origin must be exact HTTP(S), without userinfo, query, fragment or path. The
private bearer follows the existing owned-target43–128character URL-safe token
convention. The adapter supplies all headers, rejects redirects, omits cookies,
and never accepts caller-selected routes or extra request headers.

- Authenticated `GET /secureshop/system/health` must return exactly
  `{version:"secureshop-owned-system-http.v1",ready:true,isolation:"bwrap-system-config-v1",configReadCapability:"secureshop-owned-system-config-read.v1"}`.
- Authenticated `GET /secureshop/system/metrics` returns the exact closed
  `secureshop-owned-system-metrics.v1` DTO from `health-contract.js`. The listener
  measures its own process uptime and bounded cgroup-v2 memory; unavailable
  memory/load remain null. Host-wide memory, load and uptime are not substitutes.
  Application activation validates both health and metrics before mounting.
- Authenticated `POST /secureshop/system/config-read` accepts only the existing
  frozen executor request `{operationId,path}`. The raw traversal path is sent
  unchanged. It returns the exact executor receipt directly, without a wrapper.
- `read(request,{signal?,assertCurrent?})` verifies readiness before every POST.
  The optional trusted assertion must throw on lost authority. It runs before
  health, again before dispatch, and after the response. It is not learner input
  or a substitute for a retained lease/current original-session admission.

Request normalization/digest reuse the frozen pure sidecar contract. Completed
receipts require exact operation/request identity, isolation, exit0, no timeout
or truncation, drained true, and a closed read result. Positive observations
require exact input/sanitized/contained target path plus UTF-8 bytes/size/SHA256.
Completed negative observations are distinct from positive reads. The negative
allowlist matches the qualified executor's fixed fixture tree: absolute/escaped
path, missing file, nonregular path, or unavailable read. Primitive link,
non-UTF8 and changing-file errors are not accepted because the executor's checked
immutable fixtures cannot produce them; broader target support needs a versioned
contract, not relaxed acceptance.

Explicit executor-unavailable receipts have no read result. Failed health is
pre-dispatch unavailable. Once the config POST begins, failed HTTP, lost reply,
invalid/mismatched receipt, timeout, cancellation or post-response authority loss
produces a privately branded `SYSTEM_CONFIG_OUTCOME_UNCERTAIN` error with
`automaticRetry:false`; remote error prose/private causes are not exposed.
There are no retries or durable readback claims. The operation UUID does not
provide idempotency by itself.

The hard transport deadline covers both fetch and streamed body acquisition,
including a stalled stream. JSON response size is at most4MiB (512KiB text can
expand sixfold under JSON escaping). Early length rejection cancels the body;
stream overrun and abort cancel its reader. Deadline abort also bounds a fetch
implementation that ignores its signal. Authority assertions have their own
caller-owned lifetime and must not hold a database transaction around long work.

## Remaining integration dependencies

1. Authenticated sidecar service handler, strict readiness, installed fixed helper
   packaging and explicit capability activation. No existing policy-render or
   MCP endpoint is repurposed.
2. Durable full launch/persona/original-session authority, operation admission,
   immutable read receipt/readback, retirement/reset/deletion and sibling fences.
   The adapter's optional assertion alone does not establish those guarantees.
3. Mounted gateway compatibility and UI epoch/recovery handling. Projection may
   expose only safe target-relative paths, never outer host paths or credentials.
4. Native authenticated transport qualification and assembled owned-session/UI
   proof. Current adapter tests use controlled responses and a loopback HTTP
   server only; the separate executor ARM64 evidence does not prove this wire.

## Unmounted handler foundation

`http-handler.js` now supplies the opt-in factory
`createSystemConfigHttpHandler({enabled:false,token,executor?,maxConcurrent:2,bodyTimeoutMs:3000})`.
The default returns unhandled without constructing an executor. Enabled mode uses
the fixed executor factory unless a trusted controlled-test dependency is passed.
It authenticates both endpoints (including duplicate bearer rejection), invokes
actual synchronous executor readiness, bounds bodies to32KiB and concurrent
admitted reads to1–16, and aborts/joins active reads on close. Unsupported paths
remain unhandled. Errors omit executor/helper details. No main process imports
or mounts this factory. Its pure `receipt.js` validator is shared with the server
client and has no server/transport dependency.

Real loopback HTTP tests compose the actual client and handler with a controlled
executor. They qualify transport, validation, admission and shutdown behavior,
not native HTTP execution or original launch authority. Package/service activation
and native wire qualification remain required.

## Separate opt-in listener (not main sidecar activation)

`http-listener.js` exports `createSystemConfigHttpListener` with required
`enabled:true`, private `token`, literal `host`, and integer `port`. Only trusted
controlled tests inject `executor`; the default is the fixed checked executor.
`start()` performs actual synchronous executor readiness before opening the port.
`close()` rejects new requests, aborts and joins admitted reads, then destroys
remaining sockets and closes the listener. A drain timeout fails shutdown rather
than claiming successful cleanup. Header bytes/count, slow headers/body/idle
connections and concurrent executor reads are bounded.

The standalone entry is `node owned-system/http-listener.js` with explicit
`SECURESHOP_SYSTEM_CONFIG_HTTP_ENABLED=true`, `SECURESHOP_SYSTEM_CONFIG_TOKEN`,
`SECURESHOP_SYSTEM_CONFIG_HOST`, and `SECURESHOP_SYSTEM_CONFIG_PORT` environment
settings. The CLI requires a nonzero port and accepts only literal loopback or
wildcard bind addresses. SIGTERM/SIGINT use the same joined close. Output contains
only categorical READY/CLOSED/FAILED markers, never token, request, result or OS
error details. No main index, image or deployment imports this entry yet.

For combined disposable PostgreSQL/HTTP qualification, the separate executor
container uses a uniquely owned regular Docker bridge and a loopback-only
published ephemeral port. Outer egress isolation is not established by this HTTP composition. This differs from the prior outer network-none
executor-only qualification; the inner bwrap worker still has its own isolated
network namespace. The private random bearer is supplied through a temporary
private environment file removed after startup and is not recorded in evidence.

The bound application `GET /api/secureshop/admin/system/health` uses the same
canonical original launch/persona/session authority as config reads. It validates
authority before and after the private metrics request, projects only the closed
metrics DTO, and suppresses disconnected responses. A health read creates no
mutation admission or objective credit. Metrics integration has controlled
coverage; its native/full-index/browser acceptance must be recorded separately
from earlier config-only cohorts.
