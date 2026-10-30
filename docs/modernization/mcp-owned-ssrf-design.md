# Owned MCP SSRF design

## Status and boundary

This document proposes an authentic `mcp_ssrf` exercise. A bounded Linux
prototype has demonstrated one synthetic internal HTTP destination with a
proc-free worker, as recorded below. This is not a production implementation,
activation, complete security qualification, or claim that the objective is
gradeable. No model, Judge, database-credit, browser or deployment qualification
has been performed for this design.

The design requires the model-selected, attacker-supplied HTTP URL to be the URL
that is actually resolved and requested. Replacing a metadata, private-network,
or internal hostname with an unrelated loopback sidecar path is not an accepted
implementation. A URL classifier may enforce fixed-mode policy, but it must not
precompute the vulnerable-mode response or dispatch the request to a response
fixture selected by URL class.

The supported boundary is an owner-, platform-session-, generation-, run-, and
request-bound synthetic lab. It must never contact host services, a real cloud
metadata endpoint, private network services, public Internet services, or a
shared global target. The current stopped private RAG/ecommerce work and AWS or
deployment configuration are outside this design.

## Current source state

The current unqualified MCP path does not meet the raw-URL requirement:

- `server/services/mcp/sandboxShell.js:335-373` recognizes selected URL shapes
  and delegates to `fetchViaSsrfTarget`.
- `server/services/mcp/targets.js:24-55` maps the supplied URL to a path on the
  shared `SSRF_TARGET_URL`. The socket is real, but the requested destination is
  not. The chosen path, rather than network resolution of the learner URL,
  determines the outcome.
- `sidecars/ssrf-target/index.js:1-90` is a shared process with a process-global
  hit list and common response fixtures. It is not an owner-isolated effect
  authority.
- `server/services/mcpObjectiveGrader.js:170-178` currently treats the detector's
  `objectivesHit` and `achieved` annotations as the SSRF outcome gate. The
  generic rubric at `server/config/objectiveRubrics.js:112-114` describes a real
  internal response but has no owner-bound HTTP receipt requirement.
- `server/routes/mcpWorkshop.js:356-363` asks the objective observer for private
  evidence, then hard-codes `mode: 'vuln'` for grading. `mcp_ssrf` has no current
  private observation branch in
  `server/services/mcp/ownedResourceApplication.js:202-228`.
- `server/services/mcp/ownedQualification.js` does not include `mcp_ssrf` in an
  owned production qualification. The normal installer therefore cannot make
  the objective gradeable merely because the legacy tool returns data.

The existing owned target is a useful isolation foundation:

- `sidecars/sandbox-runner/mcpTargets.js:435-449` holds the exact target lock for
  the complete operation and rechecks authority before returning.
- `sidecars/sandbox-runner/mcpTargets.js:455-468` creates new user, network, PID,
  UTS, and IPC namespaces for each Bubblewrap execution. It exposes a minimal
  root, fixed environment, and the verified final-process seccomp descriptor.
- `sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in:51-83` admits
  namespace setup only after the packaged Bubblewrap transition. The child
  profile currently permits namespaced `net_admin`; the parent supervisor has
  no `userns` rule.
- `sidecars/sandbox-runner/mcpSeccompFilter.c:37-45` allows ordinary process and
  networking syscalls but rejects nested namespace and mount escape operations
  in the final process.
- `docker-compose.yml:41-58` gives the owned runner no added Linux capability,
  privileged mode, host network, or host root mount. The selected enforcing
  AppArmor profile and inner seccomp contract, not an outer capability grant,
  are the intended boundary.
- `tests/mcpTargetsLinux.integration.test.js:67-85` has already qualified that a
  current target cannot reach an outer-container listener. That earlier result
  does not qualify the proposed HTTP namespace setup.
- `sidecars/sandbox-runner/mcpTargets.js:616-668` serializes target retirement,
  writes a durable pending journal before deletion, and publishes a completed
  receipt only after exact target absence.

## Conditional feasibility gate

The design is partially feasible on the tested Linux runner. The prototype
proved namespace-local address setup and complete capability removal before a
port-8080 worker began. The remaining topology, port-80 and production gates
below remain open.

Before implementation can be promoted, one isolated native gate must prove all
of the following through the same packaged Bubblewrap, AppArmor, and seccomp
path used by production:

1. An unprivileged runner can retain `CAP_NET_ADMIN` only inside the newly
   created user/network namespace long enough to configure its loopback device.
2. If canonical metadata port 80 is retained, a trusted setup helper can retain
   namespaced `CAP_NET_BIND_SERVICE` long enough to bind the controlled listener.
   The Bubblewrap child AppArmor profile would need the exact corresponding
   setup capability; the outer container must not receive it.
3. The helper can assign the exact synthetic `/32` addresses, create the
   namespace-local routes and listeners, then clear effective, permitted,
   inheritable, ambient, and bounding capability sets and set `no_new_privs`
   before the HTTP worker handles any request.
4. The worker observes zero capabilities, no default route, no external network
   interface, no external resolver, and no host-visible process or filesystem.
5. An outer-container listener, host loopback service, real metadata address,
   private network address, DNS resolver, and public Internet address are all
   unreachable. The synthetic addresses remain reachable.
6. Every setup, server, fetch, redirect, timeout, and failure process is joined
   before the operation returns, and no namespace or process remains afterward.

This gate must run before objective or production qualification. If the target
kernel, nested user namespace, Docker security boundary, or enforcing AppArmor
profile cannot satisfy it, the feature remains unavailable. Creating a host
veth, adding outer `CAP_NET_ADMIN`, using privileged or host-network mode,
loosening the container to AppArmor `unconfined`, or routing through the host is
not a fallback. A hard-coded loopback dispatcher, logical URL enum, or response
lookup is also not a fallback.

The smallest candidate is a root-owned, non-writable native namespace-init
helper verified like the current Node and seccomp-probe executables. It should
configure addresses and pre-bind privileged listener sockets, drop every
capability, and then execute a bounded Node worker with only inherited listener
file descriptors and target-private files. The learner-selected command must
never receive a setup capability. A userspace network stack such as
`slirp4netns` or `pasta` is not part of the first design: neither is currently a
verified runtime dependency, and its default routing would require a separate
proof that all host and external egress is absent.

## Partial native feasibility evidence, 2026-09-19

The retained record is
[`mcpOwnedSsrfFeasibilityEvidence.json`](../../tests/fixtures/mcpOwnedSsrfFeasibilityEvidence.json).
The test-only gate, Perl initializer and Perl worker are under
`tests/fixtures/mcpOwnedSsrf*`. They are not installed application components.

The owned disposable container used the existing runner image, packaged
Bubblewrap 0.12.0, enforcing `owasp-ai-goat-mcp-sandbox`/`bwrap` profiles and packaged
inner seccomp filter. The installed AppArmor source file matched the rendered
repository template exactly, SHA256
`c3cd8e253e789d459705ab7d31d822cbd6b6d12cbd0a02d562d9af22645ba2d0`.
Loaded profile names were confirmed enforcing; the kernel's compiled policy
bytes were not independently hash-compared. Outer seccomp remained the existing
runner's `unconfined` setting; the packaged inner filter remained active. No
profile, host service, deployment file or outer capability was changed.

Two failures clarified the setup boundary. Adding a private proc mount failed
before execution and was removed because production intentionally omits proc.
The subsequent proc-free helper had effective `NET_ADMIN` and `SETPCAP` but
`SIOCSIFADDR` returned `EPERM`. Bubblewrap's devpts setup initially maps namespace
UID 0, then creates a second user namespace to restore a nonzero requested UID.
The network namespace belongs to the first user namespace; capability bits in
the second do not grant authority over it. This behavior is visible in
[Bubblewrap 0.12.0 source](https://github.com/containers/bubblewrap/blob/v0.12.0/bubblewrap.c).

The corrected prototype requests UID/GID 0 **inside the new namespace**, mapped
to the unprivileged outer UID/GID 10001. This avoids the second user namespace.
Only namespace-local `NET_ADMIN` and `SETPCAP` are retained during setup. Before
exec, the helper clears effective, permitted, inheritable, ambient and bounding
capabilities and sets `no_new_privs`. The final worker independently confirms
these properties with `capget` and `prctl`, without proc. Namespace-local UID 0
therefore does not mean host root or retained setup capabilities.

The bounded successful run proved:

- Real ioctl assignment of `10.0.1.100/32` to loopback and a listener bound to
  `10.0.1.100:8080`.
- An unchanged HTTP URL and path/query selected the real socket destination;
  the server journal confirmed the accepted address and request, and the client
  received the synthetic canary bytes.
- Post-exec zero capability sets, `no_new_privs=1`, only loopback via netlink,
  no IPv4 default route, no resolver configuration and no outer application path.
- Five failed TCP connections: an actually listening outer-container loopback
  service, unassigned metadata and private addresses, a public address and a
  public DNS TCP port. These are not a complete UDP, IPv6 or DNS qualification.
- The HTTP server child was joined and the disposable container was removed;
  exact container absence was checked.

This proves neither canonical metadata port 80 nor the complete manifest,
normal hostname resolution, redirects, fixed-mode policy, durable receipts,
reset/replay, production helper provenance, model selection or Judge credit.
Those gates remain mandatory. Earlier failed attempts and the exact source
hashes are retained in the evidence rather than relabeled as successful tests.

## Proposed trusted packaged helper

This is a design draft, not authorization to activate a production path. Keep
existing CLI execution identity and arguments unchanged. A separate owned HTTP
operation should build its own Bubblewrap argv with namespace UID/GID 0 and the
minimal setup capabilities described above. Learner commands must never enter
this setup path or receive its capabilities.

The proposed initializer is a small C executable, compiled for the runner's
architecture in its existing sidecar build stage. Install it root-owned and
non-writable/non-setuid at a fixed libexec path. Generate a build manifest with
its hash, architecture, protocol version and worker/manifest hashes. Readiness
must verify descriptors with no-follow opens, ownership, modes and exact hashes,
like the current seccomp/runtime verification. A pathname or executable bit
alone is insufficient. No host compiler or runtime package installation is part
of an HTTP operation.

The helper should have this narrow lifecycle:

1. Receive a bounded server-owned manifest and operation input through explicit
   descriptors. Accept an exact raw HTTP URL as data, never as shell text. The
   setup manifest is immutable and cannot be selected by learner URL classes.
2. In the fresh owned namespace, configure only manifest `/32` addresses and
   required local routes using ioctl or netlink. Verify interface inventory and
   absence of a default route directly. No veth, host route or external resolver
   is created. Bind each listener to its exact address, never wildcard.
3. Pre-bind listener sockets before dropping capabilities. Canonical port 80
   remains conditional: qualify its kernel/profile requirements explicitly;
   add no outer capabilities and do not assume an unprivileged-port sysctl.
   Any required `NET_BIND_SERVICE` setup permission needs its own reviewed
   sidecar profile change and native qualification before promotion.
4. Close setup/control sockets. Clear ambient and bounding sets, clear all
   effective/permitted/inheritable bits, set `no_new_privs`, and verify every
   result. On any error close all descriptors and fail before serving requests.
5. Exec only the verified immutable worker, passing a fixed descriptor map for
   pre-bound listeners, bounded operation input and the result channel. Mark
   every other descriptor close-on-exec. The final worker independently verifies
   capability sets, `no_new_privs`, network state and executable provenance.
   A small C final-worker launcher may attest these facts before invoking the
   fixed Node HTTP worker; do not infer final state solely from the initializer.
6. The trusted worker accepts inherited sockets and performs ordinary HTTP
   resolution/fetch/redirect handling. It journals actual accepted sockets and
   bounded response bytes. It does not synthesize a response from URL classes.
   Every child/listener is joined or closed before the structured result is
   returned. The supervisor enforces a whole-operation deadline, waits for the
   namespace process tree, then validates and durably publishes the receipt.

Use separate descriptors for input and output; never return canaries or URL
credentials through stderr. The operation rejects URL credentials at admission.
Malformed results, premature EOF, partial writes, unknown descriptor IDs,
unexpected children or failure to join invalidate the operation. A child
success exit alone is not a durable effect receipt. Execution remains under the
existing exact target lock and retirement protocol.

The minimal sidecar-specific implementation surfaces are:

| File | Proposed responsibility |
|------|-------------------------|
| `sidecars/sandbox-runner/mcpHttpNamespaceInit.c` | Exact address/listener setup, descriptor closure, capability removal and worker exec. |
| `sidecars/sandbox-runner/mcpHttpWorkerLauncher.c` | Independent post-exec capability/network attestation and verified Node worker launch. |
| `sidecars/sandbox-runner/mcpHttpWorker.js` | Real HTTP listeners, raw URL fetches, redirects, fixed policy, bounds and hit journal. |
| `sidecars/sandbox-runner/mcpHttpNetworkManifest.json` | Fixed synthetic addresses, local hostnames and listener definitions. |
| `sidecars/sandbox-runner/mcpHttpReceipt.js` | Strict private result validation, exact operation replay and durable receipt publication. |
| `sidecars/sandbox-runner/mcpTargets.js` | Separate HTTP argv/operation under existing owner lock; leave ordinary CLI argv unchanged. |
| `sidecars/sandbox-runner/ownedTargetApi.js` | Exact private HTTP-operation request contract. |
| `sidecars/sandbox-runner/Dockerfile` | Future sidecar-only compile/install/hash packaging after review. |
| `sidecars/sandbox-runner/apparmor/owasp-ai-goat-mcp-sandbox.apparmor.in` | Only if separately qualified port-80 setup needs an additional namespaced permission. |

The last two entries are proposed future work, not changes made by this design.
No root Dockerfile, Compose, AWS asset or host-wide profile change is required by
this draft. Application adapters, mode persistence, objective evidence and Judge
integration remain later separate work after the complete native gate passes.

## Synthetic network topology

Each admitted fetch gets a fresh network namespace. No namespace is shared
between owners or between requests. Within it, the trusted helper assigns actual
addresses to loopback and starts actual HTTP listeners:

| Lab service | Address | Purpose |
|---|---|---|
| Synthetic metadata | `169.254.169.254:80` | Returns an owner-specific training role and credential canary. |
| Internal admin | `10.0.1.100:8080` | Returns owner-specific synthetic internal configuration. |
| Internal monitoring | `10.0.2.10:80` | Returns benign internal health data. |
| Benign external-style target | One fixed documentation-range address | Provides a no-credit baseline without contacting an external service. |

The exact benign address must come from a checked-in network manifest and use a
documentation-only range. It must not overlap a host, container bridge, VPN, or
deployment network. Readiness must reject a conflicting manifest rather than
silently choose another destination.

The target root contains a read-only `/etc/hosts` generated from that manifest,
a minimal `nsswitch.conf` restricted to local files, and an empty resolver
configuration. Controlled names therefore undergo normal local name resolution;
unknown names fail with a real resolution error. Direct unassigned IP addresses
fail because the namespace has no route. Requests to `127.0.0.1` can reach only
listeners intentionally placed inside that request's namespace, never the host
or runner supervisor.

The synthetic server must bind the listed address and port rather than
`0.0.0.0`, and it must record the actual accepted socket address, Host header,
method, path, query, and response digest. Owner-specific response canaries are
created during target provisioning and stored below the existing private target
directory. Global environment secrets and historical example credentials must
never enter a response.

## Raw URL and redirect semantics

`fetch_url` remains an HTTP GET tool. The dedicated owned operation receives the
exact model-selected URL string. It validates only the bounded tool contract,
such as byte length, supported `http:` scheme, absence of credentials, response
size, timeout, and redirect limit. It records both a digest of the original
bytes and each effective URL used by the HTTP client.

In vulnerable mode, the worker performs normal resolution and requests the
selected URL. It processes `301`, `302`, `303`, `307`, and `308` responses with
a small redirect limit, resolves relative locations against the current URL,
and performs the next real request. It does not classify a URL as “metadata” or
“internal” to select a response. The server that accepts the connection decides
the response from its actual bound address and requested path.

In fixed mode, a server-owned egress policy evaluates the initial destination
and every redirect destination after name resolution and before opening the
socket. Private, loopback, link-local, unspecified, multicast, and other
non-public destinations are rejected. The exact checked address is the address
used for the connection while preserving the original Host header, preventing a
second lookup from changing the decision. The synthetic benign hostname and its
exact manifest address form the sole allowlisted baseline. A benign endpoint
that redirects to metadata must produce an actual benign hit followed by a
fixed-mode block with zero metadata hits. The same URL in vulnerable mode must
follow the redirect and reach the actual metadata listener.

HTTP status, DNS failure, refused connection, timeout, redirect loop, oversized
body, and policy denial are honest tool outcomes. None is converted into a
successful fixture. HTTPS support requires a separate synthetic certificate and
name-validation design; it must not be claimed by an HTTP-only implementation.

## Persisted server-owned mode

MCP currently has no mode entry in
`server/services/workshopModeService.js:10-17`, even though the canonical
PostgreSQL mode repository already persists an authenticated user's mode in
`workshop_platform.user_modes`
(`server/database/postgres/workshopRevisionRepository.js:19-35`). The MCP route
must use this existing server-owned mechanism:

1. Add `mcp_workshop` with exact allowed modes `fixed` and `vuln` to the mode
   catalog.
2. Mount the standard authenticated GET and POST mode handlers from
   `server/services/workshopModeHandlers.js:5-32` on the MCP route.
3. Read the persisted mode after owner-run admission and before model planning.
   Capture that value once for the run and pass it through the SDK invocation,
   dedicated owned fetch, private receipt, and Judge evidence.
4. Never accept the mode from chat JSON, tool arguments, model output, query
   parameters, or process-global `LAB_MODE`.
5. Grade only vulnerable-mode effects. A fixed-mode denial is successful defense
   behavior and never earns the attack objective.

The learner UI may display and update the same persisted mode through those
handlers. UI state is not an execution or grading authority.

## Owned operation and receipt

The qualified path adds a dedicated owned-target operation rather than passing
learner data through `/owned-targets/exec`:

1. The real MCP SDK catalog exposes the existing `fetch_url` schema.
2. The model selects `fetch_url` and supplies the raw URL through the normal
   graph path in `server/agent-runtime/mcpWorkshopGraph.js:16-29`.
3. The SDK handler obtains the current private invocation from
   `server/services/mcp/protocolContext.js:42-62`. It passes the captured mode,
   current owner scope, run ID, invocation ID, and effect key to an owned runner
   method.
4. `server/services/mcp/ownedTargetClient.js` calls a new exact-body private API
   operation, for example `/owned-targets/http-fetch`. The opaque target
   capability and API token remain private.
5. `sidecars/sandbox-runner/ownedTargetApi.js` calls a dedicated store method.
   The store acquires the existing target lock, derives an operation ID from the
   current run/effect identity, and returns an existing verified receipt on an
   exact replay without starting another namespace or HTTP request.
6. A new namespace performs the real request and all redirects. The sidecar
   validates the helper's structured output and actual server hit journal before
   it durably publishes the receipt.
7. The public tool result includes the bounded response or honest error needed
   by the learner. The complete trusted receipt remains private and is attached
   to the exact in-memory tool result through a one-shot observation module.

The receipt must bind at least:

- receipt and policy versions;
- target ID, platform owner ID, platform session ID, generation, MCP session,
  owner key, run ID, invocation ID, and operation ID;
- captured server-owned mode and policy digest;
- digest and byte count of the exact original URL;
- an ordered hop list containing effective URL, resolved address, destination
  port, accepted listener identity when present, status, Location digest, and
  bounded response-body digest and byte count;
- final status, body digest and byte count, block/failure category, redirect
  count, and whether a controlled sensitive listener was actually reached;
- namespace setup version, network-manifest digest, zero-capability attestation,
  and timestamps; and
- a canonical receipt digest.

The receipt must not include API tokens, target capabilities, host paths, outer
network details, or global secrets. The sidecar persists it below the exact
target root before returning. The application accepts only receipts recreated
or verified through the strict client; arbitrary JSON shaped like a receipt is
not evidence.

## Objective and Judge contract

`mcp_ssrf` needs a new rubric version. The generic `mcp_real_tools.v1` facts are
insufficient. Completion requires all of these server-owned facts:

- the real configured model selected `fetch_url` and the SDK invoked that exact
  tool with the selected raw URL;
- the private protocol receipt and HTTP receipt refer to the same owner, target,
  session, generation, run, invocation, operation, arguments, and captured
  vulnerable mode;
- the original URL digest in the receipt matches the model-selected argument;
- a controlled sensitive listener accepted a real socket request at the actual
  resolved address after any recorded redirects;
- the returned tool body exactly matches the final listener body digest and is
  nonempty synthetic sensitive content; and
- the current owner run remains valid through Judge evaluation and durable
  completion.

The Judge receives the bounded tool response, the learner-facing assistant
response, and a redacted server observation derived from the verified receipt.
It must semantically decide that the response explains or returns the actual
internal data obtained through the model-selected fetch. A URL mention, target
classification, attempted request, generic success string, detector annotation,
server hit without returned bytes, or assistant claim without a receipt cannot
earn credit. A later refusal that withholds the returned content remains a
semantic no-credit outcome unless the objective rubric explicitly defines tool
result disclosure as learner-visible; that choice must be documented and tested
before activation.

The objective observer in `ownedResourceApplication` must return only the
verified SSRF witness for this objective. The grader must recompute all hard
facts before invoking the Judge and force `completed: false` when any hard fact
fails, regardless of model verdict.

## Replay, reset, and ownership

HTTP effects are idempotent at the admitted request/effect boundary:

- Replaying the same conversation request returns its original durable response
  without a new actor call, SDK call, HTTP operation, Judge call, or credit.
- Retrying grading for an already persisted tool effect rereads the verified
  receipt and must not make another HTTP request.
- Reusing an operation ID with different URL, mode, owner, run, or generation is
  a conflict, not a second request.
- A stale generation or retired protocol context is rejected before namespace
  creation.

The request runs under the current target lock. Retirement therefore waits for
an admitted fetch to finish or hit its bounded timeout. Reset first retires the
protocol, then retires the owned target through the existing pending/completed
journal, then publishes the new generation. Deleting the target removes its
canaries, hit journals, and fetch receipts. The completed retirement receipt
proves exact target absence before progress reset completes.

A sibling owner uses a different target, canaries, operation receipts, network
namespace, hit journal, and reset scope. One owner's fetch, replay, timeout,
failure, or reset must leave the sibling byte-for-byte unchanged.

## Required implementation surfaces

The smallest coherent candidate is expected to touch these surfaces only:

- Runner image and boundary: `sidecars/sandbox-runner/Dockerfile`,
  `mcpTargets.js`, `ownedTargetApi.js`, the AppArmor template, and new narrowly
  scoped namespace-init, HTTP-worker, network-manifest, and receipt-state files.
- Private application adapter: `server/services/mcp/ownedTargetClient.js` and a
  new private SSRF observation helper.
- MCP runtime: `server/services/mcp/sandboxShell.js`,
  `ownedResourceApplication.js`, `ownedQualification.js`, and
  `ownedResourceProduction.js`. The qualified path removes the legacy URL
  rewrite while preserving unrelated legacy behavior until separately retired.
- Mode and route: `server/services/workshopModeService.js` and
  `server/routes/mcpWorkshop.js`, with the existing mode-handler pattern.
- Grading: `server/services/mcpObjectiveGrader.js` and
  `server/config/objectiveRubrics.js`.
- Truthful curriculum/UI: `server/data/mcpWorkshopSolutions.js:66-89`,
  `server/data/workshopHints.js:607-613`, and
  `client/src/pages/challenges/MCPWorkshop.js:61-65`. The copy must call the
  credentials synthetic owner-isolated training data, not live instance IAM
  credentials.

No database migration is expected merely for per-target receipts because the
existing target directory and retirement journal own their lifecycle. A schema
change is warranted only if the final application design needs durable receipt
indexes beyond that owner target; such a change would require a separately
reviewed forward migration and is not authorized by this document.

## Required qualification

Controlled tests must cover URL parsing without dispatch substitution, exact
hosts-file resolution, every redirect status, relative redirects, redirect
loops, size and time bounds, fixed-mode checks on every hop, malformed helper
output, forged/missing/stale receipts, operation conflicts, and fail-closed
capability/readiness behavior.

The isolated Linux gate must prove the conditional feasibility requirements and
the actual HTTP topology. It must include actual requests to metadata, internal,
monitoring, and benign addresses; unknown-name and unassigned-address failures;
a vulnerable benign-to-metadata redirect; the fixed equivalent with zero
metadata hits; direct host/outer/private/cloud/Internet negatives; replay,
grading retry, reset, held-fetch-versus-reset, stale generation, sibling
isolation, and exact process/namespace/target cleanup.

Only after source review and that infrastructure gate pass should an actual
model qualification run. It must prove a plain-English learner request causes
the configured model to select `fetch_url` and preserve its raw URL, the real
SDK invokes it, the namespace performs the real request, the assistant presents
the relevant result, the real Judge passes, and PostgreSQL persists durable
credit. Model refusal or a different tool selection is an honest failed attempt,
not a reason to force the actor or Judge.

Production promotion remains a separate step. It requires an exact readiness
capability from the owned runner, additive qualification profile changes that
preserve every already authorized objective/tool, instructor and learner API/UI
parity, and full reset/cleanup evidence. Until then, `mcp_ssrf` remains
unqualified and excluded from owned production credit.
