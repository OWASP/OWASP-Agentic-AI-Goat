# Owned HTTP capability for MCP SSRF

The runner Dockerfile packages this capability. Supported setup provisions its
owned service, and the application composes it through
`server/services/mcp/ownedResourceProduction.js` and `ownedHttpProduction.js`.
Owner-bound socket effects and private receipts feed canonical objective grading;
capability readiness still controls whether the objective is available.

Recorded actual-model graph/SDK/socket/Judge and lifecycle checks are scoped
proofs. Full mounted application, combined service readiness, and rendered
learner/admin qualification remain separate work. See the current
[architecture and verification audit](../../../tasks/main-workspace-preservation-2026-09-28/mcp-namespace-current-seam-audit.md)
and [exercise matrix](../../../docs/modernization/current-exercise-authenticity-matrix-2026-09-15.json).

## Historical candidate state — superseded by later integration

The following record describes the initial candidate and its early failures.
Statements about missing packaging or application integration apply to that
historical state, not the current implementation.

These files are an unmounted infrastructure candidate for the raw-URL MCP SSRF
lab. They are not shipped by the runner Dockerfile, called by application routes,
or objective-credit evidence. Ordinary MCP CLI setup remains unchanged.

`namespace-init.c` configures only the checked-in loopback aliases, prebinds exact
listener descriptors 3–6, clears capability sets, enables no-new-privileges and
re-executes its attestation branch before the fixed Node worker. The second
process checks capability sets, loopback-only interfaces, no IPv4/IPv6 default
route and actual descriptor addresses. Packaging is expected to place this at
`/usr/local/libexec/dvaia-owned-http-init`, the worker at
`/usr/local/libexec/dvaia-owned-http-worker.js`, and the manifest alongside it as
`dvaia-owned-http-manifest.json`, root-owned and non-writable. Future production
readiness must verify exact open-descriptor ownership/modes/hashes; this is not
implemented by the candidate itself.

`worker.js` receives bounded server-owned operation input on stdin. It creates
HTTP servers on inherited descriptors and resolves/requests the original URL;
it does not replace learner destinations with fixture paths. Its fixed-mode
allowlist is policy only. Redirect handling, hit records and final listener
cleanup are implemented but **not yet qualified in the isolated namespace**.
The synthetic response canary is supplied by trusted test input; production
owner/session/generation binding, durable receipt validation and reset/replay
integration do not yet exist.

The 2026-09-19 enforcing-profile gate compiled with GCC `-O2 -Wall -Wextra
-Werror`, then failed at the first canonical metadata port-80 bind with EACCES.
The tested setup retained only namespaced `NET_ADMIN` and `SETPCAP`; it did not retain `NET_BIND_SERVICE`, and the existing child AppArmor profile has no `net_bind_service` permission. The individual kernel/profile cause was not isolated. No
profile, outer capability, VM, sysctl or deployment change was made. This proves
that the current boundary does not admit the candidate listener setup, not that
the HTTP topology is qualified. See the recorded prerequisite evidence in
`tasks/mcp-owned-http-prerequisite-2026-09-19.json` and the broader design in
`docs/modernization/mcp-owned-ssrf-design.md`.

Further work requires separately reviewed namespaced setup permission and a
repeat of every network/zero-capability/redirect/negative-egress/join gate.
Worker provenance verification, externally bounded DNS/setup/operation lifetime,
UDP/IPv6 denial, actual outer-listener probes and durable target cleanup remain
mandatory before any application or Judge integration.

## Subsequent owned-profile qualification

A separately named temporary profile admitted canonical port 80, with
`net_bind_service` permitted in the trusted Bubblewrap/initializer setup chain.
An initializer-only nested profile transition was not viable: after correcting
an initially unresolved relative profile name, the kernel explicitly rejected
the absolute transition under `no_new_privs`. The successful candidate keeps the
same dedicated HTTP child profile through execution. The profile retains setup
permissions, but the helper clears effective/permitted/inheritable/ambient and
bounding capabilities before its attestation exec; it also confirms namespace,
mount and setns syscalls return EPERM under the unchanged inner seccomp filter.
This is distinct from claiming the AppArmor permission exists only in the helper.

Twelve bounded native operations passed: all four actual manifest listeners,
hostname resolution, raw URL digest preservation, vulnerable and fixed metadata
redirect behavior, redirect-loop bounds and five negative destinations including
an actually listening outer-container loopback server. The outer listener was
joined; the container was absent before unloading the unique profile; its
ownership directory was removed. Exact profile source, executable hashes, results
and remaining limitations are in
`tasks/mcp-owned-http-topology-2026-09-19.json`.

These tests do not activate the production runner or earn objective credit.
UDP/IPv6 connection probes, immutable executable-readiness integration and durable
owner/reset/replay/receipt contracts remain required. The original EACCES and
profile-transition failures remain recorded as separate evidence.

### Unmounted lifecycle transport slice (2026-09-19)

`operationStore.js` composes the existing `targetStore.withTarget` lock and
pre/post authority checks. It records a private `http-operations/<operation>.json`
under the target directory, outside the mounted rootfs. Existing canonical
`retireTarget` removes that entire directory (`mcpTargets.js`, recursive
`remove(targetPath(binding))`), so the journal follows the target lifecycle.
An exact completed replay returns its stored receipt without another request.
Any pending operation is uncertain and cannot execute again; reset or operator
investigation is required. No uncertainty is presented as a successful exploit.

The injected trusted executor must join every process on success, failure and
abort before its promise settles. Timeout aborts execution but does not release
the target lock through a Promise.race. Packaging that executor, immutable
executable readiness, and an actual canonical retirement integration test remain
required. Private filesystem ancestors are owned by the supervisor; journals
reject symlink files/directories, oversized records and permissive modes.

`api.js` is a private-token factory only; it is not mounted. The new backend
`server/services/mcp/ownedHttpClient.js` derives run/invocation/operation coordinates
from private protocol context, with admitted scope and mode supplied by trusted
composition. Only the URL comes from learner tool arguments, and its original
bytes are retained. No model argument may choose owner, mode or capabilities.
The central database receipt, graph actor tool, evidence adapter, Judge rubric
and credit path remain unwired. These files do not make SSRF feature-complete.

`tasks/mcp-owned-http-udp-ipv6-2026-09-19.json` records the revised native
qualification: after dropping all capabilities, actual UDP connects to IPv4 DNS
and IPv6 public DNS addresses must return ENETUNREACH. These are route probes,
not packet-delivery tests. All twelve original HTTP cases passed again; the
unique candidate container and AppArmor profile were removed and absence checked.
Existing installed profiles and application processes were unchanged.

### Packaged executor qualification (2026-09-19)

The sidecar Dockerfile now compiles and packages the HTTP initializer and a
separate process subreaper, worker, manifest, resolver files and root-owned asset
hash registry. `executor.js` verifies those assets, Node, bubblewrap and the
seccomp filter before launching fixed arguments. Learner input travels only as
bounded JSON on stdin. It cannot select executable paths, bind mounts or shell
commands. The HTTP namespace mounts no target or host learner directories.
`canonical.js` is shared by the packaged store and backend client, eliminating
the earlier dependency on an unpackaged server source file. Numeric target
coordinates are normalized consistently in receipt identities.

Readiness verifies the non-root zero-capability supervisor, exact dedicated
profile label and immutable packaged assets; each launched initializer verifies
actual namespace/capability/seccomp/listener conditions. This is not an assertion
that arbitrary operator-created policy bearing the same name is qualified.
Asset hashing currently repeats per operation; cross-owner admission and a
bounded immutable-asset verification cache need design before 200-student use.

The executor caps total stdout/stderr at 64 KiB and operation time at eight
seconds by default. It signals the trusted supervisor on timeout or abort and
waits for process close. The compiled supervisor adopts, terminates and reaps
its own descendants before exiting; it does not return if child cleanup cannot
be established. The original close-only implementation left defunct namespace
children under a PID1 caller, which the new supervisor corrects. No ordinary
CLI executor behavior changed.

`tasks/mcp-owned-http-packaged-executor-2026-09-19.json` contains source/image and
asset hashes, enforcing policies, successful native receipts and prior failure
evidence. Native qualification proves an actual metadata socket request,
byte-exact URL receipt, no-network replay, joined timeout, pre-aborted rejection,
read-only worker enforcement, empty child-process lists, canonical target
retirement deleting the journal, and rejection of a retired replay. A separate
owned policy deliberately lacks bind permission: child failure rejects and all
its descendants are joined. Both profiles/containers were removed and absence
verified. Eleven focused tests pass.

Remaining gates: application-owned dedicated profile selection and lifecycle;
mounting the private API with its trusted composition; cross-owner capacity
admission; central durable receipt persistence and uncertainty recovery; actor
LangGraph tool registration with unchanged model decisions; exact evidence and
Judge rules; reset/replay races across the central store; actual-model and
rendered objective qualification. The API remains unmounted and cannot grant
credit. No AWS asset, installed application process or existing profile changed.

### Final private service and central persistence qualification

`tasks/mcp-owned-http-service-central-2026-09-19.json` records the rebuilt
packaged image, enforcing uniquely owned profiles, actual raw-URL socket request,
owner isolation, immutable replay/read-only receipt lookup, canonical retirement,
and joined process cleanup. The assembled native run additionally proves central
PostgreSQL publication and uncertainty after a real request followed by SQL
failure; retry does not repeat the request. Every owned container/profile was
removed. UDP/IPv6 route-denial attestations are included.

These are infrastructure proofs, not actual-model or objective-credit proofs.
Candidate identity0083 and MCP0005 remain outside the active migration chains.
Normal installer service provisioning, complete CLI+HTTP lifecycle composition,
and actual actor/Judge/canonical-credit qualification remain separate gates.
