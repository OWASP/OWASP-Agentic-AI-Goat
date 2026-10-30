# MCP qualified-subset live activation plan — 2026-09-14

## Qualified boundary

The mounted native run `owasp-ai-goat-mcp-owned-connected-fwnn8rp2` qualifies exactly
`mcp_cmd_injection` and `mcp_confused_deputy` through actual student/admin JWTs,
the shared MCP SDK, a strict owner/session/generation runner, real Mailpit,
actual `llama3.1:8b` actor and Judge, durable progress/history, replay,
revocation, reset, and sibling isolation. It does not qualify the other nine MCP
objectives. Production activation must keep those nine visible but return the
controlled `MCP_OBJECTIVE_RUNTIME_UNQUALIFIED` result before any global effect.

The current production hook in `server/index.js` is already default-off and
constructs the owned runtime only after database initialization. Enabling it is
unsafe until both draft migrations are registered and the persistent runner
uses the same strict profile that passed qualification. The existing local
compose `mcp-sandbox` uses `apparmor:unconfined`, exposes only the legacy runner
configuration, and does not supply the private owned-target token/profile. It
cannot satisfy owned readiness.

## Forward migrations and recovery

The draft one-use database promotion package is
`tests/postgres/run-mcp-owned-runtime-live-promotion.py`, frozen by
`docs/modernization/drafts/mcp-owned-runtime-live-promotion-source-hashes-2026-09-14.json`.
It promotes identity 0050 and MCP 0004 only after exact quiet backups restore
into an owned PostgreSQL 18 container and compare byte-derived inventories. It
then runs the identity/MCP normal loaders, verifies all 16 migration ledgers,
empty replay, runtime readiness, the unchanged private environment, and the
unchanged workshop catalog after backend recovery. Any uncertain failure after
source installation holds the watcher for repair and retains the private
backups. The package remains unlaunched pending a root-issued one-use grant.

Runner provisioning remains a separate stage through
`scripts/install/mcp-owned-provision.js`. Database promotion neither invokes
that provisioner nor sets `MCP_OWNED_RESOURCES_ENABLED=true`; activation waits
for separately reviewed runner readiness. This package covers the two already
qualified objectives only. The other nine MCP objectives remain open work.

Register byte-identical candidates only after a reviewed one-use promotion
package:

- identity `0050_mcp_conversation_history.sql`, SHA-256
  `fde6cc519c887b481668d02d44bacad7976bbc8b604cf2a65e3fd5ac7dbd0d1f`,
  after the live registered identity0049 prefix;
- MCP `0004_mcp_owned_resources.sql`, SHA-256
  `30b9980f2ad0e37be8134a9868c00190b2590f4ce8e0e11c1d2d4fbc3c86ae6d`,
  after live MCP0003.

The promotion run should use the established quiet-store protocol:

1. resolve and pause the exact watcher/backend, then prove no configured identity
   or MCP store sessions remain;
2. capture fresh mode-0600 custom-format backups and complete data, sequence,
   ACL/default-ACL, schema, and migration-ledger inventories for both stores;
3. restore both backups into owned PostgreSQL 18 databases and require exact
   semantic inventory equality before installing anything live;
4. copy only the two reviewed forward files, invoke each store's normal
   initializer, and assert the exact new checksum, least-privilege runtime grants,
   full preserved table snapshots, and empty replay;
5. run all configured-store ledger/readiness checks. Identity must preserve the
   full current prefix through0050; MCP must preserve0001–0004;
6. a failure before any live mutation may resume the unchanged service after
   cleanup. A failure after either migration or configuration mutation must keep
   the watcher paused, retain both backups and exact recovery inputs, and require
   the established operator recovery path; it must not blindly restore two stores
   or resume into partially upgraded bytes. Never restore a pre-promotion dump
   after resumed new writes;
7. after every live mutation and verification succeeds, resume the watcher and
   verify a healthy current child. Treat same-child continuity and healthy
   replacement as separate facts because queued watcher events can replace the
   child.

Snapshots must include existing MCP tool logs, canonical progress, judgments,
grade packets, requests/turns, sessions, catalog totals and admin/student
visibility. Migration success cannot silently reset or reseed learner state.

## Persistent strict local runner

Install the same application-owned runner boundary used by the native gate:

- Node 26.8.2 runner image;
- no added Linux capabilities, privileged mode, host network, host root bind, or
  unsandboxed grading fallback;
- stable enforcing `owasp-ai-goat-mcp-sandbox` AppArmor supervisor profile;
- bwrap owner target with private user/PID/network/mount namespaces, empty
  procfs, minimal target root, kernel-held flock, and mandatory trusted final
  seccomp filter;
- generated private `MCP_OWNED_TARGET_TOKEN` shared only by backend and runner;
- `MCP_OWNED_TARGETS_ENABLED=true` and exact stable profile name in the runner;
- backend `MCP_OWNED_TARGET_URL` pointing to that installed service and
  `MCP_OWNED_RESOURCES_ENABLED=true` only after the service is healthy.

The Linux installer should render, parser-check, atomically install, load, and
verify the stable profile before starting the container. It must retain the
policy if unload state is uncertain and report cleanup debt rather than delete
recovery inputs. The macOS installer must apply the same profile inside its
specific managed Colima VM and verify the exact daemon/architecture/profile;
it may not infer state from the default Colima profile. Windows and unsupported
Linux kernels must leave owned grading unavailable. AWS remains unchanged and
unqualified.

The source-only provisioning candidate is `scripts/install/mcp-owned-local.js`
plus `scripts/install/mcp-owned-provision.js` (`npm run setup:mcp-owned`). It
reads and validates the existing private signing configuration without changing
the repository `.env`, and stores the owned target token and runtime flags in
the workspace-scoped private `~/.owasp-ai-goat/<workspace-id>/mcp-owned.env` file,
rejects a conflicting stable policy, requires the installed policy to be an
exact root-owned mode-0600 regular file, verifies the exact enforcing label,
and only then starts the opt-in Compose runner and Mailpit. Its authenticated
runner readiness check is deliberately separate from database/application
readiness. It leaves both owned activation flags false unless the explicit
`--activate-qualified` transition follows successful MCP and CodeBot readiness;
the server loads that private managed file before constructing either runtime.
The
candidate has controlled command-adapter coverage only and has not installed a
host or guest policy.

The compose service must use `apparmor=owasp-ai-goat-mcp-sandbox` rather than
`apparmor:unconfined`, pass the private token/profile/enablement values, persist
only the intended private target root, and expose the health endpoint consumed
by `ownedTargetClient`. Mailpit stays the controlled SMTP/API sink. Backend
readiness must be live on every admission, not a startup boolean. A later runner
outage must allocate no target, run, mail, model call, or credit.

## Activation and verification

Activation is a coordinated configuration transition after migrations and
persistent sidecars pass readiness:

1. preserve an existing valid private `JWT_SECRET` byte-for-byte. Generate it
   only for a fresh installation where it is absent; an invalid existing value
   requires an explicit maintenance repair and is never silently rotated. Create
   a separate private `MCP_OWNED_TARGET_TOKEN` without printing either value;
2. start the strict runner and Mailpit, verify exact endpoint/isolation/profile
   receipts, then enable the backend owned-runtime flag;
3. start the backend through the normal launcher and require its installer to
   publish application, request, and conversation seams atomically;
4. verify `/infra` reports the exact validated owned endpoint and only the two
   qualified objectives; legacy SSRF/rogue/global runner health cannot make this
   response green;
5. run mounted student and instructor JWT controls: benign command, command
   injection, internal mail, confused deputy, history/replay, two sessions,
   revoke, reset, immutable judgments and sibling preservation;
6. verify `/workshop-dashboard`, `/workshop/challenges`, `/workshop/progress`,
   and both admin surfaces still derive the same 11-objective total and enabled
   completion count;
7. call all nine unqualified consequential tools and prove controlled
   unavailable with zero legacy global effects.

If a later target outage occurs after an audit run is admitted, that failed run
may remain for observability, but target, mail, model, consequential effect and
credit counts must remain zero. If readiness or a schema is partial, startup must fail before listening when the
feature is enabled. If the flag remains false, the current legacy teaching mode
continues and the owned migrations are inert. The activation evidence must name
this as a qualified two-objective subset, never as full MCP authenticity.
