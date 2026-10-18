# Protected recovery source activation boundary

Status: source activation implemented and qualified. Identity0097 is registered;
the owner-only metadata endpoint is wired and readiness-gated. Installed images,
services and databases remain unchanged. Exact Linux image qualification is still
required before enabling the installer mode.

## Concrete source release delta

1. Allocate the next identity migration number with the parent orchestrator
   (current source head is 0096; 0097 is a proposal, not a reservation). Copy the
   exact qualified `drafts/mcp-protected-recovery/protected_reconciliation.candidate.sql`
   bytes, SHA256 `405fba32b5b8d3ec0eb87d048cf7bfd5954d199088356b4a0433cdc79540dc5e`.
   Existing identity initialization discovers ordered migrations automatically.
   Preserve prior ledgers and runtime SELECT/definer-only ACLs; no backfill.
2. In `ownedResourceProduction.js`, allocate two managed, budgeted dedicated
   pools only when protected recovery is selected: identity recovery lease and
   MCP resource lease, each max2 and bounded connection wait. Add an explicit
   `protected` pool purpose to `poolBudget.js` rather than increasing the global
   request pool or silently exceeding its total budget. Close these pools through
   the existing application lifecycle. They are not held during actor/Judge calls.
3. Compose `protectedOperationAdmission` using the existing identity runtime
   pool plus dedicated resource lease pool. Compose `protectedReconciliationService`
   with both dedicated pools, the real JWT/session validator and the CLI target
   client. The latter must remain accessible through optional HTTP/shadow target
   wrappers; those wrappers must forward only the trusted readback method.
4. Readiness must require both receipt tables, exact admission/append EXECUTE
   grants, no direct write grants, denied internal helper execution, strict
   runner profile/isolation, `mcp-owned-protected-operation-journal.v1` and
   `mcp-owned-protected-readback.v1`. A readiness failure clears cached client
   capability state. A missing/older image reports recovery unavailable; it
   cannot silently fall back to execute or invent a recovered receipt.
5. Add an owner-authenticated explicit metadata POST under the existing MCP
   router accepting **only** `operationId`. Apply the existing session/event/rate
   admission checks. Never accept owner/session/target/run/generation/arguments,
   origin, effect key or receipt from its body. Return original effect uncertain,
   recovered outcome/digest/time and `creditGranted:false`; never raw target
   configuration or a fabricated successful run. The admin observer requires a
   separate read-only authorization design and must not impersonate a session.
6. The supported local installer should select this mode automatically only
   when its immutable runner image includes the journal and recovery API and
   the exact required profile qualifies. Package manifest/image hashes and
   readiness gate the private configuration. Existing installations retain their
   old setting until checked additive migration and image activation; source
   default does not mutate an already running installation. No AWS asset edits.

## Verification before release

Retained admission/recovery native cohorts use actual PostgreSQL18 stores,
JWT validation, LangGraph/SDK, private HTTP sockets, durable filesystem operations
and canonical reset. A fresh child Node process receives only the current
session token and operation ID, reconstructs services, reads the exact intent
and recovers the existing target capability without provisioning. Exact repeats
append no duplicate reconciliation, conflicts fail, original uncertain effects
remain unchanged, foreign/revoked/reset callers cannot obtain results, and
canonical retirement removes journals while preserving siblings.

Before exposing the route, add mounted authenticated owner/session/CSRF policy
checks and rendered run-detail metadata, installer fresh/repeat/failure recovery,
and a fresh/populated/no-op source-chain proof using the allocated filename.
The current unnumbered migration already has those storage-path proofs; copying
it into the active chain still requires exact ledger verification at that point.

The native fixture runs on macOS with a Linux PostgreSQL container and controlled
AppArmor/bwrap readiness. It does not qualify the newly packaged runner image on
Linux ARM64/AMD64. Preserve that platform gap separately and qualify the exact
new image/profile in an owned Linux environment before installation. No model
rerun is needed for this receipt/readback protocol. Digest-only model provenance
is insufficient for recovered objective credit; adding Judge recovery is a
separate design and must not rewrite the original run or infer a lost witness.

## Pool accounting gate

The retained mixed200 artifact records a modeled fully warmed backend reservation
of72, ceiling78, observed backend peak58 and separate agent-host reservation4.
Two managed protected pools at2 each model76 backend reservations under the
unchanged78 ceiling; these are modeled maxima, not observed new workload results.
Source activation must update the allocation test and check actual startup
`getPoolBudgetSnapshot()` with all intended lazy pools activated. Allocate through
`createPool(...,{purpose:'protected'})` so global reservations and shutdown own
both pools; never construct unregistered `pg.Pool` objects in production. Both
pool registrations must be transactional at the installer/composition boundary:
on partial setup/readiness failure, close newly created pools and leave the
existing application intact. The native harness directly constructs disposable
pools intentionally; that is not a supported startup allocation pattern.

## Qualified source release

Identity `0097_mcp_protected_reconciliation.sql` is now registered with the exact
candidate SHA above. The current source-chain test excludes0097 to establish a
populated predecessor, applies0097 preserving every earlier ledger row, repeats
without changes, and independently migrates a fresh database. Native workspace
`vsna0o_2` passed those checks.

`protectedRecoveryProduction.js` owns the two pools through registered
`purpose:'protected'` allocations. It uses the canonical
`MCP_WORKSHOP_DATABASE_URL` resource URL, closes both on partial creation,
readiness or publication failure, and exposes lifecycle close. Global pool
shutdown also owns the registered pools. Runtime selection is the strict boolean
`MCP_PROTECTED_RECOVERY_ENABLED`; the default is false for an older image.

`POST /api/workshop/mcp/protected-operations/reconcile` accepts only operationId
under the existing workshop bearer authentication, runtime and rate-limit
middleware. It returns metadata only and no recovered objective credit.
The mounted production handler/nativeJWT cohort uses freshly forked Node callers,
actual production pool factory, real two-store locks, sidecar socket and journals.
Workspace `x3a3ugyt` passed invalid JWT, extra owner field, foreign owner,
same-owner different current session, conflicting receipt, revoked/reset scope,
exact repeat, immutable uncertainty and cleanup checks. The fixture mounts the
production handler and canonical platform-authority wrapper; it does not boot
the entire application or render run-detail UI. Those limits are retained.

The existing local provisioner supports `activateProtectedRecovery` together
with `protectedRecoveryRelease:{image,profileSha256}`. It compares the exact
rendered/enforced profile and inspected Docker image before writing its private
managed flag. Fresh/repeat and mismatched image paths pass controlled installer
tests. No release image digest is silently guessed or enabled by ordinary setup.
A later owned Linux image/profile qualification provides that release manifest;
there was no real installer/service/profile mutation in this source release.

Provenance correction: controlled/mock/unknown or missing provider/model
identities persist as `controlled` with no decision digest. Manual Inspector is
`manual`. Only a privately admitted decision with a recognized real provider and
non-fixture model identity may persist `model`; no digest-only record grants
credit. The current native graph uses `controlled-native/fixture-no-llm` and is
persisted honestly as controlled. Earlier model-contract fixture descriptions
are historical evidence, not actual model qualification.

## Owner discovery and rendered readback

The run-detail repository now projects only protected operation IDs, operation
names, immutable origin, original effect status and reconciliation digests/times.
The existing inspector offers readback only for the original active owner/session
and current generation when recovery is enabled. The administrator analytics
view reads the same metadata without a recovery control. The POST remains
independently authenticated and rejects administrators acting as observers,
foreign owners and replacement sessions. No original effect/run status or
objective credit is rewritten.

`tasks/mcp-protected-recovery-rendered-2026-09-19.json` records the passing
`7hv8it98` source-copy cohort: real PostgreSQL, canonical JWT sessions, actual
React App, controlled actor and Linux-readiness fixture, actual owned file
rotation/socket/lost acknowledgement, owner readback and three denied actors.
Both screenshots were visually inspected. This uses real JWT validation with
session tokens injected into isolated browser contexts; it does not claim an
interactive login-form qualification, a real model call or Linux image proof.
The disposable container and browser process were removed. Focused Inspector
30 tests and run HTTP/receipt 24 tests also passed.

## Actual Linux sidecar qualification (2026-09-20)

`tasks/mcp-protected-linux-native-r3-2026-09-20.json` records the passing
`ryqmsuru` frozen cohort. It built and used exact image
`sha256:f2eb9ec529ec228e834dab3709a8bd70648fbb83a7b94669e273bcb6c306f74a`
under a unique enforcing parent/bwrap AppArmor profile in the ARM64 verification
VM. The actual owned service performed six synthetic rotations through the SDK
and controlled decision graph. Lost acknowledgement left central uncertainty;
container recreation with the same image and volume preserved exact fresh-process
readback and append-only reconciliation. Original run/effect status and objective
credit were not rewritten.

The cohort passed replacement-session/foreign/conflicting-receipt denial,
reset/revocation fences, bounded timeout/drained lease, sibling preservation and
an explicitly injected pending-journal negative. That negative retained the
completed file under a qualification-only name: it proves conservative behavior
with pending-only authoritative state, not a naturally occurring disk failure.
The old-capability negative strips capabilities from the current service's health
reply; it proves factory rejection before HTTP mounting, not an actual historical
image run. The one expected readiness socket interruption occurred only during
container recreation; post-ready and effect/readback failures remain fatal.

All owned containers, named volume, image tag, processes/process group, exact
parent/child profiles and remote policy directory were removed with no cleanup
debt. Earlier failed cohorts remain retained (preflight, R1, R2); R2 is inconclusive,
not an application failure. This adds real Linux ARM64 service qualification to
the previous browser/JWT scope. It does not claim Linux AMD64, real model execution,
200 concurrent recovery capacity, or installed activation. The qualified image
was deliberately removed; future installer release requires its exact immutable
image availability and matching profile readiness, not a new mutable rebuild.
