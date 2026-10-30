# Owned Listings executor candidate

Not installed, mounted, advertised as ready, or qualified as an isolated runtime.

Implemented components:

- `operation-executor.js` wraps the actual import executor with immutable admissions and receipt files. Each file is written to a private temporary file, synced, linked without replacement, then the directory is synced. Same-ID/same-input replay reads the original receipt; changed input conflicts. An admission with no receipt remains unknown and is never automatically fetched again. Results include the trusted bootstrap identity and a digest, **not a cryptographic or OS attestation**. A trusted adapter must independently verify launcher identity before accepting results.
- `teaching-http.js` serves copied synthetic supplier and internal documents over real separate loopback HTTP listeners. Missing resources and unsupported methods fail. Vulnerable reader policy permits both origins; fixed reader policy permits only supplier. These are application-policy controls, **not proof of network isolation**.
- Existing import components perform real JSON worker parsing, synthetic resource reads and XML entity expansion; the JSON process does not inherit environment credentials.

Mandatory packaging requirements before use:

1. A launch gets its own Linux network/mount namespace, with no host, sibling or external routes. Supplier/internal listeners run inside that namespace. Never run this as a host Express fallback.
2. Mount a generated synthetic file tree read-only. Expose no host private paths, Docker socket, platform environment or database credentials to parsing workers.
3. Exactly one journal executor owns the namespace and a private mode-0700 durable directory. The in-process busy check is not a multi-process lease. The launcher must enforce single ownership before readiness.
4. A verified runtime manifest, namespace identity and authenticated outer listener are required. Current identity fields are provenance assertions only; never treat them as attestation on their own.
5. Add real package/native verification, listener operation GET/POST contracts, restart/retirement cleanup, per-launch file teardown and receipt acknowledgement. Completed/failed receipt replay is supported, but crash recovery deliberately leaves unfinished operations unknown.
6. Publication and grading remain backend responsibilities under canonical owner/session/reset checks. A completed executor receipt does not imply publication, genuine model use or objective credit.

Source qualification: `node --test tests/secureshopListingOperationExecutor.test.js tests/secureshopListingTeachingHttp.test.js` exercises actual JSON children and loopback HTTP with owned temporary journals. No Docker, namespace, database, browser or model qualification is claimed.

## Native packaging checkpoint

The subsequent candidate adds `namespace-executor.js`, `namespace-worker.js`,
`Dockerfile.candidate`, immutable asset generation and an authenticated
`http-listener.js`. The namespace initializer is compiled from the existing
owned HTTP initializer, which checks loopback-only interfaces/no default route,
probes IPv4/IPv6 egress denial, drops capabilities and verifies seccomp denial
before executing the worker. A separate subreaper terminates owned descendants.
The synthetic file is explicitly bound read-only into the namespace. Workers
receive neither the outer journal directory nor the listener token.

Native gate `tests/run-owned-listings-executor-native-isolated.py` passed on the
explicit reviewed ARM64 Docker daemon: real JSON, internal HTTP access/fixed
denial, actual file and HTTP XML entity reads/fixed denial, denied host/external
requests, timeout child teardown, and replay across two sequential containers
sharing a dedicated volume without re-dispatch. Both container runs had the
same verified asset digest. Exact container, volume, image, profile, temporary
remote directory and process-group cleanup passed. Evidence directory:
`/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-owned-listings-executor-b1359412`.

Remaining gates include explicit read-only write-denial probes, native outer
HTTP authentication/readback, concurrent launcher ownership/retirement,
installer integration and actual graph/publication/Judge/browser qualification.
The earlier list describes required deployment properties; native candidate
qualification does not activate this capability in the application. Receipt
hashes are integrity checks, not signatures. The trusted authenticated backend
must verify launcher/runtime identity; a learner-supplied attestation flag is
never accepted. The namespace transport flag is verified and removed before
returning the import effect to the receipt adapter.

## Shared manager candidate (source controls only)

`manager-entry.js` now composes one shared listener, persistent target
registrations, an LRU of at most 32 in-process handlers, four concurrent
namespace executions and 16 queued executions. Each target has a private token,
identity and mode-bound journal. Registering a target creates no container or
listening port; every tool call still uses the ephemeral isolated namespace.
Persisted active targets are limited to 200, total retained registrations to
400. Tombstone acknowledgement/compaction and multi-target/native capacity
qualification remain pending; this is not yet an installer-ready capacity claim.

Control authentication is separate from target authentication. Manager routes:
`GET /manager/health`, `POST /targets`, `POST /targets/inspect`, and
`POST /targets/retire`. Register/inspect bodies are exactly
`{scope,targetId,mode}`. Retirement additionally requires `operationId` and
`canonicalReceiptSha256`. The private backend adapter
`server/services/secureshopListingsTargetManager.js` derives that digest from
`products.readCleanupReceipt`, which verifies canonical lifecycle authority,
retired scope and cleared mutable product state. It cannot accept a caller's
replacement digest. It verifies canonical product reservation, owner/generation
and configured mode before registration and verifies target health afterward.

Target tokens route the existing operation API on the same shared origin.
Retirement first persists `retiring`, then blocks new target requests, drains
accepted work and retires journal entries to hash-only tombstones. On restart,
retiring targets remain unavailable; repeating the same control retirement
continues cleanup rather than reactivating them. Retired registrations omit the
raw token. Other targets retain their own registrations and receipts.

Installation/startup integration still required:

1. Reuse the application's managed runner installer authority checks to build
   this candidate once, register its exact immutable asset/profile digest and
   provision one private persistent volume and one control token.
2. Start the shared manager with `LISTINGS_MANAGER_ENABLED`, `LISTINGS_PROFILE`,
   `LISTINGS_PUBLIC_ORIGIN` and `LISTINGS_CONTROL_TOKEN`; expose its private port
   only to the backend. No per-student Docker provisioning.
3. Create the backend adapter with canonical launch/product repositories and
   trusted `resolveMode`; mount Listings application only after genuine manager
   health and package digest checks. Keep capability unavailable otherwise.
4. Connect canonical cleanup retry/readback to target retirement. Complete
   tombstone acknowledgement, shutdown/cancellation, multi-target queue and
   restart native tests before enabling the supported install/start path.

Existing native evidence predates this shared manager. Shared routing,
registrations and backend fencing currently have controlled tests only.

The source manager now also supports control `POST /targets/forget` with the
same binding and canonical cleanup identifiers. The backend's
`acknowledgeRetirement` re-reads verified canonical cleanup before requesting
this compaction. Exact retired receipt matching is required. The runner renames
only the acknowledged target into an owned forgotten directory, syncs that
rename, deletes hash-only local tombstones and releases its registration slot.
Startup resumes deletion of those forgotten directories. Original immutable
platform cleanup evidence remains the authority; lifetime target IDs need not
accumulate in the runner. This supersedes the earlier acknowledgement-pending
note, but does not establish native capacity or installer readiness.
