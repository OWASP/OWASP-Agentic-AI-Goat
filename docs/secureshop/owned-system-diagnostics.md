# Owned System diagnostics

The bound OWASP AI SecureShop System page runs diagnostic commands in a disposable Linux namespace. It preserves the intentional `cmd_template + args` shell-injection exercise. OWASP AI SecureShop authenticates the current launch binding and shop administrator session before admitting the operation; in standalone mode, both come from the independent shop account and do not require a platform login. The command never runs in the application host's shell.

## Request and recovery

`POST /api/secureshop/admin/system/diagnostic` accepts exactly `operationId`, `cmd_template`, and `args`. The service creates a target UUID in PostgreSQL before dispatch. The private executor receives that UUID, gives the namespace a corresponding hostname, and returns a receipt binding the request digest, target and actual shell outcome.

The journal has these states:

| State | Meaning | Repeat behavior |
| --- | --- | --- |
| pending | Admission exists without a terminal receipt | Read status; do not dispatch again |
| completed | A validated receipt was committed | Return the stored receipt |
| unknown | Dispatch or publication could not be confirmed | Preserve uncertainty; do not dispatch again |
| not_executed | The admitted operation failed before remote dispatch | Return its terminal state |

A browser persists only the opaque operation ID, administration scope hash and recovery state before dispatch. Commands, output and credentials are not stored in this recovery reference. Reload recovery uses `GET /api/secureshop/admin/system/diagnostic-operations/:operationId`. Another administrator login session cannot recover the original session's operation. Forgetting a browser reference does not erase database evidence or authorize replay.

## Isolation and lifecycle

The executor drops capabilities, isolates process/network/hostname namespaces, exposes no host mounts, uses a read-only synthetic `/app`, and gives each invocation temporary writable `/work` and `/tmp`. A private supervisor channel reports the shell status only after descendant processes have drained. Shell stdout cannot create an execution receipt. Output and execution time are bounded.

Canonical agents migration `0030_bound_system_diagnostics.sql` stores immutable admissions and outcomes. Retirement clears payloads and the target ID while preserving evidence digests; owner deletion removes that owner's records without changing sibling state. Manual diagnostics are ungraded: their receipts do not create a model run or award an exercise objective.

## Configuration and verification status

The optional application capability uses `SS_BOUND_SYSTEM_DIAGNOSTIC_ENABLED`, `SS_SYSTEM_DIAGNOSTIC_BASE_URL`, and `SS_SYSTEM_DIAGNOSTIC_TOKEN`. The example configuration leaves it disabled. Enabling requires PostgreSQL, bound OWASP AI SecureShop reviews, the canonical migration, and an authenticated owned listener. Setup packaging and installed activation are still under qualification; the application rejects unavailable requested capabilities at startup.

Native evidence separately covers executor isolation, private HTTP, canonical PostgreSQL lifecycle, and their assembled route/service path. Full-index/browser acceptance is tracked in `docs/modernization/current-work-queue.md`. ARM64 qualification does not establish native AMD64 installation support or AWS deployment compatibility. Existing AWS deployment assets remain unchanged.
