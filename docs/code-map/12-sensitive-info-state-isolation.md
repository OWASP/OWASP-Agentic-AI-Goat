# Sensitive Information State Isolation

## Scope

This document covers the mutable simulator state used by the Sensitive Information
Workshop. It does not change Secure Shop, database schemas, objective progress, or
workshop mode storage.

## Ownership boundary

Authenticated platform user ID is the isolation key. The route passes
`req.user.id` to `SensitiveInfoWorkshopAgent`, which obtains one lazily created
state object for that user. Every tool invocation in that request, including the
direct vulnerable-mode intercepts, receives the same object explicitly.

The user-owned state contains:

- the simulated customer database and deletion flag;
- simulated backup names and contents; and
- mutable log contents used by `admin_read_logs` and `admin_modify_logs`.

Tool definitions, prompts, the initial customer records, and the initial log
snapshot remain immutable process-wide inputs. Config and path-traversal fixtures
also remain shared read-only exercise inputs. An admin log mutation changes only
the selected user's in-memory log overlay; it never writes the shared files under
`server/sensitive_files/logs`.

Fixed and vulnerable mode deliberately select the same user state. Fixed mode
continues to block admin tools and sanitize ordinary tool output, while vulnerable
mode retains the existing backup disclosure, database deletion, log tampering,
path traversal, SSRF, and verbose-error exercise behavior.

## Reset lifecycle

- Student **Reset Progress**, whether invoked inside the lab or from the Workshop
  dashboard, deletes only that authenticated user's FinFlow progress, tool log,
  auxiliary tracking rows, central progress, and simulator state. The dashboard
  path delegates to the same authoritative reset service used by targeted admin
  resets instead of deleting only the central projection. The next request lazily
  receives a clean state.
- An admin targeted Sensitive Information reset deletes only the selected user's
  state after the database transaction commits.
- An admin workshop-wide or all-workshops reset clears every Sensitive Information
  simulator state after the database transaction commits.
- A process restart clears all simulator states because this lab data is
  intentionally in memory.

The state store owns a keyed asynchronous queue for each platform user. A chat
claims that user's queue position before its persisted mode lookup and holds it
across agent execution, objective persistence, central progress synchronization,
tool-log persistence, and response assembly.
A student reset holds the same position across durable deletion, objective
reseed, and simulator invalidation. Therefore a reset requested behind an older
chat cannot return until that chat is fully ordered, and once reset returns the
older work cannot restore progress or tool logs. This replaces the narrower
single generation check, which left an asynchronous persistence window after
validation.

Targeted admin reset uses the production simulator adapter's same per-user queue
around its database transaction and simulator invalidation. Operations for
different users use different queue keys and remain concurrent; there is no
process-wide lock for targeted resets. Workshop-wide simulator reset drains the
known per-user queue entries before removing their state.

Workshop-wide and all-workshops admin resets do not provide the same durable
request-ordering guarantee as student and targeted-admin resets. Their database
transaction commits before the simulator drains the known per-user queues, so
an already-running chat may persist durable progress after the bulk deletion.
This boundary is explicit in the minimal repair; adding a process-wide lock or
distributed reset barrier is outside this slice.

Post-commit simulator reset failures are surfaced as explicit partial reset
errors by the admin reset service. The adapter is preflighted before database work
so a missing reset owner cannot silently leave stale simulator state.

## Test seams

`createSensitiveInfoWorkshopStateStore()` creates an isolated store and keyed
operation queue for tests.
`executeVaultCorpTool()` requires an explicit state object, preventing a test or
future call site from accidentally falling back to shared mutable state. The
production agent accepts an optional state store and otherwise uses the singleton
process store. Admin reset coverage also exercises the reset service without an
injected simulator adapter, proving that its default adapter clears this same
singleton.

Focused verification:

```bash
node --test tests/sensitiveInfoResetRace.test.js tests/sensitiveInfoStateIsolation.test.js tests/adminWorkshopResetService.test.js
EXPORT_INTERNALS=1 SKIP_LLM=1 node tests/sensitiveInfoWorkshop.test.js
EXPORT_INTERNALS=1 SKIP_LLM=1 node tests/adminExploitation.test.js
EXPORT_INTERNALS=1 SKIP_LLM=1 node tests/ssrfWorkshop.test.js
node tests/path_traversal_real.test.js
```

The cross-workshop dashboard contract and its browser-local exception are
documented in [17-student-dashboard-reset-ownership.md](17-student-dashboard-reset-ownership.md).

## Lifecycle limits

The store is process-local and deliberately has no TTL or persistence. User and
backup entries remain resident until reset or process restart, so a long-lived
high-cardinality deployment can grow memory. Adding eviction in this atomic
repair would change active lab semantics and is deferred. Multiple server
processes also keep independent simulator copies; distributed continuity would
require a separate durable-state design.

The queue is process-local rather than a database generation or distributed
lock. It orders chat and reset work served by the same Node process; multiple
server processes retain the independent-state limitation described above.
Cross-user state remains isolated, and this change does not alter workshop mode
storage.
