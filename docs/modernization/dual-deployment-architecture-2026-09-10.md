# DVAIA: laptop and 200-student AWS architecture

> Superseded database recommendation: the active decision is [PostgreSQL as the sole target engine](postgresql-single-engine-plan-2026-09-10.md). SQLite-first and SQLite/PostgreSQL dual-runtime recommendations below are historical, not implementation instructions. AWS deployment changes remain deferred.

Status: DEFERRED ARCHITECTURE REFERENCE. The user has frozen all CloudFormation and AWS deployment work and requested application-only modernization. No cloud/database-service/worker-topology change below is an active ticket or an acceptance requirement for this phase. The [implementation plan](implementation-plan-2026-09-10.md) is authoritative for current scope. This document preserves a possible later hosted design, not authorization to implement it. Nothing here is implemented or load-qualified.

Application work that remains active: identical UI/curriculum, agent graph migration, SQLite-backed state, bounded in-process execution, ownership/reset/retry correctness, and controlled 200-user application tests. PostgreSQL, hosted worker pools, cloud snapshots, queue services, AWS runtime/packaging changes and fleet rollout are deferred. Current AWS deployment capacity remains unverified by those application tests.

## Decision

Use a modular Node/TypeScript application with two deployment profiles. Keep SQLite for lightweight local operation; use RDS PostgreSQL for shared AWS authentication, sessions, curriculum, canonical progress, run registry and LangGraph checkpoints. Keep challenge engines isolated from trusted storage. This introduces two implementations of a small trusted persistence boundary, not two versions of every workshop.

Do not require Redis, Kubernetes, a dedicated vector database, or a separate process per logical agent by default. Add infrastructure only for a demonstrated responsibility or measured bottleneck. Maintain an optional local Docker Compose profile with PostgreSQL to reproduce hosted behavior; ordinary local users can use SQLite.

| Concern | Local | AWS workshop |
|---|---|---|
| Frontend | Same React SPA | Same built SPA behind HTTPS/load balancer |
| API | One Node process | Stateless ECS API replicas behind ALB; starting qualification topology: two replicas |
| Platform repositories | Local SQLite | Private RDS PostgreSQL, bounded connection pools |
| LangGraph | Same graphs in local runtime | Same graphs in independently scalable trusted worker pool |
| Checkpoints | Separate SQLite saver | PostgreSQL saver with restricted ownership and retention |
| Run scheduling | Bounded local executor | Durable PostgreSQL run/job table with claim lease, fencing and retries |
| Challenge execution | Local scenario files; container sandbox for dangerous tools | Isolated per-attendee/per-run scenario sandboxes on a managed worker pool |
| Challenge databases | Existing per-lab SQLite; optional engine-specific containers | Same engines/dialects inside scenario boundaries; never trusted RDS tables |
| Artifacts/backups | Local filesystem/export | Private S3 with scoped access and lifecycle policy |
| Models | Ollama or configured provider | Bedrock/configured providers with event-wide and per-attendee quotas |
| Benchmark state | Fresh independent run directories | Same run contract with isolated worker state and versioned artifacts |

PostgreSQL provides a shared server database suitable for multiple application hosts; SQLite remains effective for device-local storage. The distinction is shared write topology, not an assumption that 200 users inherently overload SQLite. [SQLite architecture guidance](https://www.sqlite.org/whentouse.html), [RDS PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html).

## Boundaries that prevent an expensive rewrite

Define narrow repositories for identity/session validity, curriculum/progress, run ownership, and job/artifact metadata. Use explicit SQL migrations per engine and the same behavioral test suite against both. Normalize timestamps, IDs, booleans, uniqueness, JSON serialization and transaction boundaries. Do not assume one ORM makes SQLite and PostgreSQL identical.

Keep parameterized SQL in trusted repositories. Leave intentional SQL concatenation, raw prompt context, vulnerable parsers, fake credentials and tool ACL teaching modes inside challenge modules. SQLite-to-PostgreSQL portability is not required for a SQLite injection lesson. A MongoDB-specific benchmark needs the actual MongoDB engine/version as an optional isolated target.

Existing routes become adapters over the shared services. UI JSON responses, polling contracts and SecureShop SSE event names remain unchanged. Existing logical agents are graph nodes/subgraphs/tool adapters; 17 agents do not imply 17 paid containers per student.

## Isolation and state placement

Trusted API, model gateway and graph worker processes can access platform/checkpoint storage. An RCE-capable lab sandbox cannot. Give the sandbox only its scenario mount, scoped invocation identity and required simulated target network. Do not expose host Docker sockets, real cloud credentials, platform database credentials, or another attendee's directory. Serve intentionally vulnerable frontend content under the established lesson contract while enforcing the outer ownership boundary.

Use attendee isolation by default. A team-shared scenario is an explicit workshop mode: it changes ownership and experiment semantics and must not be silently used as a capacity shortcut. Read-only model/seed assets can be shared; mutable SQLite databases, inboxes, files, vector poisoning and checkpoints cannot be shared across independent runs.

Never put shared writable SQLite WAL files on EFS and let API/worker replicas open them. Current repository deployment uses stop-before-start as mitigation; it is not the target shared-state architecture. [SQLite WAL restrictions](https://www.sqlite.org/wal.html).

For lab state, provision one owning worker per active workspace lease and run SQLite on storage local to that worker. A lab worker may host multiple separately constrained scenarios. Start qualification with ECS on EC2/block storage for this stateful pool; stateless APIs and trusted graph workers can use Fargate. Fargate ephemeral scenario runners are also possible only with an implemented snapshot/restore contract; task-local storage is not durable just because PostgreSQL stores graph checkpoints. [Fargate storage](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/fargate-task-storage.html).

A supervisor outside the vulnerable sandbox freezes a completed mutating turn, takes consistent DB/filesystem snapshots and publishes a versioned artifact manifest. Persist the snapshot pointer, operation ID and generation in the trusted run registry. Acknowledge a durably saved turn only after that boundary succeeds. Do not copy live SQLite main files without their committed state or claim that graph replay can reconstruct arbitrary shell/filesystem side effects.

On worker loss, fence the old lease, restore the latest committed scenario snapshot on a new worker, and resume the matching graph version. An action executed after the last committed snapshot may have an uncertain external result; reconcile using operation IDs or fail the run explicitly, never silently replay an email/refund. Validate snapshot cost and failure recovery before choosing exact worker/storage sizing. Host-volume persistence alone does not solve rescheduling across hosts.

## Efficient execution for 200 students

Treat 200 as the number of attendees and explicitly measure simultaneous runs. Use one active mutating run per conversation, a bounded per-user backlog, event-wide model concurrency/rate limits, and fair scheduling across attendees. Durable jobs survive API restarts; a retry lease does not provide exactly-once tool actions by itself.

A PostgreSQL job table is the initial hosted scheduler so another stateful dependency is unnecessary. Implement atomic claim, lease expiry/heartbeat, attempts, cancellation and result status; use appropriate locking/skip-locked semantics and a durable read fallback for wakeups. Bound database polling. Adopt SQS or another queue later if independently scaling workloads/observed throughput justify it. [PostgreSQL locking](https://www.postgresql.org/docs/current/explicit-locking.html).

Keep synchronous web handlers out of long-running model execution. The existing client request/SSE can wait on or follow a durable run through an API adapter; graph workers publish ordered run events. Persist useful stage/tool events and final responses, not every token as an individual DB transaction. Reconnect uses server-owned run/event cursors and does not create a second run.

Avoid one unbounded connection pool per graph or agent. Set a fleet-wide PostgreSQL connection budget and divide it among API/worker/saver pools. No transaction spans an LLM call. Cache read-only curriculum/config with scoped invalidation; use existing revision polling and avoid per-student full-table progress scans.

An illustrative workload, not a capacity claim:

- 200 students, one turn per minute: approximately 3.3 new turns/second.
- Mean turn duration of 20 seconds: approximately 67 concurrent turns at steady state.
- Two provider calls per turn: approximately 400 model requests/minute.
- If each call consumes 1,500 input and 500 output tokens: approximately 600,000 input and 200,000 output tokens/minute.

Actual provider quota accounting can differ; validate the selected model/region's request and token limits before the workshop. Synchronized classroom bursts can place all 200 requests at once. Queue capacity, deadline behavior and pre-provisioned model quota must handle that explicitly. [Bedrock quotas](https://docs.aws.amazon.com/bedrock/latest/userguide/quotas.html).

Optimize deterministic intent/tool paths first. Avoid model calls for operations whose current logic already produces the answer. Share read-only embedding assets, keep warm reusable workers and pre-create active scenarios before class. Preserve raw tool payloads where truncation would remove a lesson. Stop or scale down event infrastructure outside scheduled use; do not choose instance sizes or promise a monthly bill without measurement.

## Release qualification

1. Test SQLite and PostgreSQL repository implementations against identical identity/progress/reset fixtures. Include migration from existing SQLite data, source counts, ownership mapping, and rollback checkpoints.
2. Test local clean setup on macOS/Linux/Windows and a hosted-parity Compose environment. Default local learning should not require AWS credentials or managed services.
3. Load test 200 active users with the real route mix: login burst, revision polling, progress reads, tool chats, SSE and resets. Test a separate 200-simultaneous-turn burst and an overload run. Mocks isolate application capacity; a bounded real-provider run qualifies quota/latency separately.
4. Inject API/graph/lab-worker restarts, expired sessions, PostgreSQL interruption, model throttling, duplicate delivery and reset-during-tool-call. Prove no cross-attendee access, duplicate confirmed mutations, stale post-reset writes or false success.
5. Measure API latency separately from queue delay, provider duration, sandbox work and snapshot overhead. Choose concurrency/worker/database sizes from those measurements. A starting gate is p95 under 500 ms for ordinary metadata APIs under the specified load, with zero unexpected 5xx/data-loss cases; chat SLA must include the measured provider budget.
6. Verify identical curriculum, tool schemas, database dialects, scoring and visible UI between profiles. Benchmark records identify deployment/hardware/concurrency so comparisons remain interpretable.
7. Rehearse backup/restore and one-team canary before the full event. Hosted API replicas may roll independently; stateful scenarios must follow lease/drain/snapshot rules. No unqualified zero-downtime claim for vulnerable lab state.

## Deferred delivery order — outside the current application phase

First repair identified identity/reset/provider bugs and isolate dangerous execution. Then extract narrow trusted repositories, keeping SQLite green. Add PostgreSQL plus migrations and Compose parity tests. Move hosted sessions/progress/checkpoints/run metadata to PostgreSQL. Add durable scheduling and ownership-aware scenario worker/snapshot recovery. Finally qualify the 200-student workload and tune capacity. Keep the latest dependency and LangGraph migration waves small throughout.

The existing 49–83 person-day estimate excluded substantive production data-platform redesign. This dual-profile scope adds PostgreSQL migration, repository parity, durable scheduling, sandbox lifecycle and hosted load qualification; re-estimate those after a pilot rather than claiming they fit the earlier range unchanged.
