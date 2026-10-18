# Database decision: SQLite by default for laptop learning and benchmarking

> Superseded database recommendation: the active decision is [PostgreSQL as the sole target engine](postgresql-single-engine-plan-2026-09-10.md). SQLite-first and SQLite/PostgreSQL dual-runtime recommendations below are historical, not implementation instructions. AWS deployment changes remain deferred.

Status: recommended design, based on the user's clarification that DVAIA primarily runs on learners' laptops. No database migration or runtime change has been made.

Current scope: the application must serve local users and improve behavior for workshop workloads, but the user has frozen CloudFormation and all AWS deployment changes. Retain SQLite for the active application phase. The [dual-deployment architecture](dual-deployment-architecture-2026-09-10.md) is a deferred reference only; no PostgreSQL service, hosted migration or new infrastructure is introduced now. The [implementation plan](implementation-plan-2026-09-10.md) controls current scope. Controlled 200-user application tests do not certify the existing AWS deployment.

## Decision

Keep SQLite as the default database engine. Improve ownership, migrations, reset/replay and benchmark isolation rather than replacing SQLite with a mandatory server database. SQLite's embedded design and local files fit this distribution model. PostgreSQL is an optional future hosted/high-write-concurrency profile, not an open-source installation prerequisite. [SQLite's intended uses](https://www.sqlite.org/whentouse.html).

LangChain/LangGraph adoption does not require PostgreSQL. A persistent SQLite checkpointer is appropriate to qualify for this single-host product, with a separate checkpoint database and tested concurrency/restart behavior. Memory-only checkpoints remain useful for ephemeral tests, not sessions that must survive restart. [LangGraph persistence](https://docs.langchain.com/oss/javascript/langgraph/persistence).

## Logical storage layout

Use this as a target ownership model, not an instruction to rename or consolidate existing databases immediately:

```text
data/
  platform/                  # authentication, curriculum, progress, migrations
  workspaces/<workspace-id>/
    challenges/<lab>.db      # preserve existing per-lab databases and semantics
    checkpoints.db          # graph runtime state; no provider credentials
    vectors/                # rebuildable local indexes and corpus metadata
  benchmarks/<run-id>/
    manifest.json           # reproducibility configuration
    challenges/<lab>.db      # pristine fixture-derived state for this run
    checkpoints.db          # independent execution recovery
    results.db              # attempts, verdicts, timings, costs, evidence pointers
    artifacts/              # optional tool transcripts and outputs
```

Preserve existing multiple databases when they already isolate lessons. Do not put every challenge and platform table into one database for cosmetic simplicity. Do not add a database per conversation unless measurement requires it: graph checkpoints can namespace conversations within a workspace/run database.

Separate files provide organizational/reset isolation, not a security sandbox. A process with arbitrary filesystem access can read other files. Shell, traversal, upload and MCP exploit tools should run inside a constrained process/container with only their scenario files mounted. Platform databases, host home directories and real credentials must remain outside that boundary. Preserve intentionally vulnerable behavior within the scenario.

## Benchmark correctness

1. Generate versioned pristine fixtures from schema and deterministic seeds. Start every independent run from fresh state; avoid carrying attacks, poisoned documents, progress or conversations into the next run.
2. Give each parallel benchmark worker its own run directory, challenge databases, graph checkpoints and mutable sidecar state. Separate DBs alone do not isolate shared inboxes, sandboxes or global caches.
3. Record app commit, schema/fixture hashes, provider/model version, effective parameters, graph/prompt versions, tool manifest, mode, corpus/embedding/index settings, seed where supported, concurrency, runtime and hardware. A seed does not make a hosted model fully deterministic.
4. Keep the same fixtures, tool environment, execution budgets and scoring version when comparing models. Measure provider, tool, queue and persistence latency separately so database contention does not masquerade as model latency.
5. Write bounded result batches per run; merge results after worker completion. Do not make all workers write to a single shared results database during the measured workload.
6. Reset the whole scenario graph, including external mock services and filesystem artifacts. Do not merely delete chat history. Use generation guards to stop old work from restoring state after reset.
7. Export machine-readable result summaries, with optional detailed traces. Fixture reproducibility, execution replay and deterministic model behavior are distinct guarantees.

For a consistent snapshot of a running database, use SQLite's backup facilities or a tested quiescent snapshot procedure. Copying just a live WAL database's main file can omit committed state. [SQLite backup API](https://www.sqlite.org/backup.html).

## Implementation priorities

- Add one validated data-root setting and explicit stores for platform/workspace/run scopes. Propagate it before imports; remove hidden fallback writes into repository databases during tests.
- Keep versioned migrations plus deterministic seeds, and maintain both existing auth initialization paths until intentionally unified.
- Use local disk, short transactions, a busy timeout and a tested WAL configuration. Never hold a write transaction across an LLM, network or tool call. SQLite permits one writer per database file, which should be addressed by short writes and independent run files before changing engines. [SQLite concurrency guidance](https://www.sqlite.org/whentouse.html).
- Provide reliable initialize/reset/export/import operations. Generate personal runtime data outside versioned source fixtures; ignore user DBs, WAL/SHM files, transcripts and real secrets in Git.
- Introduce narrow repositories for trusted platform/checkpoint operations. Do not place a global ORM or parameterizing wrapper over deliberately vulnerable SQL lessons.
- Gradually standardize application database access where useful; qualify whichever native driver the selected LangGraph saver requires. Test clean Windows/macOS/Linux installation and the documented Node versions. Avoid switching drivers, schemas and engine simultaneously.
- Preserve the current local vector implementation initially. A RAG workshop does not justify requiring a separate vector database service by itself.

## Optional database profiles

| Profile | Database choice | When to introduce |
|---|---|---|
| Default laptop learning | SQLite | Now; existing deployment model retained |
| Local model benchmark suite | SQLite with independent databases per run/worker | Benchmark harness work |
| PostgreSQL-specific SQL attack lab | Dedicated PostgreSQL container for that scenario | When the curriculum actually tests PostgreSQL semantics |
| MongoDB-specific injection lab | Dedicated MongoDB container for that scenario | When claiming real MongoDB behavior rather than a simulated document/query lesson |
| Shared multi-host deployment/results service | PostgreSQL for trusted shared state/checkpoints | Measured write contention or a requirement for workers on multiple hosts |

Do not advertise a simulated NoSQL lab backed by SQLite as validation against the actual MongoDB engine. Database-specific vulnerabilities need the real target engine and version in the benchmark manifest. Those optional targets remain separate from platform storage.

The trigger for PostgreSQL is shared multi-host access or sustained write contention that cannot be removed through short transactions and run isolation, not the number of agents or adoption of LangGraph. Existing session/reset/provider bugs remain code defects regardless of engine.
