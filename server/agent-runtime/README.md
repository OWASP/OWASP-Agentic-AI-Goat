# Workshop graph pilot runtime

ARIA and NOVA keep their existing `chat(userId, message, clientHistory, mode)`
contract. LangGraph is the supported application default. `ARIA_AGENT_RUNTIME=legacy`
and `NOVA_AGENT_RUNTIME=legacy` select retained regression fixtures only; they
are not a supported fallback for mounted workshop routes. Those fixtures lack
the canonical run-admission and grading metadata required by the routes and
must not be used to award learner credit. The
factory additionally returns:

- `invoke(userId, message, mode, { signal, timeoutMs })`
- `cancel(userId)` to fence queued and current runs
- `reset(userId, async resetStore)` to invalidate runs, drain existing tool writes,
  then clear the caller-supplied store before admitting new runs

One factory instance serializes each owner within its named agent family. Routes
must supply an authenticated owner and use the same instance for chat/reset.
The SQL/NoSQL chat and reset routes use this API. Disconnects cancel the
individual request. Objective credit runs inside the same owner lock as chat,
so reset drains ongoing canonical progress writes before clearing progress.
Progress/reset failures return errors instead of claiming successful clearing.

Default deadline is 120 seconds (configurable up to 300 seconds). Model waiting
ends on cancellation/deadline and stale results cannot reach persistence. The
underlying existing provider request may continue until its own timeout. In-flight
database/tool operations are drained rather than abandoned, so a stuck tool or
store/ledger operation can exceed the deadline. Already completed mutations are
not rolled back. Legacy two-message persistence is not atomic; resetting through
this API waits for writes and then clears them. External reset calls bypass its
fence; the manual progress-complete endpoint is not serialized by this runtime. No automatic tool retries or replay are enabled.

`createAgent({ store, model, runLedger, defaultTimeoutMs })` accepts an optional
async ledger implementing `begin(context)`, `assertCurrent(context)`,
`checkpoint(context, { node })`, `finish(context, { status })`, and
`invalidate({ ownerKey, generation })`. Context contains a random run ID,
family-qualified owner key, and local generation. Checkpoints here are node
milestones, not serializable graph state or resumable checkpoints. They contain
no prompt, credentials, or tool data.

Without a durable implementation, serialization and generations only cover this
factory instance and process lifetime. A PostgreSQL implementation must allocate
and validate durable generations and leases transactionally across processes;
it must not assume these local generation counters are globally authoritative.
No restart recovery, exactly-once side effects, cross-process locking, durable
LangGraph checkpointer, or automatic resume is claimed by this pilot.
