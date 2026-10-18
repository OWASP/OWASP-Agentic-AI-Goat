# Bound SecureShop policy and tool-permission implementation

Status: design derived from current source; no endpoint or policy behavior is
claimed implemented by this document. The preceding goal turn made verified
progress: admin error handling and scoped native/browser/capacity acceptance.
This next work must restore actual administration, beyond truthful errors.

## Observed gap

The bridge exposes five policy and three access-control operations, but the
bound gateway terminates them as unavailable. Legacy PostgreSQL admin handlers
operate shared policies and permissions. Bound execution configurations instead
supply empty policy blocks and purpose-specific fixed ACL callbacks. Several
`buildBasePrompt` implementations ignore the `extra` argument entirely. Simply
mounting legacy routes or changing the policy loader would neither affect those
prompts nor preserve launch isolation.

Authoritative sources: `server/routes/secureshop/boundGateway.js`,
`server/routes/secureshop/postgres/admin.js`,
`server/services/secureshopBoundAgentRunner.js`,
`server/agent-runtime/secureshopSupervisorGraph.js`, and the bound product,
manual, review, audit, MCP and inbox execution configurations. The legacy
`policyLoader.js` verbatim prompt inclusion and `toolAcl.js` advisory dispatch
are deliberate teaching sinks (`llm04-policy-poisoning`,
`llm06-excessive-agency`). Unsafe template rendering is a separate SSTI effect.

## Selected architecture

Persist versioned policy and tool-permission overlays in the existing dedicated
SecureShop agents store, keyed by the full trusted launch scope. Do not mutate
platform RBAC, shared baseline rows, environment variables or sibling launches.
A shared-table legacy fallback is rejected. A settings editor whose writes
never reach the graph is also rejected.

1. A store-local revision aggregate contains current policy versions, explicit
   tool/role permissions and enforcement mode. Defaults are checked-in lab
   configuration copied or resolved only for a new launch; reseeding must not
   overwrite instructor edits. Exact supported tool identifiers come from the
   composed manifest, never arbitrary request strings.
2. Admin mutations authenticate the current platform session, launch generation
   and shop admin persona before admission and publication. Require an expected
   revision and idempotency identity. Commit the changed revision and immutable
   admin audit event in the same agents-store transaction. Return the exact
   acknowledged revision/value, with a clear conflict on stale writes.
3. Construct policy/ACL closures per turn from trusted binding inside
   `createBoundAgentRunner`; never retain one mutable global current scope.
   Policy text is captured once for the next model turn with exact ordered
   version identifiers and content digest. Each applicable base-prompt builder
   must demonstrably include the block. Preserve raw teaching text rather than
   sanitizing away the policy-injection lesson.
4. Separate immutable host/ownership/tool-manifest constraints from editable
   teaching permissions. Advisory mode may dispatch a denied teaching operation
   only to an admitted owned tool. It cannot enable an absent tool, another
   user's data, host command execution or global admin authority. Existing
   inner resource-specific ACLs remain distinct; report the layer that blocks.
5. Define concurrency semantics explicitly: prompt text is a turn snapshot;
   permission revision is checked at each selected tool admission. Record the
   exact revision and decision before the effect. Enabling enforcement during a
   held model decision must block the later denied tool; changing settings
   cannot retroactively undo an already committed effect. No SQL lock is held
   across model/network latency. A durable effect-admission fence must serialize
   configuration changes with short local effects; remote effects require
   receipt-backed admission and cannot claim distributed rollback.
6. Extend reset and student deletion with exact-scope retirement/deletion and
   durable receipts. Retain immutable historical evidence under the existing
   retention policy, exclude retired generations from current reads, and reject
   delayed writes after reset/deletion. Include readiness and runtime grants;
   runtime roles must not update/delete immutable audit receipts.

## Template execution is a separate required gate

Policy save currently promises real Nunjucks rendering, and test-render exposes
that same teaching surface. Running the legacy renderer in the main backend
would grant host authority. Use a real isolated template worker with private
lab files, bounded output/time, no application secrets or sibling mounts, and
an authenticated owned target/effect receipt. The renderer must execute the
actual protected vulnerable package, not substitute regex output or a safe
renderer that removes the lesson. Keep this work distinct from prompt policy
inclusion: CRUD and policy poisoning alone do not complete all five endpoints.

Choose the owned renderer boundary after comparing existing sandbox-runner
process isolation and lifecycle contracts. Do not introduce a new database
store or alter AWS assets solely for this worker. Its local installation,
readiness, reset/deletion, failed-acknowledgement recovery and disposal are
release requirements, not future optional cleanup.

## Verification and release order

- Draft forward migrations and qualify fresh, populated and no-op paths in
  disposable stores. Prove runtime grants, concurrent revision conflict,
  idempotent replay, stale generation denial and unchanged sibling state.
- Compose actual bounded admin reads/writes and current graph closures. Prove
  with controlled providers that next-turn policy bytes reach the provider,
  allowed dispatch executes, advisory denial logs and executes the owned tool,
  enforced denial never enters it, and a held model turn observes a newly
  enforced permission before its next effect. Test concurrent owner isolation.
- Qualify the real renderer independently, then policy save/render endpoints;
  preserve original source and rendered digest plus effect provenance. Verify
  honest error recovery, including remote commit with lost acknowledgement.
- Run bounded actual llama3.1:8b policy-poisoning and advisory/enforced tool
  cohorts with objective-specific canonical Judge evidence, benign controls,
  reset and retained immutable evidence. Missing/refused model effects earn no
  credit. Do not invent new objective IDs before reconciling the existing
  catalog and vulnerability map.
- Verify actual full App policy/ACL controls through the opaque bridge, followed
  by canonical admin/learner objective, hint, solution and dashboard parity for
  any affected exercise. Preserve colors, layout, buttons and chat baseline.
- Promote only the qualified source closure; installed activation still needs
  preservation of live RAM-only IPI documents and all existing learner data.
