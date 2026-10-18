# SecureShop instance-scoped progress design

**Status:** implementation-ready design; no schema or runtime activation.

## Decision

Keep one stable catalog workshop, `secureshop_agent_security`, with its fixed
learning-task objective IDs. Treat `identity.secureshop_launches.scenario_id` as
a random runtime **instance UUID**, never as a workshop key or curriculum ID.
Multiple platform sessions owned by one learner may have independent launch
instances. Resetting one instance retires only facts produced by that instance.

Preserve `workshop_platform.completions` as the canonical materialized
dashboard projection. Add immutable accepted-Judge contributions beneath it.
Canonical completion means that at least one contribution remains active for
the owner/workshop/objective. This is smaller and safer than either generating
catalog rows from random UUIDs or rewriting every dashboard around a new
projection.

## Why the current shape cannot support independent instances

`objectiveJudgmentRepository.recordVerdict` inserts one owner/workshop/objective
completion and reports later passes as `already_complete`. It does not retain
which launch instance supplied the pass. The current progress checkpoint then
deletes every completion, activity counter and time row for the owner and
workshop. A reset in one session consequently clears credit and time from a
different active session while leaving that other scenario's targets intact.

The judgment column named `scenario` is a stable rubric scenario string. It is
not the launch `scenario_id` and must not be overloaded. The stable curriculum
identity remains `workshop_key + objective_id`; the runtime identity is
`launch_id + scenario_id + launch_generation`.

## Additive storage

Add one identity migration after the existing reset checkpoint migrations.
Legacy judgments remain valid because all new judgment scope columns are
nullable as an all-or-none group.

### Judgment instance binding

Add to `workshop_platform.objective_judgments`:

- `platform_launch_id uuid`
- `platform_scenario_id uuid`
- `platform_launch_generation bigint`

Require all three null for legacy rows or all three non-null. A trigger validates
new non-null scope against `identity.secureshop_launches`, the judgment owner,
and the fixed SecureShop workshop. These columns are immutable with the rest of
the judgment receipt. The existing `scenario text` keeps its rubric meaning.

### Accepted contribution history

Create `workshop_platform.objective_contributions`:

- `(user_id, evaluation_id)` primary key and foreign key to the immutable
  judgment
- `workshop_key`, `objective_id`
- `platform_launch_id`, `platform_scenario_id`
- `platform_launch_generation`
- `workshop_generation`
- `accepted_at`

Use foreign keys to the catalog objective and launch. A security-definer insert
guard rereads the judgment and launch and requires an exact awarded or
already-complete passing receipt, exact owner/scope, and matching generation.
No runtime update/delete grant is needed.

Every accepted bound SecureShop pass inserts a contribution, including a pass
whose canonical completion already exists from another instance. Exact
evaluation replay finds the same contribution. An unavailable/failing/hidden,
mode-changed, stale workshop generation, stale launch generation, or mock-
disallowed judgment inserts none.

Within `recordVerdict`, the locked canonical row determines `awarded` versus
`already_complete`; update the immutable judgment result first, insert its
contribution second, and materialize/upsert canonical completion third, all in
the same transaction. The insert guard can then verify a terminal passing
judgment without trusting caller-supplied disposition.

`identity.secureshop_progress_cleanup_history` is the immutable retirement fact
for one reset. Its existing launch/scenario/from-generation coordinates retire
all contributions from the same launch instance with
`platform_launch_generation <= from_launch_generation`. A first reset mutation
still requires the launch to be at the reset's `to_generation`; an exact stored
history may replay later without changing progress.

An active contribution must also have `workshop_generation` equal to the
owner's current `user_state.generation`. A full-workshop reset therefore retires
all older instance contributions, including contributions from already revoked
or expired launch tombstones, without deleting their provenance.

### Canonical completion projection

Keep `workshop_platform.completions` and all dashboard DTOs unchanged. In the
same transaction that records a passing bound verdict:

1. insert the immutable contribution idempotently;
2. insert canonical completion with `ON CONFLICT DO NOTHING`;
3. retain `awarded` versus `already_complete` as receipt presentation, without
   confusing it with whether a contribution was stored.

During one instance reset, insert its retirement history and recompute only the
objectives touched by that instance. Delete a canonical completion only when no
active contribution remains for that owner/workshop/objective. If another
instance contributes, keep the row and set `completed_at` to the earliest
active contribution. Legacy completion rows without contribution provenance
must be classified during the catalog migration; do not silently attribute
them to a random launch. SecureShop has no activated legacy catalog today, so
the expected initial set is empty and the migration must assert that fact.

Historical judgment/evidence/contribution rows are never deleted by instance
reset. Receipt projection must report a retired instance contribution as
historical rather than current completion. `objectiveCompletionService` must
derive `completed` from active contribution/canonical state, not only the
stored `awarded` disposition.

## Generation model

Retain two independent generations:

- `workshop_platform.user_state.generation` is the owner-wide workshop epoch.
  It changes only for a true full-workshop/admin reset and continues to fence
  all attempts for that catalog exercise.
- `identity.secureshop_launches.generation` is the runtime instance epoch. A
  launch reset changes only this value and retires that instance's older
  contributions.

Bound SecureShop attempts snapshot both. `beginEvaluation` and `recordVerdict`
recheck both before accepting a contribution. Resetting instance A therefore
does not invalidate an in-flight attempt in instance B. A verdict already
holding A's launch lock may finish first and is then retired by A's reset;
otherwise the reset wins and the verdict becomes stale before contribution.

Do not create `secureshop_agent_security:<uuid>` workshop keys. That would make
catalog/config rows unbounded, change dashboard totals, and still fail to model
several runtime instances of the same stable learning task.

Splitting conceptual task groups such as `ss_agent_loop` and
`ss_indirect_content` into separate stable workshop keys is also unnecessary:
it changes the product from one workshop into several dashboard cards and does
not solve multiple runtime instances of any one group. Stable task identity is
already the objective ID under the single catalog workshop.

## Time and activity

Add nullable all-or-none instance columns to
`workshop_platform.time_tracking`: launch ID, scenario UUID and launch
generation, plus the captured workshop generation. SecureShop heartbeats must enter through the trusted launch-bound
parent/BFF path and populate them. Existing dashboard sums remain over the same
table. Instance reset deletes only matching rows at or before the retired
generation; other instances and other workshops remain unchanged.

Keep `activity_counters` as the canonical aggregate because its current primary
key is owner/workshop/activity. Add
`workshop_platform.instance_activity_counters` keyed by owner, workshop, launch,
scenario, launch generation, workshop generation and activity key. SecureShop activity writes update the
instance row and recompute/upsert the canonical aggregate in one transaction.
Instance reset deletes matching instance rows and recomputes only touched
activity keys. Generic workshops continue using their existing path.

A full-workshop reset retires every current SecureShop instance through the
aggregate launch reset coordinator, then increments the owner-wide workshop
generation and rematerializes canonical completion from the new epoch (which is
initially empty). The epoch change also retires contributions from revoked or
expired instances that cannot start a new launch reset. Direct
`resetWorkshopProgress` for this workshop must fail closed;
it cannot bypass target, conversation, and instance retirement.

## Transaction and lock order

Use one order for bound judgment and instance reset:

1. platform owner and session (`FOR SHARE` for judgment, `FOR UPDATE` for
   launch lifecycle), then launch row (`FOR SHARE` for judgment, `FOR UPDATE`
   for reset);
2. exact launch reset row for reset only;
3. `config_revision` (`FOR SHARE`), then catalog exercise/objective;
4. owner/workshop `user_state` (`FOR UPDATE`);
5. judgment row, contribution, canonical completion, instance activity/time.

Launch fencing already occurs before external cleanup. A judgment holding the
owner/session/launch share locks commits before the reset fence; cleanup then retires its
contribution. If reset obtains the launch update lock first, the judgment's
generation recheck fails. Configuration mutation locks `config_revision` but
never waits on launch authority, so it does not create a reverse edge. The
authority locks must stay in the existing user, session, launch order;
acquiring a user row after a launch would introduce an inversion. `FOR KEY
SHARE` is insufficient because PostgreSQL can update non-key launch
generation/status under `FOR NO KEY UPDATE` while a key-share holder is
grading.

## Source changes

1. **Draft/forward migration** — add judgment scope, contribution history,
   time scope, instance activity, constraints, guards, and indexes. Extend the
   progress-cleanup draft/history rather than creating a second reset truth.
2. **`server/database/postgres/objectiveJudgmentRepository.js`** — capture and
   recheck trusted instance scope, insert every accepted contribution, maintain
   canonical completion, and project retired contributions historically.
3. **`server/services/objectiveCompletionService.js`** — bind the server-owned
   launch scope into the WeakMap attempt; never accept instance UUIDs from an
   HTTP/model payload; use repository canonical-active status on replay.
4. **`server/database/postgres/secureshopProgressCleanupCheckpointRepository.js`**
   — retire one instance generation, recompute affected completions/activity,
   delete only scoped time, and leave the global workshop generation unchanged.
5. **`server/database/postgres/workshopProgressRepository.js`** — preserve
   current dashboard DTOs and enabled-objective joins; reject the generic reset
   path for SecureShop and accept trusted scoped heartbeat/activity adapters.
6. **Bound runner/route composition** — pass the already trusted
   `{launchId, scenarioId, generation}` from the bound execution closure into
   `beginAttempt`. Do not add client authority fields.
7. **Admin reset composition** — enumerate current owner launch instances,
   retire each through the aggregate coordinator, and only then perform the
   owner-wide generation reset.

## Qualification gates

- Two sessions for one owner complete the same objective. Two immutable
  contributions exist while the canonical dashboard shows one completion.
- Reset instance A: A's contribution, time and activity retire; B remains
  current and canonical completion/time/activity remain.
- Reset B afterward: the canonical completion disappears and only B's scoped
  time/activity are removed. Both judgment and contribution histories remain.
- Reset racing A's verdict yields either a contribution that the same reset
  retires or a stale verdict with no contribution. It never survives active by
  crossing the fence.
- An exact Judge or reset replay creates no second contribution, generation
  change, revision bump, or time/activity deletion.
- Forged launch/scenario/generation, another owner, stale launch generation,
  and a rubric `scenario` string shaped like a UUID cannot bind a contribution.
- Existing dashboard/challenge/progress/admin endpoints retain identical DTOs,
  enabled totals and completion counts. Tests prove filtering before pagination
  and no per-instance N+1 reads.
- Generic SecureShop reset is unavailable until every current instance target,
  conversation, progress and effect checkpoint is composed. No isolated
  progress mutation may advertise a complete lab reset.

## Implementation order

Qualify the additive schema and contribution projection first with an unmounted
repository API. Next wire bound Judge attempts and instance time/activity.
Then replace the draft progress checkpoint with instance retirement and compose
the full-workshop admin reset. Promote the catalog and public reset only after
native concurrent-instance tests, rendered dashboard parity, and real-model
positive/negative qualifications pass.
