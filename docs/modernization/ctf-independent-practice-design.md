# Independent CTF practice alongside ranked progression

Status: design only. No implementation, model calls or installed changes.

## Finding

Existing configuration does **not** provide independent student access. `server/routes/ctf.js` checks predecessor completion in `/stage/:stageId/start`; `client/src/pages/CTFDashboard.js` also locks cards from predecessor progress. Config exposes availability, registration/capacity, timing, feedback and hint controls, but no practice or prerequisite override. Hiding a stage or changing its order is not a supported practice mechanism and changes competition semantics.

The admin stage-preview endpoint already reuses the real input defenses and guardian/output-reviewer graph. It is instructor-only, does not execute canonical learner admission/Judge/commit, and is explicitly labelled that way in `CTFAdminPanel.js`. Reuse its diagnostic presentation, not its execution shortcut, for student practice.

`tasks/ctf-stage6-reviewer-boundary-2026-09-19.json` records two genuine reviewer-blocked candidates, not a solved level. Existing positive evidence for stages1–5 does not prove6–10 solvability. A functioning stage may resist this model; neither failed attacks nor observation of a defense should be reported as earned extraction success.

## Smallest coherent product change

Keep current ranked mode and its sequential progression unchanged. Add an instructor-controlled **Practice · unranked** entry on the existing CTF dashboard. Reuse the same cards, chat, hint controls, colors and reset pattern. Practice cards allow selecting any active stage regardless of ranked progress. Show persistent unranked labelling; a verified disclosure is “Practice success”, not “Stage completed”, and cannot navigate/unlock ranked progression or award points.

One new default-only config key, `ctf_practice_enabled`, controls the entry. Keep normal CTF visibility, authentication, bans and active-stage rules. For minimal initial scope retain participant registration/capacity; practice never advances its ranked clock/activity totals. Practice duration and attempt bounds belong to the practice session rather than the participant's competition start time. Display the distinction. If instructors need practice without competition enrollment later, introduce a separately qualified admission change rather than silently bypassing registration here.

Use one practice execution mode for both learning and manually bounded benchmark attempts. Add a bounded outcome export to that mode; do not create another agent framework or automatically retry until success. Benchmark reporting includes all attempted payload hashes, stage/defense/rubric hashes, guardian/reviewer/Judge provider/model, response hashes, timings, configuration and outcomes: input blocked, reviewer blocked, no disclosure, Judge fail/inconclusive, unavailable, stale or verified disclosure. Separate application correctness from observed exploitability. Preserve existing lessonState as observations, never completion substitutes.

## Persistence and isolation

Use the existing CTF PostgreSQL database. Add forward-only practice tables rather than a mode flag across every ranked query: practice sessions, attempts/judgments, and adaptive-memory entries. Existing ranked tables and leaderboard SQL then cannot accidentally count practice rows. A session binds UUID, owner/participant, stage, stage digest, practice generation, timestamps/status and immutable mode. Attempts bind unique operation/run IDs and store the same genuine provenance and visible-response judgment evidence. Recovery must not repeat an uncertain model operation or grant retrospective ranked credit.

Reuse the CTF owner execution coordinator and its admission/generation checks; add explicit practice resource generation for reset/restart. Commit locks the current practice session and stage, checks authenticated owner/current run and stage digest, then persists only practice evidence. It must not call the current ranked `CTFHelpers.commitAttempt`, `startStage`, `incrementAttempts`, `logAttempt`, `updateLeaderboard`, or ranked hint purchase methods. Current commit writes progress, adaptive blocks, events and leaderboard in one transaction; wrapping it and subtracting afterward is unsafe.

Adaptive defenses retain their algorithms and semantics with isolated state. Per-user technique consumption keys practice namespace + owner + stage. Shared winning-payload memory keys a server-controlled practice cohort + stage, never a client-selected namespace or ranked blocklist. An initial installation-wide practice cohort preserves the shared-defense lesson across students. Explicit admin reset of that cohort is distinct from learner reset; learner reset cannot erase shared fingerprints. Record the cohort in benchmark evidence. Do not claim an individual sandbox demonstrates global sharing without a second-owner proof.

**Secret isolation is also required:** practicing against the same ranked target can reveal the later competition answer even if scores are separate. Bind an independently generated synthetic practice secret into an explicit stage-template field and success criterion. Preserve the stage's defense policy; record a distinct practice configuration digest. Do not use heuristic string replacement on instructor-edited system prompts. Canonical defaults can gain explicit practice templates through provenance-aware/default-only seed changes; a custom stage without an instructor-approved secret binding reports practice unavailable. No secret, system prompt or raw draft is returned by the stage-list or export API. This intentional target-value difference must be recorded when comparing ranked and practice results.

Reset retires only the selected practice session and its mutable owner memory; immutable outcome receipts remain according to existing evidence policy. Ranked progress/leaderboard and sibling sessions remain unchanged. Canonical CTF admin reset, participant removal and student deletion must explicitly include practice data and invalidate in-flight commits. Existing ranked reset lifecycle is not proof of coverage for new tables.

## Concrete integration map

- Next available migration in `db/postgres/workshop-migrations/ctf/`: practice tables, constraints, indexes and minimum runtime privileges. Coordinate filename; never modify0001 or applied seed/provenance migrations.
- `server/database/postgres/ctfPracticeRepository.js` (new): admission, current session, bounded attempt reservation, replay, atomic judgment commit, adaptive memory, hints and scoped retirement. Use existing CTF pool; no new store/engine.
- `server/services/ctfPracticeService.js` (new): server-bound mode/session, stage-template validation, model execution and practice response projection.
- Reuse `ctfAdmissionGraph.js`, `ctfGuardianGraph.js`, `ctfDefenseLayers.js`, `ctfGuardianResult.js`, `judgeCtfStage` and lesson receipts. Supply an explicit practice-only repository facade for admission's adaptive/attempt dependencies. Extract the currently route-local guardian/Judge orchestration into a shared executor if necessary; do not fork defense/rubric logic. `ctfResultGraph.js` currently reads ranked progress and formats scoring: add a separate small practice presenter instead of invoking it unchanged.
- `server/routes/ctf.js`: explicit `/practice/stage/:stageId/start`, `/practice/session/:id/attempt`, `/practice/session/:id/hints`, `/practice/session/:id/reset`, read/export endpoints. Server session establishes mode; reject ranked IDs/tokens on practice APIs and vice versa. A request body `mode` never changes an admitted session.
- `server/database/postgres/ctfDb.js` and existing student/admin deletion composition: extend explicit lifecycle adapters; preserve ranked accounting. Config seed/getter plus existing admin config validation allowlist gain the practice key.
- `CTFDashboard.js`, `CTFChallenge.js`, `ctfObjectives.js`, `CTFAdminPanel.js`: reuse presentation with explicit server-confirmed practice state, no points/next-ranked-stage on success, retry IDs and owner/session/reset response fencing. Ranked leaderboard component requires no change.

## Promotion gates

1. Controlled unit/HTTP: locked ranked stage remains403 while practice can start it with zero predecessor rows; forged mode/session/owner, disabled practice, inactive stage and revoked bearer denied. Model/mock provenance rules identical; missing Judge never success.
2. Disposable native fresh/populated/no-op migrations preserve every ranked row and instructor-edited stage. Snapshot ranked progress, attempts, judgments, leaderboard, hints and both blocklists before practice; assert byte/logical equality afterward for success, failure, unavailable, replay and reset.
3. Native lifecycle: restart restores independent practice session; concurrent reset, stage edits, owner deletion and late grading cannot commit; sibling preserved. Same operation replays once. Practice rank/cohort memory never aliases ranked or another cohort. Second owner demonstrates shared practice fingerprint blocking.
4. Secret binding: practice value differs from ranked; the exact practice guardian value is the Judge target; arbitrary custom prompts cannot be silently rewritten. Do not publish targets in diagnostics.
5. Actual llama3.1:8b: one bounded existing stage1 positive proves genuine practice disclosure + independent Judge + isolated commit. Stage6 resistant cohort demonstrates honest failure/defense observations. Stage8/10 technique reuse and stage9 shared-memory negatives qualify their teaching behavior; missing positive evidence remains labelled missing.
6. Rendered baseline: switch mode, access locked later card in practice, genuine status/no fake ranked completion, model unavailability, reset/reload, owner switch and unchanged ranked dashboard/leaderboard. Admin enable/disable and student visibility update consistently.

This removes access dead ends without inventing prior achievements. It does not make stages6–10 proven solvable, and it does not redefine a successful defense as a successful attack.
