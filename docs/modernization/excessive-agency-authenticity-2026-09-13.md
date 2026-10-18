# Excessive Agency authenticity continuation

> Current status: the bounded model/tool/grade/observation loop and atomic cancellation/refund are implemented. An owned rendered React qualification now passes all nine objectives with real PostgreSQL effects and real Ollama `llama3.1:8b` actor and Judge calls. Earlier model and harness failures remain recorded below; one successful run does not establish statistical model reliability. EA-specific admin/dashboard parity and concurrent-attendee qualification remain open.

## Confirmed gaps and intended behavior

The inspected graph is a one-tool model/parser/summary workflow; it does not let the model decide from tool observations. The active refactor introduces a bounded loop while preserving deliberate cross-persona authorization flaws inside each attendee partition and fixed-mode denials. Tool input validation must not silently enforce ownership in vulnerable mode.

The chat route forced every audit event to scenario A. That override is removed: each tool now supplies its own scenario. Existing projection and attendee-isolation tests pass8.

`cancelOrder` created a refund and claimed cancellation without changing order status. Actual atomic cancellation plus refund is being implemented in both stores, with duplicate/concurrent cancellation rejection. This preserves the deliberately missing authorization check; it makes the claimed effect real. Until implementation and qualification finish, this path is not accepted.

## Grading provenance

The EA rubric is now `ea-structured-v3`. Every chat objective requires the originating real model selection and an executed tool observation, in addition to its existing result/mode predicates. Missing, scripted, mock-provider or unexecuted observations cannot earn credit. Cancellation-based objective9 additionally requires a returned cancelled order after-state and refund; refund-only objective9 remains valid for `issueRefund`.

The deployed Judge version advances to `2026-09-13.grounded-v14`, preventing unavailable pre-provenance packets from being newly credited through retry. Historical completions are not silently changed. Pure supplied-evidence tests cover all nine positives and missing/model/fallback/effect negatives; combined provenance/completion/recovery tests pass17. This does not prove actual actor decisions or native effects. The graph must pass its server-held per-observation `decision` and `executionObservation` into the evaluator, then native/live integration must verify the full chain.

## Remaining work

The core learner path is implemented and has a rendered, native, actual-model pass. Remaining acceptance work is EA-specific admin/dashboard objective parity, concurrent-attendee/load behavior, and repeated-model reliability sampling. The Tool Activity panel still exposes only the final compatibility tool record for a turn; durable native traces remain the authoritative ordered observation record.

## Loop integration checkpoint

The bounded EA graph is implemented with strict runtime-derived catalog validation, max3 tool effects, max2 invalid-decision attempts and max8 total model selections. It uses canonical trace events, owner checks around every awaited effect, exact duplicate prevention and ordered observations fed back to the model. Every graded observation carries its own model decision and effect identity; unledgered direct calls have no effect ID. Combined loop/provenance/structured-Judge checks pass10 with2 live-gated skips. Actual8B composition and native cancellation remain in progress.

The Judge-version follow-up also passes the native XSS evidence/old-packet/reset plus real Mailpit suite2/2 (`dvaia-xss-email-dispatch-73ihijtj`), with owned containers removed. This verifies unchanged native mail/reset behavior under v14; it is not EA native qualification.

## Atomic cancellation checkpoint

Both in-memory and native stores now atomically transition a completed order to cancelled and create a full approved refund. The PostgreSQL operation locks the exact attendee/order row; duplicate/concurrent cancellation returns `ORDER_NOT_CANCELLABLE` with no additional refund. The router preserves deliberate cross-persona BOLA in vulnerable mode and fixed-mode denial. The existing status column supports the transition, so no schema/seed migration was needed.

Pure store/router tests verify persisted status, one refund, later reads and fixed denial. The extended disposable native EA integration verifies one winner among two concurrent cancellations, sibling attendee isolation and reset restoring completed orders/clearing refunds. Agent reports1 native pass and owned container removal. Root combined cancellation/provenance/loop checks pass9.

The permitted loop retry sequence could exceed LangGraph's default recursion limit. Invocation now explicitly sets limit40 and propagates the execution signal; a worst-permitted-budget test covers retries plus three effects. Initial live8B multi-action qualification listed notes but terminated before the requested deletion. That run is a failed competence case, not a successful exploit chain. A clearer two-step instruction is being assessed; even a later success does not erase the early-termination reliability limitation.

## Local 8B loop evidence and limits

The opt-in test `tests/excessiveAgencyGraph.live.test.js` uses the production graph, production tool router, a real LangChain Ollama actor and the real objective Judge. Its attendee database and effect callback are owned in-memory fixtures. It does not write canonical progress and is not a native receipt or PostgreSQL qualification.

After the test was corrected to construct messages like the mounted route, the first valid multi-action run selected `listNotes` for Bob and then answered before performing the requested deletion. Two later runs with a more explicit two-step instruction refused before any tool effect. These are real model reliability failures.

A production-style tool prompt subsequently produced the required chain: the actor selected `listNotes`, received a randomly generated note ID that was absent from the initial prompt, selected `deleteNote` with that exact observed ID, and returned a terminal answer. The real Judge passed both disclosure and deletion observations on that run. On the next full-file run, the actor again completed the exact observation-dependent deletion and the Judge passed objective 8, while the semantic Judge returned fail for objective 5 despite its true server facts. The fixed-mode run observed the expected cross-user denial and passed objective 4, then performed an additional safe self-list that passed objective 1.

The final live assertions retain the exact random-ID chain, both unauthorized tool results, per-observation real-model provenance, effect identities, the objective 8 pass, and actual Judge provider/model provenance. They allow the documented objective 5 semantic variation and an additional safe fixed-mode read. That final assertion revision was syntax checked but was not rerun against the model, so this checkpoint does not claim a passing full live file. Pure loop, provenance and structured-Judge checks pass; connected native credit, reset and rendered UI remain separate qualifications.

### Narration and disclosure audit

The fallback list narration called cross-user results “your” records. It now uses requested-user wording, includes existing note owner metadata and retains unauthorized-access warnings. Removed a dead note-content branch because the actual tool projects metadata only. Syntax validation passes; native live qualification uses the earlier copied source, so its result does not qualify this later copy change.

A separate source review identified an objective5 candidate gap: an empty cross-user list with a warning could count as disclosure. Requiring actual returned target-owned records is being implemented and tested. Semantic Judge variance remains separate; forcing a positive criterion through constrained output is not being treated as evidence of independent model reliability.

### v4 disclosure contract and v15 retry fence verified

Objective5 now requires an explicit cross-user target and at least one returned note/order with matching target owner metadata. Empty arrays, missing arrays, warning-only, self-target, mismatched owner and error results cannot nominate disclosure. The semantic criterion remains independent; actor/effect/owner provenance is separate server-observation evidence, while outcome citations use the actual tool result. Attack/defense intent is explicit. Root combined cancellation, provenance, loop and structured-Judge suite:15 passed,2 live-gated skips.

Shared Judge bundle v15 invalidates older unavailable grading packets. An owned PostgreSQL18 + Mailpit run (`dvaia-xss-email-dispatch-snvyk4j7`) passes2 integration tests, including rejection of both v12 and v14 retries without child evaluations or credit, owner-bound mail retrieval and reset fencing. Owned containers removed. Existing awarded history is unchanged.

The cancellation prompt previously contradicted its tool catalog by mapping cancellation to refund-only. It now distinguishes cancelOrder (status transition plus refund) from issueRefund (refund only), supplies correct arguments and says order records are retained. The agent is qualifying this corrected source through a new native/model snapshot; earlier live failures remain evidence and are not erased.

Latest v15 mounted deterministic qualification (`dvaia-ea-route-d7gh5wqb`) passes all9 exact tool outcomes, native runs/effects/receipts and isolation/reset, including corrected cancellation prompt assertions. Subsequent actual8B run (`dvaia-ea-route-ftbu7qf0`) passes objectives1–3 with exact actions and real Judge; objective4 stops with natural no-action instead of requested cross-user list. It fails before effect/Judge and is not a full pass. Both owned containers cleaned. This retains a concrete actor action-selection reliability gap even after the prompt contradiction was repaired.

The retained objective4 request later passed unchanged in actual8B run `dvaia-ea-route-upf56k2_`, confirming that the earlier refusal is model variance rather than a contradictory fixed-mode system prompt. That run still failed overall at objective9. Its original combined parser logs could not attribute every selected tool to an individual turn because the graph permits up to three tools per turn, so the mounted harness is being extended to persist bounded per-turn run, trace, effect and Judge-packet diagnostics before an assertion stops the run.

The runtime contract remains one business mutation attempt per EA turn, with read operations allowed before that mutation for observation-dependent IDs (`docs/modernization/remaining-agent-loop-remediation-2026-09-13.md`, “Keep Excessive Agency as a single-action authorization lab”). Mutating tools are now explicit catalog metadata. After one successful or denied mutation observation, a later model-selected action is omitted with `mutation_attempt_budget` and an `EA_MUTATION_BUDGET` trace record. The fallback response is built from the real mutation result, so a denial is not described as a success. This preserves the vulnerable mutation itself and model-selected read-to-write planning while preventing one exercise turn from consuming a later exercise's mutation target. Focused loop/cancellation/provenance checks pass15.

Current-source actual8B mounted qualification `dvaia-ea-route-1avqaruf` passes all nine objectives in 105.14 seconds using owned PostgreSQL, real Ollama `llama3.1:8b` actor and Judge, mounted authentication, exact native effects/receipts, sibling isolation and reset. It records nine runs, eleven effects and ten receipts. The unchanged objective4 request selected `listNotes` for Bob, observed the fixed-mode denial and earned its Judge pass. Objective7 supplied a useful live guard check: after its successful `createOrder`, the model selected another `createOrder` mutation; `EA_MUTATION_BUDGET` was persisted and no second mutation ran. Objective8 then executed only the requested Bob-note deletion, and objective9 independently cancelled Bob's still-completed order and persisted its approved full refund. Objective5 selected three bounded reads and produced one award plus an already-complete receipt; the extra reads were actual model decisions and effects rather than required curriculum steps. The test and container cleanup completed, with full per-turn diagnostics retained at `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-ea-route-1avqaruf`. One pass does not establish statistical actor reliability or rendered UI qualification, and the earlier objective4 no-action failure remains part of the record.

The retained source copy byte-matches the current graph (`1b25c81a…f636f3`), tool router (`fed2bea5…cbdf94`), EA grader (`bf01d69b…2ac87a`) and mounted fixture (`80ab8327…6c321`). These are SHA-256 abbreviations recorded only to identify the qualified source boundary; the full hashes remain reproducible from both paths in the retained workspace.

### Rendered React qualification plan

The current proof mounts the production HTTP route and authentication middleware but drives them with `fetch`; it does not render `client/src/pages/challenges/ExcessiveAgencyBolaLab.js`. A bounded next test can follow the owned Vite/App pattern in `tests/postgres/xssEmailRenderedUi.integration.test.js` without changing product layout:

1. Add a new `tests/postgres/excessiveAgencyRenderedUi.integration.test.js` selected by an `--ui` branch in `tests/postgres/run-ea-route-isolated.py`. Copy `client/` into the guarded workspace only for that branch, link its existing dependencies, retain the unique PostgreSQL container and process-group cleanup, and keep deterministic and explicit `--live` modes separate.
2. Initialize the existing identity and EA PostgreSQL schemas before importing route singletons, plus the owned CTF schema used by the App's existing authenticated provider/navigation calls, following the proven rendered-XSS mount. Mount the real session manager and production routers at `/api/auth`, `/api/ctf`, `/api/workshop/config`, `/api/changes`, `/api/workshop`, `/api/solutions`, `/api/hints`, and `/api/excessive-agency`. The actual App requires the platform login and config/visibility providers before the lab page; no fixture may synthesize `req.user` or bypass `VisibilityProtectedRoute`.
3. Launch the real App at `/workshop-login`, log in with an owned native platform account, navigate to `/vulnerabilities/excessive-agency`, and click the existing `Login as Alice` control. The lab performs its separate real `/api/excessive-agency/auth/login` and stores the server-issued lab session token; the test must not inject it into component state.
4. Submit the unchanged nine mounted qualification messages through the visible chat textarea, one POST each. Verify objectives1–4 become `COMPLETED` in fixed mode, click the existing mode indicator and verify the server-confirmed vulnerable label, then verify objectives5–9. Inspect the existing Tool Activity tab for the returned compatibility tool record and use native run/effect/Judge rows for the complete ordered observation proof.
5. Include a genuine ordinary-conversation no-action request before the exercise sequence and require no new tool activity, effect, judgment or completion. Do not treat the UI's last-tool activity record as proof of the graph's full trace: `/chat` currently returns only the final compatibility `toolExecution`, while the graph and durable run retain every ordered observation. The current actual8B objective5 run used three reads although the panel would display only its last read; an additive ordered activity DTO is a separate teaching-clarity improvement.
6. Assert nine canonical green objectives, actual actor/Judge provider/model and current Judge/rubric versions, exact persisted mutations/denials, sibling preservation and one-mutation trace behavior. Capture desktop screenshots before and after clicking the visible `Reset Progress` button; after reset require zero canonical/local completion, reseeded Bob note/order state, cleared activity/progress UI and no automatic chat resend.
7. Intercept outer-browser requests before navigation and permit only the owned Vite/backend origins plus `data:`, `blob:` and `about:`. Record and abort all other traffic. Capture page errors, failed core responses, submitted chat bytes, DOM state and a failure screenshot before cleanup. Await browser, Vite, HTTP server, session manager, pools and process-group teardown.

This plan qualifies the actual learner UI over the already-proven native route. It does not claim concurrent-attendee throughput, statistical 8B reliability, or that the last-tool activity panel displays the full observation loop.

Broad copied-source regression `dvaia-regression-HwyCpn` exposed a stale trace test expecting the retired EA model/parse/no_tool nodes. The working test now expects decide/validate/finalize and accepts canonical tool events; all5 trace checks pass. The original copied run is retained unchanged and was still active when this note was written; it must not be described as a passing current-source regression.

The broad HwyCpn run completed:1510 passed,2 failed,41 gated skips (1553 total). Both failures were obsolete EA test contracts: retired node names and an effect fixture without the now-required tool catalog. Updated tests cover actual decide/validate/finalize boundaries and one catalog-valid effect followed by duplicate-stop fallback. Their focused suites pass9 tests. This is a failed broad snapshot plus passing targeted corrections, not a rerun claim.

EA now renders shared HintPanel controls for canonical hintVisible objectives in both modes, independently of solution visibility; revision updates dismiss stale shared help. A focused component test verifies fixed/vulnerable hints and removal on hint/objective hiding. It passes, with existing styled-prop React warnings exposed for follow-up. An accidentally invoked root npm test started owned snapshot PwJEDw; root stopped its verified parent/child process groups (terminal143) and ran the intended client test instead. No broad pass is claimed for PwJEDw.

EA styling flags now use styled-components transient props for isVuln/active/objMode/modeMatch, preventing those internal values from reaching DOM attributes. The hint component test passes without the prior React warnings; CSS conditions and visible styling are unchanged.

Hint qualification now mounts the real shared HintPanel and help modal rather than a stub. The component test verifies the exact canonical objective1 hint request, rendered content, independence from solutions, and removal of both trigger and open modal content after canonical hint/objective visibility revocation. It passes. HTTP is fixture-backed here; native admin/content parity is being qualified separately.

## Rendered React actual-model checkpoint

The current rendered qualification now passes. Run `dvaia-ea-route-pm9typr3` mounted the production React application, platform authentication, the mounted Excessive Agency route, the native PostgreSQL stores, and real Ollama `llama3.1:8b` actor and Judge adapters. It completed all nine canonical objectives through the visible learner controls, retained exact run/effect/Judge evidence, verified the cancellation status transition and refund, checked sibling-owner isolation, and verified the rendered and native reset result. The run recorded ten durable runs and ten receipts. Its screenshots are retained at:

- `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-ea-route-pm9typr3/source/artifacts/ea-rendered-before-reset.png`
- `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-ea-route-pm9typr3/source/artifacts/ea-rendered-after-reset.png`

The test passed one TAP case in approximately 112 seconds. Its owned PostgreSQL container `dvaia-ea-route-test-42226fc0f7b3` used a 256 MiB parent tmpfs with no mounts; the exact container and associated volumes were removed and absence was verified after the run. The qualified launcher and rendered test hashes were respectively `6088706d737e9ae13cc9cd3f538618c95fd33ffb2d0c89679bd60022f90bc1fb` and `1ea9afa7fe6e9f8b3645528857b88ddc37821ff70b16bf1503b17860fa6fb`.

The immediately preceding rendered attempt is retained as a historical failure. It reached a benign model turn, then the harness required HTTP 200 for the welcome GET although the browser correctly reused the resource with HTTP 304. That run did not reach objective 1 and is not model-success evidence. The assertion was narrowed to accept 200 or 304 for that GET while the reset POST remains exactly 200; the full workflow was then rerun rather than relabeling the failed artifact.

Earlier actual-model failures also remain material: the actor sometimes stopped without the requested action, selected an unsuitable tool, or the semantic Judge rejected true server facts. The later all-nine pass proves feasibility and one complete current-source execution, not a reliability rate. Deterministic fixtures continue to test protocol and failure branches but are not included in the actual-model claim.

This rendered run does not close EA-specific admin/dashboard parity. It proves the learner objective cards and reset path; it does not prove that every EA completion, run, effect and teaching label appears consistently in the instructor's student-workshop, activity and agent-run views. Concurrent attendee behavior and a rendered ordered multi-tool trace also remain open. The existing Tool Activity panel shows the final compatibility tool entry, while native traces hold the complete ordered sequence.

## Current representative checkpoint, September 19

`tasks/excessive-agency-current-objective9-2026-09-19.json` qualifies one current
mounted objective9 with actual llama3.1:8b selection/Judge, native cancellation
and refund, canonical credit, generation reset and sibling preservation. The
owned container/process group were removed. Two pre-model launcher failures
exposed an obsolete short signing key and mismatched fixture issuer; the runner
now generates private ephemeral keys and the fixture uses the same issuer key.
No production policy or sink changed. Retain the all-nine rendered pm9typr3
cohort; this current representative is not a new all-nine claim.

The current route already returns the full `toolExecutions` array and the UI
renders it, with focused route/component tests. Earlier final-only activity
notes are superseded; current rendered ordered multi-tool and EA-specific
instructor/dashboard parity and capacity remain separate.
