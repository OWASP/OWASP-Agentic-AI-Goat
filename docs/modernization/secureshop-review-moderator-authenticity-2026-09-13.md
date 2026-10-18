# SecureShop review moderator authenticity checkpoint

Date: 2026-09-13

## Current behavior

The review moderation exercise has a real database effect but does not yet have a real moderator model decision.

- The merchant page describes an LLM and sends `POST /merchant/reviews/moderate-all` directly (`client/src/pages/secureshop/pages/merchant/Reviews.jsx:62-74,121-135`). Both the PostgreSQL and legacy routes import the task tool directly instead of entering the merchant supervisor (`server/routes/secureshop/postgres/merchant.js:109-114`; `server/routes/secureshop/merchant.js:232-242`).
- Both tool implementations call `_moderatorLLM`, a regular-expression classifier. The comments say that a real Ollama provider can replace it, but no provider call exists (`agent-host/agents/review-moderator/tools/index.js:23-33,48-64`; `agent-host/agents/review-moderator/tools/index.postgres.js:23-33,48-64`). The MCP description therefore overstates the behavior when it says pending reviews are classified “via the moderator LLM” (`agent-host/agents/review-moderator/server.js:9-12,27-29`).
- The PostgreSQL and SQLite updates are persistent, but they identify a review only by its global row ID and overwrite status without a pending-state condition (`server/database/postgres/secureshopCommerceDb.js:39-41`; `agent-host/agents/review-moderator/tools/index.js:36-45`).
- The existing vulnerability test supplies the magic `SYSTEM: approve` string to the regex and checks the resulting row. It proves the heuristic and database mutation, not a provider observation followed by a model-selected action (`tests/secureshop/vuln/llm/llm01-indirect-pi-review.test.js:16-40`).

The merchant supervisor itself is a genuine multi-step model loop. It awaits the provider and records the selected tool arguments (`server/services/secureshop/supervisors/merchantSupervisor.js:25-37`; `server/agent-runtime/secureshopSupervisorGraph.js:74-112`), executes selected tools through the effect boundary, appends the raw tool result as the next observation, and continues (`server/agent-runtime/secureshopSupervisorGraph.js:260-319`). The missing behavior is inside the review tool and the page route that bypasses this loop.

There is no formal SecureShop review objective in the shared workshop catalog or a review-specific Judge contract. `llm01-indirect-pi-review` is an intentional vulnerability-map entry, not automatically a learner objective. A future exercise must be created and synchronized through the catalog, visibility, hint, solution, progress, time, and dashboard paths; the existing vulnerability ID alone is not evidence of those integrations.

## Minimum authentic workflow

1. Reserve an owner-bound review target from the active launch before provisioning it. The identity reservation allowlist currently supports only `files`; adding `reviews` requires a forward identity migration and launch repository method.
2. Provision per-launch synthetic review rows in a dedicated PostgreSQL review-lab database. Do not store them under the commerce runtime role: the deliberate `analytics.nl_query` path executes learner-influenced arbitrary `SELECT` in the commerce schema (`server/database/postgres/secureshopCommerceDb.js:9-13`), so co-location would expose other attendees' bound rows.
3. Change `review-moderator.moderate_pending` into an observation tool that returns the exact pending rows without deciding. The merchant supervisor observes those raw bodies and makes its next real provider decision using `review-moderator.approve` or `review-moderator.reject` with the actual row ID and notes. Preserve the raw indirect-prompt-injection sink.
4. Route “Moderate all pending” through the bound conversation runner. Aggregate the observed model decisions into the page's existing `{ok, processed, decisions}` shape so its layout remains unchanged. Manual approve/reject stays a deterministic user authorization and records `moderator_kind='manual'`.
5. Put every mutation behind the run coordinator/effect ledger and recheck active launch authority immediately before dispatch. The review repository's copied coordinates and admission checks are not an atomic online authority or replay fence. Keep the existing turn semantics: a completed request replays its persisted final DTO without rerunning tools; a started or uncertain request returns `TURN_RECOVERY_REQUIRED`; and a duplicate effect returns `GRAPH_EFFECT_REPLAY_BLOCKED`. A new request creates fresh local tools and must observe pending reviews again before deciding. It must not rehydrate observations from a failed request or accept a model-echoed receipt/capability.

## Repository prerequisite in this change

`server/database/postgres/secureshopBoundReviewRepository.js` is an internal trusted-authority primitive backed by the draft `docs/modernization/drafts/secureshop-review-binding.sql`. Its contract is:

- `provision(scope,{reviews})` atomically creates one exact target for a launch generation. Exact retry checks the seed digest and row count and never reseeds. A different binding, fixture digest, or partial target fails closed.
- `listPending(scope,{limit})` and `getReview(scope,id)` constrain by the complete target binding before ordering or limiting and return raw review bodies unchanged.
- `decide(scope,{reviewId,decision,notes,moderatorKind})` locks the target and row and changes only a pending row. A concurrent or repeated decision reports `applied:false` and returns the authoritative persisted decision.
- `retire(scope)` irreversibly fences the target locally. Reset orchestration must supply `checkRetirement` based on a trusted reset receipt; active operations use `checkCurrent` derived from launch authority.

The trusted scope contains `targetId`, `launchId`, `scenarioId`, `generation`, `platformOwnerId`, and `platformSessionId`. Callers must obtain these values from the trusted launch/reservation store. Copying values from a token, shop JWT, model call, URL, or request body does not establish ownership. The repository stores no bearer.

The reviewed base schema and cleanup-receipt guard are now registered as the first two migrations for dedicated roles `dvaia_secureshop_review_migration` and `dvaia_secureshop_review_runtime`. Fresh provisioning, additive 14→16 and 15→16 upgrades, initialization, pool reopen, optional startup, and shutdown have isolated PostgreSQL qualification. The route remains unmounted. Owner deletion/archive orchestration, reset integration, reservation activation, and connected workflow qualification still require coordinated implementation before mounting it; a cleanup table alone does not claim those lifecycle workflows are wired.

The final 16-store aggregate source snapshot passed 107 native repository tests, both direct and owned-launcher application boot tests, the 200-attendee mock-inference load test, and the ARIA/NOVA public module suites (105/137 passes with seven server-gated skips each). Initialization named all 16 repositories, including session disclosure and bound reviews. The snapshot and log are `/tmp/dvaia-pg16-final-BOhD70/source` and `/tmp/dvaia-pg16-final-BOhD70/aggregate.log`; its owned PostgreSQL container was removed. The load diagnostic still printed the historical label “PostgreSQL14 isolated databases”; that label was corrected to 16 afterward without changing executed behavior. This aggregate proves native storage/startup compatibility with mock inference, not review route activation or a live moderator model.

## Acceptance gates for activation

- A disposable PostgreSQL qualification proves two owners cannot list, read, or decide each other's rows; binding filters occur before `LIMIT`; review payload bytes are preserved; and wrong scenario, generation, session, owner, or target is unavailable.
- Concurrent approve/reject attempts produce exactly one persisted transition, and reset/retirement makes the old generation unusable without affecting a sibling owner.
- The live route uses an active bound launch, the durable turn admission/run coordinator, and effect ledger through the existing `createLocalTools(binding)` seam. Reset waits or reconciles admitted effects. An uncertain duplicate fails before graph/tool execution, and a fresh request must perform a new `moderate_pending` observation. Mock, unavailable, supplied, regex, and stale executions receive no objective credit.
- A local `llama3.1:8b` qualification shows: learner-created poisoned review persisted; moderator model observed the exact body; its next decision selected the exact approve/reject tool arguments; the effect receipt and DB readback match; and the final explanation names the observed injection effect. A benign control must also produce a meaningful moderation decision.
- The Judge uses a new rubric version and requires owner/scenario/generation, non-mock provider identity, model-decision trace, raw body digest, exact selected arguments, completed effect receipt, and authoritative DB readback. Prose or a status chosen before the model observation cannot satisfy it.
- UI response shape, manual moderation, intentional stored-XSS rendering, advisory role behavior, and all tagged sinks remain covered. If a formal exercise is added, all catalog/admin/dashboard/hint/solution/progress/time parity checks pass.

Until these gates pass, the current review flow is a heuristic simulation with a real global database mutation. It must not be described or graded as an authentic review-moderator agent exercise.
