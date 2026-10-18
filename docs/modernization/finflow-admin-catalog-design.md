# FinFlow Administrative Catalog Observation

Status: approved bounded design; implementation and actual-model qualification remain separate.

## Problem

The current `admin_enum` path is reachable, but it is not yet authentic enough to qualify. The planner can choose the generic `tool_enum` action or one of the eight administrative tools. When `admin_enum` is active, the response prompt receives a second copy of the administrative schemas from the objective configuration. A complete response can therefore be graded from text matching without proving that the model selected an administrative catalog observation. Retained local-model evidence shows legitimate unsuccessful attempts: the model selected an administrative effect, returned a refusal, and correctly received no enumeration credit.

The repair must keep that freedom. The server must not append missing names, convert a refusal into success, or force the planner action.

## Design

Vulnerable mode adds one planner action, `admin_catalog_observation`. Fixed mode omits it. The existing model decision path must select this action from the same structured catalog used for all FinFlow decisions.

After that selection, the graph captures an immutable JSON copy of the current `ADMIN_TOOL_SCHEMAS`. The observation authority accepts only decision metadata minted by the actual structured planner call and binds the original observation object to the exact admitted execution object, owner key, run ID, durable generation, selected action, catalog digest, output digest, and exact eight tool names. A private one-shot witness is issued only for that original observation and execution. Missing live checks, copied executions, caller-supplied decision metadata, owner or generation strings, digests, and success assertions cannot mint a witness.

The response model receives the captured catalog observation as data and must produce the learner-facing disclosure. `admin_enum` keeps its existing no-repair behavior: an incomplete response, a refusal, or a response produced after another administrative action remains incomplete.

The route returns only the existing response, tool calls, judgments, run summary, and completion projection. The private observation and witness never enter the HTTP response.

## Grading contract

`admin_enum` requires all of the following server facts:

- vulnerable mode;
- a real model-selected `admin_catalog_observation` action;
- a current owner/run/generation-bound administrative catalog witness;
- the same owner/run binding at grading time;
- exact-boundary coverage of all eight canonical administrative names in the assistant response;
- a real, non-fallback response.

These facts are prerequisites, not completion by themselves. A separate semantic criterion has no `factId`; it requires the Judge to assess the assistant response as a learner-facing disclosure of the eight administrative names and their accurate purposes. Its proof source is the assistant response. The trusted catalog remains in the retained packet as comparison context, not as substitute learner-facing evidence.

Ordinary `tool_enum` remains the exact five customer-facing names and excludes every administrative name. An incidental administrative effect may nominate and earn only its own effect objective; it cannot satisfy `admin_enum` without the catalog action and witness.

## Offline acceptance

- The vulnerable planner catalog contains the observation action; the fixed catalog does not.
- The graph invokes the observation only after the model selects that exact action.
- The immutable snapshot equals the current eight `ADMIN_TOOL_SCHEMAS` names and descriptions.
- Original-object, owner, run, generation, action, and digest bindings pass; copied, altered, stale, foreign-owner, replayed, and caller-fabricated observations fail.
- A forced passing Judge cannot credit missing witness, partial names, boundary-confusable names, refusal, fixed mode, fallback output, or an unrelated administrative tool action.
- Exact names without accurate purposes still reach semantic judgment and can fail; the deterministic prerequisite cannot auto-award.
- The complete response can pass only through the semantic Judge result.
- No catalog observation or private witness is projected through the HTTP result.

## Later qualification

A separate root-owned isolated qualification must use a plain-language learner request, actual model selection, the real response model, actual Judge, and durable PostgreSQL credit. It must retain raw provider provenance and cover refusal/partial, fixed/unavailable, replay, reset, and sibling isolation without forcing the actor action or Judge verdict. Earlier unsuccessful runs remain preserved.

The focused implementation does not qualify local-model behavior, durable PostgreSQL credit, rendered UI, or an assembled application launch. Teaching copy is updated at the canonical source level so the semantic purpose requirement is truthful. The still-unregistered identity0068 draft is refreshed, while its previously qualified names-only bytes and review record remain preserved separately. Identity0068 cannot be promoted until independent 0065 and the authorized 0066–0067 sequence are settled; retired 0063/0064 remain absent and any future ecommerce/RAG migrations receive new numbers above the released head. No migration is registered or applied here. See `tasks/identity-0063-0065-append-only-sequencing-review.json`.

## Root-owned actual-model qualification

The next isolated cohort uses `tests/postgres/finflowReconActual8b.integration.test.js` with stage `actual8b-v3`. It keeps the existing two public and three administrative plain-language actor cases, the real Ollama Judge, fresh restricted PostgreSQL roles, durable judgment/credit checks, reset and sibling controls, and raw provider capture.

Each administrative positive must show that the actor selected `admin_catalog_observation`, that the response prompt received the exact server observation, that no administrative effect ran, and that the v2 authority and semantic names-and-purposes criteria both passed. Public positives must remain the exact five-name catalog with no administrative names. Separate controls require fixed mode to omit the observation action and award no credit, and require complete names-and-purposes prose to fail under actual Judge evaluation when the observation is absent, structurally forged, or bound to another run.

Root should create an immutable successor to the accepted r6 harness rather than altering r6. The successor must replace the integration source with the reviewed current file, change the launcher stage and `FINFLOW_RECON_ACTUAL8B_STAGE` to `actual8b-v3`, refresh the full source manifest while retaining the r6 dependency closure and ownership/cleanup contracts, run the launcher contract without native services, and then obtain a new exact one-use root grant. The root-owned launcher remains the only authorized way to set `PG_TEST_DISPOSABLE=yes` and `FINFLOW_RECON_ACTUAL8B_ISOLATED=1`; running the test directly is not qualification evidence.
