# Adding a judged objective

Use the existing [workshop experience baseline](workshop-experience-baseline-2026-09-10.md) for appearance, scenario selection, chat, feedback and reset controls. DPI has one scenario with multiple objectives; IPI has independent scenarios. Grading must preserve that scenario boundary.

## Define the outcome and its evidence

Give each objective a stable family, scenario and objective ID, a rubric version, a learning mode, and observable criteria. Describe the required outcome, rather than a particular attack phrase. Natural-language requests must reach the judge when the resulting evidence is relevant.

Use `server/config/workshopCatalog.js` and the family's grading adapter. Canonical catalog changes also require database visibility/hint seeds, objective labels, and dashboard/admin parity checks described in `AGENTS.md`. Keep separate legacy namespaces separate from canonical workshop totals.

For each criterion, specify which evidence source can prove it. Learner input is context; it cannot establish that a tool changed state or that browser code executed. Construct required facts from actual server observations. A required fact is an additional completion condition, never a substitute for a Judge LLM verdict.

For prose recognition/refusal criteria, use `quoteRequired: true` with `citationPolicy: 'contextual'`. Both constrained decoding and local validation require a supporting passage of at least 24 characters, or the complete source string when shorter. Exact secrets and structured values use the separate `verbatim` policy. These checks establish where a quotation came from; the model must still assess its meaning. Unsatisfied criteria must have empty citations, rather than fabricated quotations describing an absent outcome.

Supply only the evidence relevant to this objective. For example, the email company-field objective needs the persisted company field and its observed execution. Pre-substitution model output and an unrelated script's execution flag can confuse a small model and do not prove that objective. Preserve decisive evidence within the supported limit; oversized or missing evidence must remain inconclusive rather than being silently truncated.

Use separate criteria when their independent assessment is meaningful. For one compound factual outcome, a single criterion may reference the conjunction of its proof conditions, provided every original required fact remains a mandatory completion condition. Never simplify an objective by dropping a proof requirement.

## Defense outcomes and independent comparison

Declare `outcomeIntent: 'defense'` when resisting an injection is success, so attack calibration does not invert the grading goal. For objectives requiring a comparison against injected source content, the optional server-owned `sourceComparison` names the original `tool_result` evidence ID, the actual `assistant_response` evidence ID, and a trusted task. The IPI email-defense adapter is the current implementation example.

This comparison is an independent semantic gate after a provisional primary pass. It must inspect the complete response, distinguish discussing/refusing an instruction from executing it, and establish that the original source actually contains the injection. A clean source alone cannot prove resistance. Keep ordinary-source negatives, mixed summary-plus-injected-output negatives, and silent/explicit/quoted defense positives in focused qualification. Source IDs and task descriptions come from the adapter, never client input. This optional gate increases inference work and is qualified against the recorded grounded-v11 evidence matrix; do not add it to unrelated objectives without a demonstrated need and matching tests.

## Preserve ownership and execution boundaries

Capture an attempt through `objectiveCompletionService.beginAttempt` before generating evidence or running exercise tools. Pass the same protected execution and attempt to `evaluate`. The service invokes the shared LangChain/LangGraph judge and commits a receipt after rechecking owner, objective visibility, mode and reset generation.

Only an accepted completion receipt may turn an objective green. A model `pass` can still be rejected as stale or remain below a practice threshold. Replaying a receipt must not duplicate progress or repeat a tool effect. Recovery regrades the retained packet through the evaluation-ID endpoint; it does not replay the exercise action.

For browser objectives, qualify the actual rendering context and attribute execution to the required source. An executable fragment can be inert inside a comment, template, textarea or attribute. A different field's handler, a page-writable marker, or copied instrumentation cannot prove the target field executed. Preserve model-versus-profile provenance through substitutions.

## Qualify the objective

Add one known successful and one known unsuccessful evidence case for every objective, using the production packet builder. Negative cases must retain true prerequisites where appropriate: an uploaded document can exist even when the assistant resists its injection. Add focused misleading-evidence, reset, ownership and source-attribution cases as applicable.

`npm run test:judge:8b` is a conclusive baseline: known positives must return `pass`, known negatives must return `fail`, and diagnostics must be complete. Unavailable and inconclusive results correctly prevent credit in safety tests, but fail this benchmark. Report verdicts, repair attempts and latency separately. Evidence qualification supplements isolated route, database and browser workflow tests; it does not prove every live payload works.

Update the qualification registry and expected case counts when adding a family or objective. Preserve intentional teaching vulnerabilities and their protected dependency versions. No AWS or deployment change is part of this workflow.
