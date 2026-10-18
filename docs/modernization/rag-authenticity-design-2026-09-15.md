# RAG exercise authenticity correction

## Evidence and problem

Actual model-only cohort r2 retained 29 provider calls across eight cases. Both clean and poisoned sources under the same vulnerable policy produced grounded answers or missing-content refusals, not the attacker effect. The fixed recipe response followed a recipe explicitly requested by the learner, so it cannot establish indirect injection. Evidence: `tasks/ipi-rag-payload-r2-native-root-review.json`.

Source review found that the vulnerable graph labels retrieved observations as untrusted document data. The fixed filter misses both shipped multiline poisoned examples because their redirect and command occur on separate lines. Together with the off-topic learner query, these boundaries do not support the advertised teaching contrast.

## Intended application change

Keep the existing page structure, colors, controls and objective layout. Preserve the real LangGraph decision loop and per-owner retrieval/reset boundaries. For the intentionally vulnerable scenario only, demonstrate the concrete trust error of placing model-selected retrieved bytes into trusted/system knowledge context. Do not script a tool selection, tell the model to output the test marker, or manufacture a response. The attacker-controlled document carries its own instruction.

Fixed mode keeps retrieved bytes explicitly untrusted, filters the supported controlled attack forms, records the original bytes and filter observation for evaluation, and requires answers to remain grounded in retrieved content. If there is no supporting content, the assistant must abstain. Filtering has a documented limited scope; regex matching is not proof of general prompt-injection resistance.

Use one legitimate on-topic task, such as summarizing remote-work eligibility and core hours. Pair clean and poisoned sources differing only in an attacker instruction located in the same retrievable chunk. The learner must not directly request the attacker effect.

## Acceptance

- Clean vulnerable and fixed controls return grounded business information with no false attack claim.
- Poisoned vulnerable case must actually execute the unrelated attacker instruction for positive exploit qualification. A legal refusal or early answer without exposure is retained as no credit/not exposed, not an infrastructure failure.
- The same poisoned fixed case must show source-bound detection/refusal and no attacker effect under the current objective contract.
- Actual source/effect Judge calls and durable credit remain separate from protocol validity. No credit from lexical matches alone or scripted/mock output.
- Model-only evidence does not qualify upload, embedding or storage. A mounted follow-up must ingest the real file, retain selected chunk identity and bytes, run the actual actor/Judge, and verify saved completion, admin/dashboard parity and owner reset/sibling isolation.
- Update sample text, query prefill and managed hints/solutions together only after the candidate is qualified. Preserve instructor-authored content through provenance-aware migrations.

Status: approved private implementation direction; not promoted or qualified.
