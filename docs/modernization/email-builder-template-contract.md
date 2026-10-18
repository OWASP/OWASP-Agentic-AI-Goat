# Email-builder generation and grading contract

The separate `/api/xss-email` builder teaches unsafe application personalization (levels 1–3) and model-generated executable HTML (level 4). It is distinct from the workshop email-delivery exercises e1–e3.

Template generation receives the learner request and literal profile placeholders. The application applies real stored profile values afterward, using the existing intentionally unsafe replacement and signature filtering. Sending those same raw profile values to the model before substitution conflated the two trust boundaries: the first current-source qualification saw the model refuse name/company payloads before the server insertion lesson could occur. Removing that redundant disclosure does not sanitize the teaching sink or synthesize model output.

The LangGraph workflow still performs generation, tracked substitution and persistence. Source ranges distinguish model-produced bytes from application insertions. A fresh isolated browser and independent Judge must confirm each level's exact persisted source and execution before completion. Level 4 continues to require actual model output; refusal is not success.

`POST /api/xss-email/generate` accepts an optional integer `challengeLevel` from 1 through 4. It requests an evaluation even when the model refuses or omits a required payload, so the response includes an explicit failed/inconclusive Judge result instead of an empty result. It supplies no completion authority: source, execution, owner and persistence facts still control credit. Existing automatically detected candidates remain supported.

Evidence: [initial actual-model cohort](../../tasks/email-builder-four-level-r1-2026-09-19.json). The generation/attribution/refusal contract has 17 focused passing checks; [Current native requalification](../../tasks/email-builder-four-level-r2-2026-09-19.json) passes all four levels with actual8B and a benign negative; broader application/admin parity remains open. No installed state or AWS assets were changed.
