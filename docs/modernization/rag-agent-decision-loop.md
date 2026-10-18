# RAG model decision loop

## Confirmed current gap

`server/agent-runtime/ragQueryGraph.js` implements a real LangGraph pipeline,
but its edges always retrieve, prepare, generate and grade. The model produces
the answer; it does not choose retrieval or decide whether observations require
another tool call. Do not describe this as a model-selected tool loop. Document
ingestion is correctly a deterministic workflow and does not need an invented
agent decision.

The user's agentic architecture requirement calls for a bounded decision loop
for the conversational document agent. Durable storage is a prerequisite for
reliable retrieval provenance, not a replacement for this decision layer.

## Intended behavior

Keep the existing document upload, objective selection, question, answer,
retrieved-chunk and Judge UI. Replace only query orchestration:

1. Admit the existing owner/family/run/generation scope and resolve the selected
   durable document. Bind its immutable source manifest before model execution.
2. Ask the configured actual model for one schema-validated action:
   `search_document` with query and bounded topK, or `answer` with final text.
   Owner, document, generation, revision and policy are server context, never
   model-controlled tool arguments. Use actual LangChain structured tools.
3. Execute an admitted search through the durable repository facade. Capture
   exact selected query, source/chunk hashes, revision/fingerprint, scores and
   ordered output in the run's private evidence. Present the untrusted chunks to
   the next decision call under the exercise's existing vulnerable/fixed policy.
4. Let the model choose another search or final answer from those observations.
   Limit successful searches to three, permit one schema-repair attempt per
   decision and terminate duplicate identical searches. Resource ceilings and
   cancellation remain in the shared coordinator, not an independent timer.
5. Grade the raw final model answer and matching observations with the existing
   canonical objective Judge. A direct answer with no successful retrieval may
   be displayed but cannot earn a retrieval-dependent objective. Do not force a
   tool call or substitute a scripted answer to make an objective pass.

Preserve the distinct pedagogy: clean policy grounding; identification and
refusal of malicious document instructions; and observing a model following
untrusted document instructions. The active objective selects the configured
policy and rubric, not a fabricated outcome. Model-selected search terms may
miss the attack; record that as the actual result. Do not use the filename or
hidden pattern matching to force a successful retrieval or answer.

## Failure and ownership rules

Schema-invalid/model-unavailable output fails with actionable status and no
credit. Do not fall back to a regex tool selector. A search failure remains a
failed observation, not empty successful context. Missing source or stale
resource generation terminates the run; an embedding-runtime transition may
rebuild from exact stored chunks only under the durable publication protocol.

Check authority before every model/tool call, after each awaited operation and
at canonical credit publication. Reset/deletion prevents late effects or credit;
retain immutable bounded trace metadata according to existing privacy rules.
Distinguish model decisions, actual retrieval effects and Judge decisions in
agent-run details. Never put credentials or unrelated owner text in traces.

## Required proof before promotion

- Controlled model decisions demonstrate search → observation → second search
  or answer, exact argument execution, schema repair/budget/duplicate termination
  and cancellation. Scripted providers receive no genuine-model credit.
- Native PostgreSQL proof binds every retrieval to exact owner/family/document,
  source digest and runtime revision; restart/two-process and reset/deletion
  races cannot resurrect old selections or publish late results.
- Actual local llama3.1:8b runs cover clean grounding, malicious-document refusal
  and instruction following; independent Judge outcomes match observed results.
  Keep unsuccessful attacks negative rather than changing prompts until tests
  award invented completion.
- Existing objective catalog, instructor hint/solution gates, canonical totals,
  progress and UI layout remain consistent. Render the same question/answer flow
  and useful ordered decision/tool/Judge information on agent-run views.

The optional durable query branch now uses `ragDecisionLoop.js` and `ragDecisions.js`. The production route does not supply the durable facade yet, so its fixed pipeline remains active. The combined copied-source cohort passed 74 controlled checks; see `tasks/rag-decision-loop-staged-2026-09-19.json`. Actual model qualification currently covers only the decision primitive with synthetic observations. Native durable retrieval, integrated actual-model/Judge credit and rendered acceptance remain required.
