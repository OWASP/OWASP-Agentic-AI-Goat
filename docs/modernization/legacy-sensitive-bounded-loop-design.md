# Legacy file/SSI bounded decision-loop repair

The existing candidate performs one model-selected tool call and one model explanation. Replace that file/SSI flow with a bounded LangGraph loop so the model can use an observed result to choose another operation or finish. Preserve the teaching tools, exact selected path/template bytes, existing page and route response, and owner/run/reset authority. Leave the shared single-hop graph untouched because other staged consumers have separate qualification requirements.

## Flow and state

Use a dedicated graph: decide → validate → execute → record observation → decide. A structured `finish` decision leads to a separate final response node; the configured model receives the ordered actual observations and must describe only those effects. At most three tool calls are allowed. After the third observation, allow a final decision to finish; another requested tool ends with an explicit noncredit limit outcome. Never silently convert a requested fourth action into successful completion.

Each tool hop carries a server-issued ordinal, exact decision digest, previous-hop digest, owner/run/generation-bound durable receipt and immutable observation. Include the ordinal in the effect identity so two equal calls at different steps cannot accidentally replay the same receipt. Validate receipt binding before admitting its observation to another model call. Apply byte limits to the request, individual messages, observations and accumulated trajectory before later inference. Preserve the entire ordered trajectory in evidence; keep the last completed tool projection for existing consumers until objective grading explicitly supports multiple matching effects.

Every model and effect boundary checks authoritative execution/cancellation before and after work. A later failure does not roll back an already completed effect or permit later grading. Qualification comes from the configured provider's issued response identity, not self-reported metadata. Tool data remains untrusted in prompts. SSI simulated commands must remain explicitly described as simulated; this change does not authorize host command execution or private file access.

## Application and grading

A model may finish without any tool: return an ordinary noncredit answer with no observed objective, rather than manufacturing a tool invocation. A limit outcome or unqualified model cannot earn credit. A completed run must bind its final response and exact selected effect to the current attempt. Do not award two different objectives from one receipt or promote a partial trajectory into a completed run. Review and qualify grading of multiple eligible hops before claiming all effects can complete their respective objectives in one chat turn.

## Required evidence

- Two different model decisions with the second consuming the first actual observation, followed by model-selected finish and a grounded response.
- Legitimate zero-tool finish and one-tool finish; exact argument preservation.
- Same arguments at two steps have distinct effect identities and correct chain links.
- Wrong owner/run/generation/receipt, scripted/fallback responses, invalid actions, byte limits and repeated-tool limits prevent later work or credit.
- Cancellation after observation prevents the next decision or final response; retain the completed effect receipt.
- Production adapter phase qualification remains one-use per actual model response.
- Actual local8B actor/Judge and isolated file/SSI effects, then connected owner/reset/route and rendered regression. Controlled graph tests alone do not qualify the exercise.

No live activation, migration promotion, learner-data change or AWS/deployment change is part of this graph repair.

## Teaching-root configuration verification

Constructor validation now requires a real public subdirectory inside the real teaching root and a real file base within that root. This prevents a misconfigured external public directory from manufacturing protected-read evidence while preserving traversal into protected lab files. Nine focused tools/composition checks pass and independent review found no new blocker. These are static application-owned fixtures: learners must not have filesystem write authority over their ancestor directories. The realpath/open checks do not constitute a sandbox against a concurrent hostile filesystem writer.

## September 16 observed runtime repairs

The first actual8B cohort exposed a PostgreSQL trace contract error: finish emitted an unsupported event type. Finish now emits a supported decision event with termination metadata; the original failed cohort remains retained. Failure reports distinguish model, validation and infrastructure stages and query persisted effects when no graph result returns.

A follow-up source review found that the agent adapter discarded the graph’s remaining-tool allowance. Each decision prompt must receive that exact allowance and distinguish already completed work from pending work. This improves the model’s view of its current state without choosing its next action or converting a limit outcome into success. Test every allowance from three through zero and retain exact observation bytes. No context-truncation claim is established by the first cohort. Actual-model solvability remains a separate acceptance gate.

## Decision interface consistency

Use one decision catalog for both parser validation and model-facing available actions, including `finish` as a control decision. Retain a derived tool-only catalog for objective facts so finishing can never count as tool use. Accept only own catalog keys. Model-facing history contains each completed hop’s ordinal, exact decision and exact observation; prior model JSON, receipt identities and hashes remain in immutable evidence rather than being repeated as tool observations. This changes neither effects nor grading authority. Controlled tests establish catalog/projection correctness; actual8B completion remains unqualified.

## Conversational decision interface follow-up

Actual8B r3 still repeated reads. This does not prove flattened prompts caused the failure, but the next candidate will use the existing LangChain chat transport so model decisions and subsequent observations have explicit conversational roles. Server-owned system content contains the policy, complete decision catalog and exact remaining budget. The original request is a user turn; each validated selected action is an assistant JSON turn followed by a user turn containing the exact completed observation. Terminal response generation includes the model-selected finish and a request to explain actual results.

Call `transport.chat(messages, [], options)` without native tool schemas. Do not fabricate native tool-call metadata or emit unmatched tool-role messages. Retain immutable complete evidence outside the model-facing projection, phase-specific one-use qualification, cancellation and option propagation. Snapshot message inputs before awaits and measure serialized message bytes for observability. Verify actual LangChain role conversion, empty tool schemas, exact observations, final-response sequencing and all existing forged/reused-receipt denials before actual8B qualification.

## Tool affordance clarification

The model-facing catalog must describe actual argument semantics. The reader returns exact text in content on success and no content on denial, with documented teaching-root aliases and bounded parent traversal. The SSI renderer accepts literal inline text: a bare filename is not loaded. Reading a file and rendering its contents are separate model-selected actions. Include directives can read owned files inside a render but are not separate model-selected calls. Exec output remains simulated. These are truthful tool contracts, not server-selected next actions; no arguments are rewritten and no effect or Judge gate is weakened. A real-file test proves filename passthrough versus explicit read/render. The failed model reports do not reveal raw arguments, so this clarification is not proof of what caused the prior model choices.

## Reviewed optional artifact-reference design (not implemented)

For long templates, requiring the model to re-emit all previously read text consumes output tokens and risks byte changes. A separate model-selectable `render_ssi_observation({sourceOrdinal})` could resolve captured text from a successful completed read in this run. Keep literal template mode for direct SSI exercises. The reference is a scoped lookup, not authorization: check owner/run/generation, completed receipt and cancellation against the immutable run trajectory; never resolve a caller-supplied external identity or shared cache. Do not reread a mutable file.

Evidence must retain the actual selected reference, source-hop digest, resolved-template hash and completed render receipt. Grading currently reads decision.params.template and would need a separate server-resolved evidence path; it must not mistake a reference for an executed template. Qualification must cover two available source choices, exact bytes, failed/forged/out-of-range/stale references, cross-owner/run/generation rejection, reset races, preserved literal mode and no credit without matching evidence. This is an architectural option, not proof of the existing model failure’s cause or a qualified implementation.
