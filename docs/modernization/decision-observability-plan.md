# Model decisions and graph observability — implementation amendment

This amendment implements the user's September10 clarification. LangChain and LangGraph must govern actual agent decisions and observable execution. Merely wrapping an existing regular-expression dispatcher or a single provider request in graph nodes does not satisfy the goal.

## Execution design

LangChain owns provider messages, typed tool contracts and structured model decisions. For tool-using agents, the model selects the tool and arguments from the exercise's tool catalog. The decision contains a short action explanation suitable for the learner; the application does not request, store or display private chain-of-thought. Deterministic authentication, ownership, input-shape validation, resource limits and objective ground-truth checks remain application responsibilities.

LangGraph owns state transitions: load owner/scenario context → model decision → validate → conditional tool dispatch or direct response → observe result → optional bounded repair/next decision → final response → persist. Graph state includes run/scenario identifiers, messages, selected action, execution result, counters and outcome. Credentials stay in provider configuration outside graph state. Each family may use different nodes, but its meaningful branches must appear in the graph and event timeline.

Malformed or unsupported model decisions get at most a documented bounded repair attempt. On exhaustion, report a visible failed/no-action outcome. Do not silently execute a regex-selected action while presenting it as a model decision. Existing deterministic dispatch remains available for explicitly labeled mock fixtures or simulations whose teaching contract requires it. Deterministic grading can verify an exploit outcome without pretending to be model reasoning. Vulnerable tool implementations and permissive challenge boundaries remain intact.

Ollama8B is a required real-provider qualification target. Exercise native tool calls where supported and structured model-produced JSON where the model needs it; both must demonstrate that model output selects the executed action. Verify at least two different actions, a no-tool response, an invalid decision/repair outcome, and an intentional attack outcome. Provider/model/decision source must be recorded. A successful HTTP completion alone is insufficient.

## Local observability contract

Local PostgreSQL storage is authoritative and works without cloud accounts. A run record carries `runId`, authenticated owner ID, family, scenario, generation, status, provider/model, decision source, start/end timestamps and measured usage. A node event carries a stable sequence, node name, event kind, timestamp, duration, tool/action name, validation/outcome and sanitized error code. Usage that the provider does not report is unavailable, not zero. Estimated usage must be labeled separately.

Record start/end/error events for real node execution, model decisions, tool calls/results, repair attempts, cancellations and resets. Link graph-level events to the actual model and tool calls. Metadata is the default; optional local exercise evidence must have bounded size, explicit ownership and retention, render as escaped text, and never include provider secrets/auth headers. Teaching payloads still flow unchanged through their intended vulnerable sinks.

HTTP read interface, mounted behind platform authentication:

- `GET /api/agent-runs?limit=25&before=<opaque-cursor>` → `{runs,nextCursor}` for the authenticated attendee.
- `GET /api/agent-runs/:runId` → `{run,events,nextCursor,graph}` after owner verification; unknown or another attendee's run returns404.
- `GET /api/agent-runs/:runId/events?after=<sequence>&limit=100` → ordered incremental events with bounded paging.
- `GET /api/admin/agent-runs?...` and corresponding detail/events routes require the existing administrator analytics permission. Admin ownership filters apply only here.

The local inspector preserves the current palette/components. Learners inspect their runs and decision/tool timeline; administrators inspect workshop runs under existing RBAC. Display structured action explanations and observable evidence, not hidden reasoning. Poll the existing HTTP model; do not introduce WebSocket infrastructure. Graph topology comes from the executing runtime's registered graph description, not a fabricated static diagram.

LangSmith export is optional and off by default. Document that LangChain/LangGraph need no keys, while LangSmith export uses the user's own `LANGSMITH_API_KEY`, project and endpoint configuration. Explicit opt-in controls content export; the local inspector remains functional without it. No credentials are committed or generated on behalf of the user.

## Persistence, concurrency and replay

Separate bounded graph lease connections from identity/control queries, so long inference calls cannot exhaust the authentication/reset pool. Acquisition must honor cancellation and limits. Reset increments durable generation before draining active owner work; stale nodes cannot publish progress or responses afterward. Effect identifiers and uncertain outcomes prevent automatic duplicate external/tool side effects after failure or restart. Checkpoint/resume is enabled only where state and effect replay rules are defined and tested; an ambiguous external effect requires reconciliation instead of blind retry.

Trace retention and pagination must bound laptop storage and query cost. Run events, checkpoints and teaching datasets have separate lifecycles. Reset behavior is explicit: exercise reset clears its state/progress and cancels runs, while observability retains a reset/cancelled record for debugging until normal retention expires. Administrative purge is a distinct authenticated operation.

## Revised sequence and ownership

1. Update written goal and inventory; classify existing families as model-driven, scripted simulation, deterministic grading or incomplete. Keep stack/UX/storage work already verified.
2. Runtime agent: implement real ARIA/NOVA decision graphs, durable execution/event contracts and live8B tests; apply the proven pattern to other agent families.
3. Database agent: finish the in-flight native PostgreSQL slice, then adversarially review event ownership, retention, lease saturation, reset and restart semantics.
4. Root: implement owner/admin observability read APIs and integrate graph contracts with the application. UI agent: implement the local inspector and browser verification using those APIs.
5. Finish remaining PostgreSQL challenge migrations and remove temporary engine paths. Repeat complete install/build/integration/exploit suites after integration settles.
6. Independent qualification proves model decisions drive different branches, stored events match actual execution, forbidden cross-owner reads fail, restart/reset never duplicates effects, and200-attendee control traffic stays responsive. Report real8B throughput separately from mock workload capacity.

No AWS, CloudFormation, deployment workflow or existing cloud image changes are introduced by this amendment.

## MCP decision checkpoint — September 11

The workshop MCP graph now chooses tools through a constrained model decision for real providers, with two bounded validation attempts and raw string arguments. Only explicit mock mode uses the regex simulation. Every graph node awaits metadata-only traces. The nested poisoned-tool/ticket compliance path also requires a valid model choice; malformed, fallback or unavailable output cannot authorize effects. Unavailable compliance returns before sandbox effects and is distinguished from a genuine model refusal. Existing intentionally vulnerable sandbox implementations are preserved.

Targeted local llama3.1:8b checks selected list_tools/none and accepted/declined aligned harmless compliance requests; no external tool effects ran. Focused compatibility passed8 tests with one gated live-Judge skip. These checks do not prove all11 live MCP exploit workflows. The subsequent checkpoint below records CSRF model dispatch and the remaining-family node trace implementation; complete live exploit qualification remains release work.

## Remaining-family trace and CSRF checkpoint

Excessive Agency, XSS, RAG queries and indirect email now await metadata-only node start/end/error traces and forward cancellation to model calls. A failed start trace prevents the node's external effect. Focused tests cover all four graphs, bounded error metadata, and unchanged results. CSRF inbox and RAG paths also expose these traces; their forge nodes explicitly use `decisionSource: lab_gadget_interpreter`. Their existing objective rubrics grade this deterministic lab interpreter, not independent browser execution or proof that a model emitted a gadget. The deliberately vulnerable interpreter is preserved.

The main CSRF agent now uses a constrained model-selected intent/action/vector and preserves explicit mock routing separately. Parameter qualification exposed omitted destinations and invented unrelated arguments from local8B. Per-action schemas now reject unrelated fields and bind explicit quoted or structured-JSON parameters through required constants plus local validation. Both failing transfer/add-payee cases now preserve every requested field; no effects ran. Final tests also reject malformed containers, conflicting bindings and nonfinite numeric values. These tests qualify the recorded explicit-argument cases, not universal natural-language argument extraction.

Verification: final CSRF/trace/review suite26/26 passed; the earlier isolated backend snapshot passed771 with22 gated skips and zero failures. Local8B recon/no-action and corrected transfer/add-payee decision cases passed. Full end-to-end CSRF exploit and release qualification remains separate.
