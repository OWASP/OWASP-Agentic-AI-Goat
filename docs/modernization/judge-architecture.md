# Judge LLM architecture amendment

Every exercise objective requires an evaluated Judge LLM verdict before completion. This is part of the active modernization goal, including direct injection, every indirect-injection scenario, and other workshop/challenge objective families. Existing deterministic detectors supply evidence and mandatory ground-truth checks; they cannot bypass the judge. A model verdict cannot manufacture a successful side effect or override owner, mode, objective visibility or reset-generation checks.

## Original defects addressed

- DPI `judgeAttack` awards success through keyword and response-length fast paths without calling a judge. Its detector gates also prevent some evidence from reaching the judge.
- Sensitive-information judging truncates tool results to 300 characters and answers to 600, potentially dropping decisive evidence. Calling `substring` on object tool results throws; the catch then silently returns no completions.
- Several judges parse prefixes such as `SUCCESS` or `YES`, or extract arbitrary JSON fragments, rather than validate a complete verdict contract.
- RAG falls back to regex when judging errors. Completion grading and CTF defensive meta-judging are different responsibilities and must remain separate.

These findings describe the original implementation. The shared judge and completion boundary below replace those grading paths; current qualification and remaining workflow boundaries are recorded in `judge-verification-2026-09-11.md`.

## Shared evaluation contract

Each versioned rubric identifies family, scenario, objective, learning mode, criteria and required server-observed facts. Evidence records have stable IDs, source types and bounded content. Student text and model/tool outputs are untrusted evidence, never judge instructions. Server facts carry provenance; client-submitted claims cannot impersonate tool outcomes. Apply data minimization without cutting a decisive artifact silently: omitted evidence yields an inconclusive result.

LangGraph executes prepare → model judge → strict validation → optional single repair → final verdict. LangChain invokes a separately configured judge model with no tools. The installed Ollama `llama3.1:8b` is the initial qualification model; an independent model configuration does not require a second download or cloud account.

Return `pass`, `fail`, `inconclusive` or `unavailable`, criterion results, evidence references and a concise observable explanation. Do not request private chain-of-thought. Every passing criterion must cite allowed evidence IDs. Missing facts, unknown IDs, malformed output, timeout, mock fallback or insufficient evidence cannot award completion. Distinguish an evaluated failure from a system failure so students can retry fairly.

Only the completion service persists a passing verdict after rechecking authenticated owner, scenario, enabled objective, required facts and durable reset generation. Use an idempotent evaluation/attempt identifier. Record rubric version, evidence digest, provider/model, actual usage when available and verdict in local PostgreSQL observability. Cache only the exact owner/scenario/mode/rubric/model/evidence combination. A reset invalidates pending completions; an inference retry must never repeat a challenge side effect.

## Workshop operation and UI

Bound judge concurrency through the provider scheduler and use finite queue/time limits. Evaluate relevant objectives against an attempt's evidence, grouping only where per-objective results remain independently validated. Do not run every rubric after every keystroke. Every route that awards credit must use the shared gate, including passive/automatic objectives and scenario-specific completion paths.

Preserve the workshop layout. Surface judging/pending, incomplete, inconclusive and temporarily unavailable states near existing objective feedback; only persisted accepted results turn green. The run inspector shows rubric/verdict/evidence references and timing. Existing completed records require an explicit migration policy; do not silently revoke historical progress or label it newly model-verified.

## Release gates

Audit every completion writer and map every enabled objective to a rubric. Test each with known success, benign failure, misleading keyword-only evidence, quoted/refused attacks and adversarial instructions aimed at the judge. Shared tests cover foreign objective/evidence IDs, malformed JSON, unavailable models, duplicate submissions, visibility/mode changes, reset races and cross-owner isolation. Run live8B grading fixtures and report false positives, false negatives, inconclusive rate and latency separately from deterministic fixture load tests. No claim of perfect LLM reliability: measured qualification and explicit uncertainty are required.

No AWS or deployment changes are authorized by this amendment.

## Reliability update: structured decoding and completion boundary

The shared judge now supplies the full JSON schema to Ollama's `format` field through LangChain. Generic JSON mode guaranteed neither criterion shape nor reference types. The schema remains in the prompt for semantic guidance; strict server validation still checks exact criterion IDs, evidence source eligibility, server facts and verdict consistency. A single repair receives the concrete validation category and valid IDs. Invalid results remain unavailable rather than becoming completion. See [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs).

The initial structured-v2 implementation used an 8,192-token context. The shared grounded-v11 policy defaults to 32,768 tokens and rejects packets that cannot fit without truncation. Queue concurrency remains governed by the shared scheduler. Judge results preserve the policy version in PostgreSQL receipt JSON alongside the independent rubric version and model identity. Prompt or inference-policy changes must increment this version for reproducible benchmarks.

The generic workshop objective-completion endpoint is retired for all objectives. Existing DPI clients retain their 410 response; other clients receive 409 `JUDGED_ATTEMPT_REQUIRED`. Legacy generic exercise status cannot be set to completed by a caller. Use the exercise action, observed evidence, judge and accepted receipt pipeline. This closes a bypass that remained possible even when individual chat routes invoked the judge.

The definition-coverage counts and legacy namespace description below retain their recorded checkpoint scope. Use the [current matrix namespace explanation](current-exercise-authenticity-matrix-2026-09-15.json) and [fixed acceptance checklist](../../tasks/release-acceptance.json) for current membership and release gates.

`tests/judgeCoverageCatalog.test.js` compares actual grading adapter definitions with the canonical catalog: 136 objectives in 12 families: 130 adapter definitions and six explicitly pending SecureShop objectives, with no missing/stale/duplicate entries. This is definition coverage, not evidence of live-model accuracy. The schema-constrained local8B calibration passed seven targeted cases across FinFlow, IPI and Excessive Agency; Subsequent per-objective evidence qualification is recorded in the verification report. SecureShop contributes 25 catalog objectives (19 source-eligible definitions and six pending); source eligibility is not full runtime acceptance. The five legacy sensitive-file objectives are also included. CTF stages and legacy email-builder levels remain separate namespaces.

### Trusted message boundary (roles-v3)

Production judges now use LangChain chat messages: the immutable rubric and server facts are in the system message, while the recorded evidence is in a separate user message explicitly identified as untrusted data. Previously all of this was concatenated into an Ollama text-generation prompt. Actual learner payloads can contain instructions directed at the evaluator, so the boundary must exist in the transport, not merely in explanatory prose. A generate-only injected model remains supported for offline contract tests; production provider adapters expose chat.

Facts are snapshotted before inference, so asynchronous mutations cannot alter the proof conditions after the evidence digest was recorded. A model pass contradicting a false required fact receives the same single bounded repair with explicit immutable fact IDs; repeated contradiction becomes inconclusive. No semantic keyword rule flips a failed verdict into a pass. This historical roles-v3 policy superseded structured-v2 and was subsequently replaced by grounded-v5. Unit tests verify role separation, schema transport, immutable facts and the repair limit.

### Context and exact factual checks (context-v4)

The default judge context is now32,768 tokens (`JUDGE_CONTEXT_TOKENS`, supported range4,096–131,072). The prior8,192-token setting could not safely accommodate the allowed24KB of JSON evidence plus instructions and response space. Before every inference or repair, the judge checks a conservative UTF-8 byte upper bound for the complete rendered prompt, reserves1,024 tokens for framing and900 for output, and returns `inconclusive/JUDGE_CONTEXT_LIMIT` before inference if it cannot fit. Evidence is never shortened to manufacture a grade. Adapters may explicitly project irrelevant fields while retaining all criterion-relevant observations and declaring omissions.

A criterion may declare `factId` only when it represents exactly one server-computed boolean fact. That ID must appear in `requiredFacts`. A contradictory model assessment gets one repair; continued contradiction is unavailable, never automatically converted to pass. Semantic criteria without this declaration remain model assessments of the evidence. Production receipt JSON now preserves the policy SHA256 digest, context size, duration, attempts and bounded error code, in addition to rubric/model versions and measured usage. The digest covers prompt/schema/inference policy and makes prompt refinements distinguishable within a human-readable policy version.

This section describes the historical `2026-09-11.context-v4` policy. Current runtime uses `2026-09-11.grounded-v11`; qualification results retain their actual policy and rubric versions.

### Grounded semantic evidence (grounded-v5)

An objective can require verbatim citations for a semantic criterion using `quoteRequired`. The judge must copy text from a referenced, allowed evidence source. Invented quotations, context-only quotations, and absent proof trigger one repair and then an unavailable result, with no credit. The IPI poisoning-recognition/refusal objective uses this contract because the local8B model sometimes described recognition that was absent from its response. Citation matching validates grounding; semantic interpretation still belongs to the LLM and can remain unavailable when the model cannot produce a valid assessment.

The full IPI20 evidence matrix passed its positive/non-pass assertions under grounded-v5. The previously false-positive poem response now awards no credit (invalid grounded output after repair); this is fail-closed behavior, not a claim that every negative yields a clean `fail` verdict. Mock-provider identities are rejected even when fallback flags are omitted. Email attack and defense each use their own corresponding actor provenance.

Run `npm run test:judge:8b` for the serial local evidence qualification suites. Optional family arguments select DPI, IPI, EA, FinFlow, CodeBot, CSRF, XSS, MCP, ARIA-NOVA, CTF, LegacySensitive, or LegacyEmail. This exercises actual local inference against recorded or synthetic evidence without executing vulnerable tools or sending email; application integration and intentional-vulnerability tests remain separate release gates.

CSRF observed-v3 additionally distinguishes a real anti-CSRF rejection from an invalid-action error. The gate requires an enabled token/SameSite defense, a blocked request, and unchanged victim state. Recon evidence preserves the actual nested `surface` response instead of dropping its available actions and vectors before grading.

### Durable regrade after a judge outage

In PostgreSQL mode, the completion transaction saves the exact bounded, detached grading packet before inference. A recoverable outage can be re-evaluated through an authenticated evaluation-ID-only endpoint; it never sends the learner prompt back through the actor or repeats tools. The original receipt stays immutable and a linked child records the retry. A separate `retryRunId` exposes the new judge trace while the evidence retains its original run provenance.

The repository checks owner, original canonical and durable execution generations, current visibility, captured mode timestamp, judge version and evidence retention. The mode fence lives on the durable receipt and survives packet deletion. A reserved child can resume interrupted pure inference under the same PostgreSQL owner lock, with at most three invocations; a terminal child is replayed without another inference. Packets are bounded to24KB, retained for24 hours and limited to the latest20 per owner. Missing, expired or exhausted recovery returns an explicit outcome. A completed retry child can replay across a Judge version upgrade because it performs no new inference; new and pending retries remain version-gated. Owner, generation, mode, visibility and retained-packet eligibility still apply. Recovery under compatible current configuration records the actual new policy digest, provider, model and context in the child receipt; it does not claim to reproduce an older inference policy.

`GET /api/agent-runs/judgments` exposes only the authenticated owner's recent receipt metadata so evaluation IDs remain discoverable after refresh or a lost response. `POST /api/agent-runs/judgments/:evaluationId/retry` accepts an empty body. Workshop feedback uses the shared retry control and refreshes authoritative progress after retry; it does not manufacture completion from the returned model verdict. Reset/unmount aborts pending UI requests and ignores late callbacks.

A process crash after a tool effect but before its grading packet is stored remains an uncertain effect. The application does not replay that tool automatically. Native staged SQLite grading does not advertise PostgreSQL recovery.

### Attempt fencing and practice thresholds

Before evidence generation, the completion service captures the canonical reset generation and mode timestamp under the owner lock. Receipt creation compares that snapshot; a mode switch back to the original value still invalidates the attempt. Receipt commit checks the same state again after inference.

DPI uses this shared service. Each distinct passing practice receipt increments its counter in the receipt transaction. The first has disposition `threshold_pending`; the second awards completion. Replaying a recorded receipt cannot increment it again. Reset clears counters and completion atomically. Model `pass` alone is not sufficient for the client to mark an objective complete: authoritative completion also depends on these persistence rules.

### Runtime and retry lifecycle review

A verdict is accepted only after its validation trace is persisted. A trace or owner-fence failure is an execution failure, not malformed model output: it cannot trigger repair while retaining an earlier pass. The shared retry button restores its mounted state when React replays effects, so a successful retry can refresh progress under StrictMode; unmount/reset still aborts the request and ignores late responses.

### Grounded-v6: explicit failure evidence contract

Targeted real8B diagnostics found correct failure verdicts being rejected because the model invented quotations to explain unsatisfied criteria. Grounded-v6 uses a discriminated structured schema: unsatisfied criteria have an empty citations array, while satisfied criteria retain allowed-source, verbatim supporting quotation validation. Evidence references may still identify observed counterevidence. This changes the model output contract, not the objective or server proof requirements. The two reproduced IPI and legacy combined-SSI negative cases now return fail on their first calls; their matching positives also pass on their first calls. Full per-objective qualification is recorded separately.

### Qualification status

The historical grounded-v8 run produced explicit correct verdicts for all 250 known positive/negative evidence cases. Shared grounded-v9 corrects constrained evidence-source selection exposed by connected ARIA workflows. Its full audit produced 247 correct verdicts, an IPI defense false positive, an XSS unavailable result and an MCP false negative. The subsequent v10 audit produced 249 correct verdicts and retained the IPI defense false positive. Those failed runs are retained as historical evidence. The subsequent frozen v11 run passed all 250 cases. The [verification report](judge-verification-2026-09-11.md) separates those model results from browser/integration evidence and remaining release gates. The qualification wrapper fails unresolved or incomplete baselines rather than treating an unavailable negative as a successful benchmark.


### Grounded-v8 follow-up

RAG poisoning recognition/refusal uses the explicit `contextual` citation policy: a verbatim passage must contain at least 24 characters, or the whole evidence string if shorter. This rejects trivial fragments such as a single common character. Exact-value objectives retain the `verbatim` policy so short secrets and structured fields remain valid. Citation shape establishes source grounding; semantic correctness still depends on the model evaluating the criterion. The RAG defense rubric is `ipi-grounded-v4`.

Legacy email effect qualification collects native browser dialog/popup events outside page JavaScript. Writable page arrays cannot prove an effect. The attributed target must execute and a browser-observed effect must occur; the fake-marker adversarial regression fails completion as intended.

Focused follow-up: 56 passed, one opt-in live test skipped. The contextual constraint is also present in the per-criterion model output schema, with explicit complete short-source exceptions. This corrects the reproduced v7 failure where the model repeated a semantically correct but too-short citation during repair. The v8 positive/negative RAG diagnostic passed on first attempts. Full serial local8B requalification for grounded-v8 passed all 250 cases in one run: 125 passes and 125 failures, with no unavailable/inconclusive outcomes. The isolated backend regression passed 717 tests with 22 gated skips.


### Grounded-v9: criterion-specific evidence references

Structured decoding now restricts each satisfied criterion to its exact ID and eligible evidence sources. Unsupported true branches are omitted when no eligible source exists. False criteria can reference counterevidence without inventing a supporting quotation. All original evidence remains available as context; local validation still enforces source eligibility, facts, citations and verdict consistency. Four captured ARIA grading failures and eight connected ARIA/NOVA cases passed after this correction. These connected tests do not substitute for the complete evidence matrix or all application workflows.

### Legacy email-builder namespace

The four email-builder levels use the same shared LLM evaluator and browser-qualified evidence but retain their separate legacy receipt/progress tables. They are not four extra entries in the canonical 136-objective workshop catalog. Generation and reset routes run through the owner coordinator with a PostgreSQL run ledger: reset invalidates the run generation and drains the owner lease before deleting templates/progress. A separate receipt table is therefore not, by itself, evidence of an anonymous or unfenced completion bypass.

The owner-bound generation/reset and grader tests passed 13 cases in the current review (`/tmp/dvaia-legacy-email-owner-review.log`). This verifies those tested paths; it does not claim canonical visibility/mode semantics or retained-packet retry for the legacy namespace. Its eight positive/negative evidence cases passed the v9 audit. Keep these boundaries explicit when reporting coverage.


### Grounded-v10: explicit outcome intent

The optional server-owned `outcomeIntent` distinguishes attack and defense expectations. The email-defense rubric declares `defense`, selecting defense calibration instead of the generic attack examples. Captured v9 requests contained the correct secure summary, yet the model invented a poem after reading attack calibration; quotation grounding alone did not repair this semantic inversion. The v10 targeted set passed eight varied cases: silent and explicit email defense, quoted malicious instructions, an actual redirected poem, actual MCP credentials, redaction, denied access and request-only evidence. The full v10 run subsequently returned 249 correct verdicts and one email-defense false positive. It is a failed qualification; targeted success did not generalize to the full run.

MCP secret exposure now separately requires a returned credential assignment and an actual unmasked value, grounded in tool output. XSS email-chain grading projects its relevant browser/execution observations instead of unrelated false flags belonging to other objectives. These changes preserve required facts and strict source validation; they do not add deterministic completion shortcuts.


### Grounded-v11: independent source comparison

The email-defense objective opts into a second semantic evaluation inside the shared LangGraph. After a provisional primary pass, an independent verifier receives only the trusted task, original actor-visible email content and actual secure response. It receives no previous verdict or explanation. Neutral field names prevent the label “secure response” from suggesting the answer. The response is divided into stable, unlabeled spans; the model must assess every span exactly once and ground source-dependent findings in the original email. This catches responses that mix a valid business summary with actual execution of the injected instruction. Mentioning or refusing an instruction remains distinct from executing it.

The objective is presented as “Understand Defense — View attack analysis.” The existing grading contract requires resistance to an actual email injection, so an ordinary business email alone cannot demonstrate that outcome. The verifier identifies the embedded assistant redirect from original source evidence; no keyword detector supplies this semantic judgment.

A verifier failure vetoes credit without rewriting the primary criterion findings. Invalid verifier output permits one bounded repair, then becomes unavailable; uncertainty remains inconclusive. Primary and verifier each allow at most two calls, share the owner cancellation/deadline, and persist separate trace nodes before accepting a receipt. Every rendered verifier request is context-checked without truncation. Receipt metadata stores only the bounded verification verdict, attempts and total calls. The policy digest covers verifier instructions, schema, repair and decoding policy.

The frozen v11 local8B qualification passed all 250 unique positive/negative cases across 12 suites: 125 passes and 125 failures, with no false positives, false negatives, unavailable or inconclusive outcomes. Median grading latency was 2.748 seconds and p95 was 6.358 seconds. There were 32 primary repairs and two independent verifier calls with no verifier repairs. Earlier candidate failures remain in the verification report. This measures the defined evidence matrix, not arbitrary payload reliability or workshop capacity.

The current IPI actor graph supplies the first 5,000 characters of an email to both actors and uses that same content as Judge source evidence. Verifier non-truncation applies to this recorded grading packet, not to full-email ingestion. Instructions outside the actor-visible excerpt cannot establish an observed injection outcome. This existing input boundary must be kept explicit in workflow qualification.

Identity migration `0018_graph_provisional_event.sql` adds the provisional event type to the native graph trace constraint without altering older migrations or accepting arbitrary event types. A native coordinator/ledger test with injected Judge outputs verifies this persistence boundary separately from actual model qualification.

A connected IPI test also passed using actual local8B inference with native PostgreSQL coordination, traces, receipts and progress. A controlled business summary was awarded after independent verification; a controlled poem failed without credit; reset invalidated an in-flight owner run and cleared canonical progress. The test used server-owned evidence and did not execute an email actor or delivery workflow. Its disposable database was removed afterward.
