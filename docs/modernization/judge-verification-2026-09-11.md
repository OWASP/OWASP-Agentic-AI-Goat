# Judge qualification — September 11, 2026

The frozen `2026-09-11.grounded-v11` Judge passed one complete, exclusive local Ollama `llama3.1:8b` run: **250/250 correct explicit verdicts**, comprising 125 passes and 125 failures. There were no false positives, false negatives, unavailable results, inconclusive results, duplicate cases or missing diagnostics. The process exited 0.

These are recorded/synthetic evidence tests using a real model, not proof that every possible live payload succeeds. The 106 canonical objectives account for 212 cases; 19 objectives in separate namespaces account for the other 38. Separate namespaces do not inflate dashboard totals.

| Family | Objectives | Cases | Correct |
| --- | ---: | ---: | ---: |
| DPI | 8 | 16 | 16 |
| IPI | 10 | 20 | 20 |
| Excessive Agency | 9 | 18 | 18 |
| FinFlow | 18 | 36 | 36 |
| CodeBot | 6 | 12 | 12 |
| CSRF | 12 | 24 | 24 |
| XSS | 12 | 24 | 24 |
| MCP | 11 | 22 | 22 |
| ARIA | 10 | 20 | 20 |
| NOVA | 10 | 20 | 20 |
| CTF, separate namespace | 10 | 20 | 20 |
| Legacy sensitive-info | 5 | 10 | 10 |
| Legacy email builder | 4 | 8 | 8 |

Observed Judge latency was **2,748 ms median, 6,358 ms p95 and 10,642 ms maximum**. There were 32 primary repair calls. Two provisional IPI assessments used the independent verifier, with one call each and no verifier repairs. These serial measurements are not a 200-attendee model-capacity claim.

The [machine-readable report](judge-qualification-2026-09-11.json) records family counts, rubric versions, repairs, verification calls and diagnostic completeness. Run log: `/tmp/owasp-ai-goat-judge-v11-full-8b.log`. Recomputed summary: `/tmp/owasp-ai-goat-judge-v11-summary.json`.

```bash
node scripts/test-judge-8b.js
node scripts/summarize-judge-log.js /tmp/owasp-ai-goat-judge-v11-full-8b.log
```

## What changed and why

The v9 schema restricted every satisfied criterion to eligible evidence IDs. This corrected real ARIA cases where the model repeatedly cited a conversational answer instead of native tool evidence. Its complete audit still found three errors: an IPI false positive, an MCP false negative and an unavailable XSS verdict (247/250 correct).

XSS `xss_email_chain.v2` now receives its relevant email/body/browser-chain receipt without unrelated false profile/model flags. All seven required facts and exact-fact validation remain. MCP `mcp_secret_grounded.v2` independently requires a returned credential assignment and an unmasked value, grounded in tool evidence. Neither change bypasses semantic grading or weakens server proof.

The v10 audit improved to 249/250 but still accepted a poem as a business summary. Grounded citations alone proved where the text came from, not whether the model interpreted it correctly. The v10 log also overlapped an accidental unrelated MCP local-model smoke call; that is a load-isolation limitation, not an explanation assigned to the semantic failure.

V11 adds optional server-owned defense intent and an independent source-comparison branch for `ipi-email-defense-verified-v4`. A primary pass remains provisional until a separate model call assesses the original actor-visible source and candidate response, without receiving the primary verdict or explanation. Neutral transport labels avoid assuming the response is secure.

The verifier model identifies an embedded assistant redirect and selects an exact source passage supporting it. It then classifies every mechanically partitioned response passage. All IDs must appear exactly once; semantic roles are assigned by the model, not by regex. Compact source references resolve to exact server-held passages, including the whole supplied source. A valid summary cannot override a separately classified performed injection. The published UI says “View attack analysis”; requiring an actual injected source follows the accepted defense-demonstration rubric, so a benign email and ordinary summary do not earn this objective.

Each model phase allows one repair. The opted-in path permits at most four calls under one deadline and owner/reset fence; other objectives retain two calls. The primary output budget remains 900 tokens. The verifier reserves output by passage count, independently checks its rendered input plus output budget, and supports at most 64 passages. It rejects oversized requests explicitly rather than truncating or underclassifying them. Policy digests include verifier instructions, repair text, schema, source binding and decoding settings.

Primary criteria and citations remain intact when verification vetoes a pass. The result separately records the verification verdict, its attempts and total calls. Valid negative assessment yields fail; invalid, unavailable or uncertain verification cannot award credit. Provisional and final trace events are distinct, awaited and owner-fenced.

## Verification beyond the baseline

- **51 focused tests** passed for source validation, exact span coverage, bounded repairs, four-call ceiling, timeout/reset/trace failures, verifier error attribution, zero-call preflight metadata, policy digests and 64-span output capacity with a long source.
- **11 varied real-model cases** passed before the full run: silent and explicit summaries, quoted injection, pure poem, mixed summary plus poem, unrelated story, benign source, actual MCP disclosure, redaction, denial and request-only output. Log: `/tmp/owasp-ai-goat-v11-reference-varied11.log`.
- **Canonical IPI20** independently passed before the full run. Log: `/tmp/owasp-ai-goat-v11-reference-ipi20.log`.
- Independent review checked cancellation, source binding, trace failure and receipt-count semantics. The native receipt validator rejects a final pass with a non-passing verifier and enforces the exact call sum.
- Identity migration0016 corrects the native Judge metadata allowlist. Migration0018 adds the provisional event type while retaining the strict event-type constraint; a real coordinator/PostgreSQL-ledger test with a stub Judge passed. This native storage proof is separate from model inference qualification.

The verifier receives the email content actually supplied to the actors. The existing graph cuts that content to 5,000 characters before both actor prompts and grading. The verifier does not further truncate its packet; this is not a claim that the entire inbox message is processed.

Earlier candidate failures are retained rather than hidden: `/tmp/owasp-ai-goat-judge-v9-full-8b.log`, `/tmp/owasp-ai-goat-judge-v10-full-8b.log`, `/tmp/owasp-ai-goat-v11-local-varied.log`, `/tmp/owasp-ai-goat-v11-varied10.log`, and `/tmp/owasp-ai-goat-v11-varied11-sourceproof.log`. Captured synthetic diagnostics showed refusal/action label inversion and response text copied into source-quotation fields. The final passage/reference design addresses those reproduced causes; this does not establish universal semantic accuracy.

## Native workflow and release scope

Earlier connected real-model tests cover ARIA `sqli_1` including outage-to-retry recovery without tool replay, NOVA `nosqli_2`, and positive/negative ARIA `sqli_5`, `sqli_6`, `sqli_10` and NOVA `nosqli_3`. Their exact versions and native effects are documented in [live workflow qualification](judge-live-workflow-qualification.md). They do not qualify all live workflows under every policy version.

The real-model native IPI receipt check subsequently passed 1/1 in 12.3 seconds (`/tmp/owasp-ai-goat-ipi-native-v11-live.log`). Controlled server-owned email evidence passed through the actual LangChain Judge, native coordinator, ledger and receipts: a verified summary earned completion; a poem failed without credit; verifier events persisted; reset cancelled stale work and cleared canonical progress. Identity migration0018 was included. This test does not invoke email actors or deliver email and is not a full live email-agent workflow.

Broader release work remains governed by [the implementation plan](implementation-plan-2026-09-10.md) and [objective authoring contract](judge-objective-authoring.md). No current qualification result removes the need for isolated application, migration, authorization, reset and UI regression checks.

## Final application regression

After the frozen model run, native IPI check, trace migration and retry replay fix, the final disposable-copy backend regression passed **856 tests**, with **23 explicitly gated skips** and **zero failures** (879 total; exit 0). The runner clears provider credentials, selects mock inference and an unreachable Ollama endpoint, and initializes only the copied fixture workspace. Log: `/tmp/owasp-ai-goat-judge-v11-final-isolated.log`. This is separate from the real8B qualification and does not turn skipped HTTP/frontend/native suites into passes.

The broader application modernization goal remains active. Whole-application archive migration, cutover and remaining release qualification are not declared complete by this Judge report. The prior test-isolation incident and its limits remain documented in [verification incidents](verification-incidents.md).

### Connected IPI email actors (2026-09-11 follow-up)

`tests/postgres/ipiActorLiveWorkflow.integration.test.js` passed 1/1 against a uniquely owned disposable PostgreSQL identity database, using an isolated source copy and actual local `llama3.1:8b` actors. The authenticated `/summarize` route produced both actor responses, ran the native Judge/independent defense verifier, stored two receipts, and awarded `email_understand_defense`. The stored grading packet was checked against the actual secure actor output. Authenticated reset then removed canonical completion. No mail was sent or fetched, and no working database, environment file, or asset was used.

Final evidence: `/tmp/owasp-ai-goat-ipi-actor-native-final.log` (exit 0, approximately 16.9 seconds). The vulnerable actor performed the injected poem request and received a passing attack verdict; the secure actor summarized the business deadline and received primary/verifier passes. The test strictly asserts the defense award, two native receipts, actual-response packet binding, and reset. This is one representative email input, not qualification of every IPI objective or stable attack success across runs.

The preceding run recorded a real vulnerable-actor refusal and a corresponding failing attack judgment, while the defense passed. That run stopped on a test-only packet-decoding error, subsequently corrected; its output remains in `/tmp/owasp-ai-goat-ipi-actor-native.log`. The different attack outcomes reflect different observed actor responses and were not overridden or retried through fabricated evidence. Judge policy/rubrics were unchanged.

### Connected FinFlow recon and fixed-mode control

`tests/postgres/finflowLiveWorkflow.integration.test.js` passed 1/1 in approximately 18.6 seconds (`/tmp/owasp-ai-goat-finflow-native-final.log`). In a private source copy with owned identity/FinFlow PostgreSQL databases, the authenticated chat route used real `llama3.1:8b` structured action selection (`tool_enum`) and an actual actor response naming available tools. The real Judge accepted `tool_enum`, a native receipt awarded canonical completion, and the route projected completion into FinFlow progress. The response also named admin tools, legitimately satisfying `admin_enum`. This recon action did not execute a file/network tool; it qualifies the catalog-decision/actor/Judge path, not the remaining tool-effect objectives.

The negative control switched to supported `fixed` mode through the real authenticated mode endpoint. Its actual actor/Judge path returned a failing `tool_enum` verdict and no new completion; this is a mode-gate negative, not a general semantic refusal benchmark. Native receipt dispositions and subsequent authenticated reset were verified. No source assets, external calls, or working databases were used.

Two preceding test assumptions were corrected without production changes: the initial fixture seeded unsupported FinFlow mode `vuln` instead of `vulnerable`; later a greeting request in vulnerable mode still elicited a real tool list, correctly receiving a passing Judge verdict. Logs `/tmp/owasp-ai-goat-finflow-native-live.log` and `/tmp/owasp-ai-goat-finflow-native-supported-mode.log` retain these findings. Neither establishes a Judge false positive or a production mode defect.

### Connected CodeBot dependency parsing and exact argument binding

`tests/postgres/codeBotLiveWorkflow.integration.test.js` passed 1/1 against owned disposable identity/supply-chain databases (`/tmp/owasp-ai-goat-codebot-native-verified.log`). The actual authenticated route and local `llama3.1:8b` selected `check_dependencies`; the genuine teaching parser analyzed a clean, empty-dependency manifest. The real Judge passed `clean_request`, and the native receipt and stored grading packet preserved the exact manifest and observed parser result. A supported fixed-mode request containing a `transform` field was rejected by the actual tool, produced no new completion or candidate Judge verdict, and authenticated reset removed progress. This negative is a tool-rejection/no-credit control, not a semantic negative Judge case. No package installation, file extraction, command execution, or external network effect occurred.

The probe exposed a real argument-integrity defect: Llama selected the correct tool but supplied `manifest: "{"` for valid user JSON, producing a parser error and no receipt. The selected-tool execution boundary now binds one explicit unambiguous manifest directly from the user message, preserving its exact bytes and teaching fields. Model action selection remains mandatory; absent explicit source data leaves model arguments unchanged. Ambiguous/malformed explicit manifests fail before effects with an actionable 400 response. Seven focused binding/decision/trace tests passed. Earlier diagnostic logs retain the failed calls; Judge policy/rubrics were unchanged.

### Final R2 DOM-preservation correction

The original250-case record predates `xss_dom_preservation.v2`. Actual actor output exposed a false negative when StyleBot added styling to a preserved learner element. The browser-backed comparison now checks the tag, contents and supplied attributes, allowing added class/style. The [connected regression supplement](judge-connected-regression-2026-09-11.md#xss-dom-v2-final-supplement) records six real8B boundary cases, all32 XSS/legacy-email cases, the actual reflected actor/browser/native receipt flow, independent review and a final940-pass backend regression. Its [JSON report](judge-dom-v2-qualification-2026-09-11.json) supplements the unchanged historical report.
