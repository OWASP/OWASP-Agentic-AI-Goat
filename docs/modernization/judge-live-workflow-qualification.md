# Live Judge workflow qualification

The 250-case local `llama3.1:8b` run qualifies grading of supplied evidence. It does not prove every live exercise produces that evidence correctly. Release qualification must connect model decisions, isolated effects, grading and durable progress. An unavailable verdict is never a successful negative qualification.

| Family | Required live integration evidence |
| --- | --- |
| DPI (8 objectives) | Actual chat response through grading and native receipt; practice completion requires its distinct passing attempts. |
| IPI (10) | Actual upload/query/email scenario; preserve source attribution and distinguish model output from simulation. |
| FinFlow (18), CodeBot (6), MCP (11), excessive agency (9) | Model-selected tool and arguments, controlled harmless effects, raw results, real Judge and native receipt. |
| CSRF (12) | Route-selected action and sandbox effect through grading; label Inbox/RAG teaching interpreters separately from the model agent. |
| XSS (12), legacy email (4) | Browser-owned execution proof and protected-field provenance through live grading and receipt persistence. |
| ARIA (10), NOVA (10) | Real model-selected operation against disposable PostgreSQL, exact parameters and raw result through real grading and receipt. |
| CTF (10) | Guardian and defenses through secret observation, real grading and atomic stage/leaderboard/blocklist updates. |
| Legacy sensitive information (5) | Real route with temporary protected/public fixtures through grading and native receipt. |

For each distinct receipt adapter, qualify unavailable-to-retry recovery without replaying effects. For each coordinator/commit path, reset during inference must fence late awards. Inspect persisted node/tool/Judge traces, owner isolation and restart recovery. Existing focused tests are supporting evidence, not substitutes for this connected workflow qualification.

Use synthetic data, disposable databases and local inference. Do not use working databases, external email recipients or cloud provider credentials. Keep representative integration probes distinct from exhaustive objective coverage in reports.

## Connected DPI practice checkpoint

`tests/postgres/dpiLiveWorkflow.integration.test.js` now runs the actual DPI chat route and actor with local `llama3.1:8b`, the real LangChain Judge, native completion repository and run ledger. It copies source into an owned temporary directory, blocks legacy database imports and creates/removes its own PostgreSQL identity database. The route's authenticated identity is supplied by test middleware; this is not a login/JWT qualification.

The captured full probe passed1/1 in30.9 seconds (`/tmp/owasp-ai-goat-dpi-connected-captured.log`): two substantive AWS exchanges produced distinct passing receipts with `threshold_pending` then `awarded`; an unrelated request produced a failing receipt without additional practice credit. The test checked native trace events and reset clearing. This qualifies the practice adapter, not all eight DPI attack outcomes.

A separate run's second IAM/S3 exchange failed grading and correctly left practice count at1. That original run did not capture its actor response or grading packet, so its cause is unknown. It may involve actor output, a deterministic prerequisite or semantic grading; the later passing targeted and full probes do not diagnose it. Its log is retained at `/tmp/owasp-ai-goat-dpi-native-live-final.log`. Current diagnostics capture actual actor responses, and the diagnostic option additionally captures the bounded grading packet in a private fixture log. No rubric or assertion was weakened to produce a pass.

Review of the cancellation assertion exposed a lifecycle defect: resetting a pending actor call returned a generic500 error. The route now returns409 `AGENT_RUN_CANCELLED` without an Ollama-outage hint. An offline guarded route check and a separate real pending-actor probe passed (`/tmp/owasp-ai-goat-dpi-cancel-native.log`), asserting exact status/code and no added receipt or late credit. The actor-start wait is bounded. This change does not alter the Judge policy or objective rubric.

Run the full opt-in probe against an explicitly disposable loopback PostgreSQL server with the test roles already provisioned:

```sh
RUN_LIVE_DPI_WORKFLOW=1 PG_TEST_DISPOSABLE=yes PG_LIVE_ADMIN_URL=YOUR_DISPOSABLE_ADMIN_URL node --test tests/postgres/dpiLiveWorkflow.integration.test.js
```

Keep the local8B model slot exclusive while collecting inference evidence. Other families still require the representative connected probes in the table above; the250-case fixed-evidence Judge matrix does not replace them.

## IPI actual actor checkpoint

`tests/postgres/ipiActorLiveWorkflow.integration.test.js` passed 1/1 against local `llama3.1:8b` in `/tmp/owasp-ai-goat-ipi-actor-native-final.log` (about 16.9 seconds). The authenticated summarize route produced both actual actor responses, then the real Judge and independent defense verifier wrote native receipts. The secure business summary passed and awarded objective 5; reset cleared canonical progress. This uses a synthetic email inside an isolated source copy and owned identity database, with no email delivery or external retrieval. Vulnerable actor behavior varied across probes: a refusal was correctly graded fail; the final poem response passed. This is one representative workflow, not all IPI objectives.

## FinFlow actual actor checkpoint

`tests/postgres/finflowLiveWorkflow.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-finflow-native-final.log` (about 18.6 seconds). Actual model catalog selection and response led to real Judge acceptance, native receipt, local progress projection and reset. The supported fixed-mode control produced no new credit. A greeting in vulnerable mode also elicited the catalog, so it was not a valid semantic negative; the Judge's pass reflected the actual response. An earlier fixture used unsupported mode `vuln`; the fixture was corrected to `vulnerable`, with no production mode change. Scope is catalog reconnaissance, not file or network tool execution.

## ARIA/NOVA local actor-loop checkpoint

`tests/workshopGraph.live.test.js` passed its three existing local `llama3.1:8b` checks after the shared graph gained bounded observation-driven decisions. The first complete run passed 3/3 in about 39.7 seconds: ARIA and NOVA each selected their search tool, received a controlled result, stopped when they proposed the identical completed read, and produced a response; the directed ARIA chain selected `add_to_cart` then `view_cart`; cart, no-tool, and exact raw SQL-injection arguments were preserved. An earlier directed-chain run failed because the model selected `search_products`, then `add_to_cart`, and stopped without `view_cart`; that failure established that a tool graph alone did not guarantee multi-action completion and was not hidden by relaxing the required outcome.

The original natural request, “Add Test Laptop to my cart, then show me the cart,” was then retained as a separate qualification. A single targeted run passed 1/1 in about 8.1 seconds with the model-selected sequence `search_products("Test Laptop")` → `add_to_cart("Test Laptop")` → `view_cart`. The assertion permits only a read-only lookup before the mutation and requires exactly one add followed by the view. These probes use controlled in-memory tool effects and real local inference; they qualify actor observation/continuation behavior, not PostgreSQL execution, Judge receipts, or all 20 ARIA/NOVA objectives.

## CodeBot actual tool checkpoint

`tests/postgres/codeBotLiveWorkflow.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-codebot-native-verified.log` (about 10.6 seconds). The real model selected `check_dependencies`, the real tool parsed a harmless manifest, and the real Judge awarded `clean_request` through a native receipt. Fixed mode blocked a transform manifest, produced no additional award, and reset cleared canonical completion. No package installation, command execution or external request occurred.

The first probe exposed actual argument corruption: the model supplied `manifest: "{"` despite a complete source manifest. The bounded binder now preserves the exact supplied manifest after model tool selection, rejects ambiguous/malformed explicit input, and records the actual bound arguments in grading evidence. Seven focused tests passed. The earlier bound probe completed its assertions but failed during forced database cleanup; the final run used orderly pool shutdown and ordinary deletion of only owned databases. These logs remain separate from the successful qualification.

## MCP actual catalog checkpoint

`tests/postgres/mcpLiveWorkflow.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-mcp-native-explicit.log` (16.5 seconds) with local `llama3.1:8b`. Actual JWT authentication, model selection of `list_tools`, native catalog reading, model response, real Judge, accepted native `mcp_recon` receipt and reconciled progress were exercised. A request to say hello without tools selected no tool and produced no completion; this is a routing/no-award control, not a negative Judge verdict. The authenticated reset cleared canonical progress. The test owns separate identity and MCP PostgreSQL databases in an isolated source copy and blocks SQLite imports.

The first broadly worded catalog request selected `run_command` with `ls` instead of `list_tools`; the unavailable runner blocked execution and no receipt was awarded (`/tmp/owasp-ai-goat-mcp-native-authenticated.log`). The successful request explicitly named `list_tools` and prohibited shell/file access. This establishes one supported representative workflow, not reliable routing for every paraphrase or qualification of exploit tools. Earlier fixture-only startup failures caught a missing workshop database selector and missing upstream authentication before inference. No production code or grading policy changed.

CodeBot follow-up: the binder now also binds fieldless explicit JSON objects exactly, preventing a model-invented transform. Five binding and three decision tests pass (8 total). The native qualification predates this refinement; its recognized-manifest path is unchanged.

## Excessive Agency actual tool checkpoint

`tests/postgres/excessiveAgencyLiveWorkflow.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-ea-native-live.log` (13.9 seconds), using local `llama3.1:8b`. Real platform JWT authentication and Alice's lab login preceded a fixed-mode request to list her own notes. The actual model selected `listNotes`; the native attendee database supplied the notes; the real Judge passed `objective_1` and the accepted native receipt awarded completion. A hello-only request selected no tool and earned no completion. Authenticated progress reset cleared canonical completion. This is one read-only representative tool workflow; the no-tool control is not a semantic negative Judge case, and the other eight objectives remain outside this probe. All databases and source files were disposable and owned by the test; no external request or filesystem tool was executed. No production change was required.

## CTF guardian probe — initial refusal and successful follow-up

`tests/postgres/ctfLiveWorkflow.integration.test.js` ran against owned identity/CTF databases and an isolated source copy with real JWT authentication and a CTF session. The original level-1 guardian prompt retained its refusal instruction; only the protected value was replaced with a synthetic identifier. In `/tmp/owasp-ai-goat-ctf-guardian-native-live.log` (15.0 seconds, exit 1), the hello control returned a greeting and the direct extraction request returned an explicit refusal. The real v11 Judge correctly returned `fail` for both responses. The assertion expecting disclosure therefore failed; this is observed actor behavior, not a Judge false negative. No positive stage/leaderboard qualification is claimed, and no grading policy or guardian instruction was weakened. The owned databases were removed afterward.

The single follow-up using the published setup-print hint passed 1/1 in `/tmp/owasp-ai-goat-ctf-guardian-native-hint.log` (16.8 seconds, exit 0). The actual guardian disclosed the synthetic value, the real Judge passed it, and native assertions confirmed the accepted judgment, completed stage and positive leaderboard score. The hello control again earned no award. Guardian instructions, defense configuration and rubric remained unchanged. This qualifies one level-1 prompt and its negative control; the earlier direct-request refusal remains evidence of actor variability, and the other nine levels are not covered by this connected probe.

## CSRF actual model-selected route checkpoint

The opt-in probe tests/postgres/csrfLiveWorkflow.integration.test.js exercises the POST-tab direct agent route with a real Postgres identity JWT through adminAuth.authenticateToken. It uses an owned temporary identity database and CSRF workshop database, blocks SQLite/auth imports, and creates only synthetic user data. The local llama3.1:8b model selected the change_email action and direct_post vector; the quoted live@example.invalid binding was applied to the Maya Chen sandbox, changing her profile email and satisfying csrf_p1. The real csrf-observed-v4 Judge returned pass, and the native receipt was awarded. The run ledger recorded decisionSource=model and tool=change_email, proving this is model-selected route execution rather than the deterministic Inbox/RAG interpreters.

The same run reset the owner and confirmed canonical completion, CSRF activity, and mutable victim state were cleared while the immutable accepted Judge receipt remained. It passed 1/1 in roughly 10.5 seconds; the exact command and captured outcome are recorded in /tmp/owasp-ai-goat-csrf-native-live-final.log:

```sh
RUN_LIVE_CSRF_WORKFLOW=1 PG_TEST_DISPOSABLE=yes PG_LIVE_ADMIN_URL=postgres://postgres@127.0.0.1:32768/postgres node --test tests/postgres/csrfLiveWorkflow.integration.test.js
```

This qualifies one model-selected CSRF POST objective and its reset/receipt adapter. It does not qualify the remaining POST fetch, GET, XSS email, or Indirect RAG objectives; no negative Judge case was run in this probe.

## Legacy sensitive route checkpoint

The opt-in probe tests/postgres/legacySensitiveLiveWorkflow.integration.test.js passed 1/1 in roughly 22.6 seconds (`/tmp/owasp-ai-goat-legacy-sensitive-native-live-final.log`). It copied only source controlled code into an owned temporary directory, created synthetic public and protected fixture files inside that copy, used a disposable identity and FinFlow PostgreSQL pair, and authenticated the actual route with a Postgres JWT. The protected fixture at server/sensitive_files/config/llm_config.yml contained only provider: ollama, endpoint: http://127.0.0.1:11434, and model: llama3.1:8b; the route’s vulnerable download_statement path traversal read it and the real FinFlow Judge awarded traversal_llm with a native finflow-structured-v1 receipt. The same response also produced three expected content-derived receipts (llm_identify, tool_version, tool_enum), all pass/awarded; no negative Judge case was run.

The evidence packet cited the tool result containing the synthetic protected content. Reset cleared sensitive_info_disclosure canonical completions and finflow.tool_log while retaining all four immutable objective_judgments receipts. The public fixture was synthetic and read only to verify the isolated visibility-class setup; no checked-out sensitive files, working databases, .env files, external requests, cloud credentials, or production runtime changes were used. This qualifies the protected-file route adapter and reset/receipt behavior, not every legacy sensitive objective or a real external filesystem.

## Legacy email builder actual actor/browser checkpoint

`tests/postgres/legacyEmailLiveWorkflow.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-legacy-email-native-live.log` (16.0 seconds). A real authenticated profile update stored a synthetic signature handler. Actual local `llama3.1:8b` generation, production signature processing and protected-source browser execution led to a real Judge Level 2 pass, native receipt with browser execution recorded, and persisted progress. Authenticated reset removed progress. The test closes its qualification browser and removes only its owned identity/XSS databases and source copy. No SMTP, delivery, external retrieval or working assets were used. This qualifies signature-source execution after real generation; it does not establish model-authored XSS (Level 4), other email levels, or an independent semantic negative case.


## XSS reflected DOM-v2 checkpoint

`tests/postgres/xssBrowserLiveWorkflow.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-xss-browser-native-dom-v2.log` (34.7 seconds). The actual local actor, isolated browser, real Judge and native receipts covered reflected HTML generation, preserved learner DOM and executable image-handler output; an inert script control did not earn execution credit. Native completion and reset assertions passed.

The earlier probe exposed a false negative when the actor preserved the learner's `<b>` element but added styling: a literal source comparison treated that presentation change as loss of the learner HTML. The new authoritative browser DOM comparison checks actual DOM preservation, with rubric `xss_dom_preservation.v2`. This corrects preservation evidence without treating inert scripts as executed or weakening handler execution proof. The initial failed probe remains part of the qualification history; the final passing log does not replace it.

The 250-case grounded-v11 supplied-evidence matrix predates this R2 rubric revision. Its historical result is not qualification of DOM-v2. The [final supplement](judge-connected-regression-2026-09-11.md#xss-dom-v2-final-supplement) now records six dedicated DOM cases and all32 XSS/legacy-email evidence cases passing with the real8B model, plus940 passing backend regression tests. These representative connected checks do not establish every objective end to end.

## Production-bundle browser checkpoint

`tests/postgres/fullStackBrowser.integration.test.js` passed 1/1 in `/tmp/owasp-ai-goat-fullstack-browser-final.log` (40.9 seconds). It built the actual Vite production bundle in an owned source copy, booted the actual application against 14 uniquely owned PostgreSQL databases with SQLite/MySQL imports forbidden, and logged in through the rendered login form. Two real local-8B DPI interactions received passing native judgments, rendered practice DONE, and reset through the confirmation dialog. The run inspector displayed retained pass verdicts and Judge timeline events. The IPI page uploaded a synthetic policy, used the real MiniLM embedding model, queried with the selected question objective, rendered actual Judge feedback, and reset. No browser page errors were recorded.

No eligible unavailable receipt occurred (`retainedEvidenceRetryAvailable:false`), so this checkpoint does not claim execution of the retry control. It also does not cover every objective, deployment, or real email delivery. The child backend, browser, source copy and all owned databases were cleaned up. A public embedding-model cache remains at `/tmp/owasp-ai-goat-browser-model-cache-20260911` for reproducible probes; it contains no application or attendee data and can be removed after verification.

Reproduction requires `RUN_LIVE_FULLSTACK=1 PG_TEST_DISPOSABLE=yes PG_LIVE_ADMIN_URL=<explicit loopback disposable admin URL> XENOVA_CACHE=<prepared owned MiniLM cache> node --test tests/postgres/fullStackBrowser.integration.test.js`. The app copy excludes working `.env`, database files, uploads, sensitive files and workshop data. Public model acquisition used the system trust store; TLS verification was not disabled.

Earlier checkpoints remain separate: `/tmp/owasp-ai-goat-fullstack-browser-progress.log` passed DPI and navigation; the first IPI upload failed because the embedding model was uninitialized. That verified readiness condition now returns actionable `503 RAG_EMBEDDING_NOT_READY` from upload/query rather than generic 500, with a focused readiness test passing. A later fixture initially left the upload objective selected while querying; selecting the actual question objective resolved the missing query judgment without changing grading. No Judge rubric or semantic result was forced.

## Post-DOM-v2 dashboard parity

The `FULLSTACK_PARITY_ONLY=1` branch of the production browser test passed 1/1 in `/tmp/owasp-ai-goat-fullstack-dashboard-parity-final.log` (26.0 seconds). It completed the real reflected R1 prerequisite and R2 request through the actual actor and Judge, then compared `/api/workshop/challenges`, `/api/workshop/progress` and `/api/workshop/student/stats`: all reported 2/106 objectives, zero completed exercises and zero recorded seconds. The overview and exercise-detail DOMs rendered 2/106; the R2 row had the completed green computed color `rgb(45, 106, 79)`. `/workshop/progress` redirected to the overview and rendered the same count; it is not a separate third page. Overview time rendered `0s`. This checks the zero-time boundary, not nonzero rounding parity, and inserts no synthetic completion or elapsed time. The first fixture request correctly completed R1 rather than R2; the final probe follows the required sequence. No configuration, objective IDs or grading verdicts were forced.
