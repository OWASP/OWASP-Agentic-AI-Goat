# Model and graph coverage inventory

Source audit includes both external provider calls and provider-owned `this.generateResponse` educational methods across server/ and agent-host/. The initial external-only scan missed those provider-owned methods; they are now included. Transport through the shared providers uses LangChain. Transport alone does not imply the surrounding workflow is a graph.

| Family / entrypoint | Graph coverage | Remaining direct orchestration |
| --- | --- | --- |
| ARIA / NOVA chat | intent → tool → model/fallback → persist | explicit legacy override; manual progress APIs |
| SecureShop three supervisors | bounded model/tool supervisor loop | cross-process durable checkpoint/resume pending |
| SecureShop 17 MCP tools/call hosts | SDK handler invokes one-node tool graph | sinks intentionally remain ordinary tools; listing/analytics model calls are within those tool nodes |
| FinFlow | regex interception branches and model/tool loop | existing route reset/credit helpers |
| CodeBot | model/tools, text parse, manifest retry, fallback | HTTP administration/read endpoints |
| XSS chat / email generation | model → parse/tool → summary/grade; profile → generation → substitutions → save | ordinary comment/inbox APIs |
| CSRF agent | classify → document/recon/defense/query/attack/chitchat → phrase; HTML-preserving summary | inbox fetch/list/read/parse/forge/grade/summary and RAG retrieve/summary/detect/forge/grade/present are now graphs; non-chat administration remains direct |
| DPI | prepare → model → deterministic detect → conditional judge | HTTP progress management; judge helper called within graph |
| Document RAG | ingest/store/select/grade and retrieve/prompt/model/detect/grade | session delete, reads; judge helper called within graph |
| Indirect email | send/audit/credit, manual/fetch/read/analyze/credit, parallel summaries/join/grade | health/setup/read APIs |
| Excessive Agency chat | model → parse → conditional tool → grade → summarize/fallback | history persistence and reset remain route-managed; no new local fence |
| MCP workshop chat | classify → recon or injection decision → conditional real tool → grade → phrase | sandbox/session reset remains route-managed; resolveInjectionIntent preserves existing model-driven real-effect behavior |
| CTF student + admin guardian | model → ordered output-defense subgraph → grade visible answer | classification/hash, adaptive technique/payload shields, input defenses and attempt allocation are an admission graph; success/failure persistence, audit and hint feedback are a result graph; authentication/rate admission remains route middleware |
| CTF input defenses | ordered layer graph with immediate blocked exit | stage configuration remains DB-managed |
| Generic AI routes (`ai.js`) | prompt completion/persist and bias prepare/model/detect graphs; CoT/context/multiturn model/analysis graphs | conversation persistence for CoT/context/multiturn remains route callback |
| Legacy challenges (`challenges.js`, `secureChallenges.js`) | XSS prepare/model/raw reflection; CTF prepare/model/extraction grading | legacy CTF audit persistence remains route callback |
| Provider-owned educational methods | model → deterministic parsing/grading graph in both service classes: SQL/NoSQL, XSS, RCE command parsing, legacy CTF, sensitive info, exploit payload generation, CoT/context/multiturn | deterministic early interception/offline fallback remain in methods; duplicate legacy method declarations retained to avoid changing effective overrides |
| Monitoring model probe | LangChain transport | health probe deliberately ordinary request |

No claim of all-entrypoint graph coverage or durable recovery is made. Existing intentional sink arguments and both mode branches remain unchanged. New graph tests inject models/tools/stores and reject authDb imports. `remainingFamilyGraphs.test.js` covers MCP recon/no-double-execution/offline branches, CTF ordered early exit and post-defense scoring, and Excessive Agency execute/grade/summary fallback. No live CTF database, shell sandbox, email service or paid model is exercised.

## Ownership/replay review

CSRF progress reset and tab reset currently lack serialization with in-flight chat/forge/credit; some canonical reset promises are fire-and-forget. MCP workshop reset has the same late-credit risk. Excessive Agency history/reset remains outside a generation fence. CTF graph allocation preserves atomic attempt increments but admission checks and successful-stage accounting are not one cross-process transaction: concurrent requests can pass the same adaptive shield before its usage write. External email send cannot safely replay without an idempotency record from the transport. No graph checkpointer is enabled on these side-effect graphs, so they do not currently replay automatically. Durable PG generation authority, side-effect idempotency and resumable state remain a separate required slice.

AI_PROVIDER=mock now explicitly bypasses all adapters, probes, fallback ladders and model calls in generate/chat/tools/status, returning deterministic tagged mocked/fallback metadata. This is fixture behavior, not live-model proof.
