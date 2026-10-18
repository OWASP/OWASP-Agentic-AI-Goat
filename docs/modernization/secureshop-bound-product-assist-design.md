# SecureShop bound product assist design

Status: implementation in progress. The direct-provider candidate was rejected and its default composition wiring removed. Graph, target-owned retrieval, lifecycle and actual-model acceptance remain open.

## Problem and boundary

The rendered Product page calls `POST /api/secureshop/products/:id/summary` and `GET /api/secureshop/products/:id/similar` from `client/src/pages/secureshop/pages/Product.jsx`. The bound gateway currently has no production product-assist graph. Falling through to `server/routes/secureshop/postgres/customer.js` is invalid because that router reads shared commerce state. The existing agent tools are also process-level/global: `agent-host/agents/summarizer/tools/summarize_product.postgres.js` and `agent-host/agents/product-search/tools/similar.postgres.js` obtain the global SecureShop commerce database, while `similar.postgres.js` reads the global manuals vector corpus.

The feature must retain the intentional LLM01/LLM04/LLM05 teaching sinks inside a launch-owned target. It must never query the global `manuals` corpus for a bound learner, claim a mock response as model output, accept a caller target or persona, or turn a source projection into a fabricated AI response.

## Existing graph and purpose extension

Extend `server/services/secureshopConversationPurpose.js` with the server-selected `productAssist` purpose, `secureshop_product_assist`. The request cannot select this value. The existing `createBoundAgentRunner` in `server/services/secureshopBoundAgentRunner.js` already admits a turn, binds the session/persona/scope, executes a finite multi-step supervisor graph, persists messages/traces, and carries the cancellation signal. The new product runner should be created beside the review runner in `server/services/secureshopBoundReviewComposition.js`, using the same `provider`, `turns`, `conversations`, `journal`, coordinator, and target authority.

The runner manifest must be a product-specific projection, not the broad review manifest. It should expose only two local tools:

- `summarizer.summarize_product`, which reads the prepared target product and returns the raw description/HTML fields required by the intentional LLM01/LLM05 sink.
- `product-search.similar`, which retrieves only documents and products bound to the current product target and returns the poisoned retrieved context unchanged for the intentional LLM04 path.

The graph must allow a bounded decision loop with a finite `maxSteps` and a final response phase. Tool arguments are validated against the current product target, and every tool call runs `boundary.check()` before and after the effect. A model response that does not select a tool, selects an unknown tool, selects a foreign product, or returns malformed final output is an honest unavailable/error result; no deterministic fallback is substituted.

The product router should create a server-owned session/request ID and invoke this runner with the authenticated launch/persona binding. It should parse the graph's persisted final response and provenance projection, require the actual provider/model identity, and map catalog rows from the internal camel-case shape to the existing client DTOs (`product_id`, `stock_quantity`, `description_html`). Request abort/launch reset must cancel the runner and prevent a late response from being returned.

## Target-owned retrieval storage

The retrieval corpus belongs in `secureshop_review` beside the canonical `product_targets` authority. The earlier agents-store candidate failed independent review: a copied tuple in a separate database cannot serialize writes with product reset/deletion. These candidate migrations have not been applied. Keep `secureshop_agents/0018_secureshop_bound_product_retrieval.sql` limited to the conversation-purpose addition; put retrieval state in the next review migration, `0011_secureshop_bound_product_retrieval.sql`.

A retrieval configuration keyed by `target_id` must reference the existing product target. Documents reference that configuration; ownership, session, generation and lifecycle are read from the canonical product target rather than a second independently writable authority. Every read/provision/import locks and verifies the exact parent tuple. Runtime roles use bounded database functions; direct lifecycle and receipt writes are revoked. Provision/import digests cover exact source bytes, vectors and model identity, and immutable operation receipts reject mismatched replays while preserving later imports.

Extend the existing product cleanup transaction, replay checks and empty-target assertion to remove retrieval content and retain its cleanup receipt. Writers and cleanup lock the same parent row, preventing physical writes after retirement. Native tests must prove both race orders, preservation of sibling targets, and completed-operation replay. Raw poisoned chunks remain deliberately unfiltered within the owned target.

The existing `secureshopBoundCatalog.prepareTarget()` remains the sole source of target binding. Similar retrieval must call it or accept its already-validated binding, never accept `targetId`, `launchId`, `generation`, `userId` or corpus names from the request body.

## Composition and readiness

`createSecureShopBoundReviewComposition` should construct the target retrieval repository from `reviewPool`, the product graph runner from the existing conversation/journal/coordinator dependencies, and a `productAssist` application object containing summary/similar route methods plus close/reset hooks. `createSecureShopBoundApplication` passes that object to `boundGateway` only after readiness verifies the new relations, runtime privileges, provider capability, and product-purpose catalog. If readiness fails, the route returns the existing bounded unavailable response; it must not fall through to legacy SQLite/global PostgreSQL.

The product reset and student deletion compositions must include retrieval cleanup and receipt verification. A launch reset advances the product target generation before cleanup and rejects a stale tool call. Deletion fences must prevent late retrieval writes after owner deletion, matching the existing product target cleanup contract in `server/database/postgres/secureshopBoundProductRepository.js`.

## HTTP and UI contract

Keep the existing Product page layout and request paths. Summary returns the current product fields plus a model-generated `summary`, provider/model provenance, and the exact raw description/HTML fields needed by the teaching sink. Similar returns `{results, count, mode, seed, retrieved_context}` with result rows projected through the target catalog DTO. A 404 is used for an unknown target product; stale generation, unavailable provider, malformed model output, or missing target retrieval returns the existing bounded error class/status. The UI must distinguish unavailable from an empty related list and must not silently swallow a 503 as a successful empty model result.

The summary and similar graph must retain `@intentional-vulnerability` coverage for `llm01-indirect-pi-product`, `llm04-rag-poisoning`, `llm05-improper-output`, and the corresponding tests in `tests/secureshop/vuln/llm` and `tests/secureshop/vuln/chains`. The bound tests must prove that the same teaching content is confined to one target and cannot cross a sibling or shared catalog.

## Minimum tests before activation

1. Controlled graph tests: model selects each allowed tool, malformed/unknown tool, final-response repair, provider identity, bounded step/call budget, cancellation, and no mock/fallback credit.
2. Controlled target tests: summary preserves raw description/HTML, similar returns only target documents/products, foreign product IDs and stale generations reject, and sibling target bytes remain unchanged.
3. Migration tests: fresh, populated, replay/no-op, runtime privilege denial for global vectors, target retrieval reset/deletion receipts, and late-write fencing.
4. Mounted HTTP tests: authenticated customer route, exact DTOs, truthful unavailable responses, reset/replay, sibling isolation, and request cancellation.
5. Rendered/native qualification: actual `llama3.1:8b`, owned PostgreSQL/agent stores and browser, with persisted run/tool/provider receipts. Controlled provider or source projections do not qualify this final gate.

The current seam and direct provider adapter must remain out of the acceptance matrix until this graph, target retrieval migration, lifecycle cleanup and mounted/rendered tests exist.

## Implementation checkpoint — 2026-09-19

The default composition now constructs `productAssist` with the retained conversation repository, journal and reset coordinator. Retrieval stays private to the graph's local tools. Product cleanup retires the canonical parent and retrieval corpus in one review-store transaction; runtime retrieval tables are read-only and bounded database functions perform mutations. PostgreSQL's built-in SHA-256 computes canonical receipt digests, avoiding extension privileges.

Native qualification `tasks/secureshop-product-retrieval-native-35783.json` proves fresh migration, the populated 0010→0011 transition, no-op replay, runtime privilege boundaries, exact replacement replay, sibling preservation and both observed parent-lock race orders. `tasks/secureshop-product-embedder-native.json` proves the actual installed CPU embedding pipeline offline. These are separate proofs; neither qualifies the full HTTP/model/browser workflow.

Corpus modes identify actual retrieved sources (`products`, `manuals`, `mixed`). Initial indexing uses actual target product descriptions. Authentic manual upload remains incomplete: the legacy upload route uses a shared corpus and must not be mounted as the bound path. Target-owned raw bytes, upload metadata/digest, extraction and import receipts must be implemented before claiming the manual-poisoning chain works in this path. No application migration or restart has activated this candidate yet.
