# SecureShop Supervisors, Providers, and MCP Agents

## Agentic request flow

```text
React agent UI
  → POST /api/secureshop/agents/<role>/session
  → POST /api/secureshop/agents/<role>/chat
    → role supervisor
      ├─ load base prompt + role policies + tool schemas
      ├─ provider.chat(messages, tools)
      ├─ check Layer-B tool ACL
      ├─ MCP client pool.callTool(agent, tool, args + caller context)
      │    → Agent Host :8082 → task server → tool function → SQLite/network/fs
      ├─ append tool result and trace
      └─ loop until final response or step/token budget
```

## SecureShop service modules

| File | Responsibility |
|---|---|
| `agentHostSupervisor.js` | fork Agent Host, wait for health, expose port/process, stop child |
| `mcpClientPool.js` | connect/retry 17 MCP clients and call tools |
| `mcpTransport.js` | SDK SSE transport compatibility wrapper |
| `toolManifest.js` | discover native schemas, persist cache, role-filter, load external registered tools |
| `providerRouter.js` | choose configured/available SecureShop provider |
| `sessionStore.js` | agent conversation rows and token budget |
| `streaming.js` | SSE event writer |
| `trace.js` | per-hop trace records and policy violations |
| `toolAcl.js` | role/tool permission lookup and enforce/block/log decision |
| `vectorStore.js` | chunk, embed, index, search, poison/export vector corpora |

## Supervisors

`customerSupervisor.js`, `merchantSupervisor.js`, and `adminSupervisor.js`
share the same algorithm but differ in role, default tools, prompt, step/parallel
limits, and intentional teaching sinks.

Common flow:

1. load session messages and remaining token budget;
2. build `basePrompt.js` plus `policyLoader.js` policy rows;
3. obtain role-native tools plus external MCP descriptions from the manifest;
4. ask the provider for text or tool calls;
5. for each tool call, run `checkToolAcl`;
6. block if enforcement is on, otherwise annotate a violation and continue;
7. add `_ss_caller` identity/policy metadata to MCP arguments;
8. dispatch through the pool and append raw tool output;
9. write trace/session/token state and stream hop events;
10. stop at provider completion, token limit, step limit, or error.

`basePrompt.js` intentionally describes broad agent capabilities. Policy rows
are live DB content injected into the system prompt; changing the policy schema
or format affects all three supervisors.

## Authorization layers

| Layer | Location | Behavior |
|---|---|---|
| A: HTTP role | SecureShop route middleware | blocks wrong-role direct REST access |
| B: supervisor ACL | `toolAcl.js` | table-driven allow/deny; seeded enforcement off logs then dispatches |
| C: task-agent caller | `agent-host/shared/callerContext.js` | opt-in `enforceRole`; intentional vulnerable tools only extract identity |

The caller context is smuggled in `_ss_caller`, stripped before normal tool
arguments reach implementations, and recorded in traces. Any new tool must make
an explicit Layer-C enforcement choice and receive Layer-B seed permissions.

## Provider implementations

| Provider | File | Notes |
|---|---|---|
| mock | `providers/mockProvider.js` | deterministic tests and offline navigation |
| Ollama | `ollamaProvider.js` | local `/api/chat`, normalized tools/results |
| Anthropic | `anthropicProvider.js` | Messages API and tool-use normalization |
| OpenAI | `openaiProvider.js` | Chat Completions and function-call normalization |
| Bedrock | `bedrockProvider.js` | adapter/subclass driven by AWS config |

All normalize to a supervisor result containing final text or tool uses. Provider
parity tests ensure exploit outcomes remain implementation-independent.

## Agent Host

`agent-host/index.js` starts Express on 8082 and instantiates 17 task servers.
For each name it exposes an MCP SSE connect endpoint and a session-specific
message endpoint. Each `agents/<name>/server.js` registers MCP tool metadata and
wraps handlers with trace/caller-context logic. Most behavior lives in the
adjacent `tools/` module.

Shared modules:

- `shared/db.js`: lazy `better-sqlite3` handles for both SecureShop DBs;
- `shared/callerContext.js`: extract/enforce/guard caller identity;
- `shared/trace.js`: buffered task-hop trace writes;
- `shared/vectorStore.js`: compatibility export of the server vector store.

## Task-agent catalog

| Agent | Tools/functions | Data and downstream effects |
|---|---|---|
| product-search | `search`, `similar`, `personalizedFeed` | product SQL, HTML echo, vector/manual retrieval |
| summarizer | product/review/file summaries, return-policy explanation | untrusted DB/file/URL content returned to supervisor |
| price-advisor | deals, price history, competitor compare | product history plus external fetch |
| cart | view/add/remove/apply coupon | cart, product, coupon rows |
| support | ticket, order status, refund request | tickets and orders |
| listing | create/update/import bulk/optimize images | products, templates, URL/XML/object imports, optional shell |
| inventory | stock levels/set/reorder suggestion | products and order-item demand |
| pricing-strategy | suggest price/run experiment | policies/manual vectors/products |
| review-moderator | moderate pending/approve/reject | review content and status |
| analytics | natural-language query, top products, revenue breakdown | generated SQL across orders/products/reviews/users |
| user-management | lookup/set role/reset password/ban | user records and audit events |
| audit | recent/search/summarize anomalies | audit events and AI summaries |
| system | health/read config/restart/run diagnostic | filesystem and optional process execution |
| policy | read/update/apply policy | policy table and supervisor prompt content |
| mcp-registry | list/register/remove/describe/history/import | MCP registry/cache/schema history, external fetch/spawn/import |
| uploads | avatar/image/evidence/manual upload, download, extract | filesystem plus manuals vector corpus |
| email | send/read/summarize/auto-reply | email threads/messages, HTML/SMTP and inline fetch |

The server wrapper names and tool function names are authoritative. Some older
`docs/secureshop/AGENTS.md` descriptions use historical names.

## Cross-agent/data chains

The major shared channels are:

- `products.description_html` and reviews: browser XSS and indirect-prompt input;
- `policies`: admin/merchant edits flow into supervisor system prompts;
- uploaded product manuals: filesystem → chunk/embed → vector corpus → similar
  product/pricing/summarizer results;
- external MCP registration: URL/manifest → registry/cache → verbatim tool
  descriptions in supervisor prompt;
- tool result messages: raw task output → supervisor conversation → user;
- `audit_events`: user-management input → anomaly summarizer prompt;
- `agent_trace`: every supervisor/task hop → UI lane and admin diagnostics.

These are architectural relationships, not accidental duplication. A change to
encoding, sanitization, schema, or prompt formatting at one end affects multiple
labs/tests at the other end.

## Vector subsystem

`server/services/secureshop/vectorStore.js` supports LM Studio, Ollama, and a
deterministic hash fallback. It chunks source text, normalizes embeddings,
persists documents and index metadata, searches by cosine similarity, rebuilds
corpora, and exposes raw vector/document information for teaching objectives.
Corpora include products, reviews, policies, and manuals. Uploads and admin
rebuild operations are key writers.

## MCP registry lifecycle

1. native tools are discovered from live Agent Host servers;
2. `ToolManifest.refresh()` persists native schemas without deleting external
   cached servers;
3. the registry agent can register/import/remove external definitions and
   record schema history;
4. external descriptions are read from `mcp_tool_cache` and inserted verbatim
   into a supervisor prompt block;
5. optional real stdio spawn is gated by `SS_ENABLE_REAL_MCP_SPAWN`.

Keep native-agent membership in `ToolManifest.NATIVE_AGENTS`, pool agent names,
Agent Host `TASK_AGENTS`, role maps, ACL seeds, and tests synchronized.

## Adding a task tool

Update all relevant surfaces:

1. tool implementation and MCP schema/description in its agent server;
2. direct REST wrapper if the UI calls the tool without a supervisor;
3. role manifest membership;
4. `tool_permissions` seed rows and Layer-C caller enforcement choice;
5. trace/result shape consumed by the Agent Lane;
6. unit, integration, RBAC, provider-parity, and vulnerability tests;
7. intentional-vulnerability annotation and generated map when applicable;
8. this catalog.
