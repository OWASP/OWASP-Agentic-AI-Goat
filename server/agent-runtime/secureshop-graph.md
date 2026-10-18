# SecureShop graph runtime

All three role supervisors execute the same LangGraph control flow, with their
existing role-specific step/parallel-tool limits and prompts:

`initialize → budget → model → dispatch_tools → budget`, or `model → finalize → emit`.
Budget exhaustion and provider failures branch directly to `emit`. Existing trace
records, SSE tool_call/tool_result/assistant_message/done events, and return DTOs
remain unchanged. Each requested MCP invocation is a LangChain DynamicStructuredTool;
its permissive schema passes arguments unchanged to the existing pool. Advisory
ACLs still dispatch denied tools, enforced ACLs still return synthetic denials,
and poisoned policy/MCP descriptions and tool results remain verbatim teaching sinks.

The 17 task-server entrypoints import a shared MCP Server subclass. It intercepts
only public `setRequestHandler` registration for `tools/call`, placing the registered
handler in a one-node LangGraph with a permissive LangChain tool. Tool discovery,
SDK transport, original handler context, and every sink implementation are retained.
No SDK private handler registry or global prototype patch is used.

This executes graphs but does not enable durable replay. Existing session history
and trace storage remain authoritative. The backend and agent-host are separate
processes; safe restart/resume requires a shared durable run ledger, cross-process
owner leases, operation IDs and idempotency/reconciliation for side effects before
attaching a persistent LangGraph checkpointer. No exactly-once or recovery guarantee
is made. Existing supervisor concurrency/ownership behavior remains unchanged.

`tests/secureshopGraphRuntime.test.js` proves branch behavior, raw tool poison,
ACL modes, DTO/SSE ordering, real MCP transport compatibility, and all role wrappers
against disposable SQLite stores. Existing full vulnerability/chain/parity suites
remain necessary release qualification; this test is not a substitute for them.
