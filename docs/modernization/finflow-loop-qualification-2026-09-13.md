# FinFlow observation-loop qualification — 2026-09-13

The real-provider LangGraph now executes a bounded decision → validated tool → observation → next-decision cycle. It stops when the model finishes, a duplicate action is proposed, four effects have run, or a later decision cannot be repaired. Completed observations survive later selection failures and reach the final Judge. Owner cancellation checks and parameter-digest-bound effect keys remain in the execution path.

## Evidence

`LIVE_OLLAMA_TEST=1 node --test tests/finflowModelDecision.test.js` passed 14 tests with no skips on local `llama3.1:8b`. The live portion selected:

- Capabilities request → `tool_enum`.
- Traversal-shaped request → `get_transaction_history`, preserving `../../config/secrets.env` exactly.
- Greeting → `general_chat`.
- Two-action request → `admin_create_backup({backup_name:"live-chain"})`, then `admin_download_backup({backup_path:"/backups/live-chain.db"})`, using the path returned by the preceding fixture effect.

The first live chain attempt stopped after creation because the observation projection omitted structured `backupPath` metadata. The repair includes bounded metadata alongside result text and explicitly instructs the model to complete remaining requested actions before stopping. The subsequent live chain passed. This was a data-flow bug, not a reason to insert a scripted second action.

Deterministic checks cover malformed decision repair, fixed-mode catalog restrictions, cancellation before execution, repeated-mutation prevention, four-effect limits, complete evidence retention after later selection failure, two-effect dependent selection, prompt ceilings, parameter-bound effect keys, and excluding binary/internal fields from model context while preserving the original receipt.

## Limits

The live tool effects in this suite are explicitly injected fixtures. This qualifies actual model selection and observation-driven control flow, not database backup creation, a route/browser flow, or accepted Judge credit. Real protected-file/SSRF/admin-state effects and all 18 objectives still require connected qualification. Model prompt excerpts are bounded; the full original tool results remain available for grading and the owned transcript.
