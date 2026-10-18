# XSS and CSRF graph entrypoint coverage

| Entry point | Graph nodes |
| --- | --- |
| XSS workshop `POST /chat` | model → parse/save-intent gate → optional tool → summary → deterministic grade |
| Legacy XSS email `POST /generate` | profile read → model → existing profile/signature substitution → template persistence |
| CSRF `csrfWorkshopAgent.chat` (normal chat and forged agent-action callers) | classify → document/recon/defense/query/attack/chitchat → phrase |
| CSRF email/RAG `summarizeWithHtml` | model → preserve teaching HTML or report unavailable |

HTML is intentionally unchanged: XSS email bodies remain appended raw, profile
substitutions remain unescaped, signature handling keeps its original partial
script stripping, and CSRF gadgets are restored verbatim when model prose drops
them. XSS generate-only requests cannot auto-save; deterministic objective order
and CSRF guarded-action/defense/vector rules are retained.

Coverage limits: CSRF `/chat` inbox retrieval and RAG retrieval, victim forging,
and objective persistence still execute in route control flow around the summary
graph. They are not yet full workflow graphs. Email send routes and non-AI CRUD,
reset, and progress endpoints remain existing handlers. Root's scoped reset changes
were retained. No durable ledger/checkpointer or new reset cancellation is added.

`tests/xssCsrfGraphs.test.js` injects stores/models/tools, forbids live authDb imports,
and checks HTML sink preservation, save-intent gating, template persistence,
CSRF branch precedence and objective results. It sends no email or network request.
Broader route/vulnerability verification belongs in the disposable test copy.
