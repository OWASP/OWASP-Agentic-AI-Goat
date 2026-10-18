# Workshop experience adoption inventory

This inventory records the template boundary used by the current workshop pages. The template describes the learning workflow hierarchy; it does not replace domain-specific workspaces, grading, visibility, or intentionally unsafe renderers.

| Page | Template | Scenario ownership | Existing reset/help behavior retained |
|---|---|---|---|
| Direct Prompt Injection | Single | Prompt Injection chat; transcripts remain objective-scoped | Conversation reset and confirmed exercise progress reset; independent Hint/Solution gates |
| Indirect Prompt Injection | Multi | Document Upload (RAG), Email Agent | Confirmed per-scenario resets preserve siblings; RAG help gates remain independent; Email exposes no invented help |
| SQL Workshop / ARIA | Single | ShopFast SQL chat and tool results | User-scoped conversation/cart/progress reset and solution gates |
| NoSQL Workshop / NOVA | Single | ResearchVault NoSQL chat and tool results | User-scoped conversation/reading-list/progress reset and solution gates |
| Sensitive Information | Single | VaultCorp tool workspace | Category tabs organize one workflow’s objective set; progress and solution gates remain server-owned |
| Supply Chain | Single | Package review and execution workspace | Existing progress reset, hints, solutions, mode, and evidence remain intact |
| XSS Workshop | Multi | Reflected, Stored User, Stored LLM, Email | Per-scenario transcripts and detection state survive navigation; tab/full resets and independent gates remain intact; intentional raw HTML sinks remain local |
| CSRF Workshop | Multi | GET, POST, Email/XSS, Indirect/RAG | Each scenario retains its victim, transcript, payload, defense state, progress, and reset endpoints |
| Excessive Agency | Single | Agent actions | Chat/Tools are two views of one agent scenario, not separate curriculum scenarios; progress and solution gates remain intact |
| MCP Workshop | Single | MCP operations | Assistant/Inspector are two views of the same MCP scenario; progress, hints, and solutions remain intact |

All eligible workshop pages present in `client/src/pages/workshops` and the requested challenge-page set now consume a versioned baseline definition and template. No eligible RAG page remains outside the list: the standalone RAG workflow is the Document scenario in Indirect Prompt Injection.

CTF and SecureShop remain outside this adoption by design because they are specialized products with level/storefront/admin navigation. Other legacy challenge pages outside the requested U05 scope have not been relabeled as workshops.

The local tab distinction matters. Objective category filters and protocol inspectors do not become scenarios merely because their old UI used tabs. A scenario owns independent workflow state and reset scope; a view or category does not.
