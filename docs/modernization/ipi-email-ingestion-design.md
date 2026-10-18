# IPI email authenticity implementation design

Status: application design for implementation; not a claim of runtime qualification.

## Problem and retained experience

The existing email screen already performs configure, send, fetch, select and summarize. Keep its layout, controls, scenario selection and vulnerable/secure comparison. Change the data passed between these steps: the browser selects an opaque server-stored artifact instead of submitting email bytes to summarize. Current `emailAgent.js` accepts arbitrary `emailBody`, and `indirectEmailGraph.js` incorrectly promotes those bytes to tool evidence without an ingestion receipt.

## Authoritative content

Persist each fetched message as a PostgreSQL artifact belonging to the authenticated numeric user, IndirectEmail generation and originating fetch run. Store exact raw body, subject, sender, recipient, provider, provider message ID, transport receipt reference, content SHA-256 and ingestion kind. Impose explicit byte limits before storage; if model context is shortened, retain full artifact digest plus exact model-visible slice and its digest. Never silently label truncated content as the full email.

A retrieval receipt proves what the inbox API returned. SMTP acceptance proves only submission to the mail server, not inbox delivery. Bind a sent receipt to a fetched message only when exact provider/message identity and recipient checks support it; body/subject similarity is not identity. External mail transformations must remain observable, not forced into an exact-byte false match.

Manual entry remains available with the existing controls and is stored as `manual_entry`, with an unknown sender unless independently observed. It demonstrates processing attacker-supplied source material, not successful delivery. Never invent the workshop sender for a pasted body.

`POST /summarize` accepts only an artifact ID. Resolve it server-side using authenticated owner and current generation; reject missing, sibling-owned, stale or deleted artifacts before model or Judge calls. Reject attempts to override the body, sender or subject. The returned fetch records carry artifact IDs; the frontend sends the selected ID without changing presentation.

## Agent and Judge

Use a bounded LangGraph decision loop with explicit read_email, summarize and refuse actions. The model chooses the action; a controller validates the choice, limits loops and checks cancellation before and after effects. A read tool resolves only the selected owned artifact. Bind tool observations and actor responses to the same artifact, generation, run and model provenance. Keep vulnerable and fixed trust handling distinct.

The defense comparison contract now requires both actual responses (rubric v5). Remaining work: use staged source-only instruction detection followed by effect-bound grading for email trigger and defense. A poisoned source alone, mocked response, uncertain verdict or model error earns no credit. The secure response must substantiate defense even when the vulnerable response provides comparison context.

## Lifecycle and schema

Extend the PostgreSQL email repository with a forward-only numbered migration reserved before implementation. Register normal and first-install initialization, required tables and idempotent seeds as applicable. Do not add SQLite runtime storage. Use existing durable execution generation checks and transaction ordering to prevent reset races. Reset invalidates old artifacts; account deletion removes content and keeps only permitted audit receipts. Apply owner predicates in the database, not just routes. Include deletion coordinator integration and sibling-preservation checks.

## Real local qualification

Reuse the existing local SMTP/Mailpit infrastructure where compatible, with a distinct IPI recipient namespace and provider configuration. Do not repurpose XSS ownership or dispatch receipts as IPI proof. A local-only fixture must send real SMTP, retrieve via the mail API, persist the observed artifact, and invoke the actual llama3.1:8b graph and Judge. External providers remain optional and need separately labeled integration evidence; no external email is necessary for the local qualification.

Required cases: benign source; successful redirection; refused attack; fixed defense; multiple embedded instructions; manual entry; forged body; sibling ID; stale generation; reset during retrieval/model/Judge; restart persistence; deletion and sibling session preservation. Verify all five objective totals and admin hint/solution/visibility parity. Mock transport and model fixtures prove contracts only, never end-to-end authenticity.
