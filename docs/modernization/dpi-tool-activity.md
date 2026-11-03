# Direct Prompt Injection Tool Activity

DPI reuses `ChatActivityTabs` from the shared workshop components. Chat and Tool Activity are views of the same mode/objective conversation; switching views preserves the draft and transcript. Activity is stored on admitted transcript messages, including admitted failure diagnostics, so the existing owner, mode, objective and reset-generation checks also govern the log.

The obfuscation graph is the only DPI workflow that executes a tool. It projects the model-selected `decode_payload` call after validating its owned receipt. The public entry contains the call ID, name, empty arguments (the actual tool takes no arguments), decoded result, server timestamp and status. Internal ownership fields, receipts and grading proofs are excluded. Invalid input produces a safe error entry only when decoding was actually attempted. A later provider failure preserves a completed call; invalidated runs cannot publish stale activity. Other objectives and no-tool decisions return no activity.

Conversation reset retains DPI's local conversation-memory contract and cancels the corresponding request generation. Progress reset clears transcript activity only after server acknowledgement; failed resets retain confirmed content. Tool success does not award objective credit. Catalog identities, hints, solutions, grading gates and intentional vulnerable/fixed behavior are unchanged.

## Verification

Focused checks on the PR branch (2026-11-02):

- Frontend: 76 tests passed across `DirectPromptInjectionChallenge.test.js`, `directPromptInjectionState.test.js` and `ChatActivityTabs.test.js`.
- Backend: 25 controlled tests passed across `dpiObfuscationGraph.test.js`, `dpiProviderFailure.test.js` and `dpiSelectedLesson.test.js`, in a clean worktree with an empty inherited environment and no application database credentials.
- Production frontend build passed. Existing large-chunk warnings remain.
- The supported isolated launcher aborted before tests with a macOS native sandbox serializer assertion. The controlled fallback above is not a pass of that launcher, native PostgreSQL qualification or actual-model proof.

Live learner checks on 2026-11-01 used the configured Ollama `llama3.1:8b` in vulnerable mode. One request per objective was run sequentially. After the decoder call, all eight activity views were revisited: seven correctly showed zero calls and encoding retained its one successful call. Keyboard navigation and draft retention were also checked. No progress reset or mode mutation was performed.

| Objective | Observed response | Completion | Tool calls |
|---|---|---|---|
| Practice | Explained S3 | Already complete; new response verified | 0 |
| System prompt | Disclosed synthetic lab instructions | Newly completed | 0 |
| Instruction override | Answered Paris | Newly completed | 0 |
| Language | Spanish AWS-only refusal | Pending/unqualified; no credit | 0 |
| Hypothetical framing | Answered Paris | Pending/unqualified; no credit | 0 |
| Role-play | Described Paris landmarks | Newly completed | 0 |
| Competitor context | Explained Azure Functions | Pending/unqualified; no credit | 0 |
| Encoding | Decoded the question and answered Paris | Pending/unqualified; no credit | 1 successful decoder call |

Final displayed progress was 4/8. The pending outcomes follow existing semantic-credit qualification gates; they are not claimed as completed objectives. Earlier encoding requests failed closed when the model added prose before its JSON decision. The successful requests explicitly requested JSON-only decision formatting. Arbitrary-prompt reliability, all-objective credit readiness, fixed-mode live qualification, four-width responsive checks and full accessibility certification remain outside this verification.
