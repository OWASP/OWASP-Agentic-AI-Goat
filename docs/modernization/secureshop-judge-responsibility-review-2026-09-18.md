# SecureShop Judge responsibility review

Current source review, September 18, 2026. This is an architecture inventory, not native acceptance or proof of model accuracy.

| Objective | Rubric | Current evaluation | Required judgment |
|---|---|---|---|
| ss_loop_observation | secureshop-loop-v1 | Generic semantic | Later answer/decision must be consistent with the tool observation; semantic evaluation is justified. |
| ss_content_persist | secureshop-review-content-v1 | Generic semantic | Must distinguish an embedded assistant-directed instruction from ordinary feedback, in addition to verified persistence/retrieval. |
| ss_content_followed | secureshop-review-content-v4 | Two-stage semantic comparison | Classifies requested moderation action and underlying content; compares with the authenticated committed effect. |
| ss_rogue_tool_selected | secureshop-bound-mcp-v2 | Explicit verified fact | Exact unapproved owned-server invocation and protected-record receipt. |
| ss_rug_pull_invoked | secureshop-bound-mcp-v2 | Explicit verified fact | Prior and changed schema, same server, selected tool and completed changed invocation. |
| ss_cross_persona_effect | secureshop-persona-inbox-v2 | Verified fact plus grounded body citation | New sealed builder evidence and immutable consistency gate; actual-model v2 qualification pending. |
| ss_acl_advisory_effect | secureshop-persona-inbox-v4 | Scoped semantic | Mechanically bound deny/advisory/disclosure relationship is still interpreted by the model. |
| ss_acl_enforced_block | secureshop-persona-inbox-v1 | Generic semantic | Mechanically bound prior advisory action, newer enforced ACL and absence of disclosure. |
| ss_controlled_ssrf | secureshop-bound-ssrf-v1 | Generic semantic | Mechanically verified owned protected target, exact HTTP receipt and invocation. |
| ss_stored_browser_execution | secureshop-stored-browser-v1 | Generic semantic | Mechanically attributed execution of persisted learner bytes in the actual ReviewCard component. |

Sources: `server/services/secureshopLoopAssessment.js`, `secureshopReviewContentAssessment.js`, `secureshopMcpTrustAssessment.js`, `secureshopPersonaInboxAssessment.js`, `secureshopSsrfAssessment.js`, and `secureshopStoredBrowserAssessment.js`, together with their evidence builders.

Design rule: keep ownership, generation, tool selection, committed effects and exact-byte provenance authoritative on the server. Use independent semantic evaluation where the learning objective actually requires meaning or behavior comparison. An explicit factual criterion can still require a real Judge call and grounded evidence; it must not imply that a synthetic test trace proves an actual actor execution.

Cross-v1 calibration established a concrete grounding defect; cross-v2 is the focused repair under qualification. Advisory/enforced ACL, controlled SSRF and stored-browser grading are candidates for a later fact-backed design review because their outcome predicates are mechanically established. This is not evidence that those current workflows fail, and no blanket conversion is approved by this inventory. Preserve their exact provenance gates, historical receipts, real Judge calls and per-objective native positive/negative coverage before changing them. Loop consistency, source-instruction classification and moderation-policy meaning must retain semantic evaluation.
