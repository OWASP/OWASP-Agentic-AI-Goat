# Protected MCP recovery and telemetry follow-up

September 19, 2026. Diagnostic plus bounded source repair; teaching content and installed application remain unchanged.

The owned copied-source native cohort in `tasks/mcp-protected-lostack-native-2026-09-19.json` uses real PostgreSQL, the production SDK/tool/client, an actual loopback connection closed after the real target filesystem rotation, and a controlled private HTTP admission wrapper. The rotation commits once, key version advances from1 to2, and the shell catches the transport error as `PROTECTED_STATE_UNAVAILABLE`. Because it returns normally, the SDK ledger marks the effect **completed**. The returned result has no private success witness. Restarted same-key replay is blocked; no second rotation occurred. Thus this is misleading terminal effect status and missing recovery evidence, not demonstrated duplicate execution or false objective credit. The reset callback deletes only its owned target and preserves the sibling; this is not a fresh qualification of the full production retirement path.

Implemented source repair (`tasks/mcp-protected-lostack-repair-native-2026-09-19.json`): preserve typed transport uncertainty through `ownedTargetClient.js`, `sandboxShell.js` and SDK so the existing ledger records uncertain. Do not automatically replay. A later durable operation-ID journal can reconcile exact protected results after acknowledgement loss, with request-digest conflicts and pending uncertainty; it must distinguish effect identity from run identity. Known pre-effect rejection, successful effect, forged error fields and lost acknowledgement are distinguished in35 focused checks; copied-source native SDK/socket/PG qualification records uncertain and blocks replay. Full production reset/revocation qualification remains separate. Preserve intentional unprivileged rotation.

## Proposed teaching-copy correction (not applied)

`server/data/mcpWorkshopSolutions.js`, `mcp_audit_gap`:

- Hint: “The maintenance tool can disable future target telemetry or clear existing target telemetry. These are different operations.”
- Hint: “The target does not require authorization and does not record its own disable/clear action in its target telemetry.”
- Example explanation: “Disable target telemetry, then perform another protected operation. Its target audit record is omitted. Clearing removes existing target audit entries; clearing alone does not disable future entries.”
- Approach: “Compare target telemetry with the platform's retained learning and grading evidence. The platform retains the maintenance action and canonical evidence so instructors can review the exercise.”
- Tip: “The Tool Activity panel is a platform projection. Do not interpret its retained maintenance event as the target audit journal.”

`server/data/workshopHints.js`, `mcp_audit_gap`: replace “audit/telemetry log” with “owned target's telemetry”; clarify that disable stops future records while clear removes previous records. Add the platform-retention distinction.

The route at `server/routes/mcpWorkshop.js:422` deliberately records `set_audit_logging` even when subsequent activity is suppressed. The actual clear operation in `sidecars/sandbox-runner/mcpProtectedState.js` truncates the target's `audit.jsonl`, not platform activity. Keep platform evidence immutable. For visible proof, add a trusted owner/session/generation-bound target telemetry projection rather than falsely promising that the existing Tool Activity list is erased. Any content update needs default-only seeds and admin/hint/solution parity; this review does not change catalogs.

## Retained positive proof

The Sept14 cohort `~/.owasp-ai-goat/native-verification/owasp-ai-goat-mcp-owned-connected-5et0_cw9` passed all three protected objectives with actual actor/Judge and canonical awards. `tasks/mcp-protected-current-review-2026-09-19.json` records hashes, cleanup and scope. Current target-state and private-witness modules match that snapshot; adapters/grader and schema chain have since changed. Matrix pointers now retain that historical proof while current rendered/admin parity remains pending. No additional model calls were needed.

## Return-fence correction

Root review identified that `TARGET_AUTHORITY_REVOKED` and `TARGET_RETIRED` can arise after committed work, so error codes alone do not establish pre-effect rejection. Both now remain uncertain. `tasks/mcp-protected-lostack-return-fence-native-2026-09-19.json` records actual `mcpTargets.withTarget` return-phase authorization denial after a real rotation: key version2, PostgreSQL effect uncertain, same-key retry blocked without another rotation.28 focused checks pass. The initial owned container readiness attempt ended before tests and was removed; its record is retained separately. Durable receipt reconciliation remains open.
