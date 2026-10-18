# Judge evidence contract

The real SecureShop MCP qualification `umu8iien` performed protected reads but returned three valid failing Judge decisions. Its evidence packet contained hashes and behavior flags without enough of the verified invocation chain to assess the compound rubric. This finding does not prove that a richer packet will pass; that requires another connected qualification.

Every exercise adapter should distinguish two responsibilities:

- **Server verification:** authenticate the learner and exercise instance, fence the generation, reread the canonical effect, match the actual tool result digest, and validate the action/observation order. Never ask the Judge to establish ownership or trust an actor's success claim.
- **Judge assessment:** present a concise, interpretable record of what was verified and evaluate it against the objective-specific criterion. An opaque digest identifies an artifact but does not explain its content or the sequence of actions.

For MCP trust, the proposed packet includes the scoped protected record identity and classification, its content digest, the selected tool/call identity, the completed effect receipt, and—when the objective requires a change—the earlier approved invocation and schema. Private payload bodies remain excluded. The prior invocation must belong to the same target and precede the current invocation; a later invocation must not hide an earlier qualifying baseline during repository lookup.

The same review applies to other families: file exercises need actual read provenance, browser exercises need attributed execution receipts, mail exercises must distinguish SMTP acceptance from delivery, and HTTP exercises need target-observed request and response evidence. Fictional fixture data is appropriate. Claims of effects that never occurred are not evidence.

Acceptance requires positive and negative connected cases, stale/reset and other-learner rejection, refusal/unavailable outcomes with no credit, and actual configured-model qualification. Keep grading criteria stable while repairing missing evidence. Version any semantic rubric change and preserve historical judgments.

This document defines a review contract, not a claim that every adapter already satisfies it. Per-exercise gaps and qualification remain tracked in the [implementation plan](exercise-remediation-plan-2026-09-13.md) and [current release status](current-release-status.md).

## Controlled SSRF acceptance

The ordinary public-policy request and the private-policy attack must use the same application agent/tool path. The learner must be able to select the relevant issued URL; the adapter must not silently substitute a private URL for every request. An actual public fetch is a successful normal operation with no SSRF credit. An actual private fetch can become a candidate only when the selected resource crosses the recorded public-only policy.

Before writing a canonical invocation, reread the owned target's authoritative receipt and match its operation, target, nonce, request, method, path, status and response digest to the observed MCP result. A mismatch must leave no invocation row and retain pending receipt evidence for reconciliation. Reset must validate exact ownership before setting a retirement fence; rejected cross-owner cleanup must leave the legitimate target usable. A retired identity cannot reopen, including after a process restart once durable storage is integrated.

Current isolated tests exercise the HTTP/SDK adapter and in-process lifecycle. Durable restart behavior, application baseline selection, registered storage, actual-model qualification and the visible exercise remain open.
