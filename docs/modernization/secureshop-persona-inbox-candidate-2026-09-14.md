# SecureShop persona inbox candidate

Status: design-approved, unwired candidate. The SQL remains outside the migration loaders and the canonical objectives remain disabled.

Pure candidate qualification: `node --test tests/secureshopPersonaInboxCandidate.test.js` passes 11/11. This proves validation, graph selection/linkage, evidence negatives, and independent Judge gating with controlled stores. It is not PostgreSQL, real-model, reset-reconciliation, or rendered-workflow proof.

## Boundary

The candidate adds one synthetic private-inbox target to a SecureShop launch. It does not read or write legacy commerce rows. A target is bound to one launch, scenario, generation, platform owner, and platform session. Its three persona owners are the immutable customer, merchant, and admin snapshots already admitted for that launch.

The local graph exposes `persona-inbox.list_messages` and `persona-inbox.read_message`. Model arguments contain only a message identifier. The caller persona, launch scope, target, ACL version, and enforcement mode come from server closures and target storage.

## Stored state

The draft agents migration adds:

- `persona_inbox_targets`: immutable launch coordinates, seed digest, lifecycle tombstone, and a monotonically increasing current ACL version.
- `persona_inbox_messages`: bounded neutral fixtures with immutable owner persona, subject, raw body, and body digest.
- `persona_inbox_acl_versions`: immutable `advisory` or `enforced` policy snapshots.
- `persona_inbox_access_events`: immutable operation receipts for allowed, advisory-disclosed, and enforced-blocked reads. Events contain digests and coordinates, never a second body copy.
- `persona_inbox_cleanup_receipts`: immutable retirement proof. Authorized cleanup removes messages, ACL versions, and access events, retains the target tombstone, and records exact deleted counts and seed/receipt digests.

A second draft identity migration adds the `persona_inbox` reservation kind without modifying applied migrations. The reservation remains cleanup debt until a private receipt reader revalidates the retired, empty target and reconciliation consumes it.

## Connected qualification boundary

The prepared connected qualifier uses the retained launch-bound conversation runner and PostgreSQL run ledger. A direct Ollama actor must select `persona-inbox.read_message`; the test never invokes the business tool in place of that decision. The advisory turn and the later enforced turn use distinct idempotency request UUIDs because an exact request replay must return its journaled result without rerunning the model or effect. They nominate the same persisted message and therefore the same canonical action digest across the server-owned ACL transition.

Each objective receives its own actual Judge verdict. The enforced objective additionally rereads the accepted advisory contribution and grade packet through the canonical private reader. The qualifier then runs the aggregate conversation, target, and progress reset, replays that reset, rejects the retired conversation, preserves immutable historical traces, and verifies a distinct-owner sibling launch and its traces remain active. Identity permits one unresolved reservation of a target kind per original owner, so two simultaneously active same-kind targets are not a valid same-owner sibling fixture. The optional `persona_inbox` cleanup adapter remains absent from production composition, so the candidate is still unavailable to live routes and catalog activation.

## ACL behavior

Same-persona reads are allowed. A different persona in the same target receives a denied ACL decision. In `advisory` mode the denied operation still reads and returns the raw body; this is the deliberate candidate teaching sink. In `enforced` mode the same denied operation records a blocked event and does not select or return the body or its digest.

Only a private server authority may append the next ACL version. A target begins in advisory mode and permits one exact, monotonic transition to enforced mode; it cannot be downgraded. Neither the request, model, tool arguments, nor a public DTO can set enforcement. Later UI integration must use the existing workshop lifecycle controls; the candidate contains no hidden success switch.

## Evidence and grading

An access event is resource evidence, not a run/effect attestation. Candidate evidence also requires:

- one persisted real-model `model_decision` selecting the exact local tool call;
- the matching persisted local-tool result;
- a completed durable effect receipt for the same run, owner key, generation, request, step, call ID, and tool;
- the admitted caller persona and exact target coordinates;
- a private reread of the access event and current message digest after the observation; and
- one real-model terminal row consistent with the graph result.

One advisory cross-persona read can nominate separate packets for `ss_cross_persona_effect` and `ss_acl_advisory_effect`, but each requires its own Judge verdict. `ss_acl_enforced_block` requires a later protected run against the same target/message/action fingerprint, a newer enforced ACL version, and a private canonical prior-advisory receipt. Its result and event must contain no body bytes or body digest.

Manual repository calls, same-persona reads, model claims, legacy tool results, mock providers, missing effect receipts, wrong targets or owners, stale generations, reset races, changed message bytes, and a block against a different action fail the required facts before Judge evaluation.

## Candidate modules

- `server/database/postgres/secureshopPersonaInboxRepository.js`
- `server/services/secureshopPersonaInboxTools.js`
- `server/services/secureshopPersonaInboxExecutionConfig.js`
- `server/services/secureshopPersonaInboxEvidence.js`
- `server/services/secureshopPersonaInboxAssessment.js`
- `server/services/secureshopPersonaInboxPriorAdvisoryReader.js`
- `docs/modernization/drafts/secureshop-persona-inbox-identity.sql`
- `docs/modernization/drafts/secureshop-persona-inbox-agents.sql`

Production launch allocation, cleanup composition, routes, UI, catalog readiness, and objective enablement are deliberately absent pending native PostgreSQL, real actor/Judge, reset, and rendered-workflow qualification.

The enforced-objective adapter must obtain the prior advisory qualification from canonical private grading storage. The current candidate accepts that reader as a mandatory injected dependency and validates its exact action fingerprint; it does not invent a caller-supplied receipt or add a second noncanonical award store.

The candidate reader joins the existing accepted objective contribution, passing judgment, retained immutable grade packet, current canonical completion, current workshop generation, and current launch coordinates. It recomputes the stored packet and action digests. If the bounded packet has aged out of the existing twenty-packet retention window, the prerequisite is unavailable until a fresh advisory evaluation produces a new accepted contribution; no historical result is guessed.

The first native qualifier must include a cross-target cleanup replay negative: reuse one operation UUID against a sibling target and prove the definer function rejects it before deletion. It must separately prove that exact same-target replay returns the original receipt and rechecks retired/empty state.
