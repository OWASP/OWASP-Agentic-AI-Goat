# MCP owned HTTP central integration contract

Status: proposed next integration; packaged transport is qualified separately.
No SSRF objective promotion, installed migration or application restart occurs here.

## Authorities and ownership

The existing LangGraph decision schema supplies only `fetch_url({url})`.
`protocolContext` supplies current run, invocation, owner/generation and effect key.
The admitted owned target supplies target ID and platform session; trusted server
configuration supplies vulnerable/fixed mode. No model argument supplies these.
The exact original URL remains in the request digest and transport input.

The identity database owns graph runs and the existing MCP request ledger.
A new private `workshop_conversations.mcp_http_operations` intent/receipt table will therefore bind a UUID operation to
user, graph owner/run/generation, target/session, invocation, mode, original URL,
canonical request digest, and an optional immutable completed transport receipt.
The MCP database continues to own target lifecycle. There is no fictional
cross-database transaction: runtime owner/reset fences and sidecar target locks
provide effect admission; identity transactions recheck active run/generation
before publishing receipts. Target retirement drains and deletes sidecar journals.

Proposed owned files: successor identity migration (reserved candidate 0083, outside active loader), new
`server/database/postgres/mcpHttpReceiptRepository.js`, the existing
`server/services/mcp/ownedHttpClient.js`, new receipt/tool adapter and focused
native tests. Changes to `sandboxShell.js` constructor/fetch_url and owned
composition require coordination. Installer/private API/profile mounting is a
separate readiness gate; existing CLI profile and AWS remain unchanged.

## Execution and replay

1. Validate trusted private invocation and exact identity; check owner execution.
2. Transactionally lock graph owner then run; reject stale/non-running execution.
   Insert bounded pending intent before any network call. Existing operation
   with different identity conflicts. Existing pending intent is uncertain and
   cannot issue another network request. An exact completed row can replay its
   immutable receipt only within the permitted active run/generation.
3. Invoke owned transport with the raw URL. Its journal binds the same digest;
   it handles actual sockets, redirect policy and joined cancellation.
4. After network completion, validate complete transport receipt identity and
   attestation; recheck owner execution. In a new identity transaction, lock
   owner/run and intent, then attach one immutable receipt. Different receipt
   bytes/digest conflict. No credit is inferred by persistence itself.
5. Any SQL failure after dispatch leaves a pending central intent and reports
   actionable uncertainty. Never synthesize success or re-fetch. A later
   dedicated recovery path may read the sidecar journal without executing it;
   resetting/deleting the target must not retrospectively invent provenance.

## Tool and Judge boundaries

An owned tool adapter renders the actual final hop body and transport errors.
It carries receipt identity for the graph effect/evidence path but returns
`achieved:false`; the canonical Judge remains the sole completion gate.
The legacy shared SSRF fixture URL mapping must not be selected by the supported
owned path, even when the owned transport is unavailable. Existing deliberate
vulnerable/fixed behavior remains in the isolated owned HTTP worker.

Promotion requires a genuine configured actor to choose the raw URL, actual
owned socket hit and canary evidence, central receipt publication, strict evidence
adapter, genuine Judge decision, and canonical generation-bound credit. Controlled
providers and receipts do not substitute for that qualification.

## Acceptance gates

- Fresh/populated/no-op successor migration and immutable predecessor ledger.
- Exact completed replay; conflicting URL/mode/owner/session/run/receipt rejection.
- Pending admission prevents duplicate network after process or SQL failure.
- Cancellation drains network before target lock release and publishes no receipt.
- Reset during network prevents late central publication; sibling users/targets
  and receipts remain byte-identical.
- Canonical deletion removes owner-linked private URL/receipt content only after
  resource cleanup; historical completion is never credited to a new generation.
- Normal tool arguments contain URL only, and no shared fixture substitution occurs.
- Private API/profile provisioning stays unavailable until exact packaged executor
  and active isolation are ready; bounded cross-owner admission precedes workshop use.

## Implemented candidate boundary

Candidate `drafts/mcp-http/0083_mcp_http_operations.candidate.sql` is outside the
active migration chain. It stores private content under `workshop_conversations`,
not the metadata-only graph trace tables. Repository/client/tool adapter code
implements pending admission, immutable publication/replay, exact manifest/hop
and canary validation, private receipt adoption across SDK normalization, and
model-decision witness binding in the existing LangGraph tool node. The adapter
always reports `achieved:false`. Owned sandboxes lacking a dedicated HTTP adapter
fail closed; legacy shared fixture mapping remains only in the legacy sandbox.

Native evidence `tasks/mcp-http-central-receipt-2026-09-19.json` covers the copied
normal loader, predecessor preservation, populated users, no-op replay, central
receipt conflict/replay, pending publication failure, reset race, sibling records,
runtime write restrictions and private-content deletion. Its receipts are
controlled fixtures; it is not combined actual-socket or model proof.

The current `mcpObjectiveGrader` still routes SSRF through generic
`mcp_real_tools.v1` and detector annotations. That is insufficient for promotion.
It needs an owned HTTP rubric requiring genuine model selection, exact raw URL,
current central receipt, same invocation/run/owner/generation, validated sensitive
listener/canary hit, and current canonical completion authority. No existing
qualification list has been expanded.

## Dedicated service and installer design (next gate)

Keep the ordinary CLI container/profile unchanged. Package the HTTP entry point
from the same image as a distinct local service using a separately named,
qualified AppArmor profile, private token and private target-state directory.
The installer must establish readiness of that exact image/profile/asset set;
a missing capability cannot select the shared SSRF sidecar as fallback.
The HTTP service separately admits the same trusted owner/session/generation
coordinates and returns its own process-local capability. Never reuse a CLI
capability in the HTTP process. Give each service an independent capability key.

Before HTTP resource creation, persist a child lease in the MCP database linked
to the parent target tuple. A proposed successor MCP0005 records the lease and
immutable cleanup receipt. This is essential: restarting with HTTP disabled must
not erase knowledge of previously admitted HTTP resources. Composite retirement
must drain/retire both services and persist the HTTP cleanup proof before the
parent resource can be certified retired. Crash replay repeats only idempotent
retirement/readback, never the learner request. Owner deletion snapshot and
redaction must include child leases; siblings must remain unchanged. A service
unavailable during required cleanup leaves actionable cleanup debt.

Expose only private admit/readiness/execute/receipt-read/retire endpoints; bound
bodies and bearer authentication precede target lookup. Receipt-read never
executes an operation, allowing pending central intent reconciliation without
another socket request. A central reset/generation transition still invalidates
late publication. Install/start/stop manage only service-owned resources and
credentials, with no AWS changes or modification of the existing live profile.
Capacity admission must bound concurrent helpers, pending requests and queue
waits across owners before declaring workshop readiness.

## Staged local installer and production wiring

`node scripts/install/mcp-owned-http.js --plan` previews Linux provisioning;
macOS additionally requires `--colima-profile=colima-<existing-owned-profile>`.
`--provision` is the explicit mutation entry point. It installs a separately
named workspace HTTP AppArmor profile, builds the packaged helper, preserves a
private token in `~/.owasp-ai-goat/<workspace-id>/mcp-owned-http.json`, and starts a
loopback-only port8093 service with a named persistent volume. CLI profile,
containers, AWS assets and application databases are untouched. Existing image
or profile mismatch fails with a drain/recovery requirement; no automatic
replacement or data deletion is attempted. Provisioning does not enable the
exercise, apply candidate migrations, or expand the objective qualification.

Normal owned-resource production now discovers this optional private config,
composes the HTTP client plus identity receipt repository and MCP child-lease
repository before readiness, and retains the composite if the lease table
exists while HTTP is disabled or configuration is removed. Thus existing
children remain cleanup debt until their service is available. Before the
candidate lease migration exists, disabled installations keep their original
startup behavior. Explicitly enabled HTTP without the schema fails closed.

Controlled provisioning tests cover separate macOS/Linux plans and private
Linux command construction; the actual packaged service and native database
proofs remain in `tasks/mcp-owned-http-service-central-2026-09-19.json`. The
new installer itself has not mutated the installed environment or been
qualified end-to-end through real macOS/Linux provisioning. Activation still
requires schema promotion, full lifecycle qualification and actual-model
Judge/credit evidence.

### Installer qualification update and automatic setup gates

`tasks/mcp-owned-http-installer-native-2026-09-19.json` now qualifies actual
installer invocation from the macOS ARM host into the existing isolated Colima
Linux ARM VM. It covers first provision, an exact container/config-preserving
repeat, a real socket request, durable receipt replay after service restart,
retirement, actual wrong-owner container rejection and removal of the owned
container/profile/volume. The original rebuild-induced image-ID mismatch is
retained in `tasks/mcp-owned-http-installer-initial-image-drift-2026-09-19.json`;
repeat provisioning now selects the recorded immutable image instead of
rebuilding. This is not native Linux fresh-install or AMD64 qualification.

Before normal setup calls this installer automatically:

1. Promote the preservation-qualified identity0083 and MCP0005 schemas in the
   correct ordered chain after resolving the reserved0082 predecessor. Recheck
   fresh/populated/no-op ledgers, runtime grants and private deletion/reset.
2. Extend exact owned qualification/readiness with the HTTP capability, adding
   only `fetch_url`/`mcp_ssrf` after the actor/Judge witness evidence is accepted.
   Currently production qualification deliberately excludes them.
3. In `scripts/setup-application.js`, add a distinct HTTP provisioning step after
   the additive database initializer and CLI runner readiness. Reuse the exact
   selected Docker/Colima authority and workspace identity. Require service,
   central-receipt and child-lease readiness before atomically setting the private
   HTTP config `enabled:true`; errors leave it disabled with an actionable retry.
4. Add an explicit checked activation helper: provisioning currently has no
   activation switch. Preserve existing token/image/state and exact CLI flags;
   never enable through a blind JSON rewrite or in response to service readiness
   alone. Startup must retain disabled HTTP children as cleanup obligations.
5. Qualify full production composition with real CLI and HTTP sibling ownership,
   restart, reset/deletion, service outage and disabled-config cleanup debt. Then
   qualify normal setup and rendered admin/student status. The isolated actual
   model harness separately records actor/Judge/credit evidence; it does not
   replace this installation lifecycle gate.

### Combined lifecycle and checked activation update

`tasks/mcp-http-full-lifecycle-2026-09-19.json` now proves both real CLI and HTTP
services through `createMcpOwnedResourceComposition`, signed durable platform
sessions, real SDK HTTP requests, disposable identity/MCP stores and canonical
run coordination. Missing HTTP connectivity blocks reset before parent cleanup;
a fresh disabled composition resumes and persists the child cleanup. Identity
user deletion then removes private central receipts while sibling parent,
child-lease and central receipt rows remain byte-for-byte equivalent. Both
services and profiles are removed. Mail callbacks only assert empty inventories;
this test does not claim an admin HTTP deletion request or a new actual-model run.

`scripts/install/mcp-owned-http-activate.js` implements the next concrete gate:
exact candidate migration ledger hashes, runtime relation/column privileges,
real CLI isolation readiness and exact HTTP manifest readiness precede a locked,
fsynced atomic private-config activation. Native tests prove unavailable service
leaves config disabled and repeated activation preserves its bytes. The exported
`provisionOwnedHttpCandidateForSetup` hook is wired into the setup module as an
explicit nondefault seam; ordinary setup never invokes it. It does not grant an
objective release. Normal automatic setup remains contingent on ordered schema
promotion and exact HTTP capability/tool qualification.
