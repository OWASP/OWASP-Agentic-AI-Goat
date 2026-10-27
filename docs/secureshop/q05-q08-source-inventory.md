# Q05 and Q08 source inventory

This is a review aid for the two deferred qualifications. Run
`node scripts/verify-secureshop-q05-q08-inventory.js --json` from the repository
root to obtain the current machine-readable callsite inventory. The command
reads source only. Its focused contract is
`node --test tests/secureshopQ05Q08Inventory.contract.test.js`.

The original seven surfaces remain: bound RoleChat tool descriptors,
task-agent MCP tool descriptors, literal mutating SecureShop route registrations,
dynamic router verb registrations, literal confirmation terminals, storefront
fetch callsites (including direct customer, merchant and admin panels), and
`@intentional-vulnerability` annotations in server and agent code. Every row has
a repository-relative source location and the status
`source_discovered_runtime_unverified`. New source callsites appear in the next
inventory run; the test guards the presence of all seven families and selected
known actions. Schema version 3 also lists top-level `server/services/secureshop*`
authority modules and confirmation callsites, client bridge modules/fetches,
inline composition mount references, all current canonical workshop objective
IDs, and the separate CTF stage catalog. Imported family curriculum modules
and generated objective IDs are included through the pure canonical catalog.

This is **not a complete supported-action denominator**. A second static
partition now discovers non-SecureShop application API mounts, React route
components, route registrations, nested/computed registrations, page requests,
page events, and narrow same-handler literal-request candidates. It does not
establish all advertised actions, effects, or confirmations. The historical
all-lesson scope must be reconciled explicitly, not narrowed by this script's
filename. Catalog objectives alone omit manual and ungraded advertised actions.

Schema version 4 adds `reviewedPartitions.ctfAdmin`, backed by
`docs/ctf/supported-admin-action-manifest.json` and its source validator. It
enumerates thirteen consequential CTF administrator action types: participant
reset, remove, ban and unban; technique and payload blocklist clearing; full CTF
reset; stage activation, advanced editing, teaching-content editing and deletion;
model preview; and configuration changes. Parameterized rows and configuration
fields are not thirteen individual physical widgets. Preview uses a model but
does not award learner credit; manual lifecycle changes must not be assigned
invented model/Judge receipts. That administrator partition excludes participant
actions; schema version 5 reviews them separately below. Global scoring
applicability remains unresolved. Stage creation and heartbeat have supported routes but no
caller was found in the reviewed CTF UI; that is not a runtime availability claim.
The validator checks selected executable bindings and rejects tested wiring
changes; it is not a general control-flow proof. Consequence descriptions and
confirmation wording are reviewed metadata. Full transitive SQL effects,
runtime publication, and the absence of all alternative storage/model paths
are not established by these static checks.
The partition distinguishes command admission from projected effects and traces
the supported PostgreSQL authority router, not the legacy `routes/ctf.js` file.
Operation recovery requires a returned reference held by the mounted page;
it does not establish reload recovery after a lost acknowledgment. Source checks
do not prove physical confirmation, native effects, or Q05/Q08 completion.

Schema version 5 adds `reviewedPartitions.ctfParticipant`, backed by
`docs/ctf/supported-participant-action-manifest.json`. Its five primary actions
are registration, automatic stage start on challenge initialization, hint
purchase, vulnerable scored attempt, and unscored Fixed practice. Registration,
start and hints are manual/lifecycle effects without a model or Judge at the
mutation boundary; hints change potential score. Attempts have branch-dependent
guardian, Judge, publication and credit paths. Fixed practice uses a public
prompt without protected challenge context and cannot establish a scored Fixed
counterpart. The administrator manifest's five unresolved participant rows
remain exclusions from that partition; this separate partition supplies their
source review, not runtime qualification. Its selected AST binding checks do
not prove transitive control flow, every physical widget, or all runtime effects.

CTF recovery must be classified by consequence, not HTTP verb. The canonical
`ctfAuthorityFacade.recoverOperation` calls its bounded `wait` helper, which can
call `worker.pump` while an operation is pending. Thus an operation GET can
advance an already admitted lifecycle projection. Attempt recovery additionally
uses publication and blocked-publication GETs, proposal-authorization POSTs and
explicit predefense-resume POSTs. These are continuations of retained actions,
not new original submissions, and must stay in their action's consequence and
authority review. Do not label all CTF recovery GETs read-only. This source
observation does not prove native recovery or complete Q05/Q08.

The non-SecureShop partition parses source ASTs without importing the stateful
application or client. A candidate join needs one direct `app.use` module
reference, one literal router method/path, a directly mounted React page, and
one same-component event handler's immediate literal request. Duplicate or
absent matches, computed verbs, dynamic URLs, aliases, nested routers and
imported/configured component paths remain explicit unresolved rows. An
uncalled nested callback or unrelated `onClick` does not prove a request.
Tests, comments and string examples do not become route registrations.
The `/api/ctf` mount is a deferred production wrapper: source callsites trace
through `ctfAuthorityProduction.js` and `ctfAuthorityApplication.js` to
`ctfAuthorityRouter.js`, while runtime publication and returned-router
dataflow remain unverified. Legacy `server/routes/ctf.js` is not treated as
the supported router merely because it shares the family name. Workshop
objectives and CTF stages remain separate from request rows; no objective
mapping or score is inferred.

Composition references distinguish a concrete `router.use(require(...).factory())`
callsite from module comments. For example, the coupon confirmation module's
stale “Unmounted” comment does not erase its current callsite in
`secureshopBoundReviewComposition.js`. That callsite is conditional: dependencies,
transitive mounts and the actual runtime must still be checked. Imported aliases,
computed registrations and other composition forms are not resolved by this
scanner. Neither a mount reference nor its absence is a reachability verdict.

Q05 needs a per-consequence review of what the user physically confirms, what
the server binds, how an intentional teaching exception is constrained, and
what a denial leaves unchanged. Q08 needs a per-advertised-action chain from the
original user request and genuine actor decision through validated tool
arguments, owned effect and readback, independent Judge decision, and canonical
credit. The JSON lists the receipt fields required to evaluate that chain.
Read-only actions and manual panel actions need an explicit applicability
decision; a model provenance field must not be fabricated for a manual action.

The source inventory cannot determine actual reachability, dynamically built
paths, all service-side effects, or whether a model selected a tool. It does
not recursively prove every child component or imported request helper behind
a React page, nor every nested Express router. In
particular, a tool descriptor, prepared proposal, annotation, controlled test,
or prior receipt with a different source build cannot promote Q05 or Q08. Both
remain deferred and unverified until every supported row is reconciled and
connected native, rendered and genuine-model evidence is independently checked.

The supported-action manifest also carries a bounded RoleChat descriptor
partition. It preserves all 51 declarations from the merchant/admin RoleChat
tool catalog: three selected variants have deeper route/composition review;
the other 48 now have exact descriptor-to-local-handler source accounting,
grouped into merchant/admin read and proposal/handoff families. They retain
explicit unresolved downstream edges rather than becoming safe or exempt.
All 51 share the supported role-specific chat POST and saved-request GET;
that readback is not a receipt for later business effects.
`admin.audit_search` joins the model-selected search to
the owned audit service and protected operation readback; `admin.system_config_read`
joins an owned System read and saved readback, with conditional assessment only
on an eligible original completed turn; `merchant.mail_send_prepare` creates a
proposal, while a separate physical mail confirmation can send. The reviewed
rows reference existing bridge IDs rather than creating duplicate actions.
The focused AST contract checks all declarations and local handler anchors,
plus selected availability, composition, route and effect callsites, including
tested tampering failures. Availability descriptions for the other 48 and
downstream consequences are reviewed metadata, not machine-proven dataflow.
It does not prove full runtime dataflow, all physical UI controls, model/Judge
execution, or native effects. No other descriptor is deemed safe, read-only or
exempt by its unresolved status.

## Reviewed multipart upload shape and open UI mismatch

The source-reviewed `uploads.create` bridge registration has one conditional
bound effect: the active merchant listing editor renders `UploadZone` with
`kind=product_manual`; its Upload button sends multipart input to `/uploads`.
The bound gateway requires the merchant persona and this exact kind, then calls
the composed manual-ingestion service when that dependency exists. The service
checks current launch/product authority, uses an internal model-gated local
tool, writes and reads back an isolated file, and appends indexed manual chunks
under a derived operation ID. This is an indexing consequence, not merely a
temporary file selection. The current product-manual control now explains the
selected-product storage/indexing consequence and possible downstream influence
before the explicit Upload click; the public/private choice is described as
lesson metadata without a confidentiality guarantee. No extra modal is
required by this source classification. The server now has a conditional,
read-only merchant `uploads.productManual.receipt` GET for an exact six-field
descriptor and optional `recoveryScopeKey`. It returns `not_found` (still
unresolved) or an immutable indexed receipt under retained owner/scene
authority. Optional keyed POSTs add retained checks before actor, tool and
effect boundaries. The bound merchant UploadZone now uses a source-wired
pending-reference hook: immutable file/metadata hash, preflight GET, persisted
and flushed reference before one keyed POST, then exact indexed readback. Its
explicit **Check saved upload** control sends GET only after an uncertain result
or reload; `not_found` remains unresolved and no automatic POST retry occurs.
Unbound/legacy four-field uploads still lack the extra key fences. These source
and controlled-test observations do not establish rendered/native recovery,
physical denial/no-effect, or Q08 original actor/Judge provenance.
The disposable `manual-private-model` diagnostic (`run-9d7udfx1`, 1/1 passed,
zero skips) verifies a narrower native API facet: public/private original
keyed POST indexing, nine no-store read-only receipt GETs, changed-name
`not_found`, foreign-persona denials and reset-stale 409. It compared SQL,
file and model snapshots around GETs. Its lost-ack test discards an already
successful response, rather than simulating a socket or final-model failure.
There were 10 actor calls and zero Judge calls; private retrieval-context
exposure did not produce final-answer disclosure. It does not test rendered
UploadZone recovery or complete Q05/Q08 qualification.

Account mounts the same component with `kind=avatar`, but its bound action is
the separate, conditionally registered persona-scoped `/uploads/avatar` POST
and `/uploads/avatar/operations/:requestId` GET, not the merchant-only
product-manual ingestion route. The retained `run-l37zcdvr` receipt and its
independent closure accepted the bounded physical avatar facet at that source
snapshot, with zero model/Judge calls; do not count it as product-manual support
or a fresh, aggregate Q05/Q08 pass. Current-source compatibility and any wider
action coverage still require their own evidence joins. No new avatar operation
or scored objective is inferred.

## Reviewed merchant moderation source path

The bound merchant Reviews panel now links `merchant.reviews.moderateAll` and
`merchant.reviews.moderationReceipt` to the original button, bridge operations,
mounted review router, runtime composition and retained readback. Its pre-click
text says the model can approve or reject up to 100 pending reviews for the
merchant's products and that list filters affect display only. The explicit
button starts bounded batches; the server limits each model turn to at most
five reviews, but the original action may continue through up to 100 considered
reviews. Before each keyed POST, the client obtains a `not_found` preflight for
the exact request ID and remaining limit, stores an IDs-only reference under
the parent shop scene, and awaits its flush acknowledgment. No review body,
model note, decision or asserted progress counter is persisted in that reference.

After an uncertain POST or readback, the client retains the reference and sends
no automatic repeat POST. Mount/reload is also mutation-free. An explicit
**Check saved moderation** re-reads completed and pending request IDs by GET
only. `not_found`, `started` and `uncertain` are unresolved, not successful
completion. The client validates a matched completed projection and reconstructs
the aggregate quota from server results before offering a separate, deliberate
**Continue remaining** click. A completed `ok:false` result can contain partial
applied decisions and ends the action; it does not authorize continuation.
The unbound rule-based moderation simulation and intentional raw-review text
sink remain separate. This source review does not prove a rendered physical
confirmation, cancel/denial no-effect, fixed-mode outcome, native recovery, or
the original actor-to-tool-to-effect-to-independent-Judge-to-credit chain. No
vulnerability objective is inferred from the nearby review text lesson.
The disposable `review-moderation-recovery` diagnostic (`run-tal6tlrp`, 1/1
passed, zero skips) establishes a narrower native API observation: one
original keyed moderation batch, three actual actor calls, one approved review
from two original local-tool effects, exact completed readback and same-ID
replay without another effect. Ten no-store GETs and that replay left the 26
declared snapshot table groups unchanged per check, excluding auth last-seen
metadata. Foreign, revoked, old-mode and reset cases were denied or returned
scoped `not_found`, and the sibling remained unchanged. The simulated lost
acknowledgment discarded an already successful response, not a failed socket
or server acknowledgment. The fixture did not render the panel or run a
fixed-mode model effect or Judge; objective credit was false. The native API
facet does not verify physical UI recovery or close Q05/Q08.

## Minimum remaining implementation

The 12 commerce bindings retain an unresolved family-wide event-to-request
relationship. A narrower source-only review connects three profile
bindings: the protected Account route mounts the account profile form; its
Review and Confirm controls lead to the account profile POST; and the
chat-mounted Confirm path checks a saved proposal before sending its source
session, request and proposal IDs. The component saves an operation reference
and uses an exact operation read before and after either POST, with a separate
read-only recovery control. The source contract checks selected mounted AST
links, branch guards, verbs, payload keys and route/repository anchors; it is
not general control-flow proof. In particular, source IDs used in the async
chat closure are not both effect dependencies, so this review does not prove
every stale-source transition is fenced.

Another selected source review connects manual checkout's first Place order click
to a persisted quote-preparation POST and a second explicit Confirm click to
the proposal-ID checkout POST. The chat lane mounts separate checkout and cart
confirmation cards only from completed, trusted saved-turn operations; each
has an exact-proposal preflight, a retained parent-acknowledged reference,
one confirmation POST and exact outcome readback. These are distinct UI paths:
manual quote preparation creates no order; a chat cart tool creates a proposal,
not a cart effect; an approved synthetic checkout confirmation can create an
order, while declined/stale outcomes retain a receipt without that effect.
The selected saved-operation recovery controls do not repeat a POST. A third
bounded source review covers the bound Account, Checkout and chat address and
synthetic-payment controls. Their address/payment GETs can issue durable opaque
choice records, so they are not classified as side-effect-free reads. Opening
an address form reads the selected snapshot and default-set digest; Review
address stages fields before a separate Confirm sends a saved operation POST.
The synthetic-payment setup similarly requires an approved/declined scenario
selection and a separate Create click before its saved POST. These selected
controls use exact operation reads for uncertain outcomes. The unbound Account
address editor uses a different route and is not part of this review. The
shared operation binding remains globally unresolved outside these selected
consumers. These selected syntax links are not full temporal or
control-flow proof. No physical UI, runtime effect, scoring or Q08 qualification
is inferred from either source review.

1. Reconcile a supported-action manifest against the current catalogs, mounted
   application compositions and rendered action labels. Give each action a
   stable identity, route/tool/effect binding, lesson identity where applicable,
   and explicit manual/read-only/ungraded applicability. Resolve non-SecureShop
   and CTF scope; leave unresolved rows visible. Do not create scored objectives
   merely to give historical teaching sinks a mapping.
2. For Q05, attach the actual confirmation boundary or a reviewed intentional
   teaching exception to each consequence. Join proposal/request identity to
   current owner/session/reset/mode, physical confirmation, durable effect and
   readback. Verify denial/cancel leaves state unchanged and preserve existing
   intentional behavior. A `/confirm` pathname is not sufficient evidence.
3. For Q08, adapt existing family evidence readers and canonical completion
   receipts into a connected per-action record. Verify original model selection,
   exact tool arguments, observed effect/readback, independent Judge and canonical
   credit where the existing lesson requires them. Record manual or ungraded
   applicability honestly instead of inventing model or Judge provenance.
4. Reconcile connected native/rendered/genuine-model results, fixed-mode
   comparisons and ownership/reset/sibling isolation against that manifest.
   Source hashes and existing lesson contracts determine evidence compatibility;
   source discovery and controlled fixtures cannot close remaining qualifications.
