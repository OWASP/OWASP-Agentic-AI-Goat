# SecureShop bound persona and catalog activation review

Date: 2026-09-13

Status: the persona, renewal, product-reservation, and product-target schemas
remain drafts and the bound gateway is unmounted. The current owned PostgreSQL
proof establishes real bcrypt login, immutable admitted-persona snapshots,
launch-bound JWT renewal, a source-derived isolated product target, cross-owner
denial, exact reset retirement, and sibling preservation. Listing, cart,
inventory, pricing, and order mutations remain unavailable.

## Draft implementation checkpoint

The bounded product foundation now reserves one opaque `products` target for an
exact launch generation, snapshots a maximum of 256 actual commerce product
rows with per-row and aggregate SHA-256 provenance, and stores them in the
dedicated review database. Source merchant 2 is deterministically projected to
the admitted merchant ID 12, giving the ordinary UI a nonempty store. Other
source merchants remain same-target decoys, so the tagged explicit
`retailer_id` IDOR remains teachable without crossing platform owners. Customer
list/detail, merchant list, and review-product validation all resolve the same
target product IDs.

Reset cleanup takes the target lifecycle lock, retires the generation, removes
all product leaves, emits an immutable exact-binding cleanup receipt, and only
then reconciles identity reservation debt. The production readiness probe also
requires both identity target-kind constraints to admit `products`; relation
presence alone cannot enable a partially upgraded store.

The combined four-store qualification passed against PostgreSQL 18 from two
independent frozen source copies. It covers missing product-kind readiness,
template initialization under the runtime role, shared-commerce product and
persona mutation after admission, target provenance, own and decoy merchant
projections, cross-owner token denial, review/product identity, persona renewal,
logout/reset races, product and review receipts, reset replay, and sibling
retention. Retained evidence is under
`/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-secureshop-bound-review-composition-4objgae1/result.log`
and `.../owasp-ai-goat-secureshop-bound-review-composition-ji7m549t/result.log`; both
owned containers were removed.

## Verified current behavior

`student_merchant` is a real seeded commerce account with ID 12 and role
`merchant` (`db/postgres/seeds/secureshop.json:190-205`). No seeded product is
owned by ID 12. The product fixture assigns products to the older shared
merchant accounts 2, 5, 9, and 10; the first assignment is visible at
`db/postgres/seeds/secureshop.json:225-239` and the complete fixture contains
zero `retailer_id: 12` records.

The bound catalog defaults a merchant query to the authenticated shop user ID,
so a normal `student_merchant` request returns an empty store
(`server/services/secureshopBoundCatalog.js:99-124`). It also accepts an
explicit `retailer_id` and queries that owner directly. The current merchant UI
always sends `user.id`, including Overview and Listings
(`client/src/pages/secureshop/pages/merchant/Overview.jsx:27-47`;
`client/src/pages/secureshop/pages/merchant/Listings.jsx:23-66`). The ordinary
UI therefore cannot discover an existing shared merchant's inventory, while a
manually changed request can. Treating the latter as the legitimate store would
make the deliberate IDOR the only path to nonempty data.

The public customer catalog is a real read of shared PostgreSQL product rows,
and it deliberately returns raw `description_html` and `template_source`
(`server/services/secureshopBoundCatalog.js:49-96`). Review bodies are correctly
absent from these queries. This is suitable as a read-only source catalog, but
it is not a learner-owned product target. The existing Listings UI also exposes
create, update, delete, bulk import, SSTI, stored-XSS, and SSRF teaching paths.
Sending those future mutations to the shared source rows would let one learner
alter another learner's exercise and would make reset unable to restore an
independent state.

Persona sessions have the right online generation fence. They store only a
hashed JTI with exact launch, scenario, generation, original owner, original
platform session, shop user, and role coordinates
(`docs/modernization/drafts/secureshop-bound-persona-sessions.sql:4-24`). Persona
insertion and conversation retirement serialize on the same per-launch
advisory lock, and retirement revokes the exact tuple
(`docs/modernization/drafts/secureshop-bound-persona-sessions.sql:26-80`). The
conversation retirement receipt also refuses completion while an active bound
persona remains (`server/database/postgres/secureshopConversationLifecycleRepository.js:100-138`).

The aggregate student-deletion adapter recovers every immutable SecureShop
reset mapped to the deleted owner (`server/services/secureshopStudentDeletionCleanup.js:14-33`).
That path can revoke every active persona generation, but the persona table
forbids deletion and retains original owner and session IDs. Activation must
define that retained record as an explicit minimal audit exception or add a
private terminal cleanup/anonymization receipt. A claim that the student's data
was deleted is otherwise too broad.

## Minimum coherent merchant model

Provision a launch-bound product target, alongside the existing review and file
targets, from a bounded snapshot of actual commerce product records. The target
must copy the source product ID and a source-row digest as provenance, while its
mutable product ID, retailer identity, status, stock, descriptions, templates,
and image references live in a dedicated target store. Give each launch at
least two local merchants:

- the authenticated `student_merchant` owns a nonempty, deterministic subset;
- a decoy merchant owns a separate subset within the same launch target.

The default `/merchant/products` request resolves the server-captured persona
to the first local owner and returns that store. The intentional IDOR remains a
separate query behavior: an explicit `retailer_id` can select the decoy store
within the same launch target. This preserves the ownership lesson without
crossing platform owners or reaching globally shared mutable rows. The response
can retain the legacy integer `retailer_id` DTO, but the mapping from that local
ID to the launch target must be server provisioned and immutable; the browser
must not choose a target UUID, platform owner, or generation.

Customer list/detail reads should use the same launch snapshot once product
mutations are exposed, so customers, merchant pages, carts, reviews, and agents
refer to one product identity. Until that target exists, the shared commerce
adapter is acceptable only for read-only customer catalog qualification. Do not
mount the merchant Listings/Pricing/Overview operations against it and do not
seed shared products under ID 12 as a substitute for isolation.

Persona credentials can continue to be validated with real bcrypt material,
but activation should snapshot the admitted persona's public ID/role into the
launch runtime and avoid making an already admitted learner depend on later
shared-account role or ban mutations caused by a legacy challenge. If the
shared account remains the credential template, qualify its exact intended
mutability and show that one learner cannot disable or change another
learner's bound persona through any mounted route.

## Activation checklist

- Add an allowlisted `products` reservation with immutable launch/scenario/
  generation/owner/session coordinates. Reserve before provisioning and reject
  a new generation while prior cleanup is unresolved.
- Provision source-derived product rows atomically, record bounded source
  provenance, and fail closed on partial/mismatched replay. Exact replay must
  reopen without reseeding.
- Resolve default merchant ownership only from the trusted target binding.
  Prove ID 12 sees a nonempty owned store with no `retailer_id` override.
- Preserve the IDOR in an explicit override test that reaches only the launch's
  decoy merchant. Prove another platform owner's target UUID, local merchant,
  products, and mutations remain unavailable.
- Route customer and merchant product DTOs through the same target before
  enabling listing, pricing, inventory, cart, order, or review-product
  mutations. Keep raw tagged HTML/template/URL sinks unchanged.
- Add product cleanup to the aggregate reset before generation commit. Prove
  an admitted mutation racing reset cannot land afterward, cleanup is
  idempotent, exact replay does not resurrect state, and a sibling owner and a
  sibling active launch remain unchanged.
- Promote the persona-session draft only with its migration-ledger readiness
  gate. Prove login/reset and login/deletion races under the shared advisory
  lock, multiple active launches per owner, and zero unrevoked old-generation
  sessions before reset or deletion acknowledgement.
- Define the terminal policy for retained persona rows. If retained for audit,
  minimize/anonymize coordinates and document the deletion exception; if
  removed, require a private exact-scope cleanup receipt after revocation.
- Keep direct role mutation unavailable. The current UI's switch action logs
  out and asks for the distinct `student_customer`, `student_merchant`, or
  `student_admin` credential, so no `/switch-role` endpoint is needed.
- Run a rendered opaque-frame qualification: real merchant login, nonempty own
  listings, explicit same-target IDOR, blocked cross-owner request, actual
  listing mutation and tagged sink, reset to the original snapshot, token
  invalidation, and independent sibling state. No mock products or supplied
  model decisions count as this proof.

The smallest safe activation sequence is persona-session migration and
lifecycle proof, then product reservation/provisioning/cleanup, then bound
catalog/gateway composition, and only then merchant route and catalog-objective
enablement. Mounting the current shared merchant catalog earlier produces an
empty legitimate workflow and makes the exploit path look like required setup.
