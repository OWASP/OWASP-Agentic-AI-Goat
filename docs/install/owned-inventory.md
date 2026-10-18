# Owned inventory and checkout

Bound checkout uses the canonical REVIEW0025 commerce journal and the existing
owned product projection. It acquires ordered stock locks, validates all lines,
and commits stock, order amounts, coupon allocation, cart clearing and the
checkout receipt together. Replaying the same checkout UUID returns its prior
order. Inventory does not require an Analytics sidecar or `--owned-coupons`.

Inventory agent serving remains unavailable while its checked-in production
qualification gate is false. Canonical REVIEW0026 and AGENTS0040 are present,
but migration presence alone does not establish agent or objective readiness.
After the production gate is qualified, inventory is selected automatically in
the authenticated bound application when its schema, persona, policy and grading
dependencies pass readiness. Set `SS_BOUND_INVENTORY_ENABLED=false` to opt out;
setting it to `true` cannot override an unqualified production gate.

The merchant task permits stock changes only for the acting merchant's products
in both modes. Vulnerable mode deliberately omits that retailer check inside the
owned stock tool; fixed mode denies another retailer's mutation. Shop session,
launch generation and sibling learner isolation apply in both modes. In standalone
mode, the internal launch binding comes from the independent shop account and does
not require a platform login. A stock change updates the presentation overlay and
preserves the immutable base and unchanged generated-description provenance. A
refund support request does not restock inventory automatically.

Native repository qualification46559, independently reviewed, covers competing
checkout and inventory locks, replay, rollback, generated provenance, migration
paths and reset/sibling behavior. Its provenance seeds and shopper IDs are
controlled fixtures. It is not actor, Judge, rendered UI or installed application
qualification. The inventory objective remains default disabled pending those
gates. The original native review receipt is retained privately and is not
part of the source release.
