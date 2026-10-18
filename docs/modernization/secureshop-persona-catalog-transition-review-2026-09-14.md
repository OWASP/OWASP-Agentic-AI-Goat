# SecureShop persona catalog transition review — 2026-09-14

Historical phase note: this document records the pre-registration review.
Identity0047 was subsequently applied, followed by identity0048–0049 and the
eight generated application outputs, under the independently audited catalog
promotion recorded in
[the completion checkpoint](workshop-catalog-provenance-promotion-2026-09-14.md).
The original proposal language below is retained as qualification provenance.

The structural persona migrations are promoted and the copied activation path
is qualified, but production exposure remains deferred. Existing identity
stores need a forward catalog transition before activation because the normal
seed intentionally preserves an existing exercise route. A previously seeded
SecureShop row can therefore retain the empty route even though a fresh store
receives `/workshop/secureshop`.

The proposed identity migration is reserved as `0047`; `0046` is reserved for
the Judge event metadata compatibility change. Neither draft is registered or
applied by this package. The transition updates the route only when it is empty,
and updates challenge, hint and solution text only when the stored value exactly
matches the prior default. It never changes exercise visibility, objective
enablement, hint or solution toggles, labels, progress, activity, or time.

The production objective seed currently overwrites every stored label with its
source label during a reseed. The companion seed candidate narrows that behavior
for only the three released persona objectives, preserving instructor labels.
Future canonical label changes for those objectives must use another explicit
default-only forward migration whose predicate names the exact predecessor;
they must not overwrite an instructor-edited label through the broad seed.
This is deliberately a bounded Persona Inbox repair. Other workshop objectives
still use the broad label-upsert behavior and therefore retain a catalog-wide
provenance gap. A later platform design should record the installed default
version or origin per field and upgrade only values still derived from that
default; this release must not claim general instructor-edit preservation.

The activation curriculum candidate previously generated a review-moderator
example for all native-model objectives. A separate pinned curriculum candidate
changes only the three persona solution examples to the mounted Persona Inbox
sequence: request the other synthetic persona message in advisory mode, enforce
the ACL, and repeat the same read. The server-owned receipts remain the grading
authority; the copy does not promise that a payload or model response earns
credit.

The prepared owned PostgreSQL 18 gate uses the actual migration loader against
fresh and populated stores, stages the transition privately as identity `0047`,
and requires empty replay. Its populated case retains custom instructor route
adjacent settings, description, label, hint, solution, independent hint/default
solution combinations, and learner completion/activity/time rows. The fresh
case checks the exact mounted route, hidden exercise, three disabled objectives,
canonical labels, and truthful Persona Inbox content. No live migration,
catalog visibility, feature policy, private configuration, or learner data is
changed by preparing this gate.

The transition counts every changed row in one transaction. It increments the
canonical configuration revision and the workshop-scoped `workshop_config`
revision only when at least one exact predecessor was replaced. Reapplying the
SQL after the transition is satisfied must leave both revisions unchanged.
