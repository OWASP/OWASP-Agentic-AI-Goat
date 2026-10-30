# Consolidated forward migration qualification

Date: 2026-09-13

Status: all nine qualified migrations have been promoted to their application
migration directories and applied to the configured local stores. Normal
initializers and seeds passed. Exact ledger checks and a second loader pass
applied zero files for every store. No bound feature or curriculum objective
was activated by this promotion.

The backend was drained with the nodemon restart watcher paused during copying
and initialization. The watcher was resumed and the backend health endpoint
returned HTTP 200. Private archives were previously restored successfully into
disposable databases; see the consolidated migration recovery checkpoint.

Current heads are identity0037 (36 entries), agents0009 (9), review0004 (4),
and NOVA0005 (5). The historical baseline below remains the upgrade test input.
After promotion, the test stages that baseline separately from the complete
candidate directory and verifies promoted SQL against the qualified checksums.
The real-loader fresh/populated/replay rerun passed 1/1 in
`/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-consolidated-draft-promotion-mcf5nm9e/result.log`;
its exact disposable container was removed.

The exact manifest is
`docs/modernization/drafts/consolidated-forward-promotion-manifest-2026-09-13.json`.
It starts at the current checked-in heads and assigns these candidate suffixes:

| Store | Current head | Candidate suffixes |
| --- | --- | --- |
| identity | `0032_secureshop_progress_cleanup_checkpoint.sql` | `0033` product reservation; `0034` owner reset; `0035` deletion journal; `0036` DPI teaching content; `0037` NOVA objective content |
| SecureShop agents | `0007_secureshop_conversation_generation_retirement.sql` | `0008` persona templates/sessions; `0009` monotonic persona renewal |
| SecureShop review | `0003_secureshop_review_learner_submissions.sql` | `0004` bound product target and cleanup receipt |
| NOVA | `0004_import_metadata.sql` | `0005` NOVA archival objective content |

Every manifest entry records the SHA-256 of the current draft. All nine entries
are marked ready; no requested draft was omitted. This readiness means the SQL
composes with the current migration heads through the real loader. It does not
replace runtime, reset, deletion, catalog, or rendered-workflow gates.

## Qualification

`tests/postgres/consolidatedDraftPromotion.integration.test.js` copies each
complete current migration directory to a private staging tree, adds the exact
candidate suffixes, and calls the production `migrate()` loader. It runs both a
fresh database and a database first migrated and populated at the current head
for each of the four stores. Each store's second migration pass applies zero
files, and the durable ledger names and checksums exactly match the staged
directory.

The populated case retains a platform learner, canonical completion, activity,
time, an existing SecureShop launch and review reservation, a legacy agent
conversation and trace, a review target and review body, and NOVA chat history.
It also proves the product kind can be added without rewriting the existing
review reservation. Exact old shipped DPI and NOVA content is updated, while a
custom instructor DPI solution and NOVA hint remain byte-equivalent as parsed
JSON. The fresh case migrates before seeding and then verifies current identity
and NOVA seeds produce the corrected content; the content migrations therefore
remain safe when their target rows do not exist yet.

The final owned PostgreSQL 18 run passed 1/1. Its exact container was removed.
Evidence is retained at
`/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-consolidated-draft-promotion-hahbctkp/result.log`.
An earlier successful run at `.../owasp-ai-goat-consolidated-draft-promotion-xyvbjnc7`
predated the added existing-launch/reservation preservation assertion and is
retained as historical evidence.

## Promotion boundary

For any later environment promotion, independently verify private recovery backups and
exact configured-store migration ledgers, pause application migration watchers,
and copy all four store suffixes as one reviewed activation set. Run the normal
initializers and seeders, then require product-kind capability, persona,
product, owner-reset, deletion, and catalog readiness before mounting bound
SecureShop. DPI and NOVA content changes preserve exact instructor edits, but
their rendered learner and admin parity remains a separate acceptance gate.
