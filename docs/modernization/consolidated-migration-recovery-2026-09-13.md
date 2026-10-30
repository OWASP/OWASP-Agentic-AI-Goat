# Consolidated migration recovery checkpoint

The configured identity, SecureShop agents, SecureShop review and NOVA migration
ledgers were read without mutation and matched every source name/checksum. Their
current counts are 31, 7, 3 and 4, respectively. All nine qualified draft file
checksums still match the consolidated promotion manifest.

Four private custom-format PostgreSQL archives are retained outside the repository
at `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-consolidated-prepromotion-tyEiSG`.
The directory is mode 0700; archives and manifest are mode 0600. The private
manifest records sizes, SHA-256 checksums, restoration scope and time. No
credentials or learner rows are copied into this document.

Archive listing succeeded for all four stores. An initial restore attempt failed
before the first store verification; its exact disposable container was removed.
The subsequent run pre-created the four runtime policy roles and restored every
archive using `pg_restore --no-owner --no-privileges --exit-on-error` into fresh
databases on an owned PostgreSQL 18 container. All four restores completed and
their migration counts were 31, 7, 3 and 4. The exact container was removed and
its absence checked. This proves archive data/schema restoration, not restoration
of original role passwords, ownership or ACLs; those remain provisioning concerns.

These archives are a point-in-time recovery checkpoint, not an ongoing backup
service. No live migration files, configured database state, environment settings,
AWS assets or feature flags changed during this checkpoint. Before promotion,
pause the application migration watcher, recheck draft/source/ledger checksums,
and account for any application writes since archive creation. Runtime readiness,
owner reset/deletion integration and rendered activation remain separate gates.
