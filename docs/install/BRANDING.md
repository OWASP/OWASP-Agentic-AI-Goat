# Project naming and fresh installations

The application is named **OWASP Agentic AI GOAT**. User-facing pages use that name or the shorter **Agentic AI Goat**. Package names, directories and service names use `owasp-ai-goat`; identifiers that cannot contain hyphens use `owasp_ai_goat` or `OWASP_AI_GOAT`.

The renamed installer targets a fresh installation. It uses private state under `~/.owasp-ai-goat`, `OWASP_AI_GOAT_` environment variables, and databases named `owasp_ai_goat_<store>`. Do not replace the code of an existing installation and assume its old environment, journals or sidecars can be reused. This change is not a data migration or an in-place upgrade. Keep existing installations and their private state intact until an explicit migration procedure is available. Use a separate checkout when qualifying a fresh installation against the [installation guide](INSTALLATION.md).

## Installation qualification

The owned System, pricing and listings sidecars bind their source files to reviewed package manifests. Renaming those sources changes their hashes. Historical manifests remain frozen, so the renamed source can fail the existing `SYSTEM_PACKAGE_SOURCE_CHANGED`, `PRICING_PACKAGE_SOURCE_CHANGED` or `LISTINGS_PACKAGE_SOURCE_CHANGED` gates until a new native package is qualified. Updating a candidate hash does not establish native qualification. This rename alone is not proof that a complete fresh installation is ready on every supported platform.

## Required historical identifiers

Historical PostgreSQL migration files are immutable: their exact checksums form the migration ledger. They still contain the original SQL role names, `dvaia_migrations` ledger schema and `dvaia_maintenance` schema. Current database code deliberately retains these SQL contracts so fresh migration replay, privilege checks, stored functions and maintenance controls continue to agree. These internal names do not change the project's displayed name.

Forward migrations add support for newly branded synthetic data:

- Session-disclosure cookies use `owasp_ai_goat_lab_`. Existing rows with the historical prefix remain valid.
- MCP mail Message-IDs use `@owasp-ai-goat.local`. Existing mail receipts retain their original Message-IDs.
- The XSS newsletter sender changes only when the original synthetic seed row is still unchanged. Instructor and learner edits are preserved.

Keep historical security denylist values and frozen evidence intact. Removing an old known-insecure key from a denylist, or rewriting historical qualification hashes, would change security behavior rather than rename the project.
