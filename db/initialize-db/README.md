# Legacy SQLite fixture reference

This folder is retained for explicitly selected legacy SQLite fixtures and frozen AWS assets. It is not the schema authority for supported application startup. Supported installations use 16 isolated PostgreSQL stores defined in `db/postgres/initialize-application.js`; keep the legacy files available to their retained consumers without using them to initialize or reset learner data.

## Supported installation and additive initialization

From the project root, preview a fresh setup with `npm run setup -- --plan`, then run `npm run setup` for a new installation. `./start_all.sh --plan` checks required PostgreSQL URL pairs without printing them. To apply pending migrations and idempotent seeds to a configured installation, use `npm run db:initialize-all` or `./start_all.sh --init-db`; these preserve existing data. Do not use this folder's SQLite initializer for either operation.

## Retained fixture contents

`run-all.js` loads the historical schemas and seeds into SQLite files. It remains available for explicitly isolated legacy fixtures and frozen AWS callers; it is not a supported fresh-install, migration, or reset command. Local fixture runs must use an owned disposable output directory, never an application or learner database directory.

The rest of this document describes historical SQLite fixture data and interfaces. It does not describe the supported PostgreSQL schema, current student API, or an administrator reset procedure.

## Historical databases

| DB file | Purpose |
|--------|---------|
| `users_auth.db` | User authentication, admin permissions, student progress, challenge config, **prompt_injection_progress**, **rag_injection_progress** (secure) |
| `owasp-ai-goat.db` | Vulnerable workshop + admin tables (demo users, products, challenge_visibility) |
| `secureshop.db` | SecureShop: shop users, products, orders, cart, categories |
| `sql_nosql_workshop.db` | SQL/NoSQL injection workshop (levels 1–4, progress, achievements) |
| `ctf.db` | CTF: config, participants, stages, progress, attempts, leaderboard |
| `sensitive_info.db` | Sensitive info challenge: file_access_logs, documents |
| `platform_secure.db` | Secure platform copy (platform_users, permissions, progress) |
| `sqli_challenge.db` | SQLi challenge (vulnerable_users, vulnerable_products, admin_secrets) |
| `xss_challenge.db` | XSS challenge (vulnerable_comments, vulnerable_posts) |
| `ctf_ai_challenge.db` | CTF AI challenge (isolated) |

The legacy script writes `.db` files under `server/database/` by default, which is why fixture users must supply an owned disposable `DB_OUTPUT_DIR`.

## Layout

- `schemas/` – one `.sql` per database (CREATE TABLE only).
- `seeds/` – one `.js` per database (default data; uses bcrypt where needed).
- `run-all.js` – runs each schema then each seed in order.

## Historical challenge visibility (Direct & Indirect Prompt Injection / PR #6)

If **Direct Prompt Injection** (`/vulnerabilities/direct-prompt-injection`) or **Indirect Prompt Injection** (`/vulnerabilities/indirect-prompt-injection`) redirects you to the workshop dashboard, the `challenge_visibility` table in `users_auth.db` may be missing the row or have `is_visible = 0`. The seed only runs when the users table is empty, so existing DBs are not updated.

This note records an old fixture condition. Supported PostgreSQL installations use the canonical workshop catalog and its authenticated administration controls for visibility.

## Historical Prompt Injection Workshop progress (users_auth.db)

The historical SQLite fixture modeled per-user, per-objective progress in `users_auth.db`. These table notes are not the supported PostgreSQL progress contract.

### Table: `prompt_injection_progress`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | User (default 1 when unauthenticated) |
| objective_id | TEXT | One of: `interact`, `system_prompt`, `jailbreak`, `multi_language`, `virtualization`, `role_playing`, `side_stepping`, `obfuscation` |
| completed | INTEGER | 1 = objective completed |
| interaction_count | INTEGER | For practice objective `interact`: number of valid AWS interactions (complete when ≥ 2) |
| completed_at | DATETIME | When the objective was completed |
| created_at, updated_at | DATETIME | Timestamps |

The historical design used `user_key` for a logged-in user id or `anon_<sessionId>`, unique with `objective_id`. It did not require seed rows for completions.

### Table: `rag_injection_progress` (Indirect Prompt Injection)

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_key | TEXT | User ID when logged in, or `anon_<sessionId>` for anonymous (per-student isolation) |
| objective_id | TEXT | One of: `rag_upload`, `rag_query`, `rag_clean_doc`, `rag_injected_doc`, `rag_query_injection` |
| completed | INTEGER | 1 = objective completed |
| completed_at | DATETIME | When the objective was completed |
| created_at, updated_at | DATETIME | Timestamps |

**Historical objectives:** (1) Load a document, (2) Clean document, (3) Ask a question, (4) Injected document, (5) Query injection / RAG poisoning. The fixture used a unique `(user_key, objective_id)` pair and no seed rows.

## Historical challenge solutions (users_auth.db)

The historical fixture modeled solution visibility for seven prompt injection objectives, with solutions hidden by default.

### Table: `prompt_injection_solution_visibility`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| challenge_id | TEXT | One of: `system_prompt`, `jailbreak`, `multi_language`, `virtualization`, `role_playing`, `side_stepping`, `obfuscation` |
| solutions_enabled | INTEGER | 1 = solutions visible to students |
| enabled_by | INTEGER | Admin user ID who toggled (optional) |
| enabled_at | DATETIME | When solutions were enabled |
| updated_at | DATETIME | Last update |

Unique on `challenge_id`. Seeded with 7 rows (all disabled) in the schema.

### Table: `prompt_injection_solutions`
Stores the actual content of the solution guides (examples, approach, tips) for the 7 prompt injection objectives.

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| challenge_id | TEXT | One of: `system_prompt`, `jailbreak`, `multi_language`, `virtualization`, `role_playing`, `side_stepping`, `obfuscation` |
| title | TEXT | Display title for the solution |
| difficulty | TEXT | Level (Easy/Medium/Hard) |
| examples | TEXT | JSON array of `{ prompt, explanation }` |
| approach | TEXT | Detailed text explaining the technique |
| tips | TEXT | JSON array of string tips |
| updated_at | DATETIME | Last update |

The historical seed drew content from `server/data/promptInjectionSolutions.js`. Supported installations use the PostgreSQL workshop catalog, seed path, and effective visibility gates described in the root `AGENTS.md`.
