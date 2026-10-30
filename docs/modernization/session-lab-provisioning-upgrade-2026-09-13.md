# Session lab provisioning upgrade boundary

The dedicated session-disclosure database remains separate from both platform identity data and the legacy challenge role that deliberately accepts arbitrary SQL. Before the additive path was implemented, adding its initialization tuple alone made existing private provisioning manifests reject the extended plan.

The upgrade must be explicit and additive. Preserve every existing database, runtime/migration role, variable mapping and credential. Verify the recorded cluster identity and actual ownership/role privileges before creating anything. Refuse renamed, removed, reordered or rebound entries, duplicate identities and new-name collisions. Never reinterpret a collision as authority to take over a resource.

`db/postgres/provisioning-extension.js` validates that the new plan is an exact suffix extension. Provisioning and the application installer now consume that result through explicit upgrade entry points. AWS/deployment files remain frozen, and no live learner installation was upgraded during qualification.

## Explicit upgrade implementation checkpoint

`provision-application.js --upgrade /private/path/credentials.json` now verifies existing cluster/database/role ownership, validates the additive plan, checks collisions, preserves prior configuration and creates only appended roles/databases. A private `.upgrade` journal is synced before DDL and after each resource. The original manifest is replaced atomically only after completion; a pending journal blocks replay because an interrupted DDL acknowledgement is ambiguous. Existing resources are never reset or credential-rotated.

The application-level command is:

```bash
npm run setup -- --upgrade --plan
npm run setup -- --upgrade
```

The macOS, Ubuntu/Debian and Windows installer wrappers also accept `--upgrade`. This branch does not install packages, inspect or download a model, launch a browser, create an administrator, or regenerate application secrets. It requires the existing private `.env` and `~/.owasp-ai-goat/<workspace-id>/provisioning.json`. An operator using an external database supplies `PG_ADMIN_DATABASE_URL` for the same recorded cluster; the owned local PostgreSQL path reuses its existing private state and refuses to create a replacement volume.

Before PostgreSQL changes, the installer requires every configured manifest URL in `.env` to equal the private manifest and rejects duplicate, partial or conflicting managed keys. Provisioning retains the cluster advisory lock and writes `provisioning.json.upgrade` before DDL. After provisioning, the installer derives missing URL pairs from the old environment, initializes only those appended schemas, writes a mode-0600 `.env.upgrade`, syncs it and its parent, verifies that `.env` is still byte-identical, then atomically renames and syncs the directory. Existing bytes, comments, application secrets and unrelated settings are retained exactly.

Interruption handling is deliberately asymmetric:

- A provisioning failure or crash can leave `provisioning.json.upgrade`; provisioning refuses blind replay because committed DDL may not have been journaled. Inspect that private journal and cluster before remediation.
- A failure during schema initialization leaves `.env` unchanged and creates no environment staging file. If the manifest was already promoted, rerunning the same command derives the missing pairs from `.env` and repeats only their idempotent initializer.
- An interruption after `.env.upgrade` is created is fail-closed. Inspect the private staging file and current `.env`; remove only a confirmed stale staging file before retrying. The installer never overwrites an ambiguous stage.
- If `.env` changes while initialization runs, the final byte comparison fails and leaves the staging file for inspection. Concurrent upgrade commands are unsupported and converge to the same fail-closed rule rather than silently replacing settings.

Review follow-up: ownership verification rejects inherited/granted memberships involving planned roles and validates the exact prior credential-variable set with role/database/host/port binding. Altered bindings or memberships fail before DDL. The initial journal directory entry is synced before new DDL. The final provisioning-extension, provisioning, setup and wrapper suites pass 41 checks, including rejection of an incomplete prior-manifest environment before provisioning.

The application installer was qualified in a source copy against a fresh owned PostgreSQL 18 cluster. A private 14-store manifest and environment were upgraded to the 15-store plan. Old runtime credentials remained usable, an old marker row remained intact, the administrator file and JWT/session settings were byte-preserved, the new runtime authenticated and observed the initialized `session_disclosure` schema, and replay performed zero additions without changing `.env`. The final test passed 1/1; evidence is `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-setup-upgrade-1qgp4_un/result.log`. All nine executable/test source hashes matched the tested copy, and the exact owned container was removed. This proves the local fixture transition and does not prove a production cutover or crash durability under sudden power loss.

The session lab itself passes an owned native HTTP test (`owasp-ai-goat-session-disclosure-s4nbhhxj`): concurrent first access converges, owner/cookie isolation holds, four concurrent resets advance generations, old cookies fail, and reopening preserves state. Container removed. Application installation is now qualified separately as described above; no working installation was changed.
