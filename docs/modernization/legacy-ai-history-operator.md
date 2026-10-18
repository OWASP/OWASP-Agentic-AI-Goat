# Historical AI conversation archive

Supported PostgreSQL installations keep new authenticated experiment history in
`legacy_ai_private`. The intentionally vulnerable history lesson reads fictional
records. Legacy migration 0005 preserves old conversation rows while removing the
challenge runtime's access to them.

The operator tool below moves reviewed historical rows into a private archive.
It does **not** infer account ownership, restore student history, award objectives,
or change synthetic lessons. Records remain classified as unknown. Ordinary
application startup does not invoke this tool.

## Configuration

Apply the checked-in identity and legacy-challenge migrations through the supported
initializer first. Supply these migration-role connection strings through a private
process environment:

- `LEGACY_CHALLENGE_MIGRATION_DATABASE_URL`
- `IDENTITY_MIGRATION_DATABASE_URL`

The tool does not load `.env`, accept URLs on the command line, print credentials,
or provision databases. Source and target must be different databases with their
named migration roles. Runtime credentials are rejected.

Create a private directory owned by your account. Use its absolute physical path
(no symlink components); on macOS `/tmp` and `/var` may need their `/private/...`
physical equivalents. The directory must not be writable by other users. Output
files are created with mode 0600 and existing files are never overwritten.

## Review and archive

Use a fresh plan filename for each new batch:

```sh
node scripts/legacy-ai-history-cutover.js plan \
  --plan-file /absolute/private/directory/plan.json
```

This performs a read-only source snapshot and writes a plan containing endpoint
identities, database names, row IDs and hashes. It contains no prompts, responses,
or passwords. Review the source, target, row count and digest before proceeding.
The plan binds both endpoints and preserves a stable batch and review identity.

```sh
node scripts/legacy-ai-history-cutover.js quarantine \
  --plan-file /absolute/private/directory/plan.json \
  --receipt-file /absolute/private/directory/receipt.json
```

Quarantine rereads and verifies the reviewed source, copies exact records into the
private target archive, verifies the stored bytes, and writes a private receipt.
It leaves the source intact. Changed source rows reject the reviewed plan before
archival. Repeating this command with the same files verifies/resumes the same
batch; it does not overwrite the receipt or create a new ownership claim.

## Explicit source cleanup

Only after successful quarantine, invoke:

```sh
node scripts/legacy-ai-history-cutover.js cleanup \
  --plan-file /absolute/private/directory/plan.json \
  --receipt-file /absolute/private/directory/receipt.json
```

Cleanup rechecks migration authority and the reviewed target archive, then removes
only the exact source rows represented by the verified batch. A durable source
journal supports recovery if the process stops between source commit and target
acknowledgement. Changed or reappeared source rows reject cleanup. Other source
rows and synthetic teaching records remain untouched.

After interruption, retry **cleanup with the same plan and receipt**. Do not rerun
quarantine after source removal, replace the receipt, or generate a new plan to
represent the original batch. Keep both private files for recovery and audit.

Historical records with unproven ownership stay archived and inaccessible to
learners. Deleting a student does not authorize guessing ownership from a legacy
`user_id` or mutable `platform_owner_id`. Any future ownership restoration requires
independent authoritative evidence and its own reviewed implementation.

Qualification: the disposable native operator test exercises actual CLI child
processes, a changed-plan rejection, private files, exact quarantine, source
preservation, cleanup and replay. It does not constitute an installed-data cutover.
