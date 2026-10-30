# Fixed-tree asset migration

This procedure copies the remaining local application files into a **stopped,
staged candidate installation**. It does not edit the active installation,
switch traffic, restart the application, or claim a transaction across files.

The supported destinations are:

- `server/uploads/**`, except `server/uploads/secureshop/**` (SecureShop uses
  its separate asset cutover procedure)
- `server/sensitive_files/**`
- with `--include-finflow`: `server/workshop_data/documents/**`,
  `server/workshop_data/transactions/**`, `server/config/secrets.env`, and
  `server/config/server.conf`

Every bundle path is also its destination path. Absolute paths, `..`, empty
segments, symlinks, arbitrary configuration files, and unlisted trees are
rejected.

## Plan and review

Use an asset bundle already created and verified by the archive workflow. The
manifest digest must come from that workflow's immutable receipt.

```bash
node db/postgres/fixed-tree-assets.js \
  --bundle /migration/bundle \
  --manifest-digest <64-character-sha256> \
  --candidate /staging/owasp-ai-goat-next \
  --candidate-stopped \
  --candidate-is-staged \
  > /migration/fixed-tree-plan.json
```

The `review` member is the exact review envelope. Save that member as a JSON
file. Each differing destination has `action: "review_required"`; replace it
with exactly one of:

- `replace_with_bundle` to install the archived bytes
- `keep_candidate` to retain the staged candidate's current bytes

Missing destinations use `install`. Identical destinations use
`keep_identical`. The review binds every decision to the bundle manifest,
candidate-state digest, path, source hash, and candidate hash. The tool rejects
added fields, missing files, unresolved choices, or a candidate that changed
after planning.

Validate the completed review without writing:

```bash
node db/postgres/fixed-tree-assets.js \
  --bundle /migration/bundle \
  --manifest-digest <64-character-sha256> \
  --candidate /staging/owasp-ai-goat-next \
  --candidate-stopped \
  --candidate-is-staged \
  --review /migration/fixed-tree-review.json
```

Add `--include-finflow` to every command in the sequence when the reviewed
bundle includes the optional FinFlow paths. Changing that flag invalidates the
review.

## Apply to the staged candidate

The operation directory must not exist. It holds the independently restored
bundle, the failure marker, and the final receipt.

```bash
node db/postgres/fixed-tree-assets.js \
  --bundle /migration/bundle \
  --manifest-digest <64-character-sha256> \
  --candidate /staging/owasp-ai-goat-next \
  --candidate-stopped \
  --candidate-is-staged \
  --review /migration/fixed-tree-review.json \
  --apply \
  --operation-root /migration/fixed-tree-operation
```

On success, `fixed-tree-receipt.json` is created exclusively with mode `0600`.
It records the exact final hash and action for every destination and states
`applicationActivated: false` and `crossFileAtomic: false`. Activation remains
a separate operator step after the rest of the staged upgrade is verified.
The exported `verifyFixedTreeAssetReceipt()` API re-hashes every destination
against that receipt; activation tooling should require this verification with
the receipt digest returned by apply.

If any copy or verification fails, `COPY_INCOMPLETE` remains; a valid receipt
is absent. Some files in the staged candidate may already have changed. Do not
activate or repair that candidate in place: retain the operation directory for
diagnosis, discard the staged candidate, and create a new candidate from the
unchanged old installation. The tool never receives or writes the old
installation path, and the verified source bundle remains unchanged.
