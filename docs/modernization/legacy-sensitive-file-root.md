# Legacy Sensitive teaching files

`LEGACY_SENSITIVE_FILES_ROOT` optionally selects an absolute normalized directory for generated Legacy Sensitive teaching files. Without it, the existing `server/sensitive_files` location remains the default. This setting does not change FinFlow traversal fixtures or its virtual paths.

Importing `server/database/sensitiveInfoFiles.js` does not create files. Explicitly initialize missing synthetic artifacts with:

```sh
node server/database/sensitiveInfoFiles.js --initialize-missing
```

The parent directory must already exist. Existing regular files, including instructor edits, are preserved. Symlink directories and symlink/non-regular destinations are rejected. Fresh `npm run setup` now performs this explicit step after database initialization and persists a supplied root override into the generated application configuration.

The immutable full-backend qualification uses a fresh external owned directory and this initializer; it never copies installation teaching files. Existing installations are not reseeded automatically by importing routes or ordinary startup.

The canonical five-lesson workshop is available at `/workshop/file-ssi`. Fresh seeds enable its card and objectives; additive reseeding preserves existing instructor visibility choices. The canonical agent runs by default after catalog and reset-storage readiness, and `LEGACY_SENSITIVE_CANONICAL_AGENT_ENABLED=false` explicitly disables it. Real file reads and SSI include expansion stay inside the owned teaching root; SSI command directives remain simulated. The installer adds a missing protected `secret/ssi_report.shtml` template without replacing instructor files.
