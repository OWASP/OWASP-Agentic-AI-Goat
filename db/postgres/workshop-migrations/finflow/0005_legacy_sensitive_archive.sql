-- Preserve source document metadata and unowned historical access rows when
-- importing sensitive_info.db. These columns are archive fields; runtime
-- FinFlow behavior continues to use filename/file_path/category/description.
ALTER TABLE legacy_sensitive.documents ADD COLUMN IF NOT EXISTS access_level text;
ALTER TABLE legacy_sensitive.documents ADD COLUMN IF NOT EXISTS uploaded_by bigint;
ALTER TABLE legacy_sensitive.documents ADD COLUMN IF NOT EXISTS created_at timestamptz;
ALTER TABLE legacy_sensitive.access_logs ALTER COLUMN user_id DROP NOT NULL;

-- The original finflow import batch constraint only covered the agent-workshop
-- importer. Keep that importer valid while recording this separate archive
-- family with its own immutable version marker.
ALTER TABLE finflow.import_batches DROP CONSTRAINT IF EXISTS import_batches_importer_version_check;
ALTER TABLE finflow.import_batches ADD CONSTRAINT import_batches_importer_version_check
  CHECK (importer_version IN ('agent-workshop-v1','legacy-sensitive-v1'));
