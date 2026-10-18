-- Reviewed import policy and normalization metadata for the immutable NOVA batch.
ALTER TABLE nova.import_batches
  ADD COLUMN review_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
  CHECK (jsonb_typeof(review_metadata) = 'object' AND pg_column_size(review_metadata) <= 65536);
