-- Historical batches may predate owner remapping; new imports persist the
-- verified source-to-native identity-map digest without inventing old proof.
ALTER TABLE xss.import_batches
  ADD COLUMN identity_map_sha256 text
  CHECK (identity_map_sha256 IS NULL OR identity_map_sha256 ~ '^[a-f0-9]{64}$');
