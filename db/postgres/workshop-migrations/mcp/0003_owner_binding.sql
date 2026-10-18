-- Existing historical batches remain visibly unbound; new importers require a verified map.
ALTER TABLE mcp.import_batches ADD COLUMN identity_map_sha256 text
 CHECK (identity_map_sha256 IS NULL OR identity_map_sha256 ~ '^[a-f0-9]{64}$');
