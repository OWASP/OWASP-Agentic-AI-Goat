CREATE TABLE ctf.import_provenance (
  archive_sha256 text PRIMARY KEY CHECK (archive_sha256 ~ '^[a-f0-9]{64}$'),
  importer_version text NOT NULL CHECK (importer_version ~ '^[A-Za-z0-9_.-]{1,80}$'),
  source_file text NOT NULL CHECK (source_file = 'ctf.db'),
  table_counts jsonb NOT NULL CHECK (jsonb_typeof(table_counts) = 'object'),
  identity_map_sha256 text NOT NULL CHECK (identity_map_sha256 ~ '^[a-f0-9]{64}$'),
  imported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION ctf.reject_import_provenance_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'CTF import provenance is append-only' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER ctf_import_provenance_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON ctf.import_provenance
  FOR EACH STATEMENT EXECUTE FUNCTION ctf.reject_import_provenance_mutation();
REVOKE ALL ON ctf.import_provenance FROM PUBLIC,dvaia_ctf_runtime;
GRANT SELECT ON ctf.import_provenance TO dvaia_ctf_runtime;
REVOKE ALL ON FUNCTION ctf.reject_import_provenance_mutation() FROM PUBLIC;
