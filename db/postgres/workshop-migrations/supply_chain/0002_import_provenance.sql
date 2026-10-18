CREATE TABLE supply_chain.import_provenance (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 source_table text NOT NULL, source_id text NOT NULL, source_row jsonb NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(archive_sha256,source_table,source_id)
);
CREATE FUNCTION supply_chain.protect_import_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Import provenance is immutable' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER immutable_import_provenance BEFORE UPDATE OR DELETE OR TRUNCATE ON supply_chain.import_provenance
 FOR EACH STATEMENT EXECUTE FUNCTION supply_chain.protect_import_provenance();
REVOKE ALL ON supply_chain.import_provenance FROM PUBLIC;
