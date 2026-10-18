-- Retain unknown historical timestamps without inventing observation times.
ALTER TABLE secureshop_agents.vector_documents ALTER COLUMN created_at DROP NOT NULL;
ALTER TABLE secureshop_agents.vector_corpora ALTER COLUMN updated_at DROP NOT NULL;
-- Historical teaching data is retained independently of live runtime authority.
CREATE TABLE secureshop_agents.import_provenance (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 source_file text NOT NULL,
 source_table text NOT NULL,
 source_key text NOT NULL,
 source_row jsonb NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(archive_sha256,source_file,source_table,source_key)
);
CREATE TABLE secureshop_agents.import_batches (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 counts jsonb NOT NULL,
 review_metadata jsonb NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION secureshop_agents.protect_import_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Import history is immutable' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER immutable_import_provenance BEFORE UPDATE OR DELETE OR TRUNCATE ON secureshop_agents.import_provenance
 FOR EACH STATEMENT EXECUTE FUNCTION secureshop_agents.protect_import_history();
CREATE TRIGGER immutable_import_batches BEFORE UPDATE OR DELETE OR TRUNCATE ON secureshop_agents.import_batches
 FOR EACH STATEMENT EXECUTE FUNCTION secureshop_agents.protect_import_history();
REVOKE ALL ON secureshop_agents.import_provenance,secureshop_agents.import_batches FROM PUBLIC;
