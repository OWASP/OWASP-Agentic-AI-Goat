-- Historical completions are imported history, never fabricated Judge LLM verdicts.
-- No owner/catalog FKs: reset, user deletion and catalog retirement must retain provenance.
CREATE TABLE identity.historical_import_provenance (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 import_version text NOT NULL CHECK(import_version ~ '^[A-Za-z0-9_.-]{1,80}$'),
 source_file text NOT NULL CHECK(source_file ~ '^[A-Za-z0-9_.-]{1,100}\.db$'),
 source_table text NOT NULL CHECK(source_table ~ '^[A-Za-z_][A-Za-z0-9_]{0,99}$'),
 source_row_sha256 text NOT NULL CHECK(source_row_sha256 ~ '^[a-f0-9]{64}$'),
 historical_user_id bigint NOT NULL CHECK(historical_user_id > 0),
 workshop_key text NOT NULL CHECK(workshop_key ~ '^[A-Za-z0-9_-]{1,100}$'),
 objective_id text NOT NULL CHECK(objective_id ~ '^[A-Za-z0-9_.:-]{1,100}$'),
 source_created_at timestamptz NOT NULL,
 source_updated_at timestamptz NOT NULL,
 source_completed_at timestamptz NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT now(),
 provenance_kind text NOT NULL DEFAULT 'historical_completion' CHECK(provenance_kind='historical_completion'),
 PRIMARY KEY(archive_sha256,source_file,source_table,source_row_sha256,workshop_key,objective_id)
);
COMMENT ON COLUMN identity.historical_import_provenance.source_row_sha256 IS 'SHA256 of the versioned canonical source primary-key tuple; never source payload or personal identifiers in plaintext.';
COMMENT ON TABLE identity.historical_import_provenance IS 'Historical provenance only; does not grant completion and is not a model judgment. Insert through explicit migration tooling.';
CREATE INDEX historical_import_owner ON identity.historical_import_provenance(historical_user_id,workshop_key,objective_id);
CREATE FUNCTION identity.reject_historical_provenance_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'Historical import provenance is append-only' USING ERRCODE='55000';
END;
$$;
CREATE TRIGGER historical_provenance_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON identity.historical_import_provenance
FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_historical_provenance_mutation();
REVOKE ALL ON identity.historical_import_provenance FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.historical_import_provenance TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.reject_historical_provenance_mutation() FROM PUBLIC;
