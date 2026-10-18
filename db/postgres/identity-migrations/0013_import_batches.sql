-- Metadata only. Importers must never place source rows, payloads or credentials here.
CREATE FUNCTION identity.valid_import_batch_metadata(value jsonb, decisions boolean) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE entry record;
BEGIN
 IF jsonb_typeof(value) <> 'object' OR octet_length(value::text)>65536 THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(value))>512 THEN RETURN false; END IF;
 FOR entry IN SELECT * FROM jsonb_each(value) LOOP
  IF entry.key !~ '^[A-Za-z][A-Za-z0-9_.:-]{0,199}$' THEN RETURN false; END IF;
  IF decisions THEN
   IF jsonb_typeof(entry.value)<>'string' OR entry.value #>> '{}' NOT IN ('catalog_visibility_defaults_without_content','retained_archive_only','imported','explicitly_excluded','users_auth.db','nosql_workshop.db','explicit_collections_only','naive_utc','reject_naive') THEN RETURN false; END IF;
  ELSE
   IF jsonb_typeof(entry.value)<>'number' OR entry.value::text !~ '^[0-9]{1,15}$' THEN RETURN false; END IF;
  END IF;
 END LOOP;
 RETURN true;
END;
$$;
CREATE TABLE identity.import_batches (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 importer_version text NOT NULL CHECK(importer_version ~ '^[A-Za-z0-9_.-]{1,80}$'),
 plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[a-f0-9]{64}$'),
 counts jsonb NOT NULL CHECK(identity.valid_import_batch_metadata(counts,false)),
 coverage jsonb NOT NULL CHECK(identity.valid_import_batch_metadata(coverage,false)),
 review_decisions jsonb NOT NULL CHECK(identity.valid_import_batch_metadata(review_decisions,true)),
 committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(archive_sha256,importer_version,plan_sha256)
);
CREATE TRIGGER import_batches_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON identity.import_batches
FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_historical_provenance_mutation();
REVOKE ALL ON identity.import_batches FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.import_batches TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.valid_import_batch_metadata(jsonb,boolean) FROM PUBLIC;
