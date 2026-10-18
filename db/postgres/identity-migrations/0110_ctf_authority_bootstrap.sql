-- Migration-role-only preparation. Runtime publication remains default-denied.
CREATE TABLE identity.ctf_bootstrap_store (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 store_id uuid NOT NULL DEFAULT gen_random_uuid()
);
INSERT INTO identity.ctf_bootstrap_store(singleton) VALUES(true);
REVOKE ALL ON identity.ctf_bootstrap_store FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_bootstrap_store TO dvaia_identity_runtime;
CREATE TRIGGER ctf_bootstrap_store_immutable BEFORE UPDATE OR DELETE ON identity.ctf_bootstrap_store FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
CREATE TABLE identity.ctf_bootstrap_sessions (
 operation_id uuid PRIMARY KEY, source_store_id uuid NOT NULL, source_revision bigint NOT NULL CHECK(source_revision>=0),
 state text NOT NULL DEFAULT 'staging' CHECK(state IN ('staging','prepared')),
 manifest_sha256 text CHECK(manifest_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK((state='prepared')=(manifest_sha256 IS NOT NULL))
);
CREATE TABLE identity.ctf_bootstrap_pages (
 operation_id uuid NOT NULL REFERENCES identity.ctf_bootstrap_sessions(operation_id),
 table_name text NOT NULL CHECK(table_name ~ '^[a-z_]+$'),page_number integer NOT NULL CHECK(page_number>=0),
 canonical_rows text NOT NULL CHECK(octet_length(canonical_rows)<=262144 AND canonical_rows IS JSON ARRAY WITH UNIQUE KEYS),
 page_sha256 text NOT NULL CHECK(page_sha256=encode(sha256(convert_to(canonical_rows,'UTF8')),'hex')),
 PRIMARY KEY(operation_id,table_name,page_number)
);
CREATE TRIGGER ctf_bootstrap_pages_immutable BEFORE UPDATE OR DELETE ON identity.ctf_bootstrap_pages FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_bootstrap_sessions,identity.ctf_bootstrap_pages FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_bootstrap_sessions,identity.ctf_bootstrap_pages TO dvaia_identity_runtime;
CREATE TABLE identity.ctf_bootstrap_imports (
 operation_id uuid NOT NULL,table_name text NOT NULL,page_number integer NOT NULL,
 PRIMARY KEY(operation_id,table_name,page_number),
 FOREIGN KEY(operation_id,table_name,page_number) REFERENCES identity.ctf_bootstrap_pages(operation_id,table_name,page_number)
);
CREATE TRIGGER ctf_bootstrap_imports_immutable BEFORE UPDATE OR DELETE ON identity.ctf_bootstrap_imports FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_bootstrap_imports FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_bootstrap_imports TO dvaia_identity_runtime;
