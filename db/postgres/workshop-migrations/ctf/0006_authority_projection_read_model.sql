-- Inert projection linkage; historical judgments/provenance remain unchanged.
CREATE TABLE ctf.projection_cursor (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  applied_sequence BIGINT NOT NULL DEFAULT 0 CHECK (applied_sequence >= 0),
  last_operation_id UUID,
  initialized BOOLEAN NOT NULL DEFAULT FALSE
);
INSERT INTO ctf.projection_cursor(singleton) VALUES (TRUE);
CREATE TABLE ctf.projection_scopes (
  scope_key TEXT PRIMARY KEY CHECK (scope_key = 'global' OR scope_key ~ '^(stage|owner):[1-9][0-9]*$'),
  revision BIGINT NOT NULL CHECK (revision >= 0),
  owner_generation BIGINT CHECK (owner_generation >= 0),
  applied_operation_id UUID NOT NULL,
  CHECK ((scope_key LIKE 'owner:%') = (owner_generation IS NOT NULL))
);
ALTER TABLE ctf.ctf_judgments ADD COLUMN decision_id UUID;
ALTER TABLE ctf.ctf_judgments ADD COLUMN authority_version TEXT;
ALTER TABLE ctf.ctf_judgments ADD CONSTRAINT ctf_judgment_authority_link
  CHECK ((decision_id IS NULL AND authority_version IS NULL)
    OR (decision_id IS NOT NULL AND authority_version IS NOT NULL AND authority_version = 'identity-ctf-v1'));
CREATE UNIQUE INDEX ctf_judgments_decision_id ON ctf.ctf_judgments(decision_id)
  WHERE decision_id IS NOT NULL;
REVOKE ALL ON ctf.projection_cursor, ctf.projection_scopes FROM PUBLIC, dvaia_ctf_runtime;
GRANT SELECT ON ctf.projection_cursor, ctf.projection_scopes TO dvaia_ctf_runtime;
-- Existing runtime INSERT rights preserve old route behavior. No new authority is
-- inferred from nullable linkage; only the read comparison can classify it.
