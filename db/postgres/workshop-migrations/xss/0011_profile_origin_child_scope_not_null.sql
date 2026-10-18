-- Close PostgreSQL CHECK three-valued-logic admission from 0010: a scoped
-- origin must provide both coordinates, while legacy v1 remains NULL/NULL.
ALTER TABLE xss.profile_model_origins
  DROP CONSTRAINT profile_model_origins_child_scope,
  ADD CONSTRAINT profile_model_origins_child_scope CHECK (
    (scope_key IS NULL AND child_generation IS NULL)
    OR (scope_key IS NOT NULL AND child_generation IS NOT NULL
      AND scope_key='stored_llm' AND child_generation>=0)
  );
