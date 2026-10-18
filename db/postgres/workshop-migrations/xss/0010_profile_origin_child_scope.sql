-- Optional child-generation provenance for scoped stored-LLM executions.
-- Existing unscoped origins remain valid v1 rows with both columns NULL.
ALTER TABLE xss.profile_model_origins
  ADD COLUMN scope_key text,
  ADD COLUMN child_generation bigint,
  ADD CONSTRAINT profile_model_origins_child_scope CHECK (
    (scope_key IS NULL AND child_generation IS NULL)
    OR (scope_key='stored_llm' AND child_generation>=0)
  );
