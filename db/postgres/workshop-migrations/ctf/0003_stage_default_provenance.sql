CREATE TABLE ctf.stage_default_fields (
  stage_number integer NOT NULL REFERENCES ctf.ctf_stages(stage_number) ON DELETE CASCADE,
  field_name text NOT NULL CHECK (field_name IN ('stage_description','ai_guardian_personality','hints')),
  provenance_state text NOT NULL CHECK (provenance_state IN ('managed','custom','legacy_unknown')),
  applied_default_sha256 text CHECK (applied_default_sha256 IS NULL OR applied_default_sha256 ~ '^[a-f0-9]{64}$'),
  source_default_sha256 text CHECK (source_default_sha256 IS NULL OR source_default_sha256 ~ '^[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(stage_number,field_name),
  CHECK (provenance_state <> 'managed' OR applied_default_sha256 IS NOT NULL)
);

CREATE FUNCTION ctf.mark_stage_default_fields_custom(p_stage_number integer,p_fields text[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,ctf AS $$
DECLARE field text;
BEGIN
  IF p_stage_number IS NULL OR p_fields IS NULL THEN RAISE EXCEPTION 'Stage and fields required'; END IF;
  FOREACH field IN ARRAY p_fields LOOP
    IF field NOT IN ('stage_description','ai_guardian_personality','hints') THEN
      RAISE EXCEPTION 'Unsupported CTF managed field';
    END IF;
    INSERT INTO ctf.stage_default_fields(stage_number,field_name,provenance_state)
      VALUES(p_stage_number,field,'custom')
      ON CONFLICT(stage_number,field_name) DO UPDATE SET provenance_state='custom',
        applied_default_sha256=NULL,updated_at=now();
  END LOOP;
END;
$$;

REVOKE ALL ON ctf.stage_default_fields FROM PUBLIC,dvaia_ctf_runtime;
GRANT SELECT ON ctf.stage_default_fields TO dvaia_ctf_runtime;
REVOKE ALL ON FUNCTION ctf.mark_stage_default_fields_custom(integer,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctf.mark_stage_default_fields_custom(integer,text[]) TO dvaia_ctf_runtime;
