BEGIN;

ALTER TABLE ctf.stage_default_fields
  DROP CONSTRAINT stage_default_fields_field_name_check;
ALTER TABLE ctf.stage_default_fields
  ADD CONSTRAINT stage_default_fields_field_name_check
  CHECK (field_name IN ('stage_description','ai_guardian_personality','hints','system_prompt'));

CREATE OR REPLACE FUNCTION ctf.mark_stage_default_fields_custom(p_stage_number integer,p_fields text[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,ctf AS $$
DECLARE field text;
BEGIN
  IF p_stage_number IS NULL OR p_fields IS NULL THEN RAISE EXCEPTION 'Stage and fields required'; END IF;
  FOREACH field IN ARRAY p_fields LOOP
    IF field NOT IN ('stage_description','ai_guardian_personality','hints','system_prompt') THEN
      RAISE EXCEPTION 'Unsupported CTF managed field';
    END IF;
    INSERT INTO ctf.stage_default_fields(stage_number,field_name,provenance_state)
      VALUES(p_stage_number,field,'custom')
      ON CONFLICT(stage_number,field_name) DO UPDATE SET provenance_state='custom',
        applied_default_sha256=NULL,updated_at=now();
  END LOOP;
END;
$$;

REVOKE ALL ON FUNCTION ctf.mark_stage_default_fields_custom(integer,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ctf.mark_stage_default_fields_custom(integer,text[]) TO dvaia_ctf_runtime;

COMMIT;
