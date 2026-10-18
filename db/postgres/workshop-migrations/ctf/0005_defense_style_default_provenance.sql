ALTER TABLE ctf.stage_default_fields
  DROP CONSTRAINT stage_default_fields_field_name_check;
ALTER TABLE ctf.stage_default_fields
  ADD CONSTRAINT stage_default_fields_field_name_check
  CHECK (field_name IN ('stage_description','ai_guardian_personality','hints','system_prompt','defense_style'));

CREATE OR REPLACE FUNCTION ctf.mark_stage_default_fields_custom(p_stage_number integer,p_fields text[])
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,ctf AS $$
DECLARE field text;
BEGIN
  IF p_stage_number IS NULL OR p_fields IS NULL THEN RAISE EXCEPTION 'Stage and fields required'; END IF;
  FOREACH field IN ARRAY p_fields LOOP
    IF field NOT IN ('stage_description','ai_guardian_personality','hints','system_prompt','defense_style') THEN
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

WITH prior_defaults(stage_number,prior_value,prior_hash) AS (VALUES
  (1,'[]','bb303ab33e10ab687ede112cdebd040e4861428d0cad88fd02f0a8ece1e82195'),
  (2,'[]','bb303ab33e10ab687ede112cdebd040e4861428d0cad88fd02f0a8ece1e82195'),
  (3,'["output_regex_strip"]','bc9f419bc9e0e8c23e90b77bb2cdb5f5e20922bf9af539336590d1593024e3de'),
  (4,'["transformation_guard"]','d2e319c864dd57827ce7e08c4db50b6a3496b6e09c6c899c8d0fbbe5fa92e025'),
  (5,'["transformation_guard","meta_llm_judge"]','d71fcf6f63b4aa621fe149b7d36b85765329b2721d49f6346378981e5f905e1e'),
  (6,'["transformation_guard","meta_llm_judge","persona_guard"]','040f4548a11bdce7e98a5197aaf602e088b86738069aba9cbc352d9fe493ffe5'),
  (7,'["transformation_guard","meta_llm_judge","persona_guard","polyglot_decoder"]','3853d9218f3ccf62648d06736c158b48d9be925dba2b1715aba0a1cd75fe9a41'),
  (8,'["transformation_guard","meta_llm_judge","persona_guard","polyglot_decoder","instruction_leak_guard","input_blocklist"]','bc16158f2ba78dff25a714cba2d806151e0d5c57ed8ad33f48d8d764bedcec2b'),
  (9,'["transformation_guard","meta_llm_judge","persona_guard","polyglot_decoder","instruction_leak_guard","input_blocklist"]','bc16158f2ba78dff25a714cba2d806151e0d5c57ed8ad33f48d8d764bedcec2b'),
  (10,'["input_blocklist","transformation_guard","meta_llm_judge","persona_guard","polyglot_decoder","instruction_leak_guard"]','a20da135e4acf0faadee0524e3d83f524fab57ae6b5c0a135da23e91a6e7cf95')
)
INSERT INTO ctf.stage_default_fields
  (stage_number,field_name,provenance_state,applied_default_sha256,source_default_sha256)
SELECT s.stage_number,'defense_style',
  CASE WHEN s.defense_style=d.prior_value THEN 'managed' ELSE 'custom' END,
  CASE WHEN s.defense_style=d.prior_value THEN d.prior_hash ELSE NULL END,
  d.prior_hash
FROM ctf.ctf_stages s JOIN prior_defaults d USING(stage_number)
ON CONFLICT(stage_number,field_name) DO NOTHING;
