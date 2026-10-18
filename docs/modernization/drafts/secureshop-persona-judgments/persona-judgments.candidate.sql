-- Compatibility ledger entry for retained candidate fixtures.
-- The reviewed schema was promoted unchanged as identity migration 0098.
-- Candidate fixtures copy this file after all canonical migrations, so it must
-- verify that authority rather than attempt to recreate it.
DO $$
BEGIN
 IF NOT EXISTS (
   SELECT 1 FROM information_schema.columns
   WHERE table_schema='workshop_platform'
     AND table_name='objective_judgments'
     AND column_name='persona_authority_required'
     AND data_type='boolean' AND is_nullable='NO' AND column_default='false'
 ) OR to_regclass('workshop_platform.persona_evaluation_bindings') IS NULL
   OR to_regprocedure('workshop_platform.bind_persona_evaluation(integer,uuid,uuid,uuid,uuid,bigint,bigint,integer,uuid,text,bigint)') IS NULL THEN
   RAISE EXCEPTION 'Promoted persona judgment schema is unavailable';
 END IF;
END $$;
