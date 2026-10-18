-- Teaching copy is projected by the restricted delivery worker, rather than
-- the general CTF runtime role.  Keep that writer's access aligned with the
-- table's intended read/insert/update lifecycle.
GRANT SELECT, INSERT, UPDATE ON ctf.ctf_stage_teaching_content TO dvaia_ctf_delivery;
