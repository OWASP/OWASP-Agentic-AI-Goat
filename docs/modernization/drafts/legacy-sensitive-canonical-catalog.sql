-- DRAFT ONLY. These five phase-two objectives are intentionally inserted
-- inactive. The existing 18 FinFlow objectives and their UI remain unchanged.
-- Do not promote until workshopCatalog.js registers the same IDs; the normal
-- seed reconciler deactivates objectives absent from that source catalog.
-- A fresh database has not been seeded when the migration loader runs, so the
-- inactive parent must exist before the objective FK rows are installed.
INSERT INTO workshop_platform.exercises
 (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,
  is_visible,show_hints,show_solutions,catalog_active,ordinal)
VALUES ('sensitive_info_disclosure','sensitive_info_disclosure',
 '🔓 Sensitive Information Disclosure',
 'Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.',
 'web','intermediate','/workshop/sensitive-info',true,false,false,true,100)
ON CONFLICT(workshop_key) DO NOTHING;

INSERT INTO workshop_platform.objectives
 (workshop_key,objective_id,label,category,ordinal,is_enabled,catalog_active,hint_enabled,solution_enabled,hint_content,solution_content)
VALUES
 ('sensitive_info_disclosure','path_traversal','Read a protected teaching file','legacy_file_ssi',100,false,false,false,false,NULL,NULL),
 ('sensitive_info_disclosure','ssi_injection','Substitute an SSI directive','legacy_file_ssi',101,false,false,false,false,NULL,NULL),
 ('sensitive_info_disclosure','combined_traversal_ssi','Combine a protected read with SSI substitution','legacy_file_ssi',102,false,false,false,false,NULL,NULL),
 ('sensitive_info_disclosure','ai_assisted_path_traversal','Have the configured model select a protected teaching-file read','legacy_file_ssi',103,false,false,false,false,NULL,NULL),
 ('sensitive_info_disclosure','ai_assisted_ssi','Have the configured model select an SSI substitution','legacy_file_ssi',104,false,false,false,false,NULL,NULL)
ON CONFLICT(workshop_key,objective_id) DO NOTHING;
