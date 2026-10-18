-- Instructor-authored CTF teaching copy is deliberately separate from the
-- guardian/Judge stage definition. It is projected only by the ordered CTF
-- authority command path; learner reads receive the objective but never the
-- instructor solution.
CREATE TABLE ctf.ctf_stage_teaching_content (
  stage_id integer PRIMARY KEY REFERENCES ctf.ctf_stages(id) ON DELETE CASCADE,
  objective_text text NOT NULL DEFAULT '' CHECK (octet_length(objective_text) <= 8192),
  solution_text text NOT NULL DEFAULT '' CHECK (octet_length(solution_text) <= 16384),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

REVOKE ALL ON ctf.ctf_stage_teaching_content FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON ctf.ctf_stage_teaching_content TO dvaia_ctf_runtime;
