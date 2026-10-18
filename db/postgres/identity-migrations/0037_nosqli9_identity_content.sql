-- DRAFT ONLY. Replace only the exact shipped PostgreSQL defaults. Instructor
-- edits to the label, hint, or solution remain untouched.
CREATE TEMP TABLE nosqli9_content_changed(changed boolean NOT NULL) ON COMMIT DROP;

WITH changed AS (
  UPDATE workshop_platform.objectives
  SET label='Extract Author Contact Data',updated_at=now()
  WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'
    AND label='Extract Author Credentials'
  RETURNING 1
)
INSERT INTO nosqli9_content_changed SELECT true FROM changed;

WITH changed AS (
  UPDATE workshop_platform.objectives
  SET hint_content=$json${"title":"Extract Author Contact Data","hints":["Target the authors collection with regex injection","Try searching authors by email pattern: {\"email\": {\"$regex\": \".*@.*\"}}"]}$json$::jsonb,
      updated_at=now()
  WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'
    AND hint_content=$json${"title":"Extract Author Credentials","hints":["Target the authors collection with regex injection","Try searching authors by email pattern: {\"email\": {\"$regex\": \".*@.*\"}}"]}$json$::jsonb
  RETURNING 1
)
INSERT INTO nosqli9_content_changed SELECT true FROM changed;

WITH changed AS (
  UPDATE workshop_platform.objectives
  SET solution_content=$json${"title":"Extract Author Contact Data","difficulty":"Advanced","hints":["Target the authors collection with regex injection","Try searching authors by email pattern: {\"email\": {\"$regex\": \".*@.*\"}}"],"examples":[{"payload":"find authors {\"email\": {\"$regex\": \".*@.*\"}}","explanation":"Regex injection against the authors collection returns synthetic author email and profile records that normal paper search does not expose"}],"approach":"This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. Apply regex injection to the authors collection to extract synthetic email addresses, institutions, expertise, and biographies. Cross-collection injection demonstrates how a query flaw can expose contact and profile data outside the normal paper-search response.","tips":["This fixture contains email, institution, expertise, and biography fields; it does not contain passwords, tokens, or API keys","The injection technique is the same — only the collection/query type changes","Look for fields beyond what is normally returned in API responses"]}$json$::jsonb,
      updated_at=now()
  WHERE workshop_key='nosql_injection_workshop' AND objective_id='nosqli_9'
    AND solution_content=$json${"title":"Extract Author Credentials","difficulty":"Advanced","hints":["Target the authors collection with regex injection","Try searching authors by email pattern: {\"email\": {\"$regex\": \".*@.*\"}}"],"examples":[{"payload":"find authors {\"email\": {\"$regex\": \".*@.*\"}}","explanation":"Regex injection against the authors collection returns all author records that have an email field — potentially exposing credentials"}],"approach":"This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. Apply regex injection to the authors collection to extract email addresses and sensitive profile data. Cross-collection injection demonstrates how a single vulnerability can compromise the entire database.","tips":["Author data may include email, institution, API keys, or password hashes","The injection technique is the same — only the collection/query type changes","Look for fields beyond what is normally returned in API responses"]}$json$::jsonb
  RETURNING 1
)
INSERT INTO nosqli9_content_changed SELECT true FROM changed;

UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=now()
WHERE id=1 AND EXISTS(SELECT 1 FROM nosqli9_content_changed);

