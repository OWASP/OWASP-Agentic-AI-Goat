-- DRAFT ONLY. The NOVA store retains an archival solution copy. Replace the
-- complete known shipped row only; any instructor-edited field preserves it.
UPDATE nova.nosql_injection_solutions
SET title='Extract Author Contact Data',
    hints=$json$["Target the authors collection with regex injection","Try searching authors by email pattern: {\"email\": {\"$regex\": \".*@.*\"}}"]$json$,
    examples=$json$[{"payload":"find authors {\"email\": {\"$regex\": \".*@.*\"}}","explanation":"Regex injection against the authors collection returns synthetic author email and profile records that normal paper search does not expose"}]$json$,
    approach='This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. Apply regex injection to the authors collection to extract synthetic email addresses, institutions, expertise, and biographies. Cross-collection injection demonstrates how a query flaw can expose contact and profile data outside the normal paper-search response.',
    tips=$json$["This fixture contains email, institution, expertise, and biography fields; it does not contain passwords, tokens, or API keys","The injection technique is the same — only the collection/query type changes","Look for fields beyond what is normally returned in API responses"]$json$
WHERE objective_id='nosqli_9'
  AND title='Extract Author Credentials'
  AND difficulty='Advanced'
  AND hints::jsonb=$json$["Target the authors collection with regex injection","Try searching authors by email pattern: {\"email\": {\"$regex\": \".*@.*\"}}"]$json$::jsonb
  AND examples::jsonb=$json$[{"payload":"find authors {\"email\": {\"$regex\": \".*@.*\"}}","explanation":"Regex injection against the authors collection returns all author records that have an email field — potentially exposing credentials"}]$json$::jsonb
  AND approach='This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. Apply regex injection to the authors collection to extract email addresses and sensitive profile data. Cross-collection injection demonstrates how a single vulnerability can compromise the entire database.'
  AND tips::jsonb=$json$["Author data may include email, institution, API keys, or password hashes","The injection technique is the same — only the collection/query type changes","Look for fields beyond what is normally returned in API responses"]$json$::jsonb;

