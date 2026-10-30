-- Update only the unchanged synthetic seed; retain learner/instructor edits.
UPDATE xss.emails
SET sender = 'newsletter@owasp-ai-goat.local'
WHERE id = 3
  AND subject = 'Weekly Security Newsletter'
  AND sender = 'newsletter@dvaia.local'
  AND body = 'This week: patch Tuesday updates, new CVEs, and best practices for input sanitization.'
  AND user_key IS NULL;
