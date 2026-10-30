-- Accept branded cookies for new lab sessions without invalidating old rows.
ALTER TABLE session_disclosure.labs DROP CONSTRAINT labs_lab_cookie_check;
ALTER TABLE session_disclosure.labs ADD CONSTRAINT labs_lab_cookie_check
  CHECK (lab_cookie ~ '^(owasp_ai_goat|dvaia)_lab_[A-Za-z0-9_-]{43}$');
