'use strict';
/**
 * PostgreSQL user-management tools retain the deliberate teaching sinks:
 *
 * @intentional-vulnerability llm02-user-lookup
 * @teaches OWASP-LLM:LLM02
 * @intentional-vulnerability llm02-sensitive-info
 * @teaches OWASP-LLM:LLM02
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @intentional-vulnerability llm01-indirect-pi-audit-log
 * @teaches OWASP-LLM:LLM01
 *
 * The native implementation still returns credential/PII fields, permits the
 * unreauthenticated role write, and records audit parameters verbatim.
 */
module.exports = require('./index.postgres.js');
