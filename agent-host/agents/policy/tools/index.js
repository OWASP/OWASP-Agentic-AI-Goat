'use strict';
/**
 * PostgreSQL policy tools retain both deliberate teaching sinks:
 *
 * @intentional-vulnerability ssti-policy-template
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/policy/tools/index.js
 *
 * @intentional-vulnerability llm04-policy-poisoning
 * @teaches OWASP-LLM:LLM04
 *
 * The native implementation renders caller markdown through the unsafe
 * Nunjucks environment and persists it for the supervisor policy loader.
 */
module.exports = require('./index.postgres.js');
