'use strict';

/**
 * Central config for the MCP lab's real-execution backends. Endpoints resolve
 * to the in-task sidecars locally (docker-compose) and on AWS Fargate (shared
 * task netns → localhost). All are overridable via env.
 */
module.exports = {
  SANDBOX_RUNNER_URL: process.env.SANDBOX_RUNNER_URL || 'http://127.0.0.1:8090',
  CODEBOT_SANDBOX_RUNNER_URL: process.env.CODEBOT_SANDBOX_RUNNER_URL
    || process.env.SANDBOX_RUNNER_URL || 'http://127.0.0.1:8090',
  SSRF_TARGET_URL: process.env.SSRF_TARGET_URL || 'http://127.0.0.1:9099',
  ROGUE_MCP_URL: process.env.ROGUE_MCP_URL || 'http://127.0.0.1:8091',
  MAILPIT_SMTP_HOST: process.env.MAILPIT_SMTP_HOST || '127.0.0.1',
  MAILPIT_SMTP_PORT: parseInt(process.env.MAILPIT_SMTP_PORT || '1025', 10),
  MAILPIT_API_URL: process.env.MAILPIT_API_URL || 'http://127.0.0.1:8025',
  // How long to wait on a backend before deciding it is unavailable. On timeout
  // the tool fails honestly (backendDown, no score) — there is no simulation.
  BACKEND_TIMEOUT_MS: parseInt(process.env.MCP_BACKEND_TIMEOUT_MS || '4000', 10),
};
