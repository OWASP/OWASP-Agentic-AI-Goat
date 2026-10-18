'use strict';

const FLAG = 'SENSITIVE_INFO_AGGREGATE_RESET_ENABLED';

function configurationError(message) {
  return Object.assign(new Error(message), { code: 'INVALID_CONFIGURATION' });
}

// The production composition imports this policy after identity0044 and
// FinFlow0009 were promoted with the same paused release boundary.
function activationPolicy(env = process.env) {
  const value = env[FLAG];
  if (value !== undefined && value !== 'true' && value !== 'false') {
    throw configurationError(`${FLAG} must be true or false`);
  }
  const postgres = env.PLATFORM_DATABASE_ENGINE === 'postgres';
  if (postgres && env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw configurationError('Sensitive Information aggregate reset requires PostgreSQL workshop storage');
  }
  return Object.freeze({
    requested: postgres && value !== 'false',
    postgres,
    explicitlyDisabled: value === 'false',
  });
}

module.exports = { FLAG, activationPolicy };
