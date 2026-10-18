'use strict';

const FLAG = 'SS_PERSONA_INBOX_READY';

function configurationError(message) {
  return Object.assign(new Error(message), { code: 'INVALID_CONFIGURATION' });
}

function activationPolicy(env = process.env) {
  const value = env[FLAG];
  if (value !== undefined && value !== 'true' && value !== 'false') {
    throw configurationError(`${FLAG} must be true or false`);
  }
  const postgres = env.PLATFORM_DATABASE_ENGINE === 'postgres';
  if (postgres && env.WORKSHOP_DATABASE_ENGINE !== 'postgres') {
    throw configurationError('SecureShop persona inbox requires PostgreSQL workshop storage');
  }
  return Object.freeze({
    requested: postgres && value !== 'false',
    postgres,
    explicitlyDisabled: value === 'false',
  });
}

module.exports = { FLAG, activationPolicy };
