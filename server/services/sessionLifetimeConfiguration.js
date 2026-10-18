'use strict';

const MIN_SECONDS = 120;
const SHOP_DEFAULT_SECONDS = 4 * 60 * 60;
const PLATFORM_DEFAULT_SECONDS = 24 * 60 * 60;

function validateSessionLifetimeSeconds(value, maximum, name) {
  if (!Number.isSafeInteger(value) || value < MIN_SECONDS || value > maximum) {
    throw Object.assign(new Error(`${name} must be an integer from ${MIN_SECONDS} to ${maximum} seconds`),
      { code: 'INVALID_CONFIGURATION' });
  }
  return value;
}

function readSessionLifetimeConfiguration(env = process.env) {
  const read = (name, maximum) => {
    const raw = env[name];
    if (raw === undefined) return maximum;
    // Reject empty values, whitespace, fractions and alternate numeric syntax.
    if (typeof raw !== 'string' || !/^[1-9][0-9]*$/.test(raw)) {
      throw Object.assign(new Error(`${name} must contain integer seconds`), { code: 'INVALID_CONFIGURATION' });
    }
    return validateSessionLifetimeSeconds(Number(raw), maximum, name);
  };
  return Object.freeze({
    shopSessionTtlSeconds: read('SS_SESSION_TTL_SECONDS', SHOP_DEFAULT_SECONDS),
    platformSessionTtlSeconds: read('PLATFORM_SESSION_TTL_SECONDS', PLATFORM_DEFAULT_SECONDS),
  });
}

module.exports = { MIN_SECONDS, SHOP_DEFAULT_SECONDS, PLATFORM_DEFAULT_SECONDS,
  validateSessionLifetimeSeconds, readSessionLifetimeConfiguration };
