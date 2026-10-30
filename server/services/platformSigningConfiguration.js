'use strict';

const MINIMUM_SECRET_BYTES = 32;
const KNOWN_PUBLIC_SECRETS = Object.freeze([
  'dvaia-secret-key-2024',
  'owasp-ai-goat-secret-key-2024',
  'change_me_to_a_long_random_string',
  'your-secret-key',
]);

function configurationError(message) {
  return Object.assign(new Error(message), { code: 'INVALID_CONFIGURATION' });
}

function assertPlatformSigningConfiguration(env = process.env) {
  const jwtSecret = env.JWT_SECRET;
  if (typeof jwtSecret !== 'string' || jwtSecret.trim().length === 0) {
    throw configurationError(
      'JWT_SECRET is required for platform authentication. Fresh installation: run npm run setup. ' +
      'Existing installation: stop the application and follow docs/modernization/platform-signing-configuration-2026-09-14.md; keys are never rotated automatically.'
    );
  }
  if (KNOWN_PUBLIC_SECRETS.includes(jwtSecret) || Buffer.byteLength(jwtSecret, 'utf8') < MINIMUM_SECRET_BYTES) {
    throw configurationError(
      'JWT_SECRET must be a private value of at least 32 bytes. Fresh installation: run npm run setup. ' +
      'Existing installation: stop the application and follow docs/modernization/platform-signing-configuration-2026-09-14.md; keys are never rotated automatically.'
    );
  }
  return Object.freeze({ jwtSecret });
}

module.exports = {
  MINIMUM_SECRET_BYTES,
  KNOWN_PUBLIC_SECRETS,
  assertPlatformSigningConfiguration,
};
