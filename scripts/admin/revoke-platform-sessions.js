'use strict';

async function revokePlatformSessions({ repository, output = process.stdout } = {}) {
  if (typeof repository?.revokeAllActiveSessions !== 'function') {
    throw Object.assign(new Error('Platform identity repository is unavailable'), { code: 'INVALID_CONFIGURATION' });
  }
  const revoked = await repository.revokeAllActiveSessions('signing_key_rotation');
  output.write(`Revoked ${revoked} active platform session(s).\n`);
  return revoked;
}

async function main({ args = process.argv.slice(2), output = process.stdout } = {}) {
  if (args.length) {
    if (args.length === 1 && args[0] === '--help') {
      output.write('Usage: node scripts/admin/revoke-platform-sessions.js\nRevokes all active platform sessions after an operator-controlled signing-key rotation. It does not print, generate, or edit the key.\n');
      return 0;
    }
    throw Object.assign(new Error('Usage: node scripts/admin/revoke-platform-sessions.js'), { code: 'INVALID_ARGUMENT' });
  }
  require('dotenv').config({ quiet: true });
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') {
    throw Object.assign(new Error('PostgreSQL platform configuration is required'), { code: 'INVALID_CONFIGURATION' });
  }
  require('../../server/services/platformSigningConfiguration').assertPlatformSigningConfiguration(process.env);
  const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
  try {
    await revokePlatformSessions({ repository: adapter.repository, output });
  } finally {
    await adapter.pool.end();
  }
  return 0;
}

if (require.main === module) main().catch(error => {
  const code = /^[A-Z0-9_]+$/.test(String(error?.code || '')) ? error.code : 'FAILED';
  console.error(`Platform session revocation failed (${code}).`);
  process.exitCode = 1;
});

module.exports = { main, revokePlatformSessions };
