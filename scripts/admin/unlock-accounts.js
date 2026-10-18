'use strict';
const USAGE = 'Usage: node scripts/admin/unlock-accounts.js --username <username> | --all';
function parseArguments(args) {
  if (args.length === 1 && args[0] === '--all') return { username: null };
  if (args.length === 2 && args[0] === '--username' && args[1].trim()
      && args[1].length <= 50 && !args[1].startsWith('--')) return { username: args[1] };
  throw new Error(USAGE);
}
async function unlockAccounts(pool, { username }) {
  // Unlocking never changes passwords, activation, permissions or sessions.
  const result = await pool.query(`UPDATE identity.users
    SET login_attempts=0, account_locked_until=NULL, updated_at=now()
    WHERE ($1::text IS NULL OR username=$1)
      AND (login_attempts>0 OR account_locked_until IS NOT NULL)
    RETURNING id`, [username]);
  return result.rowCount;
}
async function main(args = process.argv.slice(2)) {
  if (!args.length || (args.length === 1 && ['--help', '-h'].includes(args[0]))) {
    console.log(USAGE); return;
  }
  const selection = parseArguments(args);
  require('dotenv').config({ path: require('node:path').resolve(__dirname, '../../.env'), quiet: true });
  const { resolveApplicationDatabaseEngine } = require('../../server/services/applicationDatabaseEngine');
  resolveApplicationDatabaseEngine({ env: process.env });
  if (process.env.PLATFORM_DATABASE_ENGINE !== 'postgres') throw new Error('PostgreSQL is required');
  const { createPool, verifyServer } = require('../../server/database/postgres');
  const pool = createPool(process.env, 'IDENTITY_DATABASE_URL');
  try {
    await verifyServer(pool);
    const count = await unlockAccounts(pool, selection);
    console.log(`Cleared login attempts and locks for ${count} account(s). Passwords and account activation were unchanged.`);
  } finally { await pool.end(); }
}
if (require.main === module) main().catch(error => {
  // Connection errors may contain credentials; keep diagnostics bounded.
  console.error(error.message === USAGE ? USAGE : `Account unlock failed (${error.code || 'configuration_or_database_error'}). Check PostgreSQL configuration and permissions.`);
  process.exitCode = 1;
});
module.exports = { parseArguments, unlockAccounts, main };
