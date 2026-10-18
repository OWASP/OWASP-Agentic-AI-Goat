'use strict';
const fs = require('node:fs');
const path = require('node:path');

// Validate the isolated launcher's coordinates before constructing any pool.
// Resource ownership and package integrity are separately verified by the launcher.
function assertMcpMailpitAdmission(env, sourceRoot) {
  const fail = () => { throw new Error('Exact disposable MCP Mailpit launch coordinates are required'); };
  if (env.PG_TEST_DISPOSABLE !== 'yes' || env.MCP_OWNED_RESOURCES_MAILPIT !== 'yes') fail();
  if (typeof env.MCP_OWNED_RESOURCES_SOURCE_ROOT !== 'string'
      || !path.isAbsolute(env.MCP_OWNED_RESOURCES_SOURCE_ROOT)
      || fs.realpathSync(env.MCP_OWNED_RESOURCES_SOURCE_ROOT) !== fs.realpathSync(sourceRoot)) fail();
  const port = (name, reserved) => {
    const value = env[name];
    if (typeof value !== 'string' || !/^[1-9][0-9]{0,4}$/.test(value)
        || Number(value) > 65535 || reserved.includes(Number(value))) fail();
    return value;
  };
  const pgPort = port('MCP_OWNED_RESOURCES_PG_PORT', [5432]);
  const smtpPort = port('MCP_OWNED_RESOURCES_SMTP_PORT', [1025]);
  const apiPort = port('MCP_OWNED_RESOURCES_API_PORT', [8025]);
  if (new Set([pgPort, smtpPort, apiPort]).size !== 3) fail();
  for (const [name, role] of [
    ['PG_MCP_OWNED_RESOURCES_TEST_MIGRATION_URL', 'dvaia_mcp_migration'],
    ['PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL', 'dvaia_mcp_runtime'],
  ]) {
    let url; try { url = new URL(env[name]); } catch { fail(); }
    if (url.protocol !== 'postgresql:' || url.hostname !== '127.0.0.1' || url.port !== pgPort
        || url.pathname !== '/dvaia_test_mcp_owned_mailpit' || url.username !== role
        || url.search || url.hash) fail();
  }
  if (env.MAILPIT_SMTP_HOST !== '127.0.0.1' || env.MAILPIT_SMTP_PORT !== smtpPort
      || env.MAILPIT_API_URL !== `http://127.0.0.1:${apiPort}`) fail();
}
module.exports = { assertMcpMailpitAdmission };
