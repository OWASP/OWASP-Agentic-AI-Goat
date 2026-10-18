'use strict';
const { createOwnedHttpServiceClient } = require('./ownedHttpServiceClient');
const { createOwnedHttpCompositeTargets } = require('./ownedHttpCompositeTargets');
const { createMcpHttpLeaseRepository } = require('../../database/postgres/mcpHttpLeaseRepository');
const { createMcpHttpReceiptRepository } = require('../../database/postgres/mcpHttpReceiptRepository');

// Trusted startup input only. Detect durable child state even when config was
// removed: HTTP retirement may never be silently replaced by CLI-only cleanup.
async function composeOwnedHttpProduction({ env, resourcePool, identityPool, targets, ownedHttp } = {}) {
  const managed = require('./ownedHttpManagedConfiguration').load();
  env = { ...(managed ? { MCP_OWNED_HTTP_ENABLED: String(managed.enabled), MCP_OWNED_HTTP_URL: managed.url, MCP_OWNED_HTTP_TOKEN: managed.token } : {}), ...env };
  const value = env.MCP_OWNED_HTTP_ENABLED;
  if (value !== undefined && !['', 'true', 'false'].includes(value)) throw new Error('MCP_OWNED_HTTP_ENABLED must be true or false');
  const enabled = ownedHttp?.enabled ?? value === 'true';
  const relation = (await resourcePool.query("SELECT to_regclass('mcp.http_target_leases')::text AS name")).rows[0]?.name;
  if (!relation && !enabled) return targets;
  if (!relation) throw Object.assign(new Error('HTTP lease migration is required'), { code: 'HTTP_LEASE_UNAVAILABLE' });
  let http = ownedHttp?.client || null;
  if (!http && (env.MCP_OWNED_HTTP_URL || env.MCP_OWNED_HTTP_TOKEN)) {
    http = createOwnedHttpServiceClient({ baseUrl: env.MCP_OWNED_HTTP_URL, token: env.MCP_OWNED_HTTP_TOKEN });
  }
  const readMode = ownedHttp?.readMode || (async () => {
    if (!['vuln', 'fixed'].includes(env.LAB_MODE)) throw new Error('HTTP_MODE_UNAVAILABLE');
    return env.LAB_MODE;
  });
  return createOwnedHttpCompositeTargets({ cli: targets, http,
    leases: createMcpHttpLeaseRepository(resourcePool),
    receiptRepository: createMcpHttpReceiptRepository(identityPool), readMode, enabled });
}
module.exports = { composeOwnedHttpProduction };
