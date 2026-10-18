/**
 * SecureShop v2 M14 — seed the tool_permissions ACL matrix.
 *
 * Applies to secureshop_agents.db. Idempotent via INSERT OR REPLACE — safe
 * to re-run.
 *
 * ACL matrix reflects the M14 spec's role → agent mapping:
 *
 *   customer → product-search.*, summarizer.*, price-advisor.*, cart.*,
 *              support.*, uploads.upload_avatar (self), email.read_inbox (self)
 *
 *   merchant → listing.*, inventory.*, pricing-strategy.*,
 *              review-moderator.*, analytics.*, email.*, uploads.upload_*
 *              (except upload_avatar which is customer-only), summarizer.*
 *
 *   admin    → user-management.*, audit.*, system.*, policy.*,
 *              mcp-registry.*, plus everything below (universal reach).
 *
 * The ROLE_MAP in server/services/secureshop/toolManifest.js remains as the
 * source-of-truth for the LLM's system-prompt tool listing (advisory); the
 * table below is the runtime authority the supervisor consults when
 * SS_ENFORCE_TOOL_ACL=true (or when system_config.enforce_tool_acl='true').
 *
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location db/initialize-db/seeds/22_secureshop_v2_rbac.js
 * intentional — user-management.set_role is denied for customer AND merchant
 * (rows below). When enforce_tool_acl='false' the supervisor still dispatches
 * it. This concretizes the LLM06 chain at Layer B: policy says no, runtime
 * says yes. Layer C (agent-host tool endpoint) ALSO skips the check for this
 * specific tool — see agent-host/agents/user-management/tools/index.js.
 */

const Database = require('better-sqlite3');

// Tool inventory — kept in sync with agent-host/agents/<ns>/server.js. When
// you add a new tool you should also add a permissions row here so it shows
// up in the admin Access Control matrix and gets a default allow/deny.
const {TOOLS}=require('../../../server/data/secureshopAgentSeeds');

function seed(dbPath) {
  const db = new Database(dbPath);
  try {
    const ins = db.prepare(`
      INSERT INTO tool_permissions (tool_name, role, allowed, reason, updated_at)
      VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(tool_name, role) DO UPDATE SET
        allowed = excluded.allowed,
        updated_at = CURRENT_TIMESTAMP
    `);
    const tx = db.transaction(() => {
      for (const [tool, matrix] of TOOLS) {
        for (const role of ['customer', 'merchant', 'admin']) {
          const allowed = matrix[role] ? 1 : 0;
          ins.run(tool, role, allowed, null);
        }
      }
    });
    tx();
    console.log(`  \u2713 seed 22_secureshop_v2_rbac.js applied (${TOOLS.length} tools × 3 roles)`);
  } finally {
    db.close();
  }
}

module.exports = seed;
module.exports.runSeed = seed;
module.exports.TOOL_ROWS = TOOLS;
