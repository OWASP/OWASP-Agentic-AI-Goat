'use strict';

/**
 * SecureShop v2 M14 — PostgreSQL Tool ACL (Layer B enforcement).
 *
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location server/services/secureshop/toolAcl.js
 * intentional — when enforce_tool_acl is false (the seeded default), denied
 * calls are logged and still dispatched.
 */

const pg = () => require('../../database/postgres/secureshopAgentsDb').getSecureShopAgentsDb();

function invalidateEnforcementCache() {
  // PostgreSQL reads the current setting for each decision, so no cache exists.
}

async function isEnforcementEnabled() {
  const value = String(process.env.SS_ENFORCE_TOOL_ACL || '').trim().toLowerCase();
  if (value === 'true') return true;
  if (value === 'false') return false;
  return pg().getEnforcement();
}

async function checkToolAcl(role, agentNs, toolName) {
  const [permission, enforcement] = await Promise.all([
    pg().getPermission(`${agentNs}.${toolName}`, role),
    isEnforcementEnabled(),
  ]);
  if (permission?.allowed) {
    return { allowed: true, action: 'dispatch', policyViolation: null, enforcement };
  }
  return {
    allowed: false,
    action: enforcement ? 'block' : 'log',
    policyViolation: enforcement ? 'blocked' : 'denied-by-acl',
    enforcement,
  };
}

function listAllPermissions() {
  return pg().listPermissions();
}

function setPermission(toolFullName, role, allowed) {
  return pg().setPermission(toolFullName, role, allowed);
}

function setEnforcement(enabled, updatedBy = null) {
  return pg().setEnforcement(enabled, updatedBy);
}

module.exports = {
  checkToolAcl,
  isEnforcementEnabled,
  invalidateEnforcementCache,
  listAllPermissions,
  setPermission,
  setEnforcement,
};
