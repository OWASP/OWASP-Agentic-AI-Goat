'use strict';
const { createLaunchScope, createConversationBinding } = require('./secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail = code => Object.assign(new Error('Bound access control unavailable'), { code });
function snapshot(raw) {
  const input = structuredClone(raw);
  input.scope = createLaunchScope(input.scope);
  createConversationBinding(input.scope, input.persona);
  if (input.persona.role !== 'admin') throw fail('ADMIN_REQUIRED');
  if (typeof input.personaSession?.sessionId !== 'string' || !UUID.test(input.personaSession.sessionId)
    || typeof input.personaSession.authorityVersion !== 'string' || !/^[1-9]\d*$/.test(input.personaSession.authorityVersion)) throw fail('SHOP_AUTH_INVALID');
  input.personaSession.sessionId = input.personaSession.sessionId.toLowerCase();
  return input;
}
// The repository captures the same startup-owned authority and performs the
// current original-credential check inside its short transaction. No caller
// may substitute a platform administrator for this shop administrator.
function createSecureShopBoundAccessControl({ repository } = {}) {
  if (['readPolicy', 'mutate', 'readOperation'].some(method => typeof repository?.[method] !== 'function')) {
    throw new TypeError('Bound ACL repository required');
  }
  return Object.freeze({
    async read(raw) {
      const input = snapshot(raw);
      const policy = await repository.readPolicy(input);
      return {
        enforcement_enabled: policy.enforcement,
        version: policy.version,
        registrySha256: policy.registrySha256,
        administration: { versionedPolicy: true,
          scopeKey: JSON.stringify([input.scope.launchId, input.scope.scenarioId, input.scope.generation,
            input.scope.platformOwnerId, input.scope.platformSessionId, input.persona.id]) },
        tools: policy.rows.map(row => ({ tool_name: row.toolKey,
          customer: row.allowed.customer, merchant: row.allowed.merchant, admin: row.allowed.admin,
          supported: row.supported, readOnly: row.readOnly,
          applicable_roles: { ...row.roleApplicability },
          ...(row.unavailableReason ? { unavailable_reason: row.unavailableReason } : {}) })),
      };
    },
    async mutate(raw) {
      const input = snapshot(raw);
      const receipt = await repository.mutate(input);
      return { receipt, version: receipt.version, registrySha256: receipt.registrySha256,
        ...(receipt.change.kind === 'permission'
          ? { tool_name: receipt.change.toolKey, role: receipt.change.role, allowed: receipt.change.allowed }
          : { enforcement_enabled: receipt.change.enabled }) };
    },
    async operation(raw) {
      return repository.readOperation(snapshot(raw));
    },
  });
}
module.exports = { createSecureShopBoundAccessControl };
