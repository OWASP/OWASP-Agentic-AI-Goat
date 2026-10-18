'use strict';
const { createConversationBinding } = require('./secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FIELDS = ['id','session_id','session_role','step','actor','kind','agent_ns','tool_name',
  'latency_ms','tokens_in','tokens_out','provider','ts'];
const invalid = () => Object.assign(new Error('Shop observation authority unavailable'), { code: 'SHOP_AUTH_INVALID' });
function createBoundPersonaObservations({ conversations, personaAuthority, launches }) {
  if (typeof conversations?.personaLatestTrace !== 'function' || typeof personaAuthority?.capture !== 'function'
      || typeof launches?.assertCurrent !== 'function') throw new TypeError('Bound observation dependencies required');
  return Object.freeze({ async latestTrace(input) {
    const binding = createConversationBinding(input.scope, input.persona), limit = input.limit ?? 20;
    if (!['customer','merchant'].includes(binding.role)) throw invalid();
    if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw Object.assign(new Error('Invalid trace limit'), { code: 'INVALID_ARGUMENT' });
    const session = input.personaSession;
    if (!UUID.test(session?.sessionId || '') || typeof session?.authorityVersion !== 'string'
        || !/^[1-9]\d*$/.test(session.authorityVersion)) throw invalid();
    const credential = { sessionId: session.sessionId.toLowerCase(), authorityVersion: session.authorityVersion };
    await launches.assertCurrent(binding);
    const fence = await personaAuthority.capture({ scope: binding, personaId: binding.shopUserId, role: binding.role, ...credential });
    const actual = fence?.binding;
    if (typeof fence?.assertRemoteAdmission !== 'function' || !actual
      || ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].some(k => actual[k] !== binding[k])
      || actual.personaId !== binding.shopUserId || actual.role !== binding.role
      || actual.sessionId !== credential.sessionId || actual.authorityVersion !== credential.authorityVersion) throw invalid();
    await fence.assertRemoteAdmission();
    const rows = await conversations.personaLatestTrace(binding, limit);
    await fence.assertRemoteAdmission();
    await launches.assertCurrent(binding);
    if (!Array.isArray(rows) || rows.length > limit) throw new Error('Invalid trace projection');
    return rows.map(row => Object.fromEntries(FIELDS.filter(k => Object.hasOwn(row,k)).map(k => [k,row[k]])));
  } });
}
module.exports = { createBoundPersonaObservations };
