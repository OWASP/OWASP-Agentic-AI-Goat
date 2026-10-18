'use strict';

const { createLaunchScope } = require('../../services/secureshopConversationBinding');

function identityScopeValues(value) {
  const scope = createLaunchScope(value);
  return [scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId];
}

// Callers supply trusted SQL placeholder positions, never model or HTTP input.
// This is the common identity source for the three templates plus owned signups.
function personaIdentitySource(first = 1) {
  if (!Number.isSafeInteger(first) || first < 1 || first > 64) throw new TypeError('Identity SQL position invalid');
  const types = ['uuid', 'uuid', 'bigint', 'integer', 'integer'];
  return `secureshop_agents.bound_persona_identities(${types.map((type, index) => `$${first + index}::${type}`).join(',')})`;
}

function identifier(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) throw new TypeError('Shop identity invalid');
  return value;
}

function createSecureShopBoundIdentityRepository({ pool } = {}) {
  if (typeof pool?.query !== 'function') throw new TypeError('Owned identity pool required');
  const publicFields = 't.shop_user_id AS id,t.username,t.email,t.role,t.full_name,t.phone';
  const credentialFields = `t.shop_user_id AS id,t.username,t.email,
    COALESCE(c.password_hash,t.password_hash) AS password,COALESCE(st.effective_role,t.role) AS role,
    t.full_name,t.phone,COALESCE(c.credential_version,1)::bigint AS credential_version,
    COALESCE(st.authority_version,1)::text AS authority_version,st.banned_at`;
  const coordinates = alias => `${alias}.platform_launch_id=$1 AND ${alias}.platform_scenario_id=$2
    AND ${alias}.platform_launch_generation=$3 AND ${alias}.original_platform_owner_id=$4
    AND ${alias}.original_platform_session_id=$5 AND ${alias}.shop_user_id=t.shop_user_id`;
  const credentials = `${personaIdentitySource()} t
    LEFT JOIN secureshop_agents.bound_persona_credentials c ON ${coordinates('c')}
    LEFT JOIN secureshop_agents.bound_persona_state st ON ${coordinates('st')}`;
  return Object.freeze({
    async read(scope, id) {
      return (await pool.query(`SELECT ${publicFields} FROM ${personaIdentitySource()} t WHERE t.shop_user_id=$6`,
        [...identityScopeValues(scope), identifier(id)])).rows[0] || null;
    },
    async list(scope) {
      return (await pool.query(`SELECT ${publicFields} FROM ${personaIdentitySource()} t ORDER BY t.role,t.shop_user_id`,
        identityScopeValues(scope))).rows;
    },
    async credentialByUsername(scope, username) {
      if (typeof username !== 'string' || !username || Buffer.byteLength(username) > 256) return null;
      return (await pool.query(`SELECT ${credentialFields} FROM ${credentials} WHERE t.username=$6`,
        [...identityScopeValues(scope), username.toLowerCase()])).rows[0] || null;
    },
    async credentialById(scope, id) {
      return (await pool.query(`SELECT ${credentialFields} FROM ${credentials} WHERE t.shop_user_id=$6`,
        [...identityScopeValues(scope), identifier(id)])).rows[0] || null;
    },
  });
}

module.exports = { createSecureShopBoundIdentityRepository, identityScopeValues, personaIdentitySource };
