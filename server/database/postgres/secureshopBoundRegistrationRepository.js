'use strict';

const { createLaunchScope } = require('../../services/secureshopConversationBinding');
const { identityScopeValues } = require('./secureshopBoundIdentityRepository');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const failure = code => Object.assign(new Error('Owned shop registration unavailable'), { code });

function requestId(value) {
  if (typeof value !== 'string' || !UUID.test(value)) throw failure('SHOP_REGISTRATION_INVALID');
  return value.toLowerCase();
}
function registration(row, scope) {
  if (!row) return null;
  if (row.platform_launch_id !== scope.launchId || row.platform_scenario_id !== scope.scenarioId
    || Number(row.platform_launch_generation) !== scope.generation
    || Number(row.original_platform_owner_id) !== scope.platformOwnerId
    || Number(row.original_platform_session_id) !== scope.platformSessionId
    || !Number.isSafeInteger(Number(row.shop_user_id)) || Number(row.shop_user_id) < 1000000000
    || !['customer', 'merchant'].includes(row.role) || typeof row.username !== 'string'
    || typeof row.email !== 'string' || typeof row.password_hash !== 'string') throw failure('SHOP_REGISTRATION_UNAVAILABLE');
  return Object.freeze({ id: Number(row.shop_user_id), username: row.username, email: row.email,
    role: row.role, full_name: row.full_name ?? null, phone: row.phone ?? null,
    passwordHash: row.password_hash,
    ...(row.metadata_sha256 ? { metadataSha256: Buffer.from(row.metadata_sha256).toString('hex') } : {}) });
}

function createSecureShopBoundRegistrationRepository({ pool } = {}) {
  if (typeof pool?.query !== 'function') throw new TypeError('Owned registration pool required');
  return Object.freeze({
    async findRequest(scopeValue, operationId) {
      const scope = createLaunchScope(scopeValue);
      const row = (await pool.query(`SELECT r.*,op.metadata_sha256
        FROM secureshop_agents.bound_persona_registrations op
        JOIN secureshop_agents.bound_registered_personas r ON r.shop_user_id=op.shop_user_id
          AND r.platform_launch_id=op.platform_launch_id AND r.platform_scenario_id=op.platform_scenario_id
          AND r.platform_launch_generation=op.platform_launch_generation
          AND r.original_platform_owner_id=op.original_platform_owner_id
          AND r.original_platform_session_id=op.original_platform_session_id
        WHERE op.platform_launch_id=$1 AND op.platform_scenario_id=$2 AND op.platform_launch_generation=$3
          AND op.original_platform_owner_id=$4 AND op.original_platform_session_id=$5 AND op.request_id=$6`,
      [...identityScopeValues(scope), requestId(operationId)])).rows[0];
      return registration(row, scope);
    },
    async register({ scope: scopeValue, requestId: operationId, username, email, passwordHash, role, full_name, metadataSha256 }) {
      const scope = createLaunchScope(scopeValue);
      if (typeof metadataSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(metadataSha256)) throw failure('SHOP_REGISTRATION_INVALID');
      try {
        const result = await pool.query(`SELECT * FROM secureshop_agents.register_bound_persona(
          $1::uuid,$2::uuid,$3::bigint,$4::integer,$5::integer,$6::uuid,$7::text,$8::text,$9::text,$10::text,$11::text,$12::bytea)`,
        [...identityScopeValues(scope), requestId(operationId), username, email, passwordHash, role, full_name,
          Buffer.from(metadataSha256, 'hex')]);
        const value = registration(result.rows[0], scope);
        if (!value) throw failure('SHOP_REGISTRATION_UNAVAILABLE');
        return value;
      } catch (error) {
        if (error.code === '23505') throw failure('SHOP_REGISTRATION_CONFLICT');
        if (error.code === '54000') throw failure('SHOP_REGISTRATION_CAPACITY');
        if (error.code === '55000') throw failure('STALE_LAUNCH');
        throw error;
      }
    },
  });
}

module.exports = { createSecureShopBoundRegistrationRepository };
