'use strict';

const { withTransaction } = require('./index');
const { randomUUID } = require('node:crypto');
const { copySceneBinding, executionScope, assertSceneGrant, withSceneLease } =
  require('../../services/secureshopSceneBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ADDRESSES = 32;

function fail(message) {
  throw Object.assign(new Error(message), { code: 'INVALID_ARGUMENT' });
}
function integer(value, label, maximum = 2147483647) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail(`${label} is invalid`);
  return value;
}
function nullableText(value, label, maximum) {
  if (value === null) return null;
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > maximum) fail(`${label} is invalid`);
  return value.trim() ? value : null;
}
function requiredText(value, label, maximum) {
  const result = nullableText(value, label, maximum);
  if (result === null) fail(`${label} is invalid`);
  return result;
}
function binding(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('scope is invalid');
  for (const key of ['targetId', 'launchId', 'scenarioId']) {
    if (typeof input[key] !== 'string' || !UUID.test(input[key])) fail(`${key} is invalid`);
  }
  return copySceneBinding(input, Object.freeze({
    targetId: input.targetId.toLowerCase(), launchId: input.launchId.toLowerCase(),
    scenarioId: input.scenarioId.toLowerCase(),
    generation: integer(input.generation, 'generation', Number.MAX_SAFE_INTEGER),
    platformOwnerId: integer(input.platformOwnerId, 'platformOwnerId'),
    platformSessionId: integer(input.platformSessionId, 'platformSessionId'),
  }));
}
function values(value) {
  return [value.targetId, value.launchId, value.scenarioId, value.generation,
    value.platformOwnerId, value.platformSessionId];
}
async function target(client, value) {
  const row = (await client.query(`SELECT lifecycle FROM secureshop_review.product_targets
    WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
      AND original_platform_owner_id=$5 AND original_platform_session_id=$6 FOR SHARE`, values(value))).rows[0];
  if (!row || row.lifecycle !== 'active') {
    throw Object.assign(new Error('account target unavailable'), { code: 'PRODUCT_TARGET_UNAVAILABLE' });
  }
}
async function lockAccount(client, targetId, shopUserId) {
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,$2::bigint))',
    [targetId, shopUserId]);
}
function address(row) {
  return Object.freeze({ id: Number(row.address_id), label: row.label, line1: row.line1,
    line2: row.line2, city: row.city, state: row.state, zip: row.zip, phone: row.phone,
    is_default: row.is_default === true, created_at: row.created_at });
}
function addressInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('address is invalid');
  if (typeof input.isDefault !== 'boolean') fail('isDefault is invalid');
  return Object.freeze({ label: nullableText(input.label, 'label', 128),
    line1: requiredText(input.line1, 'line1', 1024), line2: nullableText(input.line2, 'line2', 1024),
    city: nullableText(input.city, 'city', 256), state: nullableText(input.state, 'state', 128),
    zip: nullableText(input.zip, 'zip', 64), phone: nullableText(input.phone, 'phone', 128),
    isDefault: input.isDefault === true });
}
function auditPersona(shopUserId, value) {
  if (!value || Number(value.id) !== shopUserId
      || !['customer', 'merchant', 'admin'].includes(value.role)) {
    fail('audit persona is invalid');
  }
  return Object.freeze({ id: shopUserId, role: value.role });
}

async function appendAccountAudit(auditStore, client, value, shopUserId, rawPersona, action, targetId, params, sourceKind) {
    if (!auditStore) return;
    const persona = auditPersona(shopUserId, rawPersona);
    const provenance = value.scene ? { storageTargetId: value.targetId,
      sceneId: value.scene.sceneId, sceneGeneration: value.scene.sceneGeneration } : {};
    await auditStore.append(client, { eventId: randomUUID(), scope: executionScope(value), persona,
      actor: persona.role, action, target: String(targetId), paramsJson: JSON.stringify({ ...params, ...provenance }),
      outcome: 'completed', sourceKind, sourceId: String(targetId) });
  }
async function saveProfileWithClient(client, value, owner, profile, actor, audit) {
  await lockAccount(client, value.targetId, owner);
  const {email,fullName,phone}=profile;
  const row=(await client.query(`INSERT INTO secureshop_review.product_target_profile_overlays
    (target_id,shop_user_id,email,full_name,phone) VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(target_id,shop_user_id) DO UPDATE
    SET email=EXCLUDED.email,full_name=EXCLUDED.full_name,phone=EXCLUDED.phone
    RETURNING email,full_name,phone`,[value.targetId,owner,email,fullName,phone])).rows[0];
  await audit(client,value,owner,actor,'profile_update',owner,{email,fullName,phone},'profile');
  return row;
}
async function saveAddressWithClient(client, value, owner, id, requested, actor, audit) {
        await lockAccount(client, value.targetId, owner);
        if (id !== null) {
          const current = await client.query(`SELECT address_id FROM secureshop_review.product_target_addresses
            WHERE target_id=$1 AND shop_user_id=$2 AND address_id=$3 FOR UPDATE`,
          [value.targetId, owner, id]);
          if (!current.rowCount) return null;
        } else {
          const count = Number((await client.query(`SELECT count(*)::integer AS count
            FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2`,
          [value.targetId, owner])).rows[0].count);
          if (count >= MAX_ADDRESSES) fail('address capacity reached');
        }
        if (requested.isDefault) await client.query(`UPDATE secureshop_review.product_target_addresses
          SET is_default=false WHERE target_id=$1 AND shop_user_id=$2 AND is_default=true`,
        [value.targetId, owner]);
        const args = [value.targetId, owner, requested.label, requested.line1, requested.line2,
          requested.city, requested.state, requested.zip, requested.phone, requested.isDefault];
        const row = id === null
          ? (await client.query(`INSERT INTO secureshop_review.product_target_addresses
              (target_id,shop_user_id,label,line1,line2,city,state,zip,phone,is_default)
              VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`, args)).rows[0]
          : (await client.query(`UPDATE secureshop_review.product_target_addresses
              SET label=$3,line1=$4,line2=$5,city=$6,state=$7,zip=$8,phone=$9,is_default=$10
              WHERE target_id=$1 AND shop_user_id=$2 AND address_id=$11 RETURNING *`, [...args, id])).rows[0];
        const result = address(row);
        await audit(client, value, owner, actor, id === null ? 'address_create' : 'address_update',
          result.id, requested, 'address');
        return result;
}

function createSecureShopBoundAccountRepository(pool, { checkCurrent, auditStore, effectTimeoutMs } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
      || typeof checkCurrent !== 'function') fail('dependencies invalid');
  if (auditStore && typeof auditStore.append !== 'function') fail('audit dependency invalid');
  if (effectTimeoutMs !== undefined && effectTimeoutMs !== 3000) throw new TypeError('Bounded account timeout required');
  async function guarded(input, work) {
    const value = binding(input);
    const execution = executionScope(value);
    await checkCurrent(execution);
    return withSceneLease(value, () => withTransaction(pool, async client => {
      if(effectTimeoutMs)await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");
      await assertSceneGrant(client, value);
      await target(client, value);
      const result = await work(client, value);
      await checkCurrent(execution);
      await assertSceneGrant(client, value);
      return result;
    }));
  }
  const audit=(...args)=>appendAccountAudit(auditStore,...args);

  return Object.freeze({
    readProfile(input, shopUserId) {
      const owner = integer(shopUserId, 'shopUserId');
      return guarded(input, async (client, value) => (await client.query(`SELECT email,full_name,phone
        FROM secureshop_review.product_target_profile_overlays
        WHERE target_id=$1 AND shop_user_id=$2`, [value.targetId, owner])).rows[0] || null);
    },
    updateProfile(input, shopUserId, profile, persona) {
      const owner = integer(shopUserId, 'shopUserId');
      if (!profile || typeof profile !== 'object' || Array.isArray(profile)) fail('profile is invalid');
      const email = requiredText(profile.email, 'email', 320);
      if (!/^[^\s@]+@[^\s@]+$/.test(email)) fail('email is invalid');
      const fullName = nullableText(profile.fullName, 'fullName', 512);
      const phone = nullableText(profile.phone, 'phone', 128);
      const actor = auditStore ? auditPersona(owner, persona) : null;
      return guarded(input, async (client, value) => {
        return saveProfileWithClient(client,value,owner,{email,fullName,phone},actor,audit);
      });
    },
    listAddresses(input, shopUserId) {
      const owner = integer(shopUserId, 'shopUserId');
      return guarded(input, async (client, value) => Object.freeze((await client.query(`SELECT *
        FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2
        ORDER BY is_default DESC,address_id`, [value.targetId, owner])).rows.map(address)));
    },
    saveAddress(input, shopUserId, addressId, fields, persona) {
      const owner = integer(shopUserId, 'shopUserId');
      const id = addressId === null ? null : integer(addressId, 'addressId', Number.MAX_SAFE_INTEGER);
      const requested = addressInput(fields);
      const actor = auditStore ? auditPersona(owner, persona) : null;
      return guarded(input, async (client, value) => {
        return saveAddressWithClient(client, value, owner, id, requested, actor, audit);
      });
    },
    deleteAddress(input, shopUserId, addressId, persona) {
      const owner = integer(shopUserId, 'shopUserId');
      const id = integer(addressId, 'addressId', Number.MAX_SAFE_INTEGER);
      const actor = auditStore ? auditPersona(owner, persona) : null;
      return guarded(input, async (client, value) => {
        await lockAccount(client, value.targetId, owner);
        const result = await client.query(`DELETE FROM secureshop_review.product_target_addresses
          WHERE target_id=$1 AND shop_user_id=$2 AND address_id=$3`, [value.targetId, owner, id]);
        if (result.rowCount) await audit(client, value, owner, actor, 'address_delete', id, {}, 'address');
        return result.rowCount;
      });
    },
  });
}

module.exports = { createSecureShopBoundAccountRepository, MAX_ADDRESSES, saveAddressWithClient, saveProfileWithClient, appendAccountAudit };
