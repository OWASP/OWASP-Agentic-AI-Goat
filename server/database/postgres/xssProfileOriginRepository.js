'use strict';

const { createHash } = require('node:crypto');
const { withTransaction } = require('./index');
const { profileField } = require('../xssWorkshopStore');
const { canonicalDurableGeneration } = require('../../agent-runtime/durableGeneration');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION = 'xss-profile-origin-v1';
const SCOPED_VERSION = 'xss-profile-origin-v2';
const SCOPE_BINDING_KEYS = Object.freeze([
  'runId', 'ownerId', 'ownerKey', 'scopeKey', 'parentGeneration', 'childGeneration',
]);
const DEFAULT_PROFILE = Object.freeze({
  name: 'Security Student',
  bio: 'Learning about web security.',
  website: 'https://example.com',
});

function fail(code, message) {
  return Object.assign(new Error(message), { code });
}
function text(value, label, maxBytes = 262144) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maxBytes) {
    throw fail('BAD_REQUEST', `${label} must be nonempty bounded text`);
  }
  return value;
}
function profileValue(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > 262144) {
    throw fail('BAD_REQUEST', 'Profile value must be bounded text');
  }
  return value;
}
function integer(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw fail('BAD_REQUEST', `${label} must be a nonnegative integer`);
  return number;
}
function generation(value, label) {
  try { return canonicalDurableGeneration(value); }
  catch { throw fail('BAD_REQUEST', `${label} must be a nonnegative int64 generation`); }
}
function platformId(value) {
  const id = Number(value);
  if (!Number.isInteger(id) || id <= 0 || id > 2147483647) throw fail('AUTH_REQUIRED', 'Authenticated platform user required');
  return id;
}
// express-session's uid-safe identifiers are opaque, nonempty and normally
// at least 16 URL-safe characters.  Requiring that lower bound prevents a
// caller from inventing a short alias while preserving deployed/custom IDs.
const ANONYMOUS_OWNER = /^anon_[A-Za-z0-9_-]{16,128}$/;
function isAnonymousOwner(value) {
  return typeof value === 'string' && ANONYMOUS_OWNER.test(value)
    && !/^(?:anon_undefined|anon_null)$/i.test(value);
}
function anonymousOwner(value) {
  const owner = text(value, 'Anonymous profile owner', 140);
  if (!isAnonymousOwner(owner)) {
    throw fail('OWNER_MISMATCH', 'Server-derived anonymous profile owner required');
  }
  return owner;
}
function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
function revisionColumn(field) {
  return `${profileField(field)}_revision`;
}
function scopedBinding(execution, expected, scopeKey = 'stored_llm') {
  if (execution.scopeBinding === undefined) return null;
  const value = execution.scopeBinding;
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== SCOPE_BINDING_KEYS.length
      || SCOPE_BINDING_KEYS.some(key => !Object.hasOwn(value, key))) {
    throw fail('OWNER_MISMATCH', 'Exact stored-LLM scope binding required');
  }
  let parentGeneration;
  let childGeneration;
  try {
    parentGeneration = canonicalDurableGeneration(value.parentGeneration);
    childGeneration = canonicalDurableGeneration(value.childGeneration);
  } catch {
    throw fail('OWNER_MISMATCH', 'Canonical stored-LLM scope generations required');
  }
  if (typeof value.runId !== 'string' || value.runId.toLowerCase() !== expected.runId
      || value.ownerId !== expected.platformUserId || value.ownerKey !== expected.ownerKey
      || value.scopeKey !== scopeKey || parentGeneration !== expected.durableGeneration) {
    throw fail('OWNER_MISMATCH', 'Stored-LLM scope binding does not match execution');
  }
  return Object.freeze({ scopeKey, childGeneration });
}
function decisionContext(input) {
  const id = platformId(input.platformUserId);
  const userKey = text(input.userKey, 'Profile owner', 64);
  if (userKey !== String(id)) throw fail('OWNER_MISMATCH', 'Profile owner does not match authenticated platform user');
  const execution = input.execution;
  if (!execution || !UUID.test(execution.runId || '') || typeof execution.ownerKey !== 'string'
    || execution.ownerKey !== JSON.stringify(['XSS', String(id)]) || typeof execution.check !== 'function') {
    throw fail('OWNER_MISMATCH', 'Current XSS execution scope required');
  }
  const durableGeneration = generation(execution.durableGeneration, 'Durable generation');
  const binding = scopedBinding(execution, {
    runId:execution.runId.toLowerCase(), platformUserId:id,
    ownerKey:execution.ownerKey, durableGeneration,
  });
  const decision = input.decision;
  const learnerMessage = text(input.learnerMessage, 'Original learner message');
  const provider = text(decision?.provider, 'Model provider', 100);
  const model = text(decision?.model, 'Model name', 200);
  if (!provider.trim() || !model.trim() || decision?.modelSucceeded !== true
    || decision?.decisionSource !== 'model' || /mock|fixture|fallback|unavailable/i.test(provider)
    || /mock|fixture|fallback|unavailable/i.test(model)) {
    throw fail('MODEL_PROVENANCE_REQUIRED', 'A successful non-mock model decision is required');
  }
  return {
    version:binding ? SCOPED_VERSION : VERSION,
    userKey,
    platformUserId: id,
    workshopGeneration: generation(input.workshopGeneration, 'Workshop generation'),
    runId: execution.runId.toLowerCase(),
    ownerKey: execution.ownerKey,
    durableGeneration,
    decisionSource: 'model',
    provider,
    model,
    rawDecisionSha256: sha256((() => {
      const raw = text(decision.rawDecisionResponse, 'Raw model decision');
      if (!raw.trim()) throw fail('MODEL_PROVENANCE_REQUIRED', 'A nonempty raw model decision is required');
      return raw;
    })()),
    observationIndex: integer(input.observationIndex, 'Observation index'),
    ...(binding || {}),
    learnerMessage,
    check: execution.check,
  };
}
function originDto(row) {
  if (!row?.origin_revision) return null;
  const hasScope = row.scope_key != null;
  const hasChild = row.child_generation != null;
  if (hasScope !== hasChild || (hasScope && row.scope_key !== 'stored_llm')) return null;
  return {
    version:hasScope ? SCOPED_VERSION : VERSION,
    userKey: row.user_key,
    platformUserId: row.platform_user_id,
    field: row.origin_field,
    revision: String(row.origin_revision),
    valueSha256: row.origin_value_sha256,
    workshopGeneration: generation(row.workshop_generation, 'Workshop generation'),
    runId: row.run_id,
    ownerKey: row.owner_key,
    durableGeneration: generation(row.durable_generation, 'Durable generation'),
    decisionSource: row.decision_source,
    provider: row.provider,
    model: row.model,
    rawDecisionSha256: row.raw_decision_sha256,
    observationIndex: row.observation_index,
    ...(hasScope ? {
      scopeKey:row.scope_key,
      childGeneration:generation(row.child_generation, 'Child generation'),
    } : {}),
    writtenAt: row.written_at,
  };
}

function createXssProfileOriginRepository(pool) {
  if (!pool || typeof pool.query !== 'function') throw new TypeError('PostgreSQL pool required');
  async function readCurrent({ userKey, field, platformUserId: expectedOwner }) {
    field = profileField(field);
    const revision = revisionColumn(field);
    const owner = text(userKey, 'Profile owner', 64);
    if (owner !== String(platformId(expectedOwner))) throw fail('OWNER_MISMATCH', 'Profile owner mismatch');
    const row = (await pool.query(`SELECT p.user_key,p.${field} AS value,p.${revision} AS revision,
      o.field AS origin_field,o.platform_user_id,o.revision AS origin_revision,o.value_sha256 AS origin_value_sha256,
      o.workshop_generation,o.run_id,o.owner_key,o.durable_generation,o.decision_source,o.provider,o.model,
      o.raw_decision_sha256,o.observation_index,o.scope_key,o.child_generation,o.written_at
      FROM xss.profiles p LEFT JOIN xss.profile_model_origins o ON o.user_key=p.user_key AND o.field=$2
      WHERE p.user_key=$1`, [owner, field])).rows[0];
    if (!row) return null;
    const valueSha256 = sha256(row.value == null ? '' : String(row.value));
    const origin = String(row.origin_revision) === String(row.revision) && row.origin_value_sha256 === valueSha256
      ? originDto(row) : null;
    return { value: row.value, revision: String(row.revision), valueSha256, origin };
  }

  async function writeManualField({ userKey, platformUserId: expectedOwner, field, value }, check) {
    field = profileField(field);
    const revision = revisionColumn(field);
    const owner = text(userKey, 'Profile owner', 64);
    if (owner !== String(platformId(expectedOwner))) throw fail('OWNER_MISMATCH', 'Profile owner mismatch');
    value = profileValue(value);
    await check?.();
    return withTransaction(pool, async client => {
      const row = (await client.query(`INSERT INTO xss.profiles(user_key,${field},${revision}) VALUES($1,$2,1)
        ON CONFLICT(user_key) DO UPDATE SET ${field}=excluded.${field},${revision}=xss.profiles.${revision}+1,
          updated_at=clock_timestamp() RETURNING ${revision} AS revision`, [owner, value])).rows[0];
      await client.query('DELETE FROM xss.profile_model_origins WHERE user_key=$1 AND field=$2', [owner, field]);
      await check?.();
      return { userKey: owner, field, revision: String(row.revision), valueSha256: sha256(value), origin: null };
    });
  }

  function writeScopedManualField(input) {
    const id = platformId(input.platformUserId);
    const execution = input.execution;
    if (input.userKey !== String(id) || !execution || !UUID.test(execution.runId || '')
        || execution.ownerKey !== JSON.stringify(['XSS', String(id)])
        || typeof execution.check !== 'function' || !Object.isFrozen(execution.scopeBinding)) {
      throw fail('OWNER_MISMATCH', 'Protected stored-user execution required');
    }
    const binding = scopedBinding(execution, { runId:execution.runId.toLowerCase(), platformUserId:id,
      ownerKey:execution.ownerKey, durableGeneration:generation(execution.durableGeneration, 'Durable generation') }, 'stored_user');
    if (!binding) throw fail('OWNER_MISMATCH', 'Stored-user scope binding required');
    const check = execution.check;
    // Retain the profile row lock through the final authority check. A stale
    // delayed writer rolls back; a reset following a committed writer clears it.
    return writeManualField(input, check);
  }

  // Anonymous XSS practice is deliberately noncanonical: it may preserve the
  // vulnerable profile sink, but it can never carry a platform/model origin.
  async function writeAnonymousField({ userKey, field, value }) {
    const owner = anonymousOwner(userKey);
    field = profileField(field);
    const revision = revisionColumn(field);
    value = profileValue(value);
    return withTransaction(pool, async client => {
      const row = (await client.query(`INSERT INTO xss.profiles(user_key,${field},${revision}) VALUES($1,$2,1)
        ON CONFLICT(user_key) DO UPDATE SET ${field}=excluded.${field},${revision}=xss.profiles.${revision}+1,
          updated_at=clock_timestamp() RETURNING ${revision} AS revision`, [owner, value])).rows[0];
      await client.query('DELETE FROM xss.profile_model_origins WHERE user_key=$1', [owner]);
      return { userKey: owner, field, revision: String(row.revision), valueSha256: sha256(value), origin: null,
        canonical: false };
    });
  }

  async function writeModelField(input) {
    const context = decisionContext(input);
    const field = profileField(input.field);
    const revision = revisionColumn(field);
    const value = profileValue(input.value);
    const valueSha256 = sha256(value);
    const copiedFromLearner = context.learnerMessage.includes(value);
    await context.check();
    return withTransaction(pool, async client => {
      const row = (await client.query(`INSERT INTO xss.profiles(user_key,${field},${revision}) VALUES($1,$2,1)
        ON CONFLICT(user_key) DO UPDATE SET ${field}=excluded.${field},${revision}=xss.profiles.${revision}+1,
          updated_at=clock_timestamp() RETURNING ${revision} AS revision`, [context.userKey, value])).rows[0];
      if (copiedFromLearner) {
        await client.query('DELETE FROM xss.profile_model_origins WHERE user_key=$1 AND field=$2', [context.userKey, field]);
        await context.check();
        return { written: true, qualifyingOrigin: false, copiedFromLearner: true,
          userKey: context.userKey, platformUserId: context.platformUserId, field,
          revision: String(row.revision), valueSha256 };
      }
      const origin = (await client.query(`INSERT INTO xss.profile_model_origins
        (user_key,field,platform_user_id,revision,value_sha256,workshop_generation,run_id,owner_key,
         durable_generation,decision_source,provider,model,raw_decision_sha256,observation_index,
         scope_key,child_generation)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'model',$10,$11,$12,$13,$14,$15)
        ON CONFLICT(user_key,field) DO UPDATE SET platform_user_id=excluded.platform_user_id,
          revision=excluded.revision,value_sha256=excluded.value_sha256,workshop_generation=excluded.workshop_generation,
          run_id=excluded.run_id,owner_key=excluded.owner_key,durable_generation=excluded.durable_generation,
          decision_source=excluded.decision_source,provider=excluded.provider,model=excluded.model,
          raw_decision_sha256=excluded.raw_decision_sha256,observation_index=excluded.observation_index,
          scope_key=excluded.scope_key,child_generation=excluded.child_generation,
          written_at=clock_timestamp() RETURNING written_at`, [context.userKey, field, context.platformUserId,
        row.revision, valueSha256, context.workshopGeneration, context.runId, context.ownerKey,
        context.durableGeneration, context.provider, context.model, context.rawDecisionSha256,
        context.observationIndex, context.scopeKey || null, context.childGeneration || null])).rows[0];
      await context.check();
      const { check: _check, learnerMessage: _learnerMessage, ...receiptContext } = context;
      return { ...receiptContext, field, revision: String(row.revision), valueSha256,
        writtenAt: origin.written_at };
    });
  }

  async function resetProfile({ userKey, platformUserId: expectedOwner }) {
    const owner = text(userKey, 'Profile owner', 64);
    if (owner !== String(platformId(expectedOwner))) throw fail('OWNER_MISMATCH', 'Profile owner mismatch');
    return withTransaction(pool, async client => {
      const row = (await client.query(`INSERT INTO xss.profiles
        (user_key,name,bio,website,name_revision,bio_revision,website_revision)
        VALUES($1,$2,$3,$4,1,1,1) ON CONFLICT(user_key) DO UPDATE SET
          name=excluded.name,bio=excluded.bio,website=excluded.website,
          name_revision=xss.profiles.name_revision+1,bio_revision=xss.profiles.bio_revision+1,
          website_revision=xss.profiles.website_revision+1,updated_at=clock_timestamp()
        RETURNING name_revision,bio_revision,website_revision`, [owner, DEFAULT_PROFILE.name,
        DEFAULT_PROFILE.bio, DEFAULT_PROFILE.website])).rows[0];
      await client.query('DELETE FROM xss.profile_model_origins WHERE user_key=$1', [owner]);
      return { userKey: owner, revisions: { name: String(row.name_revision), bio: String(row.bio_revision),
        website: String(row.website_revision) } };
    });
  }

  async function resetAnonymousProfile({ userKey }) {
    const owner = anonymousOwner(userKey);
    return withTransaction(pool, async client => {
      const row = (await client.query(`INSERT INTO xss.profiles
        (user_key,name,bio,website,name_revision,bio_revision,website_revision)
        VALUES($1,$2,$3,$4,1,1,1) ON CONFLICT(user_key) DO UPDATE SET
          name=excluded.name,bio=excluded.bio,website=excluded.website,
          name_revision=xss.profiles.name_revision+1,bio_revision=xss.profiles.bio_revision+1,
          website_revision=xss.profiles.website_revision+1,updated_at=clock_timestamp()
        RETURNING name_revision,bio_revision,website_revision`, [owner, DEFAULT_PROFILE.name,
        DEFAULT_PROFILE.bio, DEFAULT_PROFILE.website])).rows[0];
      await client.query('DELETE FROM xss.profile_model_origins WHERE user_key=$1', [owner]);
      return { userKey: owner, canonical: false, revisions: { name: String(row.name_revision), bio: String(row.bio_revision),
        website: String(row.website_revision) } };
    });
  }

  return { writeModelField, writeManualField, writeScopedManualField, resetProfile, readCurrent,
    writeAnonymousField, resetAnonymousProfile };
}

module.exports = { VERSION, SCOPED_VERSION, createXssProfileOriginRepository, anonymousOwner, isAnonymousOwner };
