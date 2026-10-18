'use strict';

const { randomUUID } = require('node:crypto');
const { canonicalDurableGeneration } = require('../../agent-runtime/durableGeneration');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const TOP = new Set(['operationId', 'ownerId', 'graphParentGeneration', 'workshopGeneration']);
const RECEIPT_TOP = new Set(['operationId', 'ownerId', 'graphParentGeneration', 'workshopGeneration',
  'children', 'profileRevisions', 'originsRemoved', 'appliedAt', 'replayed']);
const RECONCILE_TOP = new Set(['operationId','ownerId','observedGraphParentGeneration',
  'observedWorkshopGeneration','outcome']);

function failure(code, message) { return Object.assign(new Error(message), { code }); }
function exactObject(value, allowed, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(key => !allowed.has(key))) throw new TypeError(message);
  return value;
}
function uuid(value, label) {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError(`${label} is invalid`);
  return value.toLowerCase();
}
function owner(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw new TypeError('Authenticated XSS owner is required');
  }
  return value;
}
function generation(value, label) {
  try { return canonicalDurableGeneration(value); }
  catch { throw new TypeError(`${label} must be a nonnegative int64 generation`); }
}
function positiveGeneration(value, label) {
  const result = generation(value, label);
  if (result === '0') throw new TypeError(`${label} must be positive`);
  return result;
}
function beginInput(value) {
  exactObject(value, TOP, 'Exact XSS profile reset coordinates are required');
  return Object.freeze({
    operationId:uuid(value.operationId, 'Reset operation ID'), ownerId:owner(value.ownerId),
    graphParentGeneration:generation(value.graphParentGeneration, 'Graph parent generation'),
    workshopGeneration:generation(value.workshopGeneration, 'Workshop generation'),
  });
}
function transition(value, label) {
  exactObject(value, new Set(['from', 'to']), `Exact ${label} transition is required`);
  const from = generation(value.from, `${label} from generation`);
  const to = generation(value.to, `${label} to generation`);
  if (BigInt(to) !== BigInt(from) + 1n) throw new TypeError(`${label} must advance exactly once`);
  return Object.freeze({ from, to });
}
function operation(row) {
  if (!row) return null;
  const value = {
    operationId:row.operationId, ownerId:owner(Number(row.ownerId)), ownerKey:row.ownerKey,
    graphParentGeneration:generation(row.graphParentGeneration, 'Stored graph parent generation'),
    workshopGeneration:generation(row.workshopGeneration, 'Stored workshop generation'),
    children:Object.freeze({
      stored_user:transition({ from:row.storedUserFrom, to:row.storedUserTo }, 'stored_user'),
      stored_llm:transition({ from:row.storedLlmFrom, to:row.storedLlmTo }, 'stored_llm'),
    }),
    status:row.status, leaseToken:row.leaseToken || null, leaseExpiresAt:row.leaseExpiresAt || null,
    failureCode:row.failureCode || null, createdAt:row.createdAt,
    updatedAt:row.updatedAt, completedAt:row.completedAt || null,
  };
  if (row.status === 'superseded') value.reconciliation = Object.freeze({
    kind:row.reconciliationKind,
    outcomeDigest:row.reconciliationSha256,
    observedGraphParentGeneration:generation(row.reconciledGraphParentGeneration,
      'Reconciled graph parent generation'),
    observedWorkshopGeneration:generation(row.reconciledWorkshopGeneration,
      'Reconciled workshop generation'),
  });
  return Object.freeze(value);
}
const PROJECTION = `operation_id AS "operationId",owner_id AS "ownerId",owner_key AS "ownerKey",
  graph_parent_generation::text AS "graphParentGeneration",
  workshop_generation::text AS "workshopGeneration",
  stored_user_from::text AS "storedUserFrom",stored_user_to::text AS "storedUserTo",
  stored_llm_from::text AS "storedLlmFrom",stored_llm_to::text AS "storedLlmTo",
  status,lease_token AS "leaseToken",lease_expires_at AS "leaseExpiresAt",
  failure_code AS "failureCode",created_at AS "createdAt",updated_at AS "updatedAt",
  completed_at AS "completedAt",reconciliation_kind AS "reconciliationKind",
  reconciliation_sha256 AS "reconciliationSha256",
  reconciled_graph_parent_generation::text AS "reconciledGraphParentGeneration",
  reconciled_workshop_generation::text AS "reconciledWorkshopGeneration"`;

function normalizeReceipt(value) {
  exactObject(value, RECEIPT_TOP, 'Exact XSS profile reset receipt is required');
  exactObject(value.children, new Set(['stored_user', 'stored_llm']), 'Exact receipt child scopes are required');
  exactObject(value.profileRevisions, new Set(['name', 'bio', 'website']), 'Exact profile revisions are required');
  const appliedAt = value.appliedAt instanceof Date ? value.appliedAt.toISOString() : value.appliedAt;
  if (typeof appliedAt !== 'string' || Buffer.byteLength(appliedAt) < 10 || Buffer.byteLength(appliedAt) > 64
      || !Number.isFinite(Date.parse(appliedAt))) throw new TypeError('Receipt applied time is invalid');
  if (!Number.isSafeInteger(value.originsRemoved) || value.originsRemoved < 0 || value.originsRemoved > 2147483647) {
    throw new TypeError('Receipt origin count is invalid');
  }
  if (typeof value.replayed !== 'boolean') throw new TypeError('Receipt replay flag is invalid');
  return Object.freeze({
    operationId:uuid(value.operationId, 'Receipt operation ID'), ownerId:owner(value.ownerId),
    graphParentGeneration:generation(value.graphParentGeneration, 'Receipt graph parent generation'),
    workshopGeneration:generation(value.workshopGeneration, 'Receipt workshop generation'),
    children:Object.freeze({
      stored_user:transition(value.children.stored_user, 'receipt stored_user'),
      stored_llm:transition(value.children.stored_llm, 'receipt stored_llm'),
    }),
    profileRevisions:Object.freeze({
      name:positiveGeneration(value.profileRevisions.name, 'Receipt name revision'),
      bio:positiveGeneration(value.profileRevisions.bio, 'Receipt bio revision'),
      website:positiveGeneration(value.profileRevisions.website, 'Receipt website revision'),
    }),
    originsRemoved:value.originsRemoved, appliedAt, replayed:value.replayed,
  });
}
function normalizeRetiredOutcome(value) {
  exactObject(value, new Set(['kind','operationId','ownerId','graphParentGeneration',
    'workshopGeneration','children']), 'Exact retired XSS outcome is required');
  if (value.kind !== 'retired_no_effect') throw new TypeError('Invalid XSS retirement outcome kind');
  exactObject(value.children, new Set(['stored_user','stored_llm']), 'Exact retired child scopes are required');
  return Object.freeze({
    kind:'retired_no_effect', operationId:uuid(value.operationId,'Retired operation ID'),
    ownerId:owner(value.ownerId),
    graphParentGeneration:generation(value.graphParentGeneration,'Retired graph parent generation'),
    workshopGeneration:generation(value.workshopGeneration,'Retired workshop generation'),
    children:Object.freeze({
      stored_user:transition(value.children.stored_user,'retired stored_user'),
      stored_llm:transition(value.children.stored_llm,'retired stored_llm'),
    }),
  });
}
function normalizeOutcome(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('Durable XSS store retirement outcome required');
  }
  if (value.kind === 'retired_no_effect') return normalizeRetiredOutcome(value);
  exactObject(value, new Set(['kind','receipt']), 'Exact committed XSS outcome is required');
  if (value.kind !== 'committed') throw new TypeError('Invalid XSS retirement outcome kind');
  return Object.freeze({kind:'committed',receipt:normalizeReceipt(value.receipt)});
}
function reconciliationInput(value) {
  exactObject(value, RECONCILE_TOP, 'Exact XSS parent reconciliation input required');
  return Object.freeze({
    operationId:uuid(value.operationId,'Reset operation ID'), ownerId:owner(value.ownerId),
    observedGraphParentGeneration:generation(value.observedGraphParentGeneration,
      'Observed graph parent generation'),
    observedWorkshopGeneration:generation(value.observedWorkshopGeneration,
      'Observed workshop generation'),
    outcome:normalizeOutcome(value.outcome),
  });
}
function storeError(error, stale = false) {
  if (error?.code === '22023') throw failure('XSS_PROFILE_RESET_CONFLICT', 'XSS profile reset coordinates do not match');
  if (error?.code === '55000' || error?.code === '23505') {
    throw failure(stale ? 'XSS_PROFILE_RESET_STALE' : 'XSS_PROFILE_RESET_UNAVAILABLE',
      stale ? 'XSS profile reset lease is no longer current' : 'XSS profile reset is unavailable');
  }
  throw error;
}

function createXssProfileResetJournalRepository(pool) {
  if (!pool || typeof pool.query !== 'function') throw new TypeError('PostgreSQL pool required');
  async function one(sql, values, { stale = false, nullable = false } = {}) {
    try {
      const result = await pool.query(sql, values);
      if (result.rowCount !== 1) {
        if (nullable) return null;
        throw failure(stale ? 'XSS_PROFILE_RESET_STALE' : 'XSS_PROFILE_RESET_UNAVAILABLE',
          stale ? 'XSS profile reset lease is no longer current' : 'XSS profile reset is unavailable');
      }
      return operation(result.rows[0]);
    } catch (error) { storeError(error, stale); }
  }
  return Object.freeze({
    async assertReady() {
      const row = (await pool.query(`SELECT
        to_regclass('identity.xss_profile_reset_operations') IS NOT NULL AS operations,
        to_regclass('identity.xss_profile_reset_steps') IS NOT NULL AS steps,
        to_regprocedure('identity.begin_xss_profile_reset(uuid,integer,bigint,bigint)') IS NOT NULL AS begin,
        to_regprocedure('identity.assert_xss_profile_reset_current(uuid,uuid)') IS NOT NULL AS current,
        to_regprocedure('identity.reconcile_xss_profile_reset_after_parent(uuid,integer,bigint,bigint,jsonb)') IS NOT NULL AS reconcile,
        to_regprocedure('identity.read_nonterminal_xss_profile_reset_for_owner(integer)') IS NOT NULL AS owner_lookup,
        to_regprocedure('identity.list_recoverable_xss_profile_resets(integer)') IS NOT NULL AS recovery_list,
        to_regclass('identity.xss_deletion_redaction_authority') IS NOT NULL AS deletion_redaction_authority,
        has_function_privilege(current_user,'identity.begin_xss_profile_reset(uuid,integer,bigint,bigint)','EXECUTE') AS runtime_begin,
        has_function_privilege(current_user,'identity.read_nonterminal_xss_profile_reset_for_owner(integer)','EXECUTE') AS runtime_owner_lookup,
        NOT has_table_privilege(current_user,'identity.xss_profile_reset_operations','SELECT') AS no_operation_read,
        NOT has_table_privilege(current_user,'identity.xss_profile_reset_steps','SELECT') AS no_step_read,
        NOT has_table_privilege(current_user,'identity.xss_deletion_redaction_authority','SELECT') AS no_redaction_authority_read,
        NOT has_table_privilege(current_user,'identity.xss_deletion_redaction_authority','INSERT') AS no_redaction_authority_write`)).rows[0];
      if (!row || Object.values(row).some(value => value !== true)) {
        throw failure('XSS_PROFILE_RESET_STORAGE_NOT_READY', 'XSS profile reset storage is not ready');
      }
      return true;
    },
    begin(value) {
      const reset = beginInput(value);
      return one(`SELECT ${PROJECTION} FROM identity.begin_xss_profile_reset($1,$2,$3,$4)`,
        [reset.operationId, reset.ownerId, reset.graphParentGeneration, reset.workshopGeneration]);
    },
    read(operationId) {
      return one(`SELECT ${PROJECTION} FROM identity.read_xss_profile_reset($1)`,
        [uuid(operationId, 'Reset operation ID')], { nullable:true });
    },
    readNonterminalForOwner(ownerId) {
      return one(`SELECT ${PROJECTION}
        FROM identity.read_nonterminal_xss_profile_reset_for_owner($1)`,
      [owner(ownerId)], { nullable:true });
    },
    async listRecoverable({ limit = 20 } = {}) {
      if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new TypeError('Invalid recovery limit');
      return (await pool.query('SELECT operation_id AS "operationId" FROM identity.list_recoverable_xss_profile_resets($1)',
        [limit])).rows.map(row => uuid(row.operationId, 'Stored reset operation ID'));
    },
    claim(operationId, { leaseMs = 30000 } = {}) {
      if (!Number.isInteger(leaseMs) || leaseMs < 1000 || leaseMs > 300000) throw new TypeError('Invalid lease duration');
      const leaseToken = randomUUID();
      return one(`SELECT ${PROJECTION} FROM identity.claim_xss_profile_reset($1,$2,$3)`,
        [uuid(operationId, 'Reset operation ID'), leaseToken, leaseMs], { nullable:true });
    },
    assertCurrent({ operationId, leaseToken } = {}) {
      return one(`SELECT ${PROJECTION} FROM identity.assert_xss_profile_reset_current($1,$2)`,
        [uuid(operationId, 'Reset operation ID'), uuid(leaseToken, 'Reset lease token')], { stale:true });
    },
    async acknowledgeStore({ operationId, leaseToken, receipt } = {}) {
      const result = await pool.query(`SELECT receipt_sha256 AS "receiptSha256",replayed
        FROM identity.acknowledge_xss_profile_reset_store($1,$2,$3::jsonb)`,
      [uuid(operationId, 'Reset operation ID'), uuid(leaseToken, 'Reset lease token'),
        JSON.stringify(normalizeReceipt(receipt))]).catch(error => storeError(error, true));
      if (result.rowCount !== 1 || !/^[0-9a-f]{64}$/.test(result.rows[0].receiptSha256)) {
        throw failure('XSS_PROFILE_RESET_STALE', 'XSS profile reset receipt was not acknowledged');
      }
      return Object.freeze({ receiptSha256:result.rows[0].receiptSha256, replayed:result.rows[0].replayed === true });
    },
    async fail({ operationId, leaseToken, code = 'XSS_STORE_FAILED' } = {}) {
      if (typeof code !== 'string' || !CODE.test(code)) code = 'XSS_STORE_FAILED';
      const result = await pool.query('SELECT identity.fail_xss_profile_reset($1,$2,$3) AS failed',
        [uuid(operationId, 'Reset operation ID'), uuid(leaseToken, 'Reset lease token'), code]);
      if (result.rows[0]?.failed !== true) throw failure('XSS_PROFILE_RESET_STALE', 'XSS profile reset lease is no longer current');
      return Object.freeze({ status:'failed' });
    },
    complete({ operationId, leaseToken } = {}) {
      return one(`SELECT ${PROJECTION} FROM identity.complete_xss_profile_reset($1,$2)`,
        [uuid(operationId, 'Reset operation ID'), uuid(leaseToken, 'Reset lease token')], { stale:true });
    },
    reconcileAfterParentReset(value) {
      const reconciliation = reconciliationInput(value);
      return one(`SELECT ${PROJECTION}
        FROM identity.reconcile_xss_profile_reset_after_parent($1,$2,$3,$4,$5::jsonb)`,
      [reconciliation.operationId,reconciliation.ownerId,
        reconciliation.observedGraphParentGeneration,reconciliation.observedWorkshopGeneration,
        JSON.stringify(reconciliation.outcome)]);
    },
  });
}

module.exports = { createXssProfileResetJournalRepository, normalizeXssProfileRetirementOutcome:normalizeOutcome };
