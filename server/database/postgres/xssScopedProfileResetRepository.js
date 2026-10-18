'use strict';

const { canonicalDurableGeneration } = require('../../agent-runtime/durableGeneration');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CHILD_KEYS = Object.freeze(['stored_user', 'stored_llm']);
const MAX_BIGINT = 9223372036854775807n;

function fail(code, message) { return Object.assign(new Error(message), { code }); }
function generation(value, label) {
  try { return canonicalDurableGeneration(value); }
  catch { throw fail('BAD_REQUEST', `${label} must be a nonnegative int64 generation`); }
}
function positiveGeneration(value, label) {
  const result = generation(value, label);
  if (result === '0') throw fail('XSS_PROFILE_RESET_UNAVAILABLE', `${label} must be positive`);
  return result;
}
function ownerId(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 2147483647) {
    throw fail('AUTH_REQUIRED', 'Authenticated XSS owner is required');
  }
  return value;
}
function transition(value, key) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).some(name => !['from', 'to'].includes(name))) {
    throw fail('BAD_REQUEST', `Exact ${key} child transition is required`);
  }
  const from = generation(value.from, `${key} from generation`);
  const to = generation(value.to, `${key} to generation`);
  if (BigInt(from) >= MAX_BIGINT || BigInt(to) !== BigInt(from) + 1n) {
    throw fail('BAD_REQUEST', `${key} child transition must advance exactly once`);
  }
  return Object.freeze({ from, to });
}
function input(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail('BAD_REQUEST', 'Reset input is required');
  const allowed = new Set(['operationId', 'ownerId', 'graphParentGeneration', 'workshopGeneration', 'children']);
  if (Object.keys(value).some(key => !allowed.has(key))) throw fail('BAD_REQUEST', 'Unexpected reset authority field');
  if (typeof value.operationId !== 'string' || !UUID.test(value.operationId)) {
    throw fail('BAD_REQUEST', 'Reset operation ID is invalid');
  }
  if (!value.children || typeof value.children !== 'object' || Array.isArray(value.children)
      || Object.keys(value.children).length !== CHILD_KEYS.length
      || CHILD_KEYS.some(key => !Object.hasOwn(value.children, key))) {
    throw fail('BAD_REQUEST', 'Exact stored profile child scopes are required');
  }
  return Object.freeze({
    operationId:value.operationId.toLowerCase(), ownerId:ownerId(value.ownerId),
    graphParentGeneration:generation(value.graphParentGeneration, 'Graph parent generation'),
    workshopGeneration:generation(value.workshopGeneration, 'Workshop generation'),
    children:Object.freeze({
      stored_user:transition(value.children.stored_user, 'stored_user'),
      stored_llm:transition(value.children.stored_llm, 'stored_llm'),
    }),
  });
}
function parentInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail('BAD_REQUEST', 'Parent reset input is required');
  if (Object.keys(value).some(key => !['operationId', 'ownerId'].includes(key))) {
    throw fail('BAD_REQUEST', 'Unexpected parent reset authority field');
  }
  if (typeof value.operationId !== 'string' || !UUID.test(value.operationId)) {
    throw fail('BAD_REQUEST', 'Parent reset operation ID is invalid');
  }
  return Object.freeze({ operationId:value.operationId.toLowerCase(), ownerId:ownerId(value.ownerId) });
}
function receipt(row) {
  const value = {
    operationId:row.operationId, ownerId:Number(row.ownerId),
    graphParentGeneration:generation(row.graphParentGeneration, 'Receipt graph parent generation'),
    workshopGeneration:generation(row.workshopGeneration, 'Receipt workshop generation'),
    children:Object.freeze({
      stored_user:Object.freeze({
        from:generation(row.storedUserFrom, 'Receipt stored_user from generation'),
        to:generation(row.storedUserTo, 'Receipt stored_user to generation'),
      }),
      stored_llm:Object.freeze({
        from:generation(row.storedLlmFrom, 'Receipt stored_llm from generation'),
        to:generation(row.storedLlmTo, 'Receipt stored_llm to generation'),
      }),
    }),
    profileRevisions:Object.freeze({
      name:generation(row.nameRevision, 'Receipt name revision'),
      bio:generation(row.bioRevision, 'Receipt bio revision'),
      website:generation(row.websiteRevision, 'Receipt website revision'),
    }),
    originsRemoved:Number(row.originsRemoved), appliedAt:row.appliedAt,
    replayed:row.replayed === true,
  };
  if (!Number.isSafeInteger(value.originsRemoved) || value.originsRemoved < 0) {
    throw fail('XSS_PROFILE_RESET_UNAVAILABLE', 'Reset receipt count is invalid');
  }
  return Object.freeze(value);
}
function retirementOutcome(row) {
  const operationId = String(row.operationId).toLowerCase();
  const base = {
    operationId,
    ownerId:Number(row.ownerId),
    graphParentGeneration:generation(row.graphParentGeneration, 'Retirement graph parent generation'),
    workshopGeneration:generation(row.workshopGeneration, 'Retirement workshop generation'),
    children:Object.freeze({
      stored_user:Object.freeze({
        from:generation(row.storedUserFrom, 'Retirement stored_user from generation'),
        to:generation(row.storedUserTo, 'Retirement stored_user to generation'),
      }),
      stored_llm:Object.freeze({
        from:generation(row.storedLlmFrom, 'Retirement stored_llm from generation'),
        to:generation(row.storedLlmTo, 'Retirement stored_llm to generation'),
      }),
    }),
  };
  if (row.retired === true) {
    return Object.freeze({ kind:'retired_no_effect', ...base });
  }
  return Object.freeze({ kind:'committed', receipt:receipt(row) });
}
function parentReceipt(row) {
  const appliedAt = row.appliedAt instanceof Date ? row.appliedAt.toISOString() : row.appliedAt;
  if (typeof appliedAt !== 'string' || !Number.isFinite(Date.parse(appliedAt))) {
    throw fail('XSS_PROFILE_RESET_UNAVAILABLE', 'Parent reset applied time is invalid');
  }
  const value = Object.freeze({
    operationId:String(row.operationId).toLowerCase(), ownerId:ownerId(Number(row.ownerId)),
    profileRevisions:Object.freeze({
      name:positiveGeneration(row.nameRevision, 'Parent reset name revision'),
      bio:positiveGeneration(row.bioRevision, 'Parent reset bio revision'),
      website:positiveGeneration(row.websiteRevision, 'Parent reset website revision'),
    }),
    progressRemoved:Number(row.progressRemoved), originsRemoved:Number(row.originsRemoved),
    appliedAt, replayed:row.replayed === true,
  });
  for (const key of ['progressRemoved','originsRemoved']) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) {
      throw fail('XSS_PROFILE_RESET_UNAVAILABLE', `Parent reset ${key} count is invalid`);
    }
  }
  return value;
}

function createXssScopedProfileResetRepository(pool) {
  if (!pool || typeof pool.query !== 'function') throw new TypeError('PostgreSQL pool required');
  return Object.freeze({
    async assertReady() {
      const row = (await pool.query(`SELECT
        to_regprocedure('xss.clear_parent_profile_reset(uuid,bigint)') IS NOT NULL AS parent_clear,
        to_regprocedure('xss.retire_or_read_scoped_profile_reset(uuid,bigint,bigint,bigint,bigint,bigint,bigint,bigint)') IS NOT NULL AS retirement,
        to_regclass('xss.scoped_profile_reset_owner_deletions') IS NOT NULL AS deletion_fence,
        has_function_privilege(current_user,'xss.clear_parent_profile_reset(uuid,bigint)','EXECUTE') AS can_clear,
        has_function_privilege(current_user,'xss.retire_or_read_scoped_profile_reset(uuid,bigint,bigint,bigint,bigint,bigint,bigint,bigint)','EXECUTE') AS can_retire,
        NOT has_table_privilege(current_user,'xss.parent_profile_reset_receipts','INSERT,UPDATE,DELETE') AS private_receipts,
        (SELECT count(*)=9 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname='xss' AND t.tgname='xss_owner_deletion_write_fence'
            AND NOT t.tgisinternal AND t.tgenabled IN ('O','A')
            AND c.relname IN ('profiles','progress','emails','profile_model_origins','email_profiles',
              'email_templates','template_previews','xss_challenge_progress','xss_email_judge_receipts')) AS write_fences
      `)).rows[0];
      if (!row || Object.values(row).some(value => value !== true)) {
        throw fail('XSS_PROFILE_RESET_STORAGE_NOT_READY', 'XSS reset storage is not ready');
      }
      return true;
    },
    async apply(value) {
      const reset = input(value);
      let result;
      try {
        result = await pool.query(`SELECT
          result_operation_id AS "operationId",result_owner_id AS "ownerId",
          result_graph_parent_generation::text AS "graphParentGeneration",
          result_workshop_generation::text AS "workshopGeneration",
          result_stored_user_from::text AS "storedUserFrom",
          result_stored_user_to::text AS "storedUserTo",
          result_stored_llm_from::text AS "storedLlmFrom",
          result_stored_llm_to::text AS "storedLlmTo",
          result_name_revision::text AS "nameRevision",
          result_bio_revision::text AS "bioRevision",
          result_website_revision::text AS "websiteRevision",
          result_origins_removed AS "originsRemoved",result_applied_at AS "appliedAt",
          result_replayed AS replayed
          FROM xss.apply_scoped_profile_reset($1,$2,$3,$4,$5,$6,$7,$8)`, [
          reset.operationId, reset.ownerId, reset.graphParentGeneration, reset.workshopGeneration,
          reset.children.stored_user.from, reset.children.stored_user.to,
          reset.children.stored_llm.from, reset.children.stored_llm.to,
        ]);
      } catch (error) {
        if (error?.code === '22023') {
          throw fail('XSS_PROFILE_RESET_CONFLICT', 'Reset operation coordinates do not match');
        }
        throw error;
      }
      if (result.rowCount !== 1) throw fail('XSS_PROFILE_RESET_UNAVAILABLE', 'Reset receipt is unavailable');
      return receipt(result.rows[0]);
    },
    async retireOrRead(value) {
      const reset = input(value);
      let result;
      try {
        result = await pool.query(`SELECT
          result_operation_id AS "operationId",result_owner_id AS "ownerId",
          result_graph_parent_generation::text AS "graphParentGeneration",
          result_workshop_generation::text AS "workshopGeneration",
          result_stored_user_from::text AS "storedUserFrom",
          result_stored_user_to::text AS "storedUserTo",
          result_stored_llm_from::text AS "storedLlmFrom",
          result_stored_llm_to::text AS "storedLlmTo",
          result_name_revision::text AS "nameRevision",
          result_bio_revision::text AS "bioRevision",
          result_website_revision::text AS "websiteRevision",
          result_origins_removed AS "originsRemoved",result_applied_at AS "appliedAt",
          result_replayed AS replayed,result_retired AS retired,
          result_retired_at AS "retiredAt"
          FROM xss.retire_or_read_scoped_profile_reset($1,$2,$3,$4,$5,$6,$7,$8)`, [
          reset.operationId, reset.ownerId, reset.graphParentGeneration, reset.workshopGeneration,
          reset.children.stored_user.from, reset.children.stored_user.to,
          reset.children.stored_llm.from, reset.children.stored_llm.to,
        ]);
      } catch (error) {
        if (error?.code === '22023') {
          throw fail('XSS_PROFILE_RESET_CONFLICT', 'Reset operation coordinates do not match');
        }
        throw error;
      }
      if (result.rowCount !== 1) throw fail('XSS_PROFILE_RESET_UNAVAILABLE', 'Reset retirement is unavailable');
      return retirementOutcome(result.rows[0]);
    },
    async clearParent(value) {
      const reset = parentInput(value);
      let result;
      try {
        result = await pool.query(`SELECT
          result_operation_id AS "operationId",result_owner_id AS "ownerId",
          result_name_revision::text AS "nameRevision",
          result_bio_revision::text AS "bioRevision",
          result_website_revision::text AS "websiteRevision",
          result_progress_removed AS "progressRemoved",
          result_origins_removed AS "originsRemoved",
          result_applied_at AS "appliedAt",result_replayed AS replayed
          FROM xss.clear_parent_profile_reset($1,$2)`, [reset.operationId, reset.ownerId]);
      } catch (error) {
        if (error?.code === '22023') {
          throw fail('XSS_PROFILE_RESET_CONFLICT', 'Parent reset operation coordinates do not match');
        }
        throw error;
      }
      if (result.rowCount !== 1) throw fail('XSS_PROFILE_RESET_UNAVAILABLE', 'Parent reset receipt is unavailable');
      return parentReceipt(result.rows[0]);
    },
  });
}

module.exports = { CHILD_KEYS, createXssScopedProfileResetRepository };
