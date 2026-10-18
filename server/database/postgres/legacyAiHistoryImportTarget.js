'use strict';

// Migration/operator-only target transport. There is intentionally no
// environment singleton and no arbitrary query or source-removal capability.
const MIGRATION_ROLE = 'dvaia_identity_migration';
const RUNTIME_ROLE = 'dvaia_identity_runtime';
const DIGEST = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CREATED_AT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$/;
const ROUTES = new Set(['prompt_injection', 'chain_of_thought', 'context_stuffing', 'multi_turn_jailbreak']);
const STATES = new Set(['copying', 'verified', 'source_removed', 'blocked']);
const CLASSIFICATIONS = new Set(['owned', 'unknown']);
const SOURCE_RECORD_KEYS = Object.freeze([
  'createdAt', 'id', 'modelUsed', 'platformOwnerId', 'prompt', 'response', 'userId',
]);
const FUNCTIONS = Object.freeze([
  Object.freeze({ signature: 'legacy_ai_private.begin_history_import(uuid,text,integer,text)',
    name: 'begin_history_import', arguments: 'uuid, text, integer, text' }),
  Object.freeze({ signature: 'legacy_ai_private.archive_history_import_row(uuid,bigint,jsonb,text,text,integer)',
    name: 'archive_history_import_row', arguments: 'uuid, bigint, jsonb, text, text, integer' }),
  Object.freeze({ signature: 'legacy_ai_private.promote_owned_history_import_row(uuid,bigint,integer,uuid,text,text,text,text,timestamp with time zone,text)',
    name: 'promote_owned_history_import_row',
    arguments: 'uuid, bigint, integer, uuid, text, text, text, text, timestamp with time zone, text' }),
  Object.freeze({ signature: 'legacy_ai_private.verify_history_import_quarantine(uuid,integer,text)',
    name: 'verify_history_import_quarantine', arguments: 'uuid, integer, text' }),
]);
const FUNCTION_BY_SIGNATURE = new Map(FUNCTIONS.map(item => [item.signature, item]));

function fail(message) { throw new TypeError(message); }
function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`Valid ${label} required`);
  return value;
}
function exactKeys(value, keys, label) {
  const actual = Object.keys(value).sort(), expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`Exact ${label} fields required`);
  }
}
function uuid(value, label, pattern = UUID) {
  if (typeof value !== 'string' || !pattern.test(value)) fail(`Valid ${label} required`);
  return value.toLowerCase();
}
function digest(value, label) {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail(`Valid ${label} required`);
  return value;
}
function integer(value, label, { minimum = 0, maximum = 2147483647 } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(`Valid ${label} required`);
  return value;
}
function text(value, label, { minimum = 0, maximum } = {}) {
  if (typeof value !== 'string' || Buffer.byteLength(value) < minimum
      || (maximum !== undefined && Buffer.byteLength(value) > maximum)) fail(`Valid ${label} required`);
  return value;
}
function boolean(value, label) {
  if (value !== true && value !== false) fail(`Valid ${label} required`);
  return value;
}
function nullableOwner(value, label) {
  return value === null ? null : integer(value, label, { minimum: 1 });
}
function signedInt4(value, label) {
  return integer(value, label, { minimum: -2147483648 });
}
function sourceRowId(value, label = 'source row ID') {
  const normalized = typeof value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value)
    ? Number(value) : value;
  return signedInt4(normalized, label);
}
function rawInt4(value, label) {
  if (value === null) return null;
  return signedInt4(value, label);
}
function nullableText(value, label) {
  return value === null ? null : text(value, label);
}
function sourceRecord(value) {
  object(value, 'archived source record');
  exactKeys(value, SOURCE_RECORD_KEYS, 'archived source record');
  const record = {
    id: signedInt4(value.id, 'raw source record ID'),
    userId: rawInt4(value.userId, 'raw legacy user ID'),
    prompt: text(value.prompt, 'source prompt'),
    response: nullableText(value.response, 'source response'),
    modelUsed: nullableText(value.modelUsed, 'source model'),
    createdAt: nullableText(value.createdAt, 'source timestamp'),
    platformOwnerId: rawInt4(value.platformOwnerId, 'raw source platform owner'),
  };
  return Object.freeze(record);
}
function timestamp(value, label) {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value.toISOString();
  if (typeof value === 'string' && Number.isFinite(Date.parse(value))) return value;
  fail(`Valid ${label} required`);
}
function requireDatabase(value) {
  if (typeof value !== 'string' || !value.length || value.length > 63 || value.includes('\0')) {
    fail('Exact expected database required');
  }
  return value;
}

async function assertAuthority(client, expectedDatabase) {
  const identity = (await client.query(`SELECT current_user AS current_role,
    session_user AS session_role,current_database() AS database,
    role.rolsuper,role.rolcreaterole,role.rolcreatedb,role.rolreplication,role.rolbypassrls
    FROM pg_roles role WHERE role.rolname=current_user`)).rows[0];
  if (!identity || identity.current_role !== MIGRATION_ROLE || identity.session_role !== MIGRATION_ROLE
      || identity.database !== expectedDatabase || identity.rolsuper !== false
      || identity.rolcreaterole !== false || identity.rolcreatedb !== false
      || identity.rolreplication !== false || identity.rolbypassrls !== false) {
    throw new Error('Exact unprivileged identity migration authority required');
  }

  const acl = (await client.query(`WITH expected(signature) AS (SELECT unnest($1::text[])),
    resolved AS (SELECT expected.signature,to_regprocedure(expected.signature) AS oid FROM expected)
    SELECT resolved.signature,namespace.nspname AS schema_name,procedure.proname AS function_name,
      oidvectortypes(procedure.proargtypes) AS identity_arguments,
      pg_get_userbyid(procedure.proowner) AS function_owner,
      pg_get_userbyid(namespace.nspowner) AS schema_owner,
      has_function_privilege(current_user,procedure.oid,'EXECUTE') AS migration_execute,
      has_function_privilege($2::name,procedure.oid,'EXECUTE') AS runtime_execute,
      EXISTS(SELECT 1 FROM aclexplode(COALESCE(procedure.proacl,acldefault('f',procedure.proowner))) entry
        WHERE entry.grantee=0 AND entry.privilege_type='EXECUTE') AS public_execute,
      EXISTS(SELECT 1 FROM aclexplode(COALESCE(namespace.nspacl,acldefault('n',namespace.nspowner))) entry
        WHERE entry.grantee=0 AND entry.privilege_type IN ('USAGE','CREATE')) AS public_schema_privilege
    FROM resolved
    LEFT JOIN pg_proc procedure ON procedure.oid=resolved.oid
    LEFT JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace`,
  [FUNCTIONS.map(item => item.signature), RUNTIME_ROLE])).rows;
  if (acl.length !== FUNCTIONS.length || new Set(acl.map(row => row.signature)).size !== FUNCTIONS.length) {
    throw new Error('Exact private import function inventory required');
  }
  for (const row of acl) {
    const expected = FUNCTION_BY_SIGNATURE.get(row.signature);
    if (!expected || row.schema_name !== 'legacy_ai_private' || row.function_name !== expected.name
        || row.identity_arguments !== expected.arguments || row.function_owner !== MIGRATION_ROLE
        || row.schema_owner !== MIGRATION_ROLE || row.migration_execute !== true
        || row.runtime_execute !== false || row.public_execute !== false
        || row.public_schema_privilege !== false) {
      throw new Error('Exact private import function ownership and ACL required');
    }
  }
}

function createLegacyAiHistoryImportTarget(pool, options = {}) {
  if (!pool || typeof pool.connect !== 'function') fail('Injected migration pool required');
  object(options, 'target options');
  exactKeys(options, ['database'], 'target option');
  const expectedDatabase = requireDatabase(options.database);

  async function authorized(work) {
    const client = await pool.connect();
    let discard;
    try {
      await client.query('BEGIN');
      await assertAuthority(client, expectedDatabase);
      const value = await work(client);
      await client.query('COMMIT');
      return value;
    } catch (error) {
      try { await client.query('ROLLBACK'); } catch (rollbackError) { discard = rollbackError; }
      throw error;
    } finally {
      client.release(discard);
    }
  }

  function begin(value) {
    object(value, 'import batch');
    exactKeys(value, ['batchId', 'sourceStoreIdentity', 'expectedCount', 'aggregateDigest'], 'import batch');
    const input = { batchId: uuid(value.batchId, 'import batch ID'),
      sourceStoreIdentity: text(value.sourceStoreIdentity, 'source store identity', { minimum: 1, maximum: 512 }),
      expectedCount: integer(value.expectedCount, 'expected import count'),
      aggregateDigest: digest(value.aggregateDigest, 'aggregate digest') };
    return authorized(async client => {
      const row = (await client.query('SELECT * FROM legacy_ai_private.begin_history_import($1,$2,$3,$4)',
        [input.batchId, input.sourceStoreIdentity, input.expectedCount, input.aggregateDigest])).rows[0];
      object(row, 'begin import receipt');
      const state = text(row.state, 'import state');
      if (!STATES.has(state)) fail('Valid import state required');
      const result = { batchId: uuid(row.batch_id, 'returned batch ID'), state,
        expectedCount: integer(row.expected_count, 'returned expected count'),
        aggregateDigest: digest(row.aggregate_digest, 'returned aggregate digest'),
        replayed: boolean(row.replayed, 'begin replay status') };
      if (result.batchId !== input.batchId || result.expectedCount !== input.expectedCount
          || result.aggregateDigest !== input.aggregateDigest) fail('Begin receipt differs from import request');
      return Object.freeze(result);
    });
  }

  function archive(value) {
    object(value, 'archive request');
    exactKeys(value, ['batchId', 'sourceRowId', 'sourceRecord', 'sourceDigest', 'classification', 'ownerId'],
      'archive request');
    const input = { batchId: uuid(value.batchId, 'import batch ID'),
      sourceRowId: sourceRowId(value.sourceRowId), sourceRecord: sourceRecord(value.sourceRecord),
      sourceDigest: digest(value.sourceDigest, 'source digest'),
      classification: text(value.classification, 'source classification'),
      ownerId: nullableOwner(value.ownerId, 'classified owner') };
    if (!CLASSIFICATIONS.has(input.classification)
        || (input.classification === 'owned') !== (input.ownerId !== null)
        || input.sourceRecord.id !== input.sourceRowId) {
      fail('Consistent source classification required');
    }
    return authorized(async client => {
      const row = (await client.query(
        'SELECT * FROM legacy_ai_private.archive_history_import_row($1,$2,$3::jsonb,$4,$5,$6)',
        [input.batchId, input.sourceRowId, JSON.stringify(input.sourceRecord), input.sourceDigest,
          input.classification, input.ownerId])).rows[0];
      object(row, 'archive receipt');
      const result = { batchId: uuid(row.batch_id, 'returned batch ID'),
        sourceRowId: sourceRowId(row.source_row_id, 'returned source row ID'),
        sourceDigest: digest(row.source_digest, 'returned source digest'),
        replayed: boolean(row.replayed, 'archive replay status') };
      if (result.batchId !== input.batchId || result.sourceRowId !== input.sourceRowId
          || result.sourceDigest !== input.sourceDigest) fail('Archive receipt differs from import request');
      return Object.freeze(result);
    });
  }

  function promote(value) {
    object(value, 'promotion request');
    exactKeys(value, ['batchId', 'sourceRowId', 'sourceDigest', 'ownerId', 'requestId', 'sourceRoute',
      'prompt', 'response', 'modelUsed', 'createdAt', 'historyDigest'], 'promotion request');
    const input = { batchId: uuid(value.batchId, 'import batch ID'),
      sourceRowId: sourceRowId(value.sourceRowId),
      sourceDigest: digest(value.sourceDigest, 'source digest'),
      ownerId: integer(value.ownerId, 'promotion owner', { minimum: 1 }),
      requestId: uuid(value.requestId, 'history request ID', UUID_V4),
      sourceRoute: text(value.sourceRoute, 'source route'),
      prompt: text(value.prompt, 'history prompt', { maximum: 65536 }),
      response: text(value.response, 'history response', { maximum: 262144 }),
      modelUsed: text(value.modelUsed, 'history model', { maximum: 256 }),
      createdAt: text(value.createdAt, 'history timestamp'),
      historyDigest: digest(value.historyDigest, 'history digest') };
    if (!ROUTES.has(input.sourceRoute) || !CREATED_AT.test(input.createdAt)) fail('Valid promotion route and timestamp required');
    return authorized(async client => {
      const row = (await client.query(
        'SELECT * FROM legacy_ai_private.promote_owned_history_import_row($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
        [input.batchId, input.sourceRowId, input.ownerId, input.requestId, input.sourceRoute,
          input.prompt, input.response, input.modelUsed, input.createdAt, input.historyDigest])).rows[0];
      object(row, 'promotion receipt');
      const result = { requestId: uuid(row.request_id, 'returned history request ID', UUID_V4),
        ownerId: integer(row.owner_id, 'returned owner', { minimum: 1 }),
        sourceRowId: sourceRowId(row.source_row_id, 'returned source row ID'),
        replayed: boolean(row.replayed, 'promotion replay status') };
      if (result.requestId !== input.requestId || result.ownerId !== input.ownerId
          || result.sourceRowId !== input.sourceRowId) fail('Promotion receipt differs from import request');
      return Object.freeze(result);
    });
  }

  function verify(value) {
    object(value, 'verification request');
    const keys = Object.hasOwn(value, 'replayOnly')
      ? ['batchId', 'expectedCount', 'aggregateDigest', 'replayOnly']
      : ['batchId', 'expectedCount', 'aggregateDigest'];
    exactKeys(value, keys, 'verification request');
    if (Object.hasOwn(value, 'replayOnly')) boolean(value.replayOnly, 'verification replay status');
    const input = { batchId: uuid(value.batchId, 'import batch ID'),
      expectedCount: integer(value.expectedCount, 'expected import count'),
      aggregateDigest: digest(value.aggregateDigest, 'aggregate digest') };
    return authorized(async client => {
      const row = (await client.query('SELECT * FROM legacy_ai_private.verify_history_import_quarantine($1,$2,$3)',
        [input.batchId, input.expectedCount, input.aggregateDigest])).rows[0];
      object(row, 'verification receipt');
      const result = { batchId: uuid(row.batch_id, 'verified batch ID'),
        verifiedAt: timestamp(row.verified_at, 'verification timestamp'),
        sourceRemovalReceipt: digest(row.source_removal_receipt, 'source removal receipt') };
      if (result.batchId !== input.batchId || result.sourceRemovalReceipt !== input.aggregateDigest) {
        fail('Verification receipt differs from import request');
      }
      return Object.freeze(result);
    });
  }

  function readArchived(value) {
    object(value, 'archive read request'); exactKeys(value, ['batchId'], 'archive read request');
    const batchId = uuid(value.batchId, 'import batch ID');
    return authorized(async client => {
      const rows = (await client.query(`SELECT source_row_id,source_digest,source_record,classification,classified_owner_id
        FROM legacy_ai_private.import_archive WHERE batch_id=$1 ORDER BY source_row_id`, [batchId])).rows;
      return Object.freeze(rows.map(row => {
        const classification = text(row.classification, 'archived classification');
        const ownerId = nullableOwner(row.classified_owner_id, 'archived owner');
        if (!CLASSIFICATIONS.has(classification) || (classification === 'owned') !== (ownerId !== null)) {
          fail('Consistent archived classification required');
        }
        const archivedSourceRowId = sourceRowId(row.source_row_id, 'archived source row ID');
        const archivedSourceRecord = sourceRecord(row.source_record);
        if (archivedSourceRecord.id !== archivedSourceRowId) fail('Archived source identity differs');
        return Object.freeze({ sourceRowId: archivedSourceRowId,
          sourceDigest: digest(row.source_digest, 'archived source digest'),
          sourceRecord: archivedSourceRecord, classification, ownerId });
      }));
    });
  }

  function readPromoted(value) {
    object(value, 'promotion read request'); exactKeys(value, ['batchId', 'sourceRowId'], 'promotion read request');
    const batchId = uuid(value.batchId, 'import batch ID');
    const requestedSourceRowId = sourceRowId(value.sourceRowId);
    return authorized(async client => {
      const row = (await client.query(`SELECT h.owner_id,h.request_id,r.source_route,r.source_digest,r.history_digest,
        h.prompt,h.response,h.model_used,
        to_char(h.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at
        FROM legacy_ai_private.import_history_receipts r JOIN legacy_ai_private.history h ON h.request_id=r.request_id
        WHERE r.batch_id=$1 AND r.source_row_id=$2`, [batchId, requestedSourceRowId])).rows[0];
      if (!row) return null;
      const sourceRoute = text(row.source_route, 'promoted source route');
      const createdAt = text(row.created_at, 'promoted timestamp');
      if (!ROUTES.has(sourceRoute) || !CREATED_AT.test(createdAt)) fail('Valid promoted route and timestamp required');
      return Object.freeze({ ownerId: integer(row.owner_id, 'promoted owner', { minimum: 1 }),
        requestId: uuid(row.request_id, 'promoted request ID', UUID_V4), sourceRoute,
        sourceDigest: digest(row.source_digest, 'promoted source digest'),
        historyDigest: digest(row.history_digest, 'promoted history digest'),
        prompt: text(row.prompt, 'promoted prompt', { maximum: 65536 }),
        response: text(row.response, 'promoted response', { maximum: 262144 }),
        modelUsed: text(row.model_used, 'promoted model', { maximum: 256 }), createdAt });
    });
  }

  return Object.freeze({ begin, archive, promote, verify, readArchived, readPromoted });
}

module.exports = { createLegacyAiHistoryImportTarget };
