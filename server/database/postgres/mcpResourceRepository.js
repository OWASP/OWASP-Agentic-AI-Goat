'use strict';

const crypto = require('node:crypto');
const { withTransaction } = require('./index');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const OWNER_KEY = /^[1-9][0-9]{0,9}$/;
const MESSAGE_ID = /^mcp-[0-9a-f-]{36}@(?:owasp-ai-goat|dvaia)\.local$/;
const fail = (code, message) => { const error = new Error(message); error.code = code; throw error; };
function coordinates(value) {
  if (!value || !UUID.test(value.targetId || '') || !Number.isSafeInteger(value.platformOwnerId) || value.platformOwnerId < 1
      || !Number.isSafeInteger(value.platformSessionId) || value.platformSessionId < 1
      || !Number.isSafeInteger(value.generation) || value.generation < 0) fail('MCP_RESOURCE_SCOPE_INVALID', 'Exact MCP resource coordinates are required');
  return [value.targetId.toLowerCase(), String(value.platformOwnerId), value.platformSessionId, value.generation];
}
function uuid(value, name) { if (!UUID.test(value || '')) fail('MCP_RESOURCE_SCOPE_INVALID', `${name} is invalid`); return value.toLowerCase(); }
function hash(value, name) { if (!SHA.test(value || '')) fail('MCP_RESOURCE_SCOPE_INVALID', `${name} is invalid`); return value; }
const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
function completedReceipt(receipt, value, intentCount) {
  const [target, , session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
  const expected = receipt && { version: 1, targetId: target, platformOwnerId: value.platformOwnerId,
    platformSessionId: session, generation, operationId: operation, status: 'completed', intentCount,
    completedAt: receipt.completedAt, cleanupPending: false };
  const body = receipt && Object.fromEntries(Object.entries(receipt).filter(([name]) => name !== 'receiptSha256'));
  if (!receipt || canonical(body) !== canonical(expected) || !Number.isSafeInteger(intentCount) || intentCount < 0
      || typeof receipt.completedAt !== 'string' || !Number.isFinite(Date.parse(receipt.completedAt))
      || new Date(receipt.completedAt).toISOString() !== receipt.completedAt
      || receipt.receiptSha256 !== digest(Buffer.from(canonical(body)))) fail('MCP_RESOURCE_SCOPE_INVALID', 'Completed mail receipt is invalid');
}
function completedRunnerReceipt(receipt, value) {
  const [target, , session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
  const expected = receipt && { version: 1, targetId: target, ownerId: value.platformOwnerId,
    platformSessionId: session, generation, operationId: operation, status: 'completed',
    completedAt: receipt.completedAt, cleanupPending: false };
  const body = receipt && Object.fromEntries(Object.entries(receipt).filter(([name]) => name !== 'receiptSha256'));
  if (!receipt || canonical(body) !== canonical(expected) || typeof receipt.completedAt !== 'string'
      || !Number.isFinite(Date.parse(receipt.completedAt)) || new Date(receipt.completedAt).toISOString() !== receipt.completedAt
      || receipt.receiptSha256 !== digest(Buffer.from(canonical(body)))) fail('MCP_RESOURCE_SCOPE_INVALID', 'Completed runner receipt is invalid');
}

const OWNER_RETIREMENT_SNAPSHOT = `SELECT
  COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'targetId',target_id,'ownerKey',user_key,'platformSessionId',platform_session_id::text,
    'generation',generation::text,'state',state,'retiredAt',CASE WHEN retired_at IS NULL THEN NULL
      ELSE to_char(retired_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END)
    ORDER BY created_at,target_id) FROM mcp.runner_targets WHERE user_key=$1),'[]'::jsonb) AS runner_targets,
  COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'operationId',operation_id,'targetId',target_id,'ownerKey',user_key,
    'platformSessionId',platform_session_id::text,'generation',generation::text,'status',status,
    'receiptVersion',receipt_version,'receiptSha256',receipt_sha256,'receiptJson',receipt_json,
    'completedAt',CASE WHEN completed_at IS NULL THEN NULL
      ELSE to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END)
    ORDER BY created_at,operation_id) FROM mcp.runner_target_cleanups
    WHERE user_key=$1 OR target_id IN (SELECT target_id FROM mcp.runner_targets WHERE user_key=$1)),'[]'::jsonb) AS runner_cleanups,
  COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'intentId',intent_id,'targetId',target_id,'ownerKey',user_key,
    'platformSessionId',platform_session_id::text,'generation',generation::text,
    'messageId',assigned_message_id,'recipientSha256',recipient_sha256,'payloadSha256',payload_sha256,
    'status',status,'settledAt',CASE WHEN settled_at IS NULL THEN NULL
      ELSE to_char(settled_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END,
    'cleanedAt',CASE WHEN cleaned_at IS NULL THEN NULL
      ELSE to_char(cleaned_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END)
    ORDER BY created_at,intent_id) FROM mcp.mail_intents
    WHERE user_key=$1 OR target_id IN (SELECT target_id FROM mcp.runner_targets WHERE user_key=$1)),'[]'::jsonb) AS mail_intents,
  COALESCE((SELECT jsonb_agg(jsonb_build_object(
    'operationId',operation_id,'targetId',target_id,'ownerKey',user_key,
    'platformSessionId',platform_session_id::text,'generation',generation::text,'status',status,
    'messageIds',message_ids,'receiptVersion',receipt_version,'receiptSha256',receipt_sha256,
    'receiptJson',receipt_json,'completedAt',CASE WHEN completed_at IS NULL THEN NULL
      ELSE to_char(completed_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END)
    ORDER BY created_at,operation_id) FROM mcp.mail_cleanups
    WHERE user_key=$1 OR target_id IN (SELECT target_id FROM mcp.runner_targets WHERE user_key=$1)),'[]'::jsonb) AS mail_cleanups`;

function ownerId(value) {
  if (!value || !Number.isSafeInteger(value.platformOwnerId) || !OWNER_KEY.test(String(value.platformOwnerId))) {
    fail('MCP_RESOURCE_SCOPE_INVALID', 'Exact MCP owner is required');
  }
  return value.platformOwnerId;
}
const inconsistentOwnerRetirement = () => fail('MCP_RESOURCE_CONFLICT', 'MCP owner resource retirement ledger is inconsistent');
function ledgerRow(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) inconsistentOwnerRetirement();
  return value;
}
function ledgerUuid(value) {
  if (typeof value !== 'string' || !UUID.test(value)) inconsistentOwnerRetirement();
  return value.toLowerCase();
}
function ledgerInteger(value, positive) {
  const pattern = positive ? /^[1-9][0-9]*$/ : /^(0|[1-9][0-9]*)$/;
  if (typeof value !== 'string' || !pattern.test(value)) inconsistentOwnerRetirement();
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) inconsistentOwnerRetirement();
  return parsed;
}
function ledgerTime(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    inconsistentOwnerRetirement();
  }
  return value;
}
function receiptColumns(row, value, validate) {
  if (row.receiptVersion !== 1 || !SHA.test(row.receiptSha256 || '') || !row.receiptJson
      || row.receiptJson.receiptSha256 !== row.receiptSha256
      || ledgerTime(row.completedAt) !== row.receiptJson.completedAt) inconsistentOwnerRetirement();
  try { validate(row.receiptJson, value); } catch { inconsistentOwnerRetirement(); }
}
function pendingReceiptColumns(row) {
  if (row.receiptVersion !== null || row.receiptSha256 !== null || row.receiptJson !== null || row.completedAt !== null) {
    inconsistentOwnerRetirement();
  }
}
function sameSet(left, right) {
  const sortedLeft = [...left].sort(); const sortedRight = [...right].sort();
  return sortedLeft.length === sortedRight.length
    && sortedLeft.every((value, index) => value === sortedRight[index]);
}

function verifyOwnerRetirementSnapshot(snapshot, platformOwnerId) {
  const collections = ['runner_targets', 'runner_cleanups', 'mail_intents', 'mail_cleanups'];
  if (!snapshot || collections.some(name => !Array.isArray(snapshot[name]))) inconsistentOwnerRetirement();
  const owner = String(platformOwnerId);
  const targets = new Map();
  for (const item of snapshot.runner_targets) {
    const row = ledgerRow(item);
    const targetId = ledgerUuid(row.targetId);
    if (targets.has(targetId) || row.ownerKey !== owner || !['active', 'retiring', 'retired'].includes(row.state)) {
      inconsistentOwnerRetirement();
    }
    const platformSessionId = ledgerInteger(row.platformSessionId, true);
    const generation = ledgerInteger(row.generation, false);
    if ((row.state === 'retired') !== (row.retiredAt !== null)) inconsistentOwnerRetirement();
    targets.set(targetId, { targetId, platformOwnerId, platformSessionId, generation,
      state: row.state, retiredAt: row.retiredAt === null ? null : ledgerTime(row.retiredAt), intents: [] });
  }
  const runnerCleanups = new Map();
  const runnerOperations = new Set();
  for (const item of snapshot.runner_cleanups) {
    const row = ledgerRow(item);
    const targetId = ledgerUuid(row.targetId); const operationId = ledgerUuid(row.operationId);
    const target = targets.get(targetId);
    if (!target || runnerCleanups.has(targetId) || runnerOperations.has(operationId) || row.ownerKey !== owner
        || ledgerInteger(row.platformSessionId, true) !== target.platformSessionId
        || ledgerInteger(row.generation, false) !== target.generation
        || !['pending', 'completed'].includes(row.status)) inconsistentOwnerRetirement();
    const value = { ...target, operationId };
    if (row.status === 'completed') receiptColumns(row, value, completedRunnerReceipt);
    else pendingReceiptColumns(row);
    runnerCleanups.set(targetId, { ...row, targetId, operationId });
    runnerOperations.add(operationId);
  }
  const intentIds = new Set(); const messageIds = new Set();
  for (const item of snapshot.mail_intents) {
    const row = ledgerRow(item);
    const targetId = ledgerUuid(row.targetId); const target = targets.get(targetId);
    const intentId = ledgerUuid(row.intentId);
    if (!target || intentIds.has(intentId) || messageIds.has(row.messageId) || row.ownerKey !== owner
        || !MESSAGE_ID.test(row.messageId || '')
        || !SHA.test(row.recipientSha256 || '') || !SHA.test(row.payloadSha256 || '')
        || ledgerInteger(row.platformSessionId, true) !== target.platformSessionId
        || ledgerInteger(row.generation, false) !== target.generation
        || !['pending', 'accepted', 'uncertain'].includes(row.status)
        || ((row.status === 'pending') !== (row.settledAt === null))) inconsistentOwnerRetirement();
    if (row.settledAt !== null) ledgerTime(row.settledAt);
    if (row.cleanedAt !== null) ledgerTime(row.cleanedAt);
    target.intents.push(row);
    intentIds.add(intentId); messageIds.add(row.messageId);
  }
  const mailCleanups = new Map();
  const mailOperations = new Set();
  for (const item of snapshot.mail_cleanups) {
    const row = ledgerRow(item);
    const targetId = ledgerUuid(row.targetId); const operationId = ledgerUuid(row.operationId);
    const target = targets.get(targetId); const runnerCleanup = runnerCleanups.get(targetId);
    if (!target || !runnerCleanup || mailCleanups.has(targetId) || mailOperations.has(operationId) || row.ownerKey !== owner
        || operationId !== runnerCleanup.operationId
        || ledgerInteger(row.platformSessionId, true) !== target.platformSessionId
        || ledgerInteger(row.generation, false) !== target.generation
        || !['pending', 'completed'].includes(row.status) || !Array.isArray(row.messageIds)
        || row.messageIds.some(messageId => !MESSAGE_ID.test(messageId))
        || new Set(row.messageIds).size !== row.messageIds.length) inconsistentOwnerRetirement();
    const intentIds = target.intents.map(intent => intent.messageId);
    if (!sameSet(row.messageIds, intentIds)) inconsistentOwnerRetirement();
    const value = { ...target, operationId };
    if (row.status === 'completed') receiptColumns(row, value,
      (receipt, scope) => completedReceipt(receipt, scope, row.messageIds.length));
    else pendingReceiptColumns(row);
    mailCleanups.set(targetId, { ...row, targetId, operationId });
    mailOperations.add(operationId);
  }
  let pending = false;
  for (const target of targets.values()) {
    const runnerCleanup = runnerCleanups.get(target.targetId);
    const mailCleanup = mailCleanups.get(target.targetId);
    if (target.state === 'active') {
      if (runnerCleanup || mailCleanup || target.intents.some(intent => intent.cleanedAt !== null)) inconsistentOwnerRetirement();
      pending = true;
    } else if (target.state === 'retiring') {
      if (!runnerCleanup || runnerCleanup.status !== 'pending') inconsistentOwnerRetirement();
      pending = true;
    } else {
      if (!runnerCleanup || runnerCleanup.status !== 'completed' || !mailCleanup || mailCleanup.status !== 'completed'
          || runnerCleanup.completedAt !== target.retiredAt
          || target.intents.some(intent => intent.cleanedAt !== mailCleanup.completedAt)) inconsistentOwnerRetirement();
    }
    if ((!mailCleanup || mailCleanup.status === 'pending')
        && target.intents.some(intent => intent.cleanedAt !== null)) inconsistentOwnerRetirement();
    if (mailCleanup?.status === 'completed'
        && target.intents.some(intent => intent.cleanedAt !== mailCleanup.completedAt)) inconsistentOwnerRetirement();
    if (mailCleanup?.status === 'pending' || target.intents.some(intent => intent.cleanedAt === null)) pending = true;
  }
  if (pending) fail('MCP_OWNER_RESOURCES_PENDING', 'MCP owner resources still require retirement');
  return Object.freeze({ platformOwnerId, status: 'retired', targetCount: targets.size,
    mailIntentCount: snapshot.mail_intents.length });
}

async function lockRunnerRetirement(client, { target, owner, session, generation, operation }) {
  const targetRow = (await client.query(`SELECT user_key,platform_session_id,generation,state FROM mcp.runner_targets
    WHERE target_id=$1 FOR UPDATE`, [target])).rows[0];
  if (!targetRow || targetRow.user_key !== owner || String(targetRow.platform_session_id) !== String(session)
      || String(targetRow.generation) !== String(generation) || !['retiring', 'retired'].includes(targetRow.state)) {
    fail('MCP_RESOURCE_CONFLICT', 'Runner retirement must begin before mail cleanup');
  }
  const runnerCleanup = (await client.query(`SELECT target_id,user_key,platform_session_id,generation,status
    FROM mcp.runner_target_cleanups WHERE operation_id=$1 FOR UPDATE`, [operation])).rows[0];
  if (!runnerCleanup || runnerCleanup.target_id !== target || runnerCleanup.user_key !== owner
      || String(runnerCleanup.platform_session_id) !== String(session)
      || String(runnerCleanup.generation) !== String(generation)
      || !['pending', 'completed'].includes(runnerCleanup.status)) {
    fail('MCP_RESOURCE_CONFLICT', 'Runner cleanup binding differs');
  }
  return { targetRow, runnerCleanup };
}

// Draft-only repository. The caller supplies coordinates obtained from the
// canonical identity/JWT resolver; request/model fields are never accepted as
// authority. No production composition imports this module yet.
function createMcpResourceRepository(pool) {
  async function settleMail(value, status) {
    const [target, owner, session, generation] = coordinates(value); const intent = uuid(value.intentId, 'intentId');
    const result = await pool.query(`UPDATE mcp.mail_intents SET status=$6,settled_at=clock_timestamp()
      WHERE intent_id=$1 AND target_id=$2 AND user_key=$3 AND platform_session_id=$4 AND generation=$5
        AND status IN ('pending',$6) RETURNING assigned_message_id`, [intent, target, owner, session, generation, status]);
    if (!result.rowCount) fail('MCP_RESOURCE_CONFLICT', 'Mail intent cannot be settled');
    if (status === 'accepted' && result.rows[0].assigned_message_id !== value.assignedMessageId) fail('MCP_RESOURCE_CONFLICT', 'SMTP receipt differs');
    return { status };
  }
  return Object.freeze({
    // Dedicated bounded lease pool only: the caller supplies current identity/
    // generation checks; row lock serializes retirement across app processes.
    async withActiveRunnerTarget(value,check,work) {
      const params=coordinates(value);
      if(typeof check!=='function'||typeof work!=='function')throw TypeError('Current target lease callbacks required');
      return withTransaction(pool,async client=>{
        await client.query("SET LOCAL lock_timeout='3s'");
        await client.query("SET LOCAL idle_in_transaction_session_timeout='35s'");
        await check();
        const row=await client.query("SELECT target_id FROM mcp.runner_targets WHERE target_id=$1 AND user_key=$2 AND platform_session_id=$3 AND generation=$4 AND state='active' FOR SHARE",params);
        if(row.rowCount!==1)fail('MCP_RESOURCE_SCOPE_INVALID','Current active target lease required');
        await check();const result=await work();await check();return result;
      });
    },
    async readActiveRunnerTarget(value) {
      if (!value || !Number.isSafeInteger(value.platformOwnerId) || value.platformOwnerId < 1
          || !Number.isSafeInteger(value.platformSessionId) || value.platformSessionId < 1
          || !Number.isSafeInteger(value.generation) || value.generation < 0) {
        fail('MCP_RESOURCE_SCOPE_INVALID', 'Exact current MCP owner scope is required');
      }
      const rows = (await pool.query(`SELECT target_id,user_key,platform_session_id,generation,state FROM mcp.runner_targets
        WHERE user_key=$1 AND platform_session_id=$2 AND generation=$3 AND state='active'`,
      [String(value.platformOwnerId), value.platformSessionId, value.generation])).rows;
      if (rows.length > 1) fail('MCP_RESOURCE_CONFLICT', 'Multiple active MCP targets exist for one owner scope');
      if (!rows[0]) return null;
      return { targetId: rows[0].target_id, platformOwnerId: Number(rows[0].user_key),
        platformSessionId: Number(rows[0].platform_session_id), generation: Number(rows[0].generation) };
    },
    async listRunnerTargetsForOwner(value) {
      if (!value || !Number.isSafeInteger(value.platformOwnerId) || value.platformOwnerId < 1) {
        fail('MCP_RESOURCE_SCOPE_INVALID', 'Exact MCP owner is required');
      }
      const rows = (await pool.query(`SELECT t.target_id,t.user_key,t.platform_session_id,t.generation,t.state,c.operation_id,c.status AS cleanup_status
        FROM mcp.runner_targets t LEFT JOIN mcp.runner_target_cleanups c ON c.target_id=t.target_id
        WHERE t.user_key=$1 AND t.state <> 'retired' ORDER BY t.created_at,t.target_id`, [String(value.platformOwnerId)])).rows;
      return rows.map(row => ({ targetId: row.target_id, platformOwnerId: Number(row.user_key),
        platformSessionId: Number(row.platform_session_id), generation: Number(row.generation), state: row.state,
        operationId: row.operation_id || null, cleanupStatus: row.cleanup_status || null }));
    },
    async assertOwnerResourcesRetired(value) {
      const platformOwnerId = ownerId(value);
      const result = await pool.query(OWNER_RETIREMENT_SNAPSHOT, [String(platformOwnerId)]);
      if (!result || !Array.isArray(result.rows) || result.rows.length !== 1) inconsistentOwnerRetirement();
      const verified = verifyOwnerRetirementSnapshot(result.rows[0], platformOwnerId);
      for (const target of result.rows[0].runner_targets) {
        await require('./mcpHttpLeaseRepository').assertHttpChildRetired(pool, target.targetId);
      }
      return verified;
    },
    async reserveRunnerTarget(value) {
      const [target, owner, session, generation] = coordinates(value);
      const row = (await pool.query(`INSERT INTO mcp.runner_targets(target_id,user_key,platform_session_id,generation)
        VALUES($1,$2,$3,$4) ON CONFLICT(target_id) DO NOTHING RETURNING target_id`, [target, owner, session, generation])).rows[0];
      if (row) return { replayed: false };
      const prior = (await pool.query('SELECT user_key,platform_session_id,generation,state FROM mcp.runner_targets WHERE target_id=$1', [target])).rows[0];
      if (!prior || prior.user_key !== owner || String(prior.platform_session_id) !== String(session)
          || String(prior.generation) !== String(generation) || prior.state !== 'active') fail('MCP_RESOURCE_CONFLICT', 'Runner target binding differs or is retired');
      return { replayed: true };
    },
    async beginRunnerRetirement(value) {
      const [target, owner, session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
      return withTransaction(pool, async client => {
        const targetRow = (await client.query('SELECT user_key,platform_session_id,generation,state FROM mcp.runner_targets WHERE target_id=$1 FOR UPDATE', [target])).rows[0];
        if (!targetRow || targetRow.user_key !== owner || String(targetRow.platform_session_id) !== String(session)
            || String(targetRow.generation) !== String(generation)) fail('MCP_RESOURCE_CONFLICT', 'Current runner target is unavailable');
        await client.query(`INSERT INTO mcp.runner_target_cleanups(operation_id,target_id,user_key,platform_session_id,generation,status)
          VALUES($1,$2,$3,$4,$5,'pending') ON CONFLICT(operation_id) DO NOTHING`, [operation, target, owner, session, generation]);
        const cleanup = (await client.query('SELECT target_id,user_key,platform_session_id,generation,status FROM mcp.runner_target_cleanups WHERE operation_id=$1 FOR UPDATE', [operation])).rows[0];
        if (!cleanup || cleanup.target_id !== target || cleanup.user_key !== owner || String(cleanup.platform_session_id) !== String(session)
            || String(cleanup.generation) !== String(generation)) fail('MCP_RESOURCE_CONFLICT', 'Runner cleanup binding differs');
        if (targetRow.state === 'retired' && cleanup.status !== 'completed') fail('MCP_RESOURCE_CONFLICT', 'Retired target has incomplete cleanup evidence');
        if (targetRow.state === 'active') await client.query("UPDATE mcp.runner_targets SET state='retiring' WHERE target_id=$1", [target]);
        return { replayed: cleanup.status === 'completed' };
      });
    },
    async completeRunnerRetirement(value) {
      const [target, owner, session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
      completedRunnerReceipt(value.receipt, value);
      return withTransaction(pool, async client => {
        await require('./mcpHttpLeaseRepository').assertHttpChildRetired(client, target);
        const targetRow = (await client.query('SELECT user_key,platform_session_id,generation,state FROM mcp.runner_targets WHERE target_id=$1 FOR UPDATE', [target])).rows[0];
        const cleanup = (await client.query('SELECT target_id,user_key,platform_session_id,generation,status,receipt_json FROM mcp.runner_target_cleanups WHERE operation_id=$1 FOR UPDATE', [operation])).rows[0];
        if (!targetRow || !cleanup || targetRow.user_key !== owner || cleanup.user_key !== owner || cleanup.target_id !== target
            || String(targetRow.platform_session_id) !== String(session) || String(cleanup.platform_session_id) !== String(session)
            || String(targetRow.generation) !== String(generation) || String(cleanup.generation) !== String(generation)) fail('MCP_RESOURCE_CONFLICT', 'Runner cleanup binding differs');
        if (cleanup.status === 'completed') {
          if (canonical(cleanup.receipt_json) !== canonical(value.receipt) || targetRow.state !== 'retired') fail('MCP_RESOURCE_CONFLICT', 'Completed runner cleanup differs');
          return cleanup.receipt_json;
        }
        if (targetRow.state !== 'retiring') fail('MCP_RESOURCE_CONFLICT', 'Runner target is not retiring');
        await client.query(`UPDATE mcp.runner_target_cleanups SET status='completed',receipt_version=1,receipt_sha256=$2,
          receipt_json=$3::jsonb,completed_at=$4 WHERE operation_id=$1 AND status='pending'`, [operation, value.receipt.receiptSha256, JSON.stringify(value.receipt), value.receipt.completedAt]);
        await client.query("UPDATE mcp.runner_targets SET state='retired',retired_at=$2 WHERE target_id=$1 AND state='retiring'", [target, value.receipt.completedAt]);
        return value.receipt;
      });
    },
    async readRunnerRetirement(value) {
      const [target, owner, session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
      const row = (await pool.query(`SELECT c.receipt_json,t.state FROM mcp.runner_target_cleanups c JOIN mcp.runner_targets t ON t.target_id=c.target_id
        WHERE c.operation_id=$1 AND c.target_id=$2 AND c.user_key=$3 AND c.platform_session_id=$4 AND c.generation=$5 AND c.status='completed'`,
      [operation, target, owner, session, generation])).rows[0];
      if (!row || row.state !== 'retired') return null;
      completedRunnerReceipt(row.receipt_json, value);
      return row.receipt_json;
    },
    async beginMailIntent(value) {
      const [target, owner, session, generation] = coordinates(value); const intent = uuid(value.intentId, 'intentId');
      const assigned = String(value.assignedMessageId || '');
      if (!MESSAGE_ID.test(assigned)) fail('MCP_RESOURCE_SCOPE_INVALID', 'Assigned SMTP Message-ID is invalid');
      hash(value.recipientSha256, 'recipientSha256'); hash(value.payloadSha256, 'payloadSha256');
      return withTransaction(pool, async client => {
        const active = (await client.query(`SELECT 1 FROM mcp.runner_targets WHERE target_id=$1 AND user_key=$2
          AND platform_session_id=$3 AND generation=$4 AND state='active' FOR SHARE`, [target, owner, session, generation])).rowCount;
        if (!active) fail('MCP_RESOURCE_RETIRED', 'Runner target is not active');
        const inserted = await client.query(`INSERT INTO mcp.mail_intents(intent_id,target_id,user_key,platform_session_id,generation,assigned_message_id,recipient_sha256,payload_sha256)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(intent_id) DO NOTHING`, [intent, target, owner, session, generation, assigned, value.recipientSha256, value.payloadSha256]);
        const row = (await client.query('SELECT * FROM mcp.mail_intents WHERE intent_id=$1', [intent])).rows[0];
        if (!row || row.target_id !== target || row.user_key !== owner || String(row.platform_session_id) !== String(session)
            || String(row.generation) !== String(generation) || row.assigned_message_id !== assigned
            || row.recipient_sha256 !== value.recipientSha256 || row.payload_sha256 !== value.payloadSha256) fail('MCP_RESOURCE_CONFLICT', 'Mail intent differs');
        return { replayed: inserted.rowCount === 0, status: row.status };
      });
    },
    markMailUncertain: value => settleMail(value, 'uncertain'),
    markMailAccepted: value => settleMail(value, 'accepted'),
    async readAcceptedMailIntent(value) {
      const [target, owner, session, generation] = coordinates(value); const intent = uuid(value.intentId, 'intentId');
      const row = (await pool.query(`SELECT assigned_message_id,recipient_sha256,payload_sha256,status
        FROM mcp.mail_intents WHERE intent_id=$1 AND target_id=$2 AND user_key=$3
          AND platform_session_id=$4 AND generation=$5`, [intent, target, owner, session, generation])).rows[0];
      if (!row || row.status !== 'accepted') return null;
      return Object.freeze({ assignedMessageId: row.assigned_message_id,
        recipientSha256: row.recipient_sha256, payloadSha256: row.payload_sha256, status: row.status });
    },
    async beginMailCleanup(value) {
      const [target, owner, session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
      return withTransaction(pool, async client => {
        await lockRunnerRetirement(client, { target, owner, session, generation, operation });
        let cleanup = (await client.query(`SELECT * FROM mcp.mail_cleanups WHERE target_id=$1 AND user_key=$2
          AND platform_session_id=$3 AND generation=$4 FOR UPDATE`, [target, owner, session, generation])).rows[0];
        if (cleanup) {
          if (cleanup.operation_id !== operation || !Array.isArray(cleanup.message_ids)) {
            fail('MCP_RESOURCE_CONFLICT', 'Mail cleanup binding differs');
          }
          return { replayed: cleanup.status === 'completed', messageIds: cleanup.message_ids };
        }
        const ids = (await client.query(`SELECT assigned_message_id FROM mcp.mail_intents WHERE target_id=$1 AND user_key=$2
          AND platform_session_id=$3 AND generation=$4 AND cleaned_at IS NULL ORDER BY assigned_message_id FOR UPDATE`, [target, owner, session, generation])).rows.map(row => row.assigned_message_id);
        await client.query(`INSERT INTO mcp.mail_cleanups(operation_id,target_id,user_key,platform_session_id,generation,status,message_ids)
          VALUES($1,$2,$3,$4,$5,'pending',$6::jsonb)`,
        [operation, target, owner, session, generation, JSON.stringify(ids)]);
        return { replayed: false, messageIds: ids };
      });
    },
    async completeMailCleanup(value) {
      const [target, owner, session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
      const receipt = value.receipt;
      const claimed = [...new Set(value.messageIds || [])].sort();
      completedReceipt(receipt, value, claimed.length);
      return withTransaction(pool, async client => {
        await lockRunnerRetirement(client, { target, owner, session, generation, operation });
        const cleanup = (await client.query('SELECT * FROM mcp.mail_cleanups WHERE operation_id=$1 FOR UPDATE', [operation])).rows[0];
        if (!cleanup || cleanup.target_id !== target || cleanup.user_key !== owner || String(cleanup.platform_session_id) !== String(session)
            || String(cleanup.generation) !== String(generation) || !Array.isArray(cleanup.message_ids)
            || JSON.stringify([...cleanup.message_ids].sort()) !== JSON.stringify(claimed)) fail('MCP_RESOURCE_CONFLICT', 'Mail cleanup binding differs');
        if (cleanup.status === 'completed') {
          completedReceipt(cleanup.receipt_json, value, claimed.length);
          return cleanup.receipt_json;
        }
        const current = (await client.query(`SELECT assigned_message_id FROM mcp.mail_intents WHERE target_id=$1 AND user_key=$2
          AND platform_session_id=$3 AND generation=$4 AND cleaned_at IS NULL ORDER BY assigned_message_id FOR UPDATE`, [target, owner, session, generation])).rows.map(row => row.assigned_message_id);
        if (JSON.stringify(current.sort()) !== JSON.stringify(claimed)) fail('MCP_RESOURCE_CONFLICT', 'Mail cleanup set changed');
        await client.query(`UPDATE mcp.mail_intents SET cleaned_at=$5 WHERE target_id=$1 AND user_key=$2
          AND platform_session_id=$3 AND generation=$4 AND assigned_message_id=ANY($6::text[]) AND cleaned_at IS NULL`,
        [target, owner, session, generation, receipt.completedAt, claimed]);
        await client.query(`UPDATE mcp.mail_cleanups SET status='completed',receipt_version=1,receipt_sha256=$2,receipt_json=$3::jsonb,completed_at=$4
          WHERE operation_id=$1 AND status='pending'`, [operation, receipt.receiptSha256, JSON.stringify(receipt), receipt.completedAt]);
        return receipt;
      });
    },
    async readMailCleanup(value) {
      const [target, owner, session, generation] = coordinates(value); const operation = uuid(value.operationId, 'operationId');
      const cleanup = (await pool.query(`SELECT receipt_json,message_ids FROM mcp.mail_cleanups WHERE operation_id=$1 AND target_id=$2
        AND user_key=$3 AND platform_session_id=$4 AND generation=$5 AND status='completed'`, [operation, target, owner, session, generation])).rows[0];
      if (!cleanup) return null;
      if (!Array.isArray(cleanup.message_ids)) fail('MCP_RESOURCE_CONFLICT', 'Mail cleanup message set is invalid');
      const rows = cleanup.message_ids.length ? (await pool.query(`SELECT assigned_message_id FROM mcp.mail_intents WHERE target_id=$1 AND user_key=$2
        AND platform_session_id=$3 AND generation=$4 AND assigned_message_id=ANY($5::text[]) AND cleaned_at IS NOT NULL ORDER BY assigned_message_id`,
      [target, owner, session, generation, cleanup.message_ids])).rows : [];
      const observed = rows.map(row => row.assigned_message_id).sort();
      const expected = [...cleanup.message_ids].sort();
      if (JSON.stringify(observed) !== JSON.stringify(expected)) fail('MCP_RESOURCE_CONFLICT', 'Mail cleanup evidence is incomplete');
      return { receipt: cleanup.receipt_json, messageIds: cleanup.message_ids };
    },
  });
}

module.exports = { createMcpResourceRepository, _internals: { coordinates, completedReceipt, completedRunnerReceipt } };
