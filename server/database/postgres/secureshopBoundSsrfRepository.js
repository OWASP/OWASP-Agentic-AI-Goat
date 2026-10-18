'use strict';

const crypto = require('node:crypto');
const {policyHtml: validatePolicyHtml}=require('../../services/secureshopPolicyFinalHtmlContract');
const { createConversationBinding } = require('../../services/secureshopConversationBinding');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const SCOPE_KEYS = Object.freeze(['targetId', 'launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId']);
function unavailable(message = 'Bound SSRF repository unavailable') {
  return Object.assign(new Error(message), { code: 'BOUND_SSRF_UNAVAILABLE' });
}
function uuid(value) { if (!UUID.test(value || '')) throw unavailable(); return value.toLowerCase(); }
function scope(value) {
  if (!value || !Number.isSafeInteger(value.generation) || value.generation < 1
    || !Number.isSafeInteger(value.platformOwnerId) || value.platformOwnerId < 1
    || !Number.isSafeInteger(value.platformSessionId) || value.platformSessionId < 1) throw unavailable();
  return Object.freeze({ targetId: uuid(value.targetId), launchId: uuid(value.launchId), scenarioId: uuid(value.scenarioId),
    generation: value.generation, platformOwnerId: value.platformOwnerId, platformSessionId: value.platformSessionId });
}
const scopeArgs = value => SCOPE_KEYS.map(key => value[key]);
function digest(value) { if (!SHA256.test(value || '')) throw unavailable(); return value; }
function invocation(row) {
  if (!row) return null;
  return Object.freeze({ operationId: row.operation_id, targetId: row.target_id, runId: row.run_id,
    launchId: row.launch_id, scenarioId: row.scenario_id, generation: Number(row.generation),
    platformOwnerId: Number(row.original_platform_owner_id), platformSessionId: Number(row.original_platform_session_id),
    requestId: row.request_id, sessionId: row.session_id, callId: row.call_id,
    argumentsSha256: row.arguments_hex, resultSha256: row.result_hex, responseSha256: row.response_hex,
    egressReceiptSha256: row.egress_hex, egressPolicySha256: row.policy_hex,
    requestMethod: row.request_method, requestPath: row.request_path, responseStatus: Number(row.response_status),
    resourceKind: row.resource_kind, policyDecision: row.policy_decision,
    completedAt: new Date(row.completed_at).toISOString() });
}

function createSecureShopBoundSsrfRepository(pool, { checkCurrent, checkCleanup, auditStore, randomUUID = crypto.randomUUID } = {}) {
  if (typeof pool?.query !== 'function' || typeof pool?.connect !== 'function'
    || typeof checkCurrent !== 'function' || typeof checkCleanup !== 'function' || typeof randomUUID !== 'function') throw unavailable();
  if (auditStore !== undefined && typeof auditStore?.append !== 'function') throw unavailable();
  async function tx(work) { const client = await pool.connect(); try { await client.query('BEGIN'); const value = await work(client);
    await client.query('COMMIT'); return value; } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
    finally { client.release(); } }
  async function serializeTarget(client, targetId) {
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))', [targetId]);
  }
  async function active(client, value) {
    const row = (await client.query(`SELECT * FROM secureshop_agents.bound_ssrf_targets
      WHERE target_id=$1 AND launch_id=$2 AND scenario_id=$3 AND generation=$4
      AND original_platform_owner_id=$5 AND original_platform_session_id=$6`, scopeArgs(value))).rows[0];
    if (!row || row.lifecycle !== 'active') throw unavailable(); return row;
  }
  async function readRequestWith(client, value, requestId) {
    return (await client.query(`SELECT r.*,EXISTS(SELECT 1 FROM secureshop_agents.bound_ssrf_invocations i
      WHERE i.operation_id=r.operation_id) AS completed FROM secureshop_agents.bound_ssrf_requests r
      JOIN secureshop_agents.bound_ssrf_targets t ON t.target_id=r.target_id
      WHERE r.target_id=$1 AND r.request_id=$2 AND t.launch_id=$3 AND t.scenario_id=$4
      AND t.generation=$5 AND t.original_platform_owner_id=$6 AND t.original_platform_session_id=$7
      AND t.lifecycle='active'`, [value.targetId, requestId, ...scopeArgs(value).slice(1)])).rows[0] || null;
  }
  async function readInvocationWith(client, value, operationId) {
    return (await client.query(`SELECT i.*,t.launch_id,t.scenario_id,t.generation,t.original_platform_owner_id,
      t.original_platform_session_id,encode(i.arguments_sha256,'hex') AS arguments_hex,
      encode(i.result_sha256,'hex') AS result_hex,encode(i.response_sha256,'hex') AS response_hex,
      encode(i.egress_receipt_sha256,'hex') AS egress_hex,encode(i.egress_policy_sha256,'hex') AS policy_hex
      FROM secureshop_agents.bound_ssrf_invocations i JOIN secureshop_agents.bound_ssrf_targets t USING(target_id)
      WHERE i.operation_id=$1 AND i.target_id=$2 AND t.launch_id=$3 AND t.scenario_id=$4 AND t.generation=$5
      AND t.original_platform_owner_id=$6 AND t.original_platform_session_id=$7`,
    [operationId, ...scopeArgs(value)])).rows[0] || null;
  }
  function cleanupScope(value, data, { requireReceipt = false } = {}) {
    if (!data || SCOPE_KEYS.some(key => data[key] !== undefined && data[key] !== value[key])) throw unavailable();
    const cleanup = { ...value, operationId:uuid(data.operationId) };
    if (requireReceipt || data.receiptSha256 !== undefined) cleanup.receiptSha256 = digest(data.receiptSha256);
    return Object.freeze(cleanup);
  }
  async function recordInvocationWithClient(client,input,record,inputPersona,options={}) {
      const value=scope(input),actor=auditStore?createConversationBinding(value,inputPersona):null;
      await checkCurrent(value);
      if(options.effectTimeoutMs!==undefined){if(options.effectTimeoutMs!==3000)throw unavailable();await client.query("SELECT set_config('statement_timeout','3000',true),set_config('lock_timeout','3000',true)");}
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-bound-audit-owner:${value.platformOwnerId}`]);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-conversation-admission:${value.launchId}`]);
      await serializeTarget(client, value.targetId); await active(client, value); const operationId = uuid(record?.operationId);
      const request = (await client.query('SELECT * FROM secureshop_agents.bound_ssrf_requests WHERE operation_id=$1 AND target_id=$2 FOR UPDATE',
        [operationId, value.targetId])).rows[0];
      if (!request || request.request_id !== record.requestId || request.resource_kind !== record.resourceKind || !request.nonce) throw unavailable();
      const prior = await readInvocationWith(client, value, operationId);
      const params = [operationId,value.targetId,uuid(record.runId),uuid(record.requestId),record.sessionId,record.callId,
        digest(record.argumentsSha256),digest(record.resultSha256),digest(record.responseSha256),digest(record.egressReceiptSha256),
        digest(record.egressPolicySha256),record.requestMethod,record.requestPath,record.responseStatus,record.resourceKind,record.policyDecision];
      if (!prior) await client.query(`INSERT INTO secureshop_agents.bound_ssrf_invocations
        (operation_id,target_id,run_id,request_id,session_id,call_id,arguments_sha256,result_sha256,response_sha256,
        egress_receipt_sha256,egress_policy_sha256,request_method,request_path,response_status,resource_kind,policy_decision)
        VALUES($1,$2,$3,$4,$5,$6,decode($7,'hex'),decode($8,'hex'),decode($9,'hex'),decode($10,'hex'),decode($11,'hex'),$12,$13,$14,$15,$16)
        ON CONFLICT(operation_id) DO NOTHING`, params);
      const row = prior || await readInvocationWith(client, value, operationId);
      const mapped = invocation(row); const expected = Object.freeze({ operationId, targetId:value.targetId, runId:params[2], requestId:params[3],
        sessionId:record.sessionId,callId:record.callId,argumentsSha256:params[6],resultSha256:params[7],responseSha256:params[8],
        egressReceiptSha256:params[9],egressPolicySha256:params[10],requestMethod:record.requestMethod,requestPath:record.requestPath,
        responseStatus:record.responseStatus,resourceKind:record.resourceKind,policyDecision:record.policyDecision });
      if (!mapped || Object.keys(expected).some(key => mapped[key] !== expected[key])) throw unavailable('Bound SSRF operation conflict');
      if (auditStore) await auditStore.append(client, {
        eventId: operationId, scope: value, persona: { id: actor.shopUserId, role: actor.role },
        actor: actor.role, action: 'ssrf_invocation_recorded', target: `ssrf:${value.targetId}`,
        paramsJson: JSON.stringify(expected), outcome: 'completed',
        sourceKind: 'bound_ssrf_invocation', sourceId: operationId,
      });
      await checkCurrent(value);
      return mapped;
  }
  return Object.freeze({
    async provision(input) { const value = scope(input); await checkCurrent(value); return tx(async client => {
      await serializeTarget(client, value.targetId);
      await client.query(`INSERT INTO secureshop_agents.bound_ssrf_targets
        (target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(launch_id,generation) DO NOTHING`, scopeArgs(value));
      await active(client, value); return value;
    }); },
    async claimRequest(input, { requestId, resourceKind, policyHtml = null } = {}) { const value = scope(input); requestId = uuid(requestId);
      if (!['public-policy', 'private-policy', 'html-policy'].includes(resourceKind)) throw unavailable();
      if(resourceKind==='html-policy')validatePolicyHtml(policyHtml);else if(policyHtml!==null)throw unavailable();
      await checkCurrent(value);
      return tx(async client => { await serializeTarget(client, value.targetId); await active(client, value); const operationId = uuid(randomUUID());
        const inserted = (await client.query(`INSERT INTO secureshop_agents.bound_ssrf_requests
          (operation_id,target_id,request_id,resource_kind,policy_html) VALUES($1,$2,$3,$4,$5)
          ON CONFLICT(target_id,request_id) DO NOTHING RETURNING *`, [operationId, value.targetId, requestId, resourceKind, policyHtml])).rows[0];
        const row = inserted || await readRequestWith(client, value, requestId);
        if (!row || row.resource_kind !== resourceKind || (row.policy_html ?? null)!==policyHtml) throw unavailable('Bound SSRF request conflict');
        return Object.freeze({ operationId: row.operation_id, targetId: row.target_id, requestId: row.request_id,
          resourceKind: row.resource_kind, ...(row.resource_kind==='html-policy'?{policyHtml:row.policy_html}:{}), nonce: row.nonce, url: row.issued_url,
          completed: row.completed === true, replayed: !inserted });
      });
    },
    async attachRequest(input, request) { const value = scope(input); await checkCurrent(value);
      const operationId = uuid(request?.operationId), requestId = uuid(request?.requestId), nonce = uuid(request?.nonce);
      if (typeof request?.url !== 'string' || request.url.length > 512) throw unavailable();
      return tx(async client => { await serializeTarget(client, value.targetId); await active(client, value); const row = (await client.query(`UPDATE secureshop_agents.bound_ssrf_requests
        SET nonce=$3,issued_url=$4 WHERE operation_id=$1 AND target_id=$2 AND request_id=$5 AND nonce IS NULL RETURNING *`,
      [operationId, value.targetId, nonce, request.url, requestId])).rows[0] || await readRequestWith(client, value, requestId);
      if (!row || row.operation_id !== operationId || row.nonce !== nonce || row.issued_url !== request.url) {
        throw unavailable('Bound SSRF request attachment conflict');
      }
      return Object.freeze({ operationId, targetId: value.targetId, requestId, resourceKind: row.resource_kind, ...(row.resource_kind==='html-policy'?{policyHtml:row.policy_html}:{}),
        nonce, url: request.url, completed: row.completed === true, replayed: row.nonce !== null }); });
    },
    async readRequest(input, { requestId } = {}) { const value = scope(input); await checkCurrent(value);
      const row = await tx(async client => { await serializeTarget(client, value.targetId); await active(client, value);
        return readRequestWith(client, value, uuid(requestId)); }); return row ? Object.freeze({ operationId: row.operation_id,
        targetId: row.target_id, requestId: row.request_id, resourceKind: row.resource_kind, ...(row.resource_kind==='html-policy'?{policyHtml:row.policy_html}:{}), nonce: row.nonce,
        url: row.issued_url, completed: row.completed === true }) : null;
    },
    async recordInvocation(input,record,inputPersona){return tx(client=>recordInvocationWithClient(client,input,record,inputPersona));},
    recordInvocationWithClient,
    async readInvocation(input, operationId) { const value = scope(input); await checkCurrent(value);
      const row = await readInvocationWith(pool, value, uuid(operationId));
      if (!row) throw unavailable(); return invocation(row);
    },
    async retire(input, data) { const value = scope(input); const cleanup = cleanupScope(value, data, { requireReceipt:true }); await checkCleanup(cleanup);
      const rows = (await pool.query(`SELECT * FROM secureshop_agents.retire_bound_ssrf_target
        ($1,$2,$3,$4,$5,$6,$7,decode($8,'hex'))`, [cleanup.operationId, ...scopeArgs(value), cleanup.receiptSha256])).rows;
      if (rows.length !== 1) throw unavailable(); return rows[0];
    },
    async readCleanupReceipt(input, data) { const value = scope(input); const cleanup = cleanupScope(value, data); await checkCleanup(cleanup);
      const row = (await pool.query(`SELECT r.*,encode(r.receipt_sha256,'hex') AS receipt_hex
        FROM secureshop_agents.bound_ssrf_cleanup_receipts r WHERE r.operation_id=$1 AND r.target_id=$2
        AND r.launch_id=$3 AND r.scenario_id=$4 AND r.generation=$5 AND r.original_platform_owner_id=$6
        AND r.original_platform_session_id=$7`, [cleanup.operationId, ...scopeArgs(value)])).rows[0];
      if (!row) throw unavailable(); return Object.freeze({ targetId:row.target_id,launchId:row.launch_id,scenarioId:row.scenario_id,
        fromGeneration:Number(row.generation),platformOwnerId:Number(row.original_platform_owner_id),
        platformSessionId:Number(row.original_platform_session_id),operationId:row.operation_id,targetReceiptVersion:1,
        targetReceiptSha256:row.receipt_hex,targetCompletedAt:new Date(row.completed_at).toISOString(),
        retainedRequestCount:Number(row.retained_request_count),retainedInvocationCount:Number(row.retained_invocation_count) });
    },
  });
}

module.exports = { createSecureShopBoundSsrfRepository };
