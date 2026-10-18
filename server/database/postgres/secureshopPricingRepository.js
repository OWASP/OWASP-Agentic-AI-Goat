'use strict';

// Unregistered candidate durable admission/receipt storage; external execution never occurs here.
const {
  createLaunchScope,
  createConversationBinding
} = require('../../services/secureshopConversationBinding');
const {
  canonicalDigest
} = require('../../services/mcp/protocolContext');
const {
  randomUUID,
  randomBytes
} = require('node:crypto');
const {
  request: normalizeRequest,
  requestDigest,
  TASK_ROLE,
  UUID
} = require('../../services/secureshopPricingContract');
const {
  targetSnapshot,
  executionReceipt,
  pricingDenialReceipt
} = require('../../services/secureshopPricingReceipt');
const { withSceneLease } = require('../../services/secureshopSceneBinding');
const C = 'platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';
const W = C.split(',').map((column, index) => `${column}=$${index + 1}`).join(' AND ');
const T = 'secureshop_agents.bound_pricing_';
const fail = code => Object.assign(new Error('Bound pricing unavailable'), {
  code
});
const values = x => [x.scope.launchId, x.scope.scenarioId, x.scope.generation, x.scope.platformOwnerId, x.scope.platformSessionId];
function snapshot(raw, withRequest = true, withOperation = true) {
  const x = structuredClone(raw);
  if (Object.hasOwn(x, 'targetId') || Object.hasOwn(x, 'request') || Object.hasOwn(x, 'digest') || Object.hasOwn(x, 'targetSnapshot') || Object.hasOwn(x, 'canary')) throw fail('INVALID_ARGUMENT');
  x.scope = createLaunchScope(x.scope);
  createConversationBinding(x.scope, x.persona);
  if (!['customer', 'merchant'].includes(x.persona.role)) throw fail('PRICING_ROLE_REQUIRED');
  if (!UUID.test(x.personaSession?.sessionId) || typeof x.personaSession?.authorityVersion !== 'string' || !/^[1-9]\d{0,15}$/.test(x.personaSession.authorityVersion) || BigInt(x.personaSession.authorityVersion) > 9007199254740991n) throw fail('SHOP_AUTH_INVALID');
  if (withOperation && !UUID.test(x.operationId)) throw fail('INVALID_ARGUMENT');
  if (withRequest) {
    x.request = normalizeRequest({
      operationId: x.operationId,
      task: x.task,
      productId: x.productId,
      message: x.message,
      ...(Object.hasOwn(x,'experiment')?{experiment:x.experiment}:{}),
      ...(Object.hasOwn(x,'competitorUrl')?{competitorUrl:x.competitorUrl}:{})
    });
    x.digest = requestDigest(x.request);
    if (TASK_ROLE[x.task] !== x.persona.role) throw fail('PRICING_ROLE_REQUIRED');
  }
  return x;
}
function bindingDigest(x, request, targetId, runId, snapshot) {
  return canonicalDigest({
    scope: x.scope,
    persona: {
      id: x.persona.id,
      role: x.persona.role
    },
    personaSession: {
      sessionId: x.personaSession.sessionId,
      authorityVersion: x.personaSession.authorityVersion
    },
    targetId,
    runId,
    targetSnapshot: snapshot,
    request
  });
}
function createPricingRepository({
  pool,
  personaAuthority,
  audit,
  checkRunBinding,
  captureTarget
} = {}) {
  if (typeof pool?.query !== 'function' || typeof personaAuthority?.capture !== 'function' || typeof audit?.append !== 'function' || typeof checkRunBinding !== 'function' || typeof captureTarget !== 'function') throw TypeError('Trusted pricing repository dependencies required');
  async function transaction(x, work, write = false) {
    const expected = {
      ...x.scope,
      personaId: x.persona.id,
      role: x.persona.role,
      sessionId: x.personaSession.sessionId,
      authorityVersion: x.personaSession.authorityVersion
    };
    const fence = await personaAuthority.capture({
      scope: x.scope,
      personaId: x.persona.id,
      role: x.persona.role,
      sessionId: x.personaSession.sessionId,
      authorityVersion: x.personaSession.authorityVersion
    });
    if (!fence?.binding || Object.keys(expected).some(k => fence.binding[k] !== expected[k]) || typeof fence.withPersonaEffect !== 'function' || typeof fence.assertRemoteAdmission !== 'function') throw fail('SHOP_AUTH_INVALID');
    let completed = false;
    try {
      const result = await fence.withPersonaEffect(async client => {
        await client.query("SET LOCAL statement_timeout='3000ms'");
        await client.query("SET LOCAL lock_timeout='3000ms'");
        // Authority holds canonical owner→launch/persona locks first. The same
        // scope lock is also enforced by INSERT triggers for direct SQL writes.
        await client.query("SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(':','secureshop-pricing',$1::text,$2::text,$3::text,$4::text,$5::text),0))", values(x));
        const value = await work(client);
        completed = true;
        return value;
      });
      await fence.assertRemoteAdmission();
      return result;
    } catch (cause) {
      if (write && completed) throw fail('PRICING_OUTCOME_UNCERTAIN');
      throw cause;
    }
  }
  async function admission(client, x, required = false) {
    const row = (await client.query(`SELECT * FROM ${T}admissions WHERE ${W} AND operation_id=$6`, [...values(x), x.operationId])).rows[0];
    if (!row) {
      if (required) throw fail('PRICING_NOT_FOUND');
      return null;
    }
    if (Number(row.persona_id) !== x.persona.id || row.persona_role !== x.persona.role || row.persona_session_id !== x.personaSession.sessionId || String(row.authority_version) !== x.personaSession.authorityVersion) throw fail('OPERATION_CONFLICT');
    if (!row.request_json || !UUID.test(row.target_id) || !UUID.test(row.run_id)) throw fail('PRICING_RETIRED');
    const request = normalizeRequest(row.request_json),
      digest = requestDigest(request);
    if (request.operationId !== x.operationId || row.request_sha256.toString('hex') !== digest || row.binding_sha256.toString('hex') !== bindingDigest(x, request, row.target_id, row.run_id, targetSnapshot(row.target_snapshot_json, request.productId))) throw fail('PRICING_INTEGRITY_UNAVAILABLE');
    if (x.digest && x.digest !== digest) throw fail('OPERATION_CONFLICT');
    return row;
  }
  async function outcome(client, x, row) {
    const result = (await client.query(`SELECT * FROM ${T}outcomes WHERE ${W} AND operation_id=$6`, [...values(x), x.operationId])).rows[0];
    const base = {
      runId: row.run_id,
      operationId: x.operationId,
      requestSha256: row.request_sha256.toString('hex'),
      targetId: row.target_id
    };
    if (!result) return {
      state: 'pending',
      ...base
    };
    if (Number(result.persona_id) !== x.persona.id || result.persona_role !== x.persona.role || result.persona_session_id !== x.personaSession.sessionId || String(result.authority_version) !== x.personaSession.authorityVersion || result.run_id !== row.run_id || !result.request_sha256.equals(row.request_sha256) || !result.binding_sha256.equals(row.binding_sha256)) throw fail('PRICING_INTEGRITY_UNAVAILABLE');
    if (['unknown', 'not_executed'].includes(result.state) && result.receipt_json === null && result.receipt_sha256 === null) return {
      state: result.state,
      ...base
    };
    if (!['completed','blocked'].includes(result.state) || !result.receipt_json || canonicalDigest(result.receipt_json) !== result.receipt_sha256?.toString('hex')) throw fail('PRICING_INTEGRITY_UNAVAILABLE');
    const capturedTarget=targetSnapshot(row.target_snapshot_json,row.request_json.productId);
    const expected={targetId:row.target_id,operationId:x.operationId,runId:row.run_id,requestSha256:row.request_sha256.toString('hex'),task:row.request_json.task,productId:row.request_json.productId,product:capturedTarget.product,manual:capturedTarget.manual,
      ...(Object.hasOwn(row.request_json,'competitorUrl')?{competitorUrl:row.request_json.competitorUrl}:{}),
      ...(Object.hasOwn(row.request_json,'experiment')?{experiment:row.request_json.experiment}:{})};
    const receipt=result.state==='blocked'?pricingDenialReceipt(result.receipt_json,expected):executionReceipt(result.receipt_json,expected);
    const purposes=require('../../services/secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES;
    const modeCapability=await require('./secureshopTurnModeProjection').readTurnModeProjection(client,{scope:x.scope,persona:x.persona,requestId:x.operationId,
      purpose:row.request_json.task==='price-advisor'?purposes.priceAdvisor:purposes.pricingStrategy,message:row.request_json.message,featureId:'pricing',
      expectedStopReason:result.state==='blocked'?'tool_denied':'end_turn',
      verifyResult:turn=>(result.state!=='blocked'||turn.taskMetadata?.state==='blocked')&&turn.taskMetadata?.operationId===x.operationId&&turn.taskMetadata?.requestSha256===row.request_sha256.toString('hex')&&turn.taskMetadata?.receiptSha256===canonicalDigest(receipt)});
    return {
      state: result.state,
      ...base,
      ...(modeCapability?{modeCapability}:{}),
      receipt
    };
  }
  async function auditOutcome(client, x, state, receipt) {
    // Audit enum describes the observation; terminal protocol state remains metadata.
    const auditState = state === 'completed' ? 'completed' : 'failed';
    await audit.append(client, {
      eventId: x.operationId,
      scope: x.scope,
      persona: x.persona,
      actor: x.persona.role,
      action: 'pricing_execution',
      target: x.operationId,
      paramsJson: JSON.stringify({
        operationId: x.operationId,
        requestSha256: x.digest,
        state,
        receiptSha256: receipt ? canonicalDigest(receipt) : null
      }),
      outcome: auditState,
      sourceKind: 'pricing_execution',
      sourceId: x.operationId
    });
  }
  async function finish(raw, state) {
    const x = snapshot(raw);
    let receipt = null;
    return transaction(x, async client => {
      const row = await admission(client, x, true),
        existing = await outcome(client, x, row);
      if (x.runId !== row.run_id) throw fail('OPERATION_CONFLICT');
      receipt = state === 'completed' ? executionReceipt(x.receipt, {
        targetId: row.target_id,
        operationId: x.operationId,
        runId: row.run_id,
        requestSha256: x.digest,
        task: x.task,
        productId: x.productId,
        product: targetSnapshot(row.target_snapshot_json,x.productId).product,
        manual: targetSnapshot(row.target_snapshot_json,x.productId).manual,
        ...(Object.hasOwn(x.request,'competitorUrl')?{competitorUrl:x.request.competitorUrl}:{}),
        ...(x.request.experiment?{experiment:x.request.experiment}:{})
      }) : state === 'blocked' ? pricingDenialReceipt(x.receipt, {
        targetId: row.target_id,
        operationId: x.operationId,
        runId: row.run_id,
        requestSha256: x.digest,
        productId: x.productId,
        ...(Object.hasOwn(x.request,'competitorUrl')?{competitorUrl:x.request.competitorUrl}:{})
      }) : null;
      if (existing.state === 'completed') {
        if (state === 'completed' && canonicalDigest(existing.receipt) !== canonicalDigest(receipt)) throw fail('OPERATION_CONFLICT');
        return existing;
      }
      if (existing.state === 'blocked') {
        if (state === 'blocked' && canonicalDigest(existing.receipt) !== canonicalDigest(receipt)) throw fail('OPERATION_CONFLICT');
        return existing;
      }
      if (['unknown', 'not_executed'].includes(existing.state)) {
        if (state === 'completed' || state === 'blocked') throw fail('PRICING_OUTCOME_UNCERTAIN');
        return existing;
      }
      if ((state === 'completed' || state === 'blocked') && (await checkRunBinding(client, {
        ...x,
        runId: row.run_id
      })) !== true) throw fail('PRICING_RUN_AUTHORITY_UNAVAILABLE');
      await client.query(`INSERT INTO ${T}outcomes (${C},operation_id,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,state,receipt_json,receipt_sha256,run_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,decode($11,'hex'),decode($12,'hex'),$13,$14::jsonb,decode($15,'hex'),$16)`, [...values(x), x.operationId, x.persona.id, x.personaSession.sessionId, x.persona.role, x.personaSession.authorityVersion, x.digest, bindingDigest(x, x.request, row.target_id, row.run_id, row.target_snapshot_json), state, receipt ? JSON.stringify(receipt) : null, receipt ? canonicalDigest(receipt) : null, row.run_id]);
      await auditOutcome(client, x, state, receipt);
      return {
        state,
        runId: row.run_id,
        operationId: x.operationId,
        requestSha256: x.digest,
        targetId: row.target_id,
        ...(receipt ? {
          receipt
        } : {})
      };
    }, true);
  }
  return Object.freeze({
    // Server-only assessment read. This private projection is never a route DTO.
    async readAssessment(raw) {
      const x = snapshot(raw);
      return transaction(x, async client => {
        const row = await admission(client, x, true);
        if (row.run_id !== x.runId || await checkRunBinding(client, x) !== true) throw fail('PRICING_RUN_UNAVAILABLE');
        const completed = await outcome(client, x, row);
        if (!['completed','blocked'].includes(completed.state)) throw fail('PRICING_OUTCOME_UNAVAILABLE');
        return Object.freeze({ request: structuredClone(row.request_json),
          targetSnapshot: targetSnapshot(row.target_snapshot_json, row.request_json.productId),
          ...completed });
      });
    },
    async administration(raw) {
      const x = snapshot(raw, false, false);
      return transaction(x, async () => Object.freeze({
        scopeKey: canonicalDigest({
          version: 'secureshop-pricing-administration.v1',
          scope: x.scope,
          persona: {
            id: x.persona.id,
            role: x.persona.role
          },
          personaSession: {
            sessionId: x.personaSession.sessionId,
            authorityVersion: x.personaSession.authorityVersion
          }
        })
      }));
    },
    async begin(raw, preparedTarget) {
      const x = snapshot(raw);
      const effect = () => transaction(x, async client => {
        const row = await admission(client, x);
        if (row) return outcome(client, x, row);
        const count = Number((await client.query(`SELECT count(*) AS n FROM ${T}admissions WHERE ${W}`, values(x))).rows[0]?.n);
        if (!Number.isInteger(count) || count >= 128) throw fail('PRICING_QUOTA_EXCEEDED');
        const pending = Number((await client.query(`SELECT count(*) AS n FROM ${T}admissions a WHERE ${W.split(' AND ').map(v => 'a.' + v).join(' AND ')} AND persona_session_id=$6 AND NOT EXISTS(SELECT 1 FROM ${T}outcomes o WHERE (o.platform_launch_id,o.platform_scenario_id,o.platform_launch_generation,o.original_platform_owner_id,o.original_platform_session_id,o.operation_id)=(a.platform_launch_id,a.platform_scenario_id,a.platform_launch_generation,a.original_platform_owner_id,a.original_platform_session_id,a.operation_id))`, [...values(x), x.personaSession.sessionId])).rows[0]?.n);
        if (!Number.isInteger(pending) || pending >= 8) throw fail('PRICING_QUOTA_EXCEEDED');
        if (!UUID.test(x.runId) || (await checkRunBinding(client, x)) !== true) throw fail('PRICING_RUN_AUTHORITY_UNAVAILABLE');
        const captured = await captureTarget(client, structuredClone(x), preparedTarget);
        const target = targetSnapshot({
          version: 1,
          product: captured?.product,
          manual: captured?.manual,
          canary: randomBytes(32).toString('hex')
        }, x.productId);
        if ((await checkRunBinding(client, x)) !== true) throw fail('PRICING_RUN_AUTHORITY_UNAVAILABLE');
        const targetId = randomUUID();
        await client.query(`INSERT INTO ${T}admissions (${C},operation_id,persona_id,persona_session_id,persona_role,authority_version,request_sha256,binding_sha256,request_json,target_id,run_id,target_snapshot_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,decode($11,'hex'),decode($12,'hex'),$13::jsonb,$14::uuid,$15::uuid,$16::jsonb)`, [...values(x), x.operationId, x.persona.id, x.personaSession.sessionId, x.persona.role, x.personaSession.authorityVersion, x.digest, bindingDigest(x, x.request, targetId, x.runId, target), JSON.stringify(x.request), targetId, x.runId, JSON.stringify(target)]);
        return {
          state: 'admitted',
          operationId: x.operationId,
          requestSha256: x.digest,
          targetId,
          runId: x.runId,
          targetSnapshot: target
        };
      }, true);
      return preparedTarget === undefined ? effect() : withSceneLease(preparedTarget, effect);
    },
    complete: raw => finish(raw, 'completed'),
    block: raw => finish(raw, 'blocked'),
    markUnknown: raw => finish(raw, 'unknown'),
    markNotExecuted: raw => finish(raw, 'not_executed'),
    async assertCurrent(raw, expectedTargetId) {
      const x = snapshot(raw);
      await transaction(x, async client => {
        const row = await admission(client, x, true);
        if (!UUID.test(expectedTargetId) || row.target_id !== expectedTargetId || x.runId !== row.run_id) throw fail('OPERATION_CONFLICT');
        if ((await checkRunBinding(client, {
          ...x,
          runId: row.run_id
        })) !== true) throw fail('PRICING_RUN_AUTHORITY_UNAVAILABLE');
        if ((await outcome(client, x, row)).state !== 'pending') throw fail('PRICING_OPERATION_TERMINAL');
      });
    },
    async operation(raw) {
      const x = snapshot(raw, false);
      return transaction(x, async client => {
        const row = await admission(client, x);
        return row ? outcome(client, x, row) : {
          state: 'not_found',
          operationId: x.operationId
        };
      });
    },
    async checkReadiness() {
      return require('./secureshopPricingReadiness').assertPricingReadiness(pool);
    }
  });
}
module.exports = {
  createPricingRepository
};
