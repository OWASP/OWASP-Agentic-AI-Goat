'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const root = process.cwd();
const { createSceneBinding } = require(path.join(root, 'server/services/secureshopSceneBinding'));
const { createV01TeachingTokenAuthority } = require(path.join(root, 'server/services/secureshopV01TeachingToken'));
const { createV01CheckoutAuditLesson } = require(path.join(root, 'server/services/secureshopV01CheckoutAuditLesson'));
const { createCheckoutAuditReadStore } = require(path.join(root,
  'server/services/secureshopBoundReviewComposition'));

function fixture() {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 3,
    platformOwnerId: 19, platformSessionId: 23 };
  const storage = { ...scope, generation: 1, platformSessionId: 17 };
  const targetId = randomUUID(), sceneId = randomUUID();
  const target = createSceneBinding({ ...storage, targetId }, { sceneId, sceneGeneration: 2,
    grantId: randomUUID(), execution: scope, withLease: work => work() });
  const persona = { id: 41, role: 'customer' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '2' };
  const checkoutOperationId = randomUUID(), eventId = randomUUID(), requestId = randomUUID();
  const checkout = { operationId: checkoutOperationId, status: 'completed',
    order: { id: 83, total: 17.25 } };
  const paramsJson = JSON.stringify({ total: 17.25, shippingAddress: 'Synthetic private address',
    paymentMethod: 'synthetic_card', storageTargetId: targetId,
    sceneId, sceneGeneration: 2 });
  const row = { event_id: eventId, ts: '2026-10-15T02:02:02.000000Z', actor: 'customer',
    action: 'checkout', outcome: 'completed', target: '83', source_kind: 'order',
    source_id: '83', params_json: paramsJson, order_total: '17.25',
    payment_method: 'synthetic_card', shipping_address: 'Synthetic private address' };
  let mode = 'vuln', stale = false, rowMode = 'one', rowReads = 0,
    receiptReads = 0, grants = 0;
  const client = { async query(sql, values) {
    if (sql.includes('assert_scene_execution_grant')) { grants++; return { rows: [{ allowed: !stale }] }; }
    if (sql.includes('FROM secureshop_review.bound_audit_events e')) {
      rowReads++;
      assert.match(sql, /e\.original_platform_owner_id=\$4/);
      assert.match(sql, /e\.source_kind='order'/);
      assert.deepEqual(values.slice(0, 8), [scope.launchId, scope.scenarioId, scope.generation,
        scope.platformOwnerId, scope.platformSessionId, targetId, persona.id, checkout.order.id]);
      assert.equal(values[9], sceneId);
      assert.equal(values[10], 2);
      assert.deepEqual(values.slice(11), [storage.launchId, storage.scenarioId,
        storage.generation, storage.platformOwnerId, storage.platformSessionId]);
      return { rows: values[8] && values[8] !== eventId ? []
        : rowMode === 'missing' ? [] : rowMode === 'duplicate' ? [row, row] : [row] };
    }
    return { rows: [] };
  }, release() {} };
  const launches = {
    async assertCurrent(s) { assert.equal(s.launchId, scope.launchId); if (stale) throw Error('reset'); },
  };
  const auditStore = createCheckoutAuditReadStore({
    reviewPool: { query() {}, async connect() { return client; } }, launches,
  });
  const checkoutHistory = { async read(t, id, operationId) {
    receiptReads++;
    assert.equal(t, target); assert.equal(id, persona.id); assert.equal(operationId, checkoutOperationId);
    return checkout;
  } };
  const modeAuthority = { async capture() {
    const captured = mode;
    return { snapshot: { featureId: 'checkout_audit_jwt', mode: captured, scope },
      async assertCurrent() { if (stale || mode !== captured) throw Error('mode stale'); },
      async assertCurrentAtEffect() { if (stale || mode !== captured) throw Error('mode stale'); } };
  }, assertToken(token) { return token; } };
  const personaAuthority = { async capture(x) { return { binding: { ...x.scope,
    personaId: x.personaId, role: x.role, sessionId: x.sessionId,
    authorityVersion: x.authorityVersion },
    async assertRemoteAdmission() { if (stale) throw Error('persona stale'); } }; } };
  const secretMaterial = Buffer.alloc(32, 17);
  const lesson = createV01CheckoutAuditLesson({ secretMaterial, checkoutHistory,
    auditStore, launches,
    personaAuthority, modeAuthority, async resolveExistingTarget() { return target; } });
  const execution = { runId: randomUUID(), ownerKey: '["SecureShop",19]',
    durableGeneration: '3', async check() { if (stale) throw Error('reset'); } };
  const input = { scope, persona, personaSession, checkoutOperationId, requestId, execution };
  function observed(result, teachingToken) {
    const step = 1, callId = 'v01-model-call-1', tool = 'auth.audit_probe';
    return { index: 0, step, callId, tool,
      args: { checkoutOperationId, teachingToken },
      result: structuredClone(result),
      effectReceipt: { version: 1, status: 'completed', runId: execution.runId,
        ownerKey: execution.ownerKey, generation: execution.durableGeneration,
        effectKey: `${requestId}:${JSON.stringify([step, callId, tool])}` } };
  }
  return { scope, target, persona, checkout, eventId, row, lesson, input, observed,
    tokens: createV01TeachingTokenAuthority({ secretMaterial }),
    mode(value) { mode = value; }, stale(value = true) { stale = value; },
    rowMode(value) { rowMode = value; },
    counts() { return { rowReads, receiptReads, grants }; } };
}

function forgeNone(signed) {
  const [header, payload] = signed.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  claims.role = 'admin';
  return `${Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'none' })).toString('base64url')}.`
    + `${Buffer.from(JSON.stringify(claims)).toString('base64url')}.`;
}

function report(result) { return JSON.parse(result.content[0].text); }


const { createSecureShopV01AuditChat, V01_AUDIT_MANIFEST } = require(path.join(root,'server/services/secureshopV01AuditChat'));
const { POLICIES } = require(path.join(root,'server/services/secureshopFeatureModeAuthority'));
const { normalizeConversationPurpose } = require(path.join(root,'server/services/secureshopConversationPurpose'));
const { createTurnRequest } = require(path.join(root,'server/services/secureshopTurnRequest'));

test('V01 application stays a dedicated customer purpose and one declared tool', () => {
  assert.equal(normalizeConversationPurpose('secureshop_checkout_audit_jwt'),'secureshop_checkout_audit_jwt');
  assert.equal(POLICIES.checkout_audit_jwt,'owned-checkout-admin-audit-practice-jwt-v1');
  assert.deepEqual(V01_AUDIT_MANIFEST.map(row=>`${row.agent}.${row.tool}`),['auth.audit_probe']);
  assert.deepEqual(V01_AUDIT_MANIFEST[0].inputSchema,
    {type:'object',properties:{},required:[],additionalProperties:false});
});

test('V01 production HTTP chat route binds an empty model action to the immutable request and guarded audit read', async () => {
  const express=require('express');
  const {createBoundV01AuditLessonRouter}=require(path.join(root,
    'server/routes/secureshop/boundV01AuditLesson'));
  const f=fixture(), sessionId=randomUUID(), requestId=f.input.requestId;
  const signed=(await f.lesson.presentCustomerToken(f.input)).token, teachingToken=forgeNone(signed);
  const messages=[], traces=[], effects=[], completed=[]; let calls=0, modelCalls=0;
  let firstEnvelope=null, savedResult=null, chatMode='vuln', sceneCurrent=f.target;
  const binding={...f.scope,shopUserId:f.persona.id,role:'customer'};
  const repository={
    async getBoundSession(id){return {id,state:'active',purpose:'secureshop_checkout_audit_jwt',binding};},
    async appendMessage(_id,_binding,message){messages.push(message);},
    async getMessages(){return messages;},
    async getTokens(){return 0;},async addTokens(){},
    async appendTraces(_id,_binding,rows){traces.push(...rows);},
  };
  const journal={
    async claim(input){
      if(savedResult){
        if(input.message!==firstEnvelope) throw Object.assign(new Error('request changed'),{code:'TURN_REQUEST_CONFLICT'});
        return {status:'completed',result:savedResult};
      }
      firstEnvelope=input.message;return {status:'claimed',claimId:input.requestId};
    },
    async complete(value){completed.push(value);savedResult=value.result;},async markUncertain(){},
    async readV01AuditRequest(){return savedResult?{status:'completed',result_json:savedResult,
      request_version:1,request_hash:createTurnRequest({sessionId,requestId,binding,
        message:firstEnvelope}).hash}:null;},
  };
  const modeAuthority={async capture(scope,featureId){return {snapshot:{version:1,featureId,
    policyVersion:POLICIES[featureId],mode:chatMode,generation:scope.generation,
    modeStamp:'test',scope},async assertCurrent(){},async assertCurrentAtEffect(){}};},
    assertToken(value){return value;}};
  const personaAuthority={capture({scope,personaId,role,sessionId,authorityVersion}){return {
    binding:{...scope,personaId,role,sessionId,authorityVersion},
    async assertRemoteAdmission(){}, async withPersonaEffect(work){return work({query(){}});}};}};
  const coordinator={async run(_id,options,operation){return operation({
    runId:f.input.execution.runId,ownerKey:f.input.execution.ownerKey,
    generation:'3',durableGeneration:f.input.execution.durableGeneration,
    async check(){},async effectWithReceipt(node,work){effects.push(node);return {value:await work(),receipt:{
      version:1,status:'completed',runId:f.input.execution.runId,
      ownerKey:f.input.execution.ownerKey,generation:f.input.execution.durableGeneration,
      effectKey:`${options.idempotencyKey}:${node}`}};},
  });}};
  const provider={async chat(){modelCalls++;return {stop_reason:'tool_use',tool_uses:[{
    id:'selected-v01-call',name:'auth.audit_probe',args:{}}]};},
    async finalResponse(){calls++;return {stop_reason:'end_turn',text:'Observed the protected audit report.',responseMode:'structured_final'};}};
  const launches={async assertCurrent(){},async resolveCapability(){return f.scope;}};
  const chat=createSecureShopV01AuditChat({launches,personaAuthority,
    modeAuthority,conversations:repository,journal,coordinator,provider,
    scenes:{async readExisting(){return sceneCurrent;}},lesson:f.lesson});
  const router=createBoundV01AuditLessonRouter({launches,
    authenticatePersona(req,_res,next){req.ssUser=f.persona;
      req.ssPersonaSession=f.input.personaSession;next();},runtime:chat,
    assessment:{async runAttempt(){throw Error('assessment unused');},
      async readOutcome(){throw Error('assessment unused');}}});
  const app=express();app.use(express.json());app.use('/api/secureshop',router);
  const server=app.listen(0);
  const body={sessionId,requestId,checkoutOperationId:f.input.checkoutOperationId,
    teachingToken,message:'Read the protected audit for my checkout.'};
  try {
    const response=await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/agents/customer/checkout-audit/chat`,{
      method:'POST',headers:{'content-type':'application/json',
        'x-owasp-ai-goat-secureshop-launch':'a'.repeat(43)},body:JSON.stringify(body)});
    assert.equal(response.status,200);assert.match(response.headers.get('content-type')||'',/^text\/event-stream/);
    const stream=await response.text();assert.match(stream,/event: assistant_message/);
    assert.match(stream,/event: done/);assert.match(stream,/\"params\":\{\}/);
    assert.match(stream,/\\\"status\\\":\\\"disclosed\\\"/);
    for(const privateValue of ['sourceSha256','originalEnvelope','platformSessionId',teachingToken])
      assert.equal(stream.includes(privateValue),false,`SSE exposed ${privateValue}`);
  } finally { await new Promise(resolve=>server.close(resolve)); }
  const outcome=savedResult;
  assert.equal(outcome.stopReason,'end_turn');
  assert.equal(calls,1);assert.equal(effects.length,1);
  assert.equal(effects[0],JSON.stringify([1,'selected-v01-call','auth.audit_probe']));
  assert.equal(completed.length,1);
  assert.equal(outcome.taskMetadata.checkoutAuditJwt.state,'observed');
  assert.equal(outcome.taskMetadata.checkoutAuditJwt.version,2);
  assert.deepEqual(outcome.hops[0].params,{});
  const evidence=outcome.taskMetadata.checkoutAuditJwt.originalEvidence;
  assert.equal(evidence.eventId,f.eventId);
  assert.equal(evidence.effectReceipt.effectKey,`${requestId}:${effects[0]}`);
  assert.equal(outcome.taskMetadata.checkoutAuditJwt.originalEnvelope.includes(teachingToken),true);
  assert.equal(JSON.stringify(outcome).includes('platformSessionId'),true); // private service result, not route projection
  const saved=await chat.readRequest({scope:f.scope,persona:f.persona,personaSession:f.input.personaSession,
    sessionId,requestId});
  assert.equal(saved.status,'completed');assert.equal(saved.result.status,'disclosed');
  assert.equal(saved.result.eventId,f.eventId);assert.equal(saved.result.report.orderId,f.checkout.order.id);
  assert.equal(JSON.stringify(saved).includes(teachingToken),false);
  assert.equal(JSON.stringify(saved).includes('sourceSha256'),false);
  assert.equal(JSON.stringify(saved).includes('platformSessionId'),false);
  const replay=await chat.run({scope:f.scope,persona:f.persona,personaSession:f.input.personaSession,
    sessionId,requestId,checkoutOperationId:f.input.checkoutOperationId,teachingToken,
    message:'Read the protected audit for my checkout.'});
  assert.equal(replay.replayed,true);assert.equal(modelCalls,1);assert.equal(effects.length,1);
  chatMode='fixed';
  await assert.rejects(chat.readRequest({scope:f.scope,persona:f.persona,personaSession:f.input.personaSession,
    sessionId,requestId}));
  await assert.rejects(chat.run({scope:f.scope,persona:f.persona,personaSession:f.input.personaSession,
    sessionId,requestId,checkoutOperationId:f.input.checkoutOperationId,teachingToken,
    message:'Read the protected audit for my checkout.'}),{code:'TURN_REQUEST_CONFLICT'});
  chatMode='vuln';
  sceneCurrent=createSceneBinding({...f.target,scene:undefined},{sceneId:randomUUID(),sceneGeneration:3,
    grantId:randomUUID(),execution:f.scope,withLease:work=>work()});
  await assert.rejects(chat.run({scope:f.scope,persona:f.persona,personaSession:f.input.personaSession,
    sessionId,requestId,checkoutOperationId:f.input.checkoutOperationId,teachingToken,
    message:'Read the protected audit for my checkout.'}),{code:'TURN_REQUEST_CONFLICT'});
  await assert.rejects(chat.readRequest({scope:f.scope,persona:f.persona,personaSession:f.input.personaSession,
    sessionId,requestId}));
  assert.equal(modelCalls,1);assert.equal(effects.length,1);assert.equal(completed.length,1);
});
