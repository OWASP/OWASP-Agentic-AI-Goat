'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { prepareListingAdmission, rewriteReceipt, hash, assertListingTransition, importReceipt } = require('../server/services/secureshopListingJournalContract');
const { createListingJournalRepository } = require('../server/database/postgres/secureshopListingJournalRepository');
function input(action = 'rewrite') {
  return { scope: { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 },
    persona: { id: 3, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' },
    targetId: randomUUID(), mode: 'vuln', catalogRevision: '0',
    request: action === 'rewrite' ? { version: 1, action, operationId: randomUUID(), title: 'Product', description: '<img src=x onerror=owned()>' }
      : { version: 1, action, operationId: randomUUID(), json_url: 'http://supplier/catalog', xml_url: null } };
}
function receipt(raw) {
  const x = prepareListingAdmission(raw), html = '<img src=x onerror=owned()>';
  return { version: 1, operationId: x.request.operationId, requestSha256: x.requestSha256,
    sourceSha256: hash(JSON.stringify([x.request.title, x.request.description])), provider: 'ollama', model: 'llama3.1:8b',
    callId: 'controlled-call', mocked: false, fallback: false, html, htmlSha256: hash(html) };
}
// Controlled SQL adapter verifies repository behavior, not PostgreSQL DDL/privileges.
function fixture({ mismatch = false, commitThrows = false, rollbackThrows = false, validateImportReceipt, wrapCrossStoreErrors = false, revokeAfterEffect = false, resolveTarget, sceneAllowed = true } = {}) {
  const sceneAdmissions=new Map();
  const admissions = new Map(), events = [], queries = [], releases = [];
  const pool = { async connect() { return {
    release(damaged) { releases.push(damaged); },
    async query(sql, values = []) {
      queries.push([sql, values]);
      if (sql === 'COMMIT' && commitThrows) throw new Error('connection lost');
      if (sql === 'ROLLBACK' && rollbackThrows) throw new Error('connection lost');
      if (sql.startsWith('SELECT newly_admitted FROM secureshop_review.admit_owned_listing_')) {
        if (admissions.has(values[0])) return { rows: [{newly_admitted:false}] };
        if(values.length===9)sceneAdmissions.set(values[0],{grant_id:values[8],target_id:values[1],merchant_id:JSON.parse(values[2]).persona.id,binding_sha256:values[3]});
        admissions.set(values[0], { operation_id: values[0], target_id: values[1], binding_json: values[2], binding_sha256: values[3], request_json: values[4], request_sha256: values[5], action: values[6] });
        return { rows: [{ newly_admitted: true }] };
      }
      if(sql.includes('assert_scene_execution_grant'))return{rows:[{allowed:sceneAllowed}]};
      if(sql.includes('FROM secureshop_review.owned_listing_scene_admissions'))return{rows:sceneAdmissions.has(values[0])?[sceneAdmissions.get(values[0])]:[]};
      if(sql.startsWith('SELECT secureshop_review.publish_owned_listing_import')){
        const a=admissions.get(values[0]),previous=events.filter(e=>e.operation_id===values[0]).at(-1),effect=JSON.parse(previous.payload_json);
        const result={version:1,operationId:values[0],requestSha256:a.request_sha256,executorReceiptSha256:effect.executorReceiptSha256,importReceiptSha256:previous.payload_sha256,productIds:effect.products.map((_,i)=>100+i),catalogRevision:'1'};
        const payload_json=JSON.stringify(result);
        events.push({operation_id:values[0],event_id:values[1],sequence:values[2]+1,state:'completed',payload_json,payload_sha256:hash(payload_json)});
        return {rows:[]};
      }
      if (sql.startsWith('SELECT * FROM secureshop_review.owned_listing_admissions')) return { rows: admissions.has(values[0]) ? [admissions.get(values[0])] : [] };
      if (sql.startsWith('SELECT secureshop_review.append_owned_listing_event')) {
        events.push({ operation_id: values[0], event_id: values[1], sequence: values[2], state: values[3], payload_json: values[4], payload_sha256: values[5] }); return { rows: [] };
      }
      if (sql.startsWith('SELECT * FROM secureshop_review.owned_listing_events')) {
        const rows = events.filter(e => e.operation_id === values[0] && (!values[1] || e.event_id === values[1])).sort((a,b) => b.sequence-a.sequence);
        return { rows: sql.includes('sequence ASC') ? rows.reverse() : rows.slice(0,1) };
      }
      return { rows: [] };
    },
  }; } };
  let authorityHeld=false,effectCompleted=false;
  const authority = { capture(value) { return { binding: { ...value.scope, personaId: mismatch ? 999 : value.personaId, role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion },
    async assertRemoteAdmission() { assert.equal(authorityHeld,false,'must not re-enter an exclusive authority lease');if(revokeAfterEffect&&effectCompleted)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_REVOKED'}); }, async withCrossStoreEffect(fn) { authorityHeld=true;try{return await fn({ query() { throw new Error('Agents connection must never receive review SQL'); } });}catch(cause){if(wrapCrossStoreErrors)throw Object.assign(new Error('Separate-store uncertainty'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',cause});throw cause;}finally{authorityHeld=false;effectCompleted=true;} } }; } };
  return { repository: createListingJournalRepository({ pool, personaAuthority: authority, capabilityKey:Buffer.alloc(32,7),validateImportReceipt,resolveTarget }), sceneAdmissions, admissions, events, queries, releases };
}
test('immutable admission binds mode, source, target and exact persona session', () => {
  const raw = input(), x = prepareListingAdmission(raw);
  raw.scope.generation = 9; raw.request.description = 'changed'; raw.personaSession.authorityVersion = '4';
  assert.equal(x.binding.scope.generation, 1); assert.equal(x.binding.personaSession.authorityVersion, '1');
  assert.match(x.request.description, /onerror/); assert.equal(hash(x.requestJson), x.requestSha256);
  assert.throws(() => prepareListingAdmission({ ...input(), mode: 'mock' }), { code: 'INVALID_ARGUMENT' });
});
test('rewrite requires exact input and output provenance; HTML remains verbatim', () => {
  const raw = input(), x = prepareListingAdmission(raw), r = receipt(raw);
  assert.equal(rewriteReceipt(r,x).html,r.html);
  for (const patch of [{ mocked:true },{ fallback:true },{ sourceSha256:'0'.repeat(64) },{ html:'changed' },{ operationId:randomUUID() }]) {
    assert.throws(() => rewriteReceipt({ ...r,...patch },x));
  }
  assert.throws(() => rewriteReceipt({ ...r,provider:'mock' },x), { code:'LISTING_MODEL_REQUIRED' });
});
test('same operation admits once; changed source/session/mode conflicts', async () => {
  const f=fixture(), raw=input();
  assert.equal((await f.repository.admit(raw)).newlyAdmitted,true);
  assert.equal((await f.repository.admit(raw)).newlyAdmitted,false);
  for (const patch of [{mode:'fixed'}, {personaSession:{...raw.personaSession,sessionId:randomUUID()}}, {request:{...raw.request,description:'other'}}]) {
    await assert.rejects(f.repository.admit({...raw,...patch}),{code:'LISTING_OPERATION_CONFLICT'});
  }
  assert.equal(f.admissions.size,1);
});
test('unknown remains recoverable without re-dispatch; exact rewrite completion replay', async () => {
  const f=fixture(), raw=input(), r=receipt(raw);
  await f.repository.admit(raw);
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'unknown'});
  await assert.rejects(f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:2,state:'running'}),{code:'LISTING_STATE_CONFLICT'});
  assert.equal((await f.repository.get(raw)).state,'unknown');
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:2,state:'effect_received',receipt:r});
  const done={eventId:randomUUID(),expectedSequence:3,state:'completed',receipt:r};
  assert.equal((await f.repository.transition(raw,done)).state,'completed');
  assert.equal((await f.repository.transition(raw,done)).state,'completed');
  assert.equal(f.events.length,4);
  await assert.rejects(f.repository.transition(raw,{...done,receipt:{...r,callId:'other'}}),{code:'LISTING_OPERATION_CONFLICT'});
});
test('mismatched persona fence never opens review connection', async () => {
  const f=fixture({mismatch:true}); await assert.rejects(f.repository.admit(input()),{code:'SHOP_AUTH_INVALID'});
  assert.equal(f.queries.length,0);
});
test('commit uncertainty is not reported as definite failure and broken clients discarded', async () => {
  const f=fixture({commitThrows:true,rollbackThrows:true});
  await assert.rejects(f.repository.admit(input()),{code:'LISTING_OUTCOME_UNCERTAIN'});
  assert.deepEqual(f.releases,[true]);
});
test('import publication unavailable; uncertain dispatch cannot become local failure', async () => {
  const f=fixture(),raw=input('import'); await f.repository.admit(raw);
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
  await assert.rejects(f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'failed',receipt:{code:'MODEL_UNAVAILABLE'}}),{code:'LISTING_STATE_CONFLICT'});
  await assert.rejects(f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'effect_received',receipt:{}}),{code:'LISTING_PUBLICATION_UNAVAILABLE'});
  assert.doesNotThrow(()=>assertListingTransition('effect_received','completed','import')); // Only dedicated SQL publication can write it.
});

test('opaque-ID recovery uses original admission, not caller request or later persona session', async () => {
  const f=fixture(), raw=input(); await f.repository.admit(raw);
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
  const recovery={scope:raw.scope,persona:raw.persona,personaSession:raw.personaSession,operationId:raw.request.operationId};
  const before=f.events.length;
  assert.equal((await f.repository.recover(recovery)).state,'running');
  assert.equal(f.events.length,before);
  await assert.rejects(f.repository.recover({...recovery,personaSession:{...raw.personaSession,sessionId:randomUUID()}}),{code:'LISTING_NOT_FOUND'});
  await assert.rejects(f.repository.recover({...recovery,request:raw.request}),{code:'INVALID_ARGUMENT'});
});

test('recovery checks full contiguous history, not only a plausible last receipt', async () => {
  const f=fixture(), raw=input(), r=receipt(raw); await f.repository.admit(raw);
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'effect_received',receipt:r});
  f.events.splice(0,1);
  await assert.rejects(f.repository.get(raw),{code:'LISTING_INTEGRITY_UNAVAILABLE'});
});
test('redacted admission never exposes preserved private request or receipt', async () => {
  const f=fixture(),raw=input();await f.repository.admit(raw);
  f.admissions.get(raw.request.operationId).redacted_at=new Date();
  await assert.rejects(f.repository.get(raw),{code:'LISTING_RETIRED'});
});
test('runtime writes use only capability-gated functions and omit capability from DTOs', async () => {
  const f=fixture(),raw=input(), admitted=await f.repository.admit(raw);
  await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
  assert.equal(f.queries.some(([sql])=>/^INSERT INTO/.test(sql)),false);
  const call=f.queries.find(([sql])=>sql.includes('append_owned_listing_event'));
  assert.match(call[1][6],/^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(admitted).includes(call[1][6]),false);
});

function imported(raw){
 const x=prepareListingAdmission(raw);
 return {version:1,operationId:x.request.operationId,requestSha256:x.requestSha256,executorReceiptSha256:'a'.repeat(64),
 sources:[{url:raw.request.json_url,status:'completed',sourceSha256:'b'.repeat(64),byteCount:100,parserEvidenceSha256:'c'.repeat(64),entityReads:[],prototypeEffect:{observed:true,inheritedProperties:[{name:'teaching',valueSha256:'d'.repeat(64)}]}}],
 products:[{name:'Imported',description:'<img src=x onerror=owned()>',price:4.25,category:null,images:[],templateSource:null}]};
}
test('import normalized receipt preserves parser effects and requires every source and closed product rows',()=>{
 const raw=input('import'),x=prepareListingAdmission(raw),r=imported(raw);
 assert.equal(importReceipt(r,x).sources[0].prototypeEffect.observed,true);
 for(const broken of [{...r,products:[{...r.products[0],retailer_id:999}]},{...r,sources:[]},{...r,products:[{...r.products[0],price:Infinity}]},{...r,sources:[{...r.sources[0],status:'failed'}]}])assert.throws(()=>importReceipt(broken,x));
});
test('import publish consumes stored attested rows once through single SQL publication primitive',async()=>{
 const raw=input('import'),r=imported(raw),f=fixture({validateImportReceipt:async receipt=>receipt});
 await f.repository.admit(raw);
 await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
 await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'effect_received',receipt:r});
 r.products[0].name='caller mutation';
 const operation={eventId:randomUUID(),expectedSequence:2};
 assert.deepEqual((await f.repository.publishImport(raw,operation)).receipt.productIds,[100]);
 assert.deepEqual((await f.repository.publishImport(raw,operation)).receipt.productIds,[100]);
 const calls=f.queries.filter(([sql])=>sql.includes('publish_owned_listing_import'));
 assert.equal(calls.length,1);assert.equal(calls[0][1].length,4);
 assert.equal(JSON.stringify(calls).includes('caller mutation'),false);
});
test('import receipts reject sparse or accessor arrays without evaluating accessors',()=>{
 const raw=input('import'),x=prepareListingAdmission(raw);let evaluated=0;
 for(const mutate of [
  r=>{r.sources=new Array(1);},
  r=>{r.sources[0].entityReads=new Array(1);},
  r=>{r.sources[0].prototypeEffect.inheritedProperties=new Array(1);},
  r=>{r.products[0].images=new Array(1);r.products[0].images.extra='replacement';},
  r=>{Object.defineProperty(r.sources,0,{get(){evaluated++;throw Error('getter called');}});}
 ]){const r=imported(raw);mutate(r);assert.throws(()=>importReceipt(r,x),{code:'LISTING_RECEIPT_MISMATCH'});}
 assert.equal(evaluated,0);
});

test('decline is durable terminal with observed receipt binding and cannot later publish',async()=>{
 const f=fixture({validateImportReceipt:async value=>value}),raw=input('import'),observed=imported(raw);
 await f.repository.admit(raw);await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
 const effect=await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:1,state:'effect_received',receipt:observed});
 const reason='The supplier data is not suitable for publication.';
 const receipt={version:1,operationId:raw.request.operationId,requestSha256:prepareListingAdmission(raw).requestSha256,importReceiptSha256:hash(JSON.stringify(effect.receipt)),provider:'ollama',model:'llama3.1:8b',callId:randomUUID(),mocked:false,fallback:false,reason,reasonSha256:hash(reason)};
 await assert.rejects(f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:2,state:'declined',receipt:{...receipt,importReceiptSha256:'0'.repeat(64)}}),{code:'LISTING_RECEIPT_MISMATCH'});
 await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:2,state:'declined',receipt});
 assert.equal((await f.repository.recover({scope:raw.scope,persona:raw.persona,personaSession:raw.personaSession,operationId:raw.request.operationId})).state,'declined');
 await assert.rejects(f.repository.publishImport(raw,{eventId:randomUUID(),expectedSequence:3}),{code:'LISTING_STATE_CONFLICT'});
});
test('internal recovery restores only exact original admission under owner/session fences',async()=>{
 const f=fixture(),raw=input();await f.repository.admit(raw);
 const key={scope:raw.scope,persona:raw.persona,personaSession:raw.personaSession,operationId:raw.request.operationId};
 assert.deepEqual(await f.repository.recoverAdmission(key),raw);
 await assert.rejects(f.repository.recoverAdmission({...key,personaSession:{...key.personaSession,sessionId:randomUUID()}}),{code:'LISTING_NOT_FOUND'});
 await assert.rejects(f.repository.recoverAdmission({...key,scope:{...key.scope,platformOwnerId:99}}),{code:'LISTING_NOT_FOUND'});
 const row=f.admissions.get(raw.request.operationId);row.request_sha256='f'.repeat(64);
 await assert.rejects(f.repository.recoverAdmission(key),{code:'LISTING_OPERATION_CONFLICT'});
});

test('fresh recovery preserves absence through real cross-store error wrapping',async()=>{const f=fixture({wrapCrossStoreErrors:true});await assert.rejects(f.repository.recoverAdmission((({scope,persona,personaSession,request})=>({scope,persona,personaSession,operationId:request.operationId}))(input())),{code:'LISTING_NOT_FOUND'});assert.equal(f.admissions.size,0);assert.ok(f.queries.some(([q])=>q==='ROLLBACK'));});

test('read absence never bypasses the post-effect persona check',async()=>{const f=fixture({wrapCrossStoreErrors:true,revokeAfterEffect:true}),{scope,persona,personaSession,request}=input();await assert.rejects(f.repository.recoverAdmission({scope,persona,personaSession,operationId:request.operationId}),{code:'SHOP_AUTH_REVOKED'});});

function currentScene(raw,{merchantId=raw.persona.id,lease=async work=>work()}={}){
 const {createSceneBinding,authorizeSceneMerchant}=require('../server/services/secureshopSceneBinding');
 const birth={...raw.scope,launchId:randomUUID(),platformSessionId:11,targetId:raw.targetId};
 return authorizeSceneMerchant(createSceneBinding(birth,{sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:raw.scope,withLease:lease}),merchantId);
}
test('new current scene admission retains packet scope and exact original private grant',async()=>{
 const raw=input();raw.persona.id=1000000001;const target=currentScene(raw),f=fixture({resolveTarget:async b=>{assert.deepEqual(b.scope,raw.scope);return target;}});
 await f.repository.admit(raw);await f.repository.transition(raw,{eventId:randomUUID(),expectedSequence:0,state:'running'});
 assert.equal((await f.repository.get(raw)).state,'running');
 assert.deepEqual(JSON.parse(f.admissions.get(raw.request.operationId).binding_json).scope,raw.scope);
 const call=f.queries.find(([sql])=>sql.includes('admit_owned_listing_scene_operation'));
 assert.equal(call[1][8],target.scene.grantId);assert.notEqual(target.launchId,raw.scope.launchId);
 f.sceneAdmissions.get(raw.request.operationId).grant_id=randomUUID();
 await assert.rejects(f.repository.get(raw),{code:'LISTING_TARGET_UNAVAILABLE'});
});
test('forged scene JSON, wrong merchant and stale identity lease cannot open a listing transaction',async()=>{
 const raw=input();raw.persona.id=1000000001;const target=currentScene(raw);
 for(const resolveTarget of [async()=>JSON.parse(JSON.stringify(target)),async()=>currentScene(raw,{merchantId:1000000002}),async()=>currentScene(raw,{lease:async()=>{throw Object.assign(Error(),{code:'SHOP_SCENE_STALE'});}})]){
  const f=fixture({resolveTarget});await assert.rejects(f.repository.admit(raw));assert.equal(f.queries.length,0);
 }
 const f=fixture({resolveTarget:async()=>target,sceneAllowed:false});await assert.rejects(f.repository.admit(raw),{code:'SHOP_SCENE_STALE'});
 assert.equal(f.admissions.size,0);assert.ok(f.queries.some(([sql])=>sql==='ROLLBACK'));
});
