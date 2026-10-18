'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{createHash}=require('node:crypto');
const {createCtfPredefenseRecoveryRepository,validateCtfPredefenseRecoveryState}=require('../server/database/postgres/ctfPredefenseRecoveryRepository');
const {createCtfPredefenseRecoveryService}=require('../server/services/ctfPredefenseRecoveryService');
const {buildCtfLifecycleCommand,canonicalCtfJson}=require('../server/services/ctfLifecycleCommands');
const runId='00000000-0000-0000-0000-000000000001',admissionId='00000000-0000-0000-0000-000000000002',blockedOperationId='00000000-0000-0000-0000-000000000003';
const input={runId,session:{actorId:'7',sessionId:'8',rawToken:'private-original-token'}};
const state=name=>({version:1,state:name,runId,admissionId,blockedOperationId,decisionId:null,currentCompletion:false});
const read=name=>fs.readFileSync('db/postgres/identity-migrations/'+name,'utf8');
const sql=read('0122_ctf_predefense_recovery.sql');
function body(text,name){const match=text.match(new RegExp('CREATE (?:OR REPLACE )?FUNCTION identity\\.'+name+'\\(.*?END; \\$\\$;','s'));assert(match,name);return match[0];}
test('recovery consume is exact qualified0113 body with only narrow new-effect helper substitution',()=>{
 const expected=body(read('0113_ctf_predefense_claim.sql'),'consume_ctf_predefense').replace('identity.consume_ctf_predefense(','identity.consume_ctf_predefense_recovery(').replace('PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,true);','PERFORM identity.lock_ctf_predefense_recovery_effect(p_actor,p_session,p_token_hash,p_run);');
 assert.equal(body(sql,'consume_ctf_predefense_recovery'),expected);
});
test('blocked builder exactly preserves latest0118 locator/counters/feedback/timestamp, enqueue never invokes running-only prepare',()=>{
 const expected=body(read('0118_ctf_predefense_registration_locator.sql'),'prepare_ctf_blocked_predefense').replace('CREATE OR REPLACE FUNCTION identity.prepare_ctf_blocked_predefense(','CREATE FUNCTION identity.prepare_ctf_blocked_recovery(').replace('PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,true);','PERFORM identity.lock_ctf_predefense_recovery_effect(p_actor,p_session,p_token_hash,p_run);');
 assert.equal(body(sql,'prepare_ctf_blocked_recovery'),expected);assert(expected.includes('ctf_predefense_registration_locators'));
 const enqueue=body(sql,'enqueue_ctf_blocked_recovery');assert(enqueue.includes('identity.prepare_ctf_blocked_recovery('));assert(enqueue.includes('identity.enqueue_ctf_user_command('));assert(!enqueue.includes('identity.prepare_ctf_blocked_predefense('));
});
test('new migration cannot replace qualified helpers or grant table DML; read path has no mutations',()=>{
 assert(!sql.includes('CREATE OR REPLACE'));assert(!/GRANT\s+(?:ALL|INSERT|UPDATE|DELETE)\b/i.test(sql));
 for(const name of ['lock_ctf_predefense_recovery_state','lock_ctf_predefense_recovery_effect'])assert(sql.includes(`REVOKE ALL ON FUNCTION identity.${name}(integer,integer,text,uuid) FROM PUBLIC,dvaia_identity_runtime`));
 const get=body(sql,'read_ctf_predefense_recovery');assert(!/\b(?:INSERT INTO|UPDATE identity|DELETE FROM|enqueue_ctf|consume_ctf|store_ctf|claim_ctf)\b/.test(get));
 const guard=body(sql,'lock_ctf_predefense_recovery_effect');assert(guard.includes("rr.status='completed'"));assert(guard.includes("aa.lifecycle_state='ready'"));assert(guard.includes("o.outcome->>'inputHash' IS DISTINCT FROM c.input_hash"));
 const locked=body(sql,'lock_ctf_predefense_recovery_state');assert(locked.includes('ctf_publication_bootstrap_ready()'));assert(locked.includes("pr.progress_id IS DISTINCT FROM (b->>'progressId')"));assert(locked.includes('session_token_hash=p_hash'));assert(locked.indexOf('identity.ctf_authority')<locked.indexOf('identity.users'));
});
function repositoryFixture(handler){const queries=[],released=[];return{queries,released,repository:createCtfPredefenseRecoveryRepository({async connect(){return{async query(text,args){queries.push({text,args});return{rows:await handler(text,args)||[]};},release(value){released.push(value);}};}})};}
test('read snapshots original auth/hash and accepts only closed non-credit state, never payload',async()=>{
 let unlock;const gate=new Promise(r=>unlock=r);const f=repositoryFixture(async text=>{if(text.includes('read_ctf_predefense_recovery')){await gate;return[{value:state('outcome_stored')}];}});
 const supplied=structuredClone(input),pending=f.repository.read(supplied);supplied.session.rawToken='replacement';supplied.session.sessionId='99';unlock();
 assert.equal((await pending).state,'outcome_stored');const q=f.queries.find(x=>x.text.includes('read_ctf_predefense_recovery'));
 assert.deepEqual(q.args,['7','8',createHash('sha256').update(input.session.rawToken).digest('hex'),runId]);assert(!JSON.stringify(q).includes(input.session.rawToken));assert.equal(f.released.length,1);
 assert.throws(()=>validateCtfPredefenseRecoveryState({...state('outcome_stored'),payload:'private'},runId));assert.throws(()=>validateCtfPredefenseRecoveryState({...state('outcome_stored'),currentCompletion:true},runId));
});
test('blocked preparation and enqueue share one transaction and preserve saved locator bytes',async()=>{
 const command=buildCtfLifecycleCommand('record_blocked_attempt',{admissionOperationId:admissionId,matchedPayloadHash:null,attemptNumber:1,payload:'synthetic',response:null,responseTime:0,teachingSessionToken:'saved-original-locator',techniqueTag:'other',techniqueConfidence:0,reason:'blocked',payloadHash:null},{actorId:'7',operationId:blockedOperationId,occurredAt:'2026-09-27T00:00:00.000Z',scope:{ownerId:'7',ownerGeneration:'1',globalRevision:'0',stageRevision:'0',stageId:'1',participantId:'9',progressId:'10'}});
 const {commandHash,...content}=command;
 const f=repositoryFixture(async(text,args)=>{if(text.includes('prepare_ctf_blocked_recovery'))return[{value:{operationId:blockedOperationId,currentState:false,replayed:true,command:content,canonicalCommand:canonicalCtfJson(content)}}];if(text.includes('enqueue_ctf_blocked_recovery')){assert.equal(args[4],canonicalCtfJson(content));assert.equal(args[5],commandHash);return[{value:{operationId:blockedOperationId,replayed:true,currentState:false}}];}});
 assert.equal((await f.repository.enqueueBlocked(input)).replayed,true);assert.equal(f.queries.filter(q=>q.text==='BEGIN').length,1);assert.equal(f.queries.filter(q=>q.text==='COMMIT').length,1);assert.equal(f.released.length,1);
});
test('known SQL errors and uncertain COMMIT are retained without repository retry',async()=>{
 for(const [where,error] of [['SELECT',Object.assign(Error('constraint'),{code:'23514'})],['COMMIT',Object.assign(Error('lost commit'),{code:'08006'})]]){
  const f=repositoryFixture(async text=>{if(text.startsWith(where))throw error; if(text.includes('read_ctf'))return[{value:state('outcome_stored')}];});
  await assert.rejects(f.repository.read(input),e=>e===error);assert.equal(f.queries.filter(q=>q.text.includes('read_ctf_predefense_recovery')).length,1);assert.equal(f.released.length,1);
 }
});
function serviceFixture(sequence){let index=0;const calls=[];const repository={async read(){calls.push('read');return state(sequence[Math.min(index++,sequence.length-1)]);},async consume(){calls.push('consume');},async enqueueBlocked(){calls.push('enqueue');}};const worker={async pump(options){calls.push('pump');assert.equal(options.maxEvents,1);}};return{calls,repository,worker,service:createCtfPredefenseRecoveryService({repository,worker})};}
test('completed stored outcome follows deterministic consume/delivery/enqueue only and final state is not credit',async()=>{
 const f=serviceFixture(['outcome_stored','admission_pending','blocked_ready_to_enqueue','blocked_pending','blocked_publishable']);
 assert.equal((await f.service.resume(input)).state,'blocked_publishable');assert.deepEqual(f.calls,['read','consume','read','pump','read','enqueue','read','pump','read']);
});
test('unknown/running/continue/proposal states never consume, enqueue or invoke providers',async()=>{
 for(const name of ['outcome_indeterminate','in_progress','guardian_not_started_or_unknown','proposal_staged','recovery_required']){const f=serviceFixture([name]);assert.equal((await f.service.resume(input)).state,name);assert.deepEqual(f.calls,['read']);}
 assert.throws(()=>createCtfPredefenseRecoveryService({repository:{},worker:{},evaluate(){}}),/Closed/);
});
test('uncertain mutation stops immediately; explicit later resume reads persisted state without redoing consume',async()=>{
 const f=serviceFixture(['outcome_stored','blocked_publishable']);f.repository.consume=async()=>{f.calls.push('lost');throw Object.assign(Error('commit response lost'),{code:'08006'});};
 const service=createCtfPredefenseRecoveryService({repository:f.repository,worker:f.worker});
 assert.equal((await service.resume(input)).state,'recovery_pending');assert.deepEqual(f.calls,['read','lost']);
 assert.equal((await service.resume(input)).state,'blocked_publishable');assert.deepEqual(f.calls,['read','lost','read']);
});

test('deadline aborts underlying read and late resolution cannot consume; external abort rejects',async()=>{
 for(const external of [false,true]){
  let resolve,passed;const controller=new AbortController();let consumed=0;
  const repository={read:(_,options)=>{passed=options.signal;return new Promise(r=>resolve=r);},consume:async()=>consumed++,enqueueBlocked:async()=>assert.fail()};
  const service=createCtfPredefenseRecoveryService({repository,worker:{pump:async()=>assert.fail()}},{timeoutMs:10});
  const result=service.resume(input,{signal:controller.signal});if(external)controller.abort();
  if(external)await assert.rejects(result,{name:'AbortError'});else assert.equal((await result).state,'recovery_pending');
  assert.equal(passed.aborted,true);resolve(state('outcome_stored'));await new Promise(r=>setImmediate(r));assert.equal(consumed,0);
 }
});
test('known constraint errors propagate and maxSteps bounds delivery without automatic retry',async()=>{
 const f=serviceFixture(['admission_pending']);const service=createCtfPredefenseRecoveryService({repository:f.repository,worker:f.worker},{maxSteps:2});
 assert.equal((await service.resume(input)).state,'recovery_pending');assert.deepEqual(f.calls,['read','pump','read','pump']);
 const error=Object.assign(Error('constraint'),{code:'23514'});f.repository.read=async()=>{throw error;};
 await assert.rejects(createCtfPredefenseRecoveryService({repository:f.repository,worker:f.worker}).resume(input),e=>e===error);
});

test('SQL direct enqueue binds exact closed encoding and read validates full receipt and source scope',()=>{
 const enqueue=body(sql,'enqueue_ctf_blocked_recovery');assert(enqueue.includes("p_document IS DISTINCT FROM identity.canonical_ctf_recovery_blocked(expected->'command')"));
 const encoder=body(sql,'canonical_ctf_recovery_blocked');assert(encoder.includes('SET extra_float_digits=1'));assert(encoder.includes('confidence<0.000001'));assert(encoder.includes("confidence=0 THEN token:='0'"));assert(encoder.includes('raw::jsonb IS DISTINCT FROM v'));
 const get=body(sql,'read_ctf_predefense_recovery');assert.equal((get.match(/identity.ctf_result_matches\(receipt\) IS NOT TRUE/g)||[]).length,2);assert.equal((get.match(/ev.command->'scope' IS DISTINCT FROM jsonb_build_object/g)||[]).length,2);
});
test('service pending envelope is a closed non-credit union separate from repository read state',()=>{
 const {validateCtfPredefenseRecoveryResult:validate}=require('../server/services/ctfPredefenseRecoveryService');
 const pending={version:1,state:'recovery_pending',runId,currentCompletion:false};assert.deepEqual(validate(pending,runId),pending);assert.throws(()=>validate({...pending,decisionId:admissionId},runId));assert.throws(()=>validate({...pending,currentCompletion:true},runId));assert.deepEqual(validate(state('outcome_stored'),runId),state('outcome_stored'));
});
