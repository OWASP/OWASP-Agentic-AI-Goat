'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {createCtfAuthorityRuntime}=require('../server/services/ctfAuthorityRuntime');
const activation={activation_id:'00000000-0000-0000-0000-000000000001',bootstrap_operation_id:'00000000-0000-0000-0000-000000000002',ctf_store_id:'00000000-0000-0000-0000-000000000003',identity_store_id:'00000000-0000-0000-0000-000000000004',authority_sha256:'a'.repeat(64),manifest_sha256:'b'.repeat(64),protocol_version:1,source_revision:'0'};
const req={headers:{authorization:'Bearer synthetic'},user:{id:7},identitySession:{id:8}};
function deferred(){let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};}
function fixture({roleValid=true,roleGate,validateSession,attempts,sqlHook}={}){
 const calls=[],ends=[];
 function pool(name){return{async connect(){calls.push([name,'CONNECT']);return{async query(sql,args){calls.push([name,sql,args]);
  if(sqlHook){const result=await sqlHook(name,sql,args);if(result)return result;}
  if(sql.includes('session_user AS login')){if(roleGate)await roleGate.promise;return{rows:[{login:roleValid?'dvaia_ctf_delivery':'dvaia_ctf_runtime',effective:'dvaia_ctf_delivery',database:'isolated_ctf',rolcanlogin:true,rolsuper:false,rolcreatedb:false,rolcreaterole:false,rolreplication:false,rolbypassrls:false,membership:false}]};}
  if(sql.includes('a.activation_id::text'))return{rows:[activation]};
  if(sql.includes('SELECT 1 FROM ctf.bootstrap_control')||sql.includes('SELECT 1 FROM identity.ctf_bootstrap_sessions'))return{rows:[{}]};
  if(sql.includes('prepare_ctf_heartbeat'))return{rows:[{value:{state:'noop'}}]};
  if(sql.includes('read_ctf_decision_recovery'))return{rows:[{recovery:{state:'decided',receipt:{accepted:true,decision_id:activation.activation_id,privateSentinel:'must-not-spread'}}}]};
  if(sql.includes('ctf_current_decision_pending'))return{rows:[{pending:false}]};
  return{rows:[]};},release(){calls.push([name,'RELEASE']);}};},async end(){ends.push(name);}};}
 const options={identityPool:pool('identity'),ctfPool:pool('read'),deliveryPool:pool('delivery'),deliveryDatabaseUrl:'postgresql://dvaia_ctf_delivery:synthetic@127.0.0.1:1/isolated_ctf',activation,validateSession:validateSession||(async()=>({user:{id:7},session:{id:8,user_id:7}})),...(attempts?{attempts}:{})};
 const runtime=createCtfAuthorityRuntime(options,{workerOptions:{pollMs:60000,batchTimeoutMs:100,drainMs:20},drainMs:20});return{runtime,options,calls,ends};
}
test('construction is inert, unsupported commands cannot access pools and stop preserves borrowed pools',async()=>{const f=fixture();assert.equal(f.calls.length,0);assert.equal(f.runtime.status().state,'paused');assert.throws(()=>f.runtime.bootstrap(),/OPERATOR_ONLY/);assert.throws(()=>f.runtime.activate(),/OPERATOR_ONLY/);await assert.rejects(f.runtime.mutate({kind:'admit_attempt'}),/Unsupported/);await assert.rejects(f.runtime.read({kind:'status'}),/UNAVAILABLE/);assert.equal(f.calls.length,0);assert.equal((await f.runtime.stop()).drained,true);assert.deepEqual(f.ends,[]);});
test('options cannot replace canonical authority, pool, readiness or decision repository',()=>{const f=fixture();for(const key of ['identity','ctfPool','readiness'])assert.throws(()=>createCtfAuthorityRuntime(f.options,{workerOptions:{[key]:{}}}),/Unsupported worker/);assert.throws(()=>createCtfAuthorityRuntime({...f.options,attempts:{repository:{},loadAdmittedAttempt(){},runGuardian(){},buildCurrentResponse(){}}}),/Unsupported attempt/);assert.equal(f.calls.length,0);});
test('explicit start validates real delivery role and paired tuple, then authenticated optional heartbeat retains status ok',async()=>{const f=fixture();try{await f.runtime.start();assert.equal(f.runtime.status().state,'running');const response=await f.runtime.heartbeat({req});assert.deepEqual(response,{status:200,body:{status:'ok'}});assert(f.calls.some(c=>c[0]==='delivery'&&c[1].includes('session_user')));assert(f.calls.some(c=>c[0]==='identity'&&c[1].includes('prepare_ctf_heartbeat')));assert(!f.calls.some(c=>/UPDATE|INSERT|DELETE/.test(c[1])));await assert.rejects(f.runtime.attempt({req}),/COMPOSITION_UNAVAILABLE/);}finally{assert.equal((await f.runtime.stop()).drained,true);}assert.deepEqual(f.ends,[]);});
test('failed role verification never starts a worker or publishes readiness',async()=>{const f=fixture({roleValid:false});await assert.rejects(f.runtime.start(),/ROLE_INVALID/);assert.equal(f.runtime.status().state,'paused');assert.equal(f.runtime.status().worker.state,'paused');await assert.rejects(f.runtime.heartbeat({req}),/UNAVAILABLE/);await f.runtime.stop();assert.deepEqual(f.ends,[]);});
test('stop during startup cannot resurrect worker and reports incomplete drain honestly',async()=>{const gate=deferred(),f=fixture({roleGate:gate});const started=f.runtime.start();started.catch(()=>{});await new Promise(resolve=>setImmediate(resolve));const result=await f.runtime.stop();assert.equal(result.drained,false);gate.resolve();await assert.rejects(started);assert.equal(f.runtime.status().state,'stopped');assert.equal(f.runtime.status().worker.state,'stopped');assert.deepEqual(f.ends,[]);});
test('stop counts outstanding auth request, blocks new ingress and never leaks cancelled response',async()=>{const gate=deferred(),entered=deferred(),f=fixture({validateSession:async()=>{entered.resolve();await gate.promise;return{user:{id:7},session:{id:8,user_id:7}};}});await f.runtime.start();const request=f.runtime.heartbeat({req});request.catch(()=>{});await entered.promise;assert.equal(f.runtime.status().requests,1);assert.equal((await f.runtime.stop()).requestsDrained,false);await assert.rejects(f.runtime.heartbeat({req}),/UNAVAILABLE/);gate.resolve();await assert.rejects(request);assert.equal((await f.runtime.stop()).drained,true);assert.deepEqual(f.ends,[]);});
test('historical recovery exposes only explicit state/reference, never accepted receipt fields',async()=>{const f=fixture();try{await f.runtime.start();const result=await f.runtime.recoverDecision({req,admissionId:activation.activation_id});assert.deepEqual(result,{state:'historical_receipt',admissionId:activation.activation_id,decisionId:activation.activation_id,currentCompletion:false});assert(!JSON.stringify(result).includes('must-not-spread'));}finally{await f.runtime.stop();}});

test('explicit start recovers a paused worker only after revalidating delivery role and activation',async()=>{let first=true;const f=fixture({sqlHook:async(name,sql)=>{if(first&&sql.includes('JOIN identity.ctf_outbox')){first=false;throw Error('controlled worker failure');}}});try{await f.runtime.start();for(let n=0;n<20&&f.runtime.status().worker.state==='running';n++)await new Promise(r=>setTimeout(r,5));assert.equal(f.runtime.status().worker.state,'paused');const checked=f.calls.filter(c=>c[1].includes('session_user')).length;await f.runtime.start();assert.equal(f.runtime.status().worker.state,'running');assert.equal(f.calls.filter(c=>c[1].includes('session_user')).length,checked+1);}finally{await f.runtime.stop();}});
test('request credentials and locator are captured before asynchronous readiness',async()=>{const f=fixture(),input={req:{headers:{authorization:'Bearer synthetic'},user:{id:7},identitySession:{id:8}},registrationToken:null};try{await f.runtime.start();const work=f.runtime.heartbeat(input);input.req.user.id=99;input.req.identitySession.id=100;input.req.headers.authorization='Bearer replacement';input.registrationToken='replacement';await work;const query=f.calls.find(c=>c[1].includes('prepare_ctf_heartbeat'));assert.deepEqual(query[2].slice(0,2),['7','8']);assert.equal(query[2][4],null);}finally{await f.runtime.stop();}});
test('transaction-local blocked readiness uses only provided client and exact tuple',async()=>{const {createTransactionLocalPublicationReadiness}=require('../server/services/ctfAuthorityRuntime');let running=true,calls=0,row=activation;const check=createTransactionLocalPublicationReadiness({activation,isRunning:()=>running});const client={async query(sql){calls++;assert(sql.includes("b.state='prepared'"));assert(sql.includes('identity.ctf_delivery_control'));return{rows:row?[row]:[]};}};assert.equal(await check(client),true);assert.equal(calls,1);row={...activation,authority_sha256:'c'.repeat(64)};assert.equal(await check(client),false);running=false;assert.equal(await check({query(){throw Error('No query while stopped');}}),false);});
test('private response building cannot bypass final current publication rejection',async()=>{let built=0;const f=fixture({attempts:{loadAdmittedAttempt(){throw Error('unused');},runGuardian(){throw Error('unused');},buildCurrentResponse(){built++;return{status:200,body:{success:true,aiResponse:'PRIVATE_RESPONSE'}};}},sqlHook:async(name,sql)=>{if(sql.includes('authorize_ctf_current_publication'))throw Object.assign(Error('SESSION_REVOKED'),{code:'28000'});}});try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id}),{code:'28000'});assert.equal(built,1);}finally{await f.runtime.stop();}});

test('exact current pending decision returns bounded202 without private response or final publication',async()=>{
 let built=0;
 const f=fixture({attempts:{loadAdmittedAttempt(){},runGuardian(){},buildCurrentResponse(){built++;throw Error('private response must not be built');}},sqlHook:async(name,sql)=>sql.includes('ctf_current_decision_pending')?{rows:[{pending:true}]}:undefined});
 try{await f.runtime.start();const response=await f.runtime.publishDecision({req,decisionId:activation.activation_id});
  assert.deepEqual(response,{status:202,body:{success:false,pending:true,decisionId:activation.activation_id}});
  assert.equal(built,0);
  const probes=f.calls.filter(c=>c[1].includes('ctf_current_decision_pending'));
  assert.equal(probes.length,1);
  assert.deepEqual(probes[0][2],[activation.activation_id,'7','8',createHash('sha256').update('synthetic').digest('hex')]);
  assert(!f.calls.some(c=>c[1].includes('authorize_ctf_current_publication')));
 }finally{await f.runtime.stop();}
});
test('pending probe never converts denial, unknown decision or malformed result into202',async()=>{
 for(const answer of ['42501','28000',false,null]){
  let built=0;
  const f=fixture({attempts:{loadAdmittedAttempt(){},runGuardian(){},buildCurrentResponse(){built++;throw Object.assign(Error('private publication unavailable'),{code:'CTF_ATTEMPT_RESPONSE_UNAVAILABLE'});}},sqlHook:async(name,sql)=>{
   if(!sql.includes('ctf_current_decision_pending'))return;
   if(answer==='42501'||answer==='28000')throw Object.assign(Error('denied'),{code:answer});
   return{rows:[{pending:answer}]};
  }});
  try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id}),error=>answer===null?error.message==='CTF_PENDING_PUBLICATION_INVALID':error.code===(answer===false?'CTF_ATTEMPT_RESPONSE_UNAVAILABLE':answer));
   assert.equal(built,answer===false?1:0);
   assert(!f.calls.some(c=>c[1].includes('authorize_ctf_current_publication')));
  }finally{await f.runtime.stop();}
 }
});

test('authentication denial retains401 rather than service-unavailable503',async()=>{
 const f=fixture({validateSession:async()=>null});
 assert.throws(()=>f.runtime.heartbeat({req:{headers:{},user:{id:7},identitySession:{id:8}}}),{code:'SESSION_REVOKED',statusCode:401});
 assert.equal(f.calls.length,0);
 try{await f.runtime.start();await assert.rejects(f.runtime.heartbeat({req}),{code:'SESSION_REVOKED',statusCode:401});}finally{await f.runtime.stop();}
});
test('owned execution cancellation reaches nested execution.signal users and retains bound receiver/budget',async()=>{
 const {createOwnedCtfExecution}=require('../server/services/ctfAuthorityRuntime');
 for(const source of ['owned','original']){
  const owned=new AbortController(),original=new AbortController(),events=[];
  class Execution{constructor(){this.signal=original.signal;this.ownerId='7';this.budget={remaining:2};}async check(){this.budget.remaining--; }trace(event){events.push([this.ownerId,event]);}}
  const execution=new Execution(),facade=createOwnedCtfExecution(execution,owned.signal);assert(Object.isFrozen(facade));assert.notEqual(facade.signal,execution.signal);assert.equal(facade.budget,execution.budget);await facade.check();facade.trace('observed');assert.deepEqual(events,[['7','observed']]);assert.equal(execution.budget.remaining,1);
  // Mirrors input language/output reviewer/Judge callbacks using execution.signal,
  // without reading the separate outer signal or making an actual provider call.
  let completed=false;const nested=new Promise((resolve,reject)=>{facade.signal.addEventListener('abort',()=>reject(facade.signal.reason),{once:true});}).then(()=>{completed=true;});nested.catch(()=>{});
  (source==='owned'?owned:original).abort(new Error(source+' cancelled'));await assert.rejects(nested,new RegExp(source+' cancelled'));await assert.rejects(facade.check(),new RegExp(source+' cancelled'));assert.equal(completed,false);assert.equal(execution.budget.remaining,1);
 }
});
test('known JWT verifier errors become401 while database and programming failures remain visible',async()=>{
 for(const name of ['TokenExpiredError','JsonWebTokenError','NotBeforeError','DatabaseError','TypeError']){
  const error=Object.assign(Error('controlled verifier failure'),{name}),f=fixture({validateSession:async()=>{throw error;}});
  try{await f.runtime.start();for(const work of [()=>f.runtime.heartbeat({req}),()=>f.runtime.mutate({req,kind:'register',input:{}})])await assert.rejects(work(),e=>['TokenExpiredError','JsonWebTokenError','NotBeforeError'].includes(name)?e.code==='SESSION_REVOKED'&&e.statusCode===401:e===error);}finally{await f.runtime.stop();}
 }
});

const unavailableBody=()=>({error:'AI system temporarily unavailable. Please try again.',retryable:true,attemptNumber:1,judgment:{verdict:'unavailable'}});
function publicationFixture(response,authorization){return fixture({attempts:{loadAdmittedAttempt(){throw Error('unused');},runGuardian(){throw Error('unused');},buildCurrentResponse(){return response;}},sqlHook:async(name,sql)=>sql.includes('authorize_ctf_current_publication')?{rows:[{publication:{decisionId:activation.activation_id,...authorization}}]}:undefined});}
test('exact guardian unavailable503 requires current unavailable and noncompletion authority',async()=>{for(const lesson of [false,true]){const body=unavailableBody();if(lesson)body.lessonState={input_guard_observed:false,reviewer_observed:true,category_consumed:false,category_reuse_blocked:false,shared_similarity_blocked:false};const f=publicationFixture({status:503,body},{verdict:'unavailable',currentCompletion:false});try{await f.runtime.start();assert.deepEqual(await f.runtime.publishDecision({req,decisionId:activation.activation_id}),{status:503,body});}finally{await f.runtime.stop();}}});
test('503 rejects extra/private fields, malformed shape and incompatible canonical verdict',async()=>{const mutations=[b=>b.success=false,b=>b.aiResponse='private',b=>b.retryable=false,b=>b.attemptNumber=0,b=>b.judgment.extra=true,b=>b.judgment='unavailable',b=>b.lessonState={reviewer_observed:true}];for(const change of mutations){const body=unavailableBody();change(body);const f=publicationFixture({status:503,body},{verdict:'unavailable',currentCompletion:false});try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id}),{code:'CTF_ATTEMPT_RESPONSE_INVALID'});}finally{await f.runtime.stop();}}for(const authorization of [{verdict:'pass',currentCompletion:true},{verdict:'fail',currentCompletion:false},{currentCompletion:false},{verdict:'unavailable',currentCompletion:true}]){const f=publicationFixture({status:503,body:unavailableBody()},authorization);try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id}),{code:'CTF_ATTEMPT_RESPONSE_INVALID'});}finally{await f.runtime.stop();}}});
test('ordinary200 success still exactly matches final authorization',async()=>{const f=publicationFixture({status:200,body:{success:true}},{verdict:'unavailable',currentCompletion:false});try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id}),{code:'CTF_ATTEMPT_RESPONSE_INVALID'});}finally{await f.runtime.stop();}});
test('production constructor creates trusted adapters without acquiring pools and rejects request override',async()=>{const f=fixture({attempts:'production'});assert.equal(f.calls.length,0);assert.equal(f.runtime.status().attemptsSupported,true);try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id,attempts:{buildCurrentResponse(){assert.fail('request callback must never run');}}}),{code:'CTF_ATTEMPT_RESPONSE_UNAVAILABLE'});}finally{await f.runtime.stop();}});
test('503 private build is discarded when final publication authority is revoked',async()=>{let built=false;const f=fixture({attempts:{loadAdmittedAttempt(){},runGuardian(){},buildCurrentResponse(){built=true;return{status:503,body:unavailableBody()};}},sqlHook:async(name,sql)=>{if(sql.includes('authorize_ctf_current_publication')){assert(built);throw Object.assign(Error('revoked'),{code:'28000'});}}});try{await f.runtime.start();await assert.rejects(f.runtime.publishDecision({req,decisionId:activation.activation_id}),{code:'28000'});}finally{await f.runtime.stop();}});

test('canonical account lock normalizes423 through direct and facade ingress without private details',async()=>{const f=fixture({validateSession:async()=>{throw Object.assign(Error('PRIVATE'),{name:'AccountLocked',lockedUntil:'PRIVATE_TIME'});}});try{await f.runtime.start();for(const work of [()=>f.runtime.heartbeat({req}),()=>f.runtime.mutate({req,kind:'register',input:{}})])await assert.rejects(work(),e=>e.code==='ACCOUNT_LOCKED'&&e.statusCode===423&&!Object.hasOwn(e,'lockedUntil')&&!e.message.includes('PRIVATE'));}finally{await f.runtime.stop();}});
test('recovery rejects malformed decision references and never treats staged proposals as current completion',async()=>{
 for(const stored of [{state:'proposal_staged',proposalId:activation.activation_id,receipt:null},{state:'decided',receipt:{decision_id:'invalid-private-reference',accepted:true}}]){
  const f=fixture({sqlHook:async(name,sql)=>sql.includes('read_ctf_decision_recovery')?{rows:[{recovery:stored}]}:undefined});
  try{await f.runtime.start();
   if(stored.state==='decided')await assert.rejects(f.runtime.recoverDecision({req,admissionId:activation.activation_id}),{code:'CTF_RECOVERY_INVALID'});
   else assert.deepEqual(await f.runtime.recoverDecision({req,admissionId:activation.activation_id}),{state:'proposal_staged',admissionId:activation.activation_id,decisionId:null,currentCompletion:false});
  }finally{await f.runtime.stop();}
 }
});

function blockedSql({originalSession='8',applied=true,runStatus='completed',ready=true,pause}={}){
 let publicationLocked=false;
 const {buildCtfLifecycleCommand,canonicalCtfJson}=require('../server/services/ctfLifecycleCommands');
 const {buildCtfProjectionResult}=require('../server/services/ctfProjectionResults');
 const runId=activation.activation_id,admission=activation.bootstrap_operation_id,blocked=activation.ctf_store_id;
 const binding={ownerId:'7',sessionId:'8',runId,ownerGeneration:'1',globalRevision:'2',stageRevision:'3',ownerRevision:'4',participantId:'9',progressId:'10',stageId:'1',stageDigest:'a'.repeat(64)};
 const scope={ownerId:'7',ownerGeneration:'1',globalRevision:'2',stageRevision:'3',participantId:'9',progressId:'10',stageId:'1'},rows={};
 for(const [operationId,kind,body,data] of [[admission,'admit_attempt',{failed:true},{progressId:'10',attemptNumber:1,failedAttempts:1}],[blocked,'record_blocked_attempt',{admissionOperationId:admission,matchedPayloadHash:null,attemptNumber:1,payload:'PRIVATE_PAYLOAD',response:null,responseTime:0,teachingSessionToken:null,techniqueTag:'other',techniqueConfidence:0,reason:'Blocked current result',payloadHash:null},{attemptId:'11',admissionOperationId:admission,payloadHitIncremented:false}]]){
  const command=buildCtfLifecycleCommand(kind,body,{actorId:'7',operationId,occurredAt:'2026-09-27T00:00:00.000Z',scope}),{commandHash,...content}=command,result=buildCtfProjectionResult(command,'1',data);
  rows[operationId]={state:applied?'applied':'pending',kind,actor_id:7,session_id:8,canonical_command:canonicalCtfJson(content),command_hash:commandHash,canonical_result:result.canonicalResult,result_hash:result.resultHash,sequence:'1'};
 }
 return async(name,sql,args)=>{
  let row;
  if(sql.includes('ctf_predefense_claims'))row={owner_id:7,session_id:originalSession,input:{binding},admission_operation_id:admission,blocked_operation_id:blocked};
  else if(sql.includes('ctf_authority WHERE'))row={lifecycle_state:'ready',revision:args[0]==='global'?'2':args[0]==='stage:1'?'3':'4',owner_generation:'1',banned:false};
  else if(sql.includes('graph_runtime.owners'))row={generation:'1'};
  else if(sql.includes('graph_runtime.runs'))row={owner_key:'["CTF","7"]',generation:'1',status:runStatus};
  else if(sql.includes('SELECT p.active'))row={active:true,banned:false,status:'in_progress',progress_id:'10',participant_id:'9',stage_number:1,stage_digest:binding.stageDigest,stage_active:true,feedback_mode:'silent',enabled:true,visible_to_students:true,time_limit_ms:'-1'};
  else if(sql.includes('ctf_predefense_consumptions'))row={operation_id:admission,final_disposition:'input',matched_payload_hash:null,failed:true};
  else if(sql.includes('ctf_predefense_outcomes'))row={outcome:{languageStatus:'non_english'}};
  else if(sql.includes('ctf_predefense_blocked_commands'))row={operation_id:blocked,command_hash:rows[blocked].command_hash};
  else if(sql.includes('ctf_outbox WHERE operation_id'))row=rows[args[0]];
  else if(sql.includes('lock_ctf_blocked_publication')){publicationLocked=true;if(pause){pause.entered.resolve();await pause.gate.promise;}}
  else if(publicationLocked&&!ready&&sql.includes('FROM identity.ctf_delivery_control'))return{rows:[]};
  return row?{rows:[row]}:undefined;
 };
}
test('blocked publication uses original session and applied receipts without attempt composition or writes',async()=>{
 const f=fixture({sqlHook:blockedSql()});try{
  await f.runtime.start();const start=f.calls.length;
  const result=await f.runtime.publishBlocked({req,runId:activation.activation_id});
  assert.equal(result.status,200);assert.equal(result.body.blocked,true);assert.equal(result.body.success,false);assert.equal(result.body.attemptNumber,1);
  assert(!JSON.stringify(result).includes('PRIVATE_PAYLOAD'));assert(!Object.hasOwn(result.body,'languageStatus'));
  assert(!f.calls.slice(start).some(x=>/enqueue_|prepare_ctf|UPDATE|INSERT|DELETE/.test(x[1])));
 }finally{await f.runtime.stop();}
});
test('blocked publication rejects wrong original session, unapplied receipt, terminal failure and lost publication readiness',async()=>{
 for(const option of [{originalSession:'99'},{applied:false},{runStatus:'cancelled'},{runStatus:'failed'},{ready:false}]){const f=fixture({sqlHook:blockedSql(option)});try{await f.runtime.start();await assert.rejects(f.runtime.publishBlocked({req,runId:activation.activation_id}),{code:'CTF_BLOCKED_PUBLICATION_UNAVAILABLE'});}finally{await f.runtime.stop();}}
});
test('blocked publication rejects malformed run before database work and stopped ingress',async()=>{
 const f=fixture();await assert.rejects(f.runtime.publishBlocked({req,runId:'bad'}),TypeError);assert.equal(f.calls.length,0);
 await assert.rejects(f.runtime.publishBlocked({req,runId:activation.activation_id}),{code:'CTF_RUNTIME_UNAVAILABLE'});assert.equal(f.calls.length,0);await f.runtime.stop();
});
test('blocked publication abort during protected read discards late result',async()=>{
 const pause={entered:deferred(),gate:deferred()},controller=new AbortController(),f=fixture({sqlHook:blockedSql({pause})});
 try{await f.runtime.start();const pending=f.runtime.publishBlocked({req,runId:activation.activation_id,signal:controller.signal});pending.catch(()=>{});await pause.entered.promise;controller.abort();pause.gate.resolve();await assert.rejects(pending);}
 finally{pause.gate.resolve();await f.runtime.stop();}
});

test('predefense recovery is closed current state without coordinator/model and rejects scope loss',async()=>{
 const id=activation.activation_id,value={version:1,state:'outcome_indeterminate',runId:id,admissionId:activation.bootstrap_operation_id,blockedOperationId:activation.ctf_store_id,decisionId:null,currentCompletion:false};
 let denied=false;
 const f=fixture({sqlHook:async(name,sql)=>{if(sql.includes('read_ctf_predefense_recovery')){if(denied)throw Object.assign(Error('stale owner/session/reset'),{code:'42501'});return{rows:[{value}]};}}});
 try{await f.runtime.start();for(const method of ['recoverPredefense','resumePredefense']){assert.deepEqual(await f.runtime[method]({req,runId:id}),{status:200,body:value});await assert.rejects(f.runtime[method]({req,runId:'bad'}),TypeError);}
 assert(!f.calls.some(x=>/claim_ctf|store_ctf_predefense|consume_ctf_predefense|enqueue_ctf|stage_ctf_response/.test(x[1])));
 denied=true;await assert.rejects(f.runtime.resumePredefense({req,runId:id}),{code:'42501'});
 }finally{await f.runtime.stop();}await assert.rejects(f.runtime.recoverPredefense({req,runId:id}),{code:'CTF_RUNTIME_UNAVAILABLE'});
});
test('predefense recovery rejects absent session and discards late state after cancellation',async()=>{
 const missing=fixture({validateSession:async()=>null});try{await missing.runtime.start();await assert.rejects(missing.runtime.resumePredefense({req,runId:activation.activation_id}),{code:'SESSION_REVOKED'});assert(!missing.calls.some(x=>String(x[1]).includes('read_ctf_predefense_recovery')));}finally{await missing.runtime.stop();}
 const gate=deferred(),entered=deferred();const f=fixture({sqlHook:async(name,sql)=>{if(sql.includes('read_ctf_predefense_recovery')){entered.resolve();await gate.promise;return{rows:[{value:{version:1,state:'not_found',runId:activation.activation_id,admissionId:null,blockedOperationId:null,decisionId:null,currentCompletion:false}}]};}}});
 const controller=new AbortController();try{await f.runtime.start();const pending=f.runtime.recoverPredefense({req,runId:activation.activation_id,signal:controller.signal});pending.catch(()=>{});await entered.promise;controller.abort();gate.resolve();await assert.rejects(pending);}finally{gate.resolve();await f.runtime.stop();}
});
