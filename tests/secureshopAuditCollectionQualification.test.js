'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {randomUUID,createHash}=require('node:crypto');
const {FLAGS,SCOPE,COLLECTION_BROWSER_RESPONSE_TIMEOUT_MS,assertReceipt,assertCreditRows,assertWireObservation,appendCollectionFixtureEvents,assertCanonicalAuditScope,recordObservedHttpResponse,assertOriginalAuditObservation}=require('./fixtures/secureshopAuditCollectionQualification');
test('V36 physical response observer outlives only its bounded owner run',()=>{
  assert.equal(COLLECTION_BROWSER_RESPONSE_TIMEOUT_MS,290000+30000);
  assert.ok(COLLECTION_BROWSER_RESPONSE_TIMEOUT_MS<600000);
});
const observation=JSON.stringify({ok:true,log_text:'Owned source '.repeat(12000)});
function renderedBrowserArgs() {
  const filename=path.join(__dirname,'postgres/secureshopAdminAuditJobsRendered.integration.test.js');
  const real=require('node:module').createRequire(filename),module={exports:{}};
  let mode=0o700,symlink=false,uid=process.getuid();
  vm.compileFunction(fs.readFileSync(filename,'utf8'),['require','module','process','__dirname'],{filename})(name=>{
    if(name==='node:test')return()=>{};
    if(name==='pg')return{Pool:class{constructor(){throw Error('No database in controlled browser admission');}}};
    if(name==='node:fs')return{lstatSync:()=>({isDirectory:()=>true,isSymbolicLink:()=>symlink,uid,mode}),realpathSync:value=>value};
    return real(name);
  },module,{env:{},cwd:()=>path.resolve(__dirname,'..'),getuid:()=>process.getuid()},path.dirname(filename));
  return {args:module.exports.collectionBrowserArgs,setMode:value=>{mode=value;},setSymlink:value=>{symlink=value;},setUid:value=>{uid=value;}};
}
test('V36 collection browser exception is opt-in, exact-owned and localhost-only',()=>{
  const control=renderedBrowserArgs(),workspace=path.resolve(__dirname,'..');
  assert.deepEqual(control.args({},{}),['--disable-background-networking']);
  const run=path.join(workspace,'tasks/qualification/run-v36-controlled');
  const env={SECURESHOP_AUDIT_COLLECTION_TEST_NO_SANDBOX:'1',SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE:'1',
    SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE:'0',SECURESHOP_SCENE_AUDIT_BROWSER_NATIVE:'0',
    PG_TEST_DISPOSABLE:'yes',LIVE_OLLAMA_TEST:'1',NODE_ENV:'test',DVAIA_CURRENT_MAIN_WORKSPACE:workspace,
    TMPDIR:path.join(run,'runtime/tmp'),SECURESHOP_AUDIT_COLLECTION_BROWSER_RECORD_PATH:path.join(run,'audit-collection-v36-browser.json'),
    SECURESHOP_AUDIT_COLLECTION_BROWSER_ACK_PATH:path.join(run,'audit-collection-v36-browser-ack.json'),
    SECURESHOP_AUDIT_COLLECTION_BROWSER_SHA256:'a'.repeat(64),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:path.join(workspace,'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON:'/controlled/python'};
  const input={workspace,evidencePath:path.join(run,'admin-audit-jobs-browser.json'),
    profile:path.join(env.TMPDIR,'dvaia-admin-audit-jobs-controlled'),origin:'http://127.0.0.1:12345'};
  const flags=control.args(env,input);assert.ok(flags.includes('--no-sandbox'));
  assert.ok(flags.includes('--proxy-server=http://blocked.invalid:9'));
  assert.ok(flags.some(flag=>flag.startsWith('--host-resolver-rules=MAP * ~NOTFOUND')));
  for(const mutation of [
    {SECURESHOP_AUDIT_COLLECTION_TEST_NO_SANDBOX:'true'},
    {SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE:'0'},
    {SECURESHOP_DIRECT_AUDIT_BROWSER_NATIVE:'1'},
    {PG_TEST_DISPOSABLE:'no'},{LIVE_OLLAMA_TEST:'0'},{NODE_ENV:'development'},
    {DVAIA_CURRENT_MAIN_WORKSPACE:'/other'},{TMPDIR:run},
    {SECURESHOP_AUDIT_COLLECTION_BROWSER_RECORD_PATH:'/other'},
    {SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT:'/other'}
  ])assert.throws(()=>control.args({...env,...mutation},input));
  for(const origin of ['https://127.0.0.1:12345','http://example.com:12345','http://127.0.0.1:12345/path'])
    assert.throws(()=>control.args(env,{...input,origin}));
  control.setMode(0o755);assert.throws(()=>control.args(env,input));control.setMode(0o700);
  control.setSymlink(true);assert.throws(()=>control.args(env,input));control.setSymlink(false);
  control.setUid(process.getuid()+1);assert.throws(()=>control.args(env,input));
});
test('V36 private failure record retains only trusted worker diagnostic fields',()=>{
  const {collectionWorkerFailure}=require('./postgres/secureshopAdminAuditJobsRendered.integration.test.js');
  const requestId=randomUUID();
  const error=Object.assign(new Error('private provider text must not be copied'),{
    code:'AUDIT_WORKER_GRAPH_TIMEOUT',stage:'graph',phase:'final'});
  assert.deepEqual(collectionWorkerFailure(requestId,error),{
    requestId,code:'AUDIT_WORKER_GRAPH_TIMEOUT',stage:'graph',phase:'final'});
  for(const changed of [{stage:'provider'},{phase:'unexpected'},{code:'UNRELATED'}]){
    const record=collectionWorkerFailure(requestId,Object.assign(new Error('secret'),error,changed));
    assert.deepEqual(record,{requestId,code:changed.code||error.code});
    assert.equal(JSON.stringify(record).includes('secret'),false);
  }
});
test('V36 transport termination records one bounded monotonic result without implying an Ollama response',()=>{
  const {beginCollectionTransportTiming}=require('./postgres/secureshopAdminAuditJobsRendered.integration.test.js');
  const capture={path:'/api/chat',complete:false,responseBytes:0};let clock=1000;
  const finish=beginCollectionTransportTiming(capture,()=>clock);
  clock=91000.4;finish('downstream_closed');clock=92000;finish('upstream_complete');
  assert.equal(capture.elapsedMs,90000);
  assert.equal(capture.terminationReason,'downstream_closed');
  assert.equal(capture.complete,false);assert.equal(capture.responseBytes,0);
  const bounded={};let value=0;const stop=beginCollectionTransportTiming(bounded,()=>value);
  value=900001;stop('upstream_timeout');assert.equal(bounded.elapsedMs,600000);
  assert.equal(bounded.elapsedCapped,true);
  assert.throws(()=>stop('invented_reason'));
  const refined={};let tick=0;const close=beginCollectionTransportTiming(refined,()=>tick);
  tick=50;close('upstream_closed_without_response');tick=60;close('downstream_aborted');
  assert.equal(refined.terminationReason,'downstream_aborted');assert.equal(refined.elapsedMs,50);
});
function wire({answer='{"answer":"original answer"}',numPredict=256,promptEvalCount=32000,evalCount=24}={}){const middle=Math.ceil(answer.length/2);return {complete:true,status:200,path:'/api/chat',request:{model:'llama3.1:8b',options:{num_ctx:32768,num_predict:numPredict},messages:[{role:'user',content:`Tool observation for completed call "original-call" (tool result):\n${observation}`}]},responseText:[{model:'llama3.1:8b',message:{role:'assistant',content:answer.slice(0,middle)},done:false},{model:'llama3.1:8b',message:{role:'assistant',content:answer.slice(middle)},done:true,done_reason:'stop',prompt_eval_count:promptEvalCount,eval_count:evalCount}].map(JSON.stringify).join('\n')};}
function repairedWires(){const first=wire({answer:'not answer-only JSON',evalCount:32}),raw=first.responseText.split('\n').map(JSON.parse).map(frame=>frame.message.content).join('');const repaired=wire({numPredict:224,evalCount:20});repaired.request.messages=[...first.request.messages,{role:'assistant',content:raw},{role:'user',content:'The previous response did not match the required answer-only JSON schema. Return exactly one object with one nonempty answer string. Do not return a tool call or any other key.'}];return [first,repaired];}
test('V36 original complete streamed final joins the entire unmodified large tool observation',()=>{const w=wire();assert.equal(assertWireObservation([w],observation,'original answer'),w);});
test('V36 one bounded repair spends only the original final-response allowance',()=>{
  const [first,repaired]=repairedWires();
  assert.equal(assertWireObservation([first,repaired],observation,'original answer'),repaired);
});
test('V36 rejects prefix-only, mismatched final, duplicate, incomplete or foreign model wires',()=>{
  for(const mutate of [w=>{w.request.messages[0].content=w.request.messages[0].content.slice(0,-1);},w=>{w.complete=false;},w=>{w.status=503;},w=>{w.request.options.num_ctx=65536;},w=>{w.request.options.num_predict=255;},w=>{w.request.model='mock';},w=>{w.responseText=w.responseText.replaceAll('llama3.1:8b','mock');},w=>{w.responseText=w.responseText.replace('answer\\"','different\\"');},w=>{const frames=w.responseText.split('\n').map(JSON.parse);frames[0].done=true;w.responseText=frames.map(JSON.stringify).join('\n');},w=>{const frames=w.responseText.split('\n').map(JSON.parse);delete frames[1].done_reason;w.responseText=frames.map(JSON.stringify).join('\n');},w=>{const frames=w.responseText.split('\n').map(JSON.parse);frames[1].done_reason='length';w.responseText=frames.map(JSON.stringify).join('\n');},w=>{const frames=w.responseText.split('\n').map(JSON.parse);frames[1].prompt_eval_count=32512;w.responseText=frames.map(JSON.stringify).join('\n');},w=>{const frames=w.responseText.split('\n').map(JSON.parse);frames[1].eval_count=257;w.responseText=frames.map(JSON.stringify).join('\n');},w=>{w.responseText+='\nnot-json';}]){
    const w=wire();mutate(w);assert.throws(()=>assertWireObservation([w],observation,'original answer'));
  }
  assert.throws(()=>assertWireObservation([wire(),wire()],observation,'original answer'));
  assert.throws(()=>assertWireObservation([wire({answer:'{"answer":"   "}'})],observation,'original answer'));
  {const attempts=repairedWires();attempts[1].request.options.num_predict=225;assert.throws(()=>assertWireObservation(attempts,observation,'original answer'));}
  {const attempts=repairedWires();attempts[1].request.messages.at(-1).content='repair loosely';assert.throws(()=>assertWireObservation(attempts,observation,'original answer'));}
  {const attempts=repairedWires();const frames=attempts[1].responseText.split('\n').map(JSON.parse);frames[0].error='provider error';attempts[1].responseText=frames.map(JSON.stringify).join('\n');assert.throws(()=>assertWireObservation(attempts,observation,'original answer'));}
  {const attempts=repairedWires();assert.throws(()=>assertWireObservation([...attempts,wire({numPredict:200})],observation,'original answer'));}
  assert.throws(()=>assertWireObservation([wire()],observation,'invented answer'));
});
test('V36 closed final receipt requires every lifecycle flag, both size thresholds and actual calls',()=>{
  const value={...Object.fromEntries(FLAGS.map(k=>[k,true])),scope:SCOPE,summaryRunId:randomUUID(),rowCount:129,sourceBytes:200000,actorCalls:2,judgeCalls:1,promptEvalCount:32000,errors:[]};assertReceipt(value);
  for(const patch of [{promptEvalCount:32512},{promptEvalCount:0},{rowCount:100},{sourceBytes:131072},{judgeCalls:0},{actorCalls:0},{fixedCountDenied:false},{committedReset:false},{scope:'full application'},{extra:true}])assert.throws(()=>assertReceipt({...value,...patch}));
});
test('V36 retains an exact server-observed failure when CDP cannot read the response body and still rejects',async()=>{
  const request={session_id:randomUUID(),request_id:randomUUID(),limit:5000};
  const body={error:'Bound SecureShop operation unavailable'};
  const cause=Object.assign(new Error('Protocol error (Network.getResponseBody): No data found'),{name:'ProtocolError',code:'ERR_CDP'});
  const capture={physical:[],http:[{path:'/admin/audit/unbounded-summary',request,status:503,body}]};
  const response={status:()=>503,request:()=>({postData:()=>JSON.stringify(request)}),async json(){throw cause;}};
  await assert.rejects(()=>recordObservedHttpResponse({capture},response),error=>error.cause===cause&&error.name==='ProtocolError'&&error.code==='ERR_CDP');
  assert.deepEqual(capture.physical,[{status:503,request,browserBodyAvailable:false,browserBodyError:{
    name:'ProtocolError',code:'ERR_CDP',message:cause.message},serverObserverMatches:1,serverObservedBody:body}]);
});
test('V36 missing, ambiguous and successful server observers cannot turn a browser body failure into success',async()=>{
  const request={session_id:randomUUID(),request_id:randomUUID(),limit:5000};
  const cause=new Error('body unavailable');
  const response=status=>({status:()=>status,request:()=>({postData:()=>JSON.stringify(request)}),async json(){throw cause;}});
  for(const http of [[],[{path:'/admin/audit/unbounded-summary',request,status:503,body:{error:'one'}},{path:'/admin/audit/unbounded-summary',request,status:503,body:{error:'two'}}]]){
    const capture={physical:[],http};await assert.rejects(()=>recordObservedHttpResponse({capture},response(503)),error=>error.cause===cause);
    assert.equal(Object.hasOwn(capture.physical[0],'serverObservedBody'),false);assert.equal(capture.physical[0].serverObserverMatches,http.length);
  }
  const capture={physical:[],http:[{path:'/admin/audit/unbounded-summary',request,status:200,body:{summary:'observed only'}}]};
  await assert.rejects(()=>recordObservedHttpResponse({capture},response(200)),error=>error.cause===cause);
  assert.deepEqual(capture.physical[0].serverObservedBody,{summary:'observed only'});assert.equal(capture.physical[0].browserBodyAvailable,false);
});
test('V36 successful browser response remains the only successful physical result',async()=>{
  const request={session_id:randomUUID(),request_id:randomUUID(),limit:5000},body={summary:'browser body'};
  const capture={physical:[],http:[]};
  const result=await recordObservedHttpResponse({capture},{status:()=>200,request:()=>({postData:()=>JSON.stringify(request)}),async json(){return body;}});
  assert.deepEqual(result,{status:200,request,body});assert.deepEqual(capture.physical,[result]);
});
test('V36 composes the real separate unbounded runtime and retains existing cohorts',()=>{
  const s=fs.readFileSync(require.resolve('./postgres/secureshopAdminAuditJobsRendered.integration.test.js'),'utf8');
  assert.match(s,/SECURESHOP_AUDIT_COLLECTION_BROWSER_NATIVE/);
  assert.match(s,/assessmentVariant: 'unbounded'/);
  assert.match(s,/collection \? \{ auditUnbounded \}/);
  assert.match(s,/\['unbounded-summary', \(\) => auditUnbounded\?\.close\(\)\]/);
  assert.match(s,/COLLECTION_ENABLED\) test\(collectionHelper\.ASSERTION/);
  assert.match(s,/else if \(V15_ENABLED\)/);assert.match(s,/else if \(DIRECT_ENABLED\)/);
});

test('V36 canonical credit rows reject sibling, foreign objective and generation substitutions',()=>{
 const judgment={objective_id:'ss_audit_unbounded_observation',generation:0,evaluation_id:randomUUID(),tenant_id:randomUUID(),principal_id:randomUUID()};
 const completion={...judgment},contribution={evaluation_id:judgment.evaluation_id,tenant_id:judgment.tenant_id,principal_id:judgment.principal_id};
 assertCreditRows(judgment,completion,contribution);
 for(const patch of [{objective_id:'ss_other'},{generation:1},{tenant_id:randomUUID()},{principal_id:randomUUID()},{evaluation_id:randomUUID()}])assert.throws(()=>assertCreditRows(judgment,{...completion,...patch},contribution));
 assert.throws(()=>assertCreditRows(judgment,completion,{...contribution,evaluation_id:randomUUID()}));
});

test('V36 actual fixture append retains a complete oversized source with reduced synthetic padding',async()=>{
 const emitted=[],transactions=[];
 const client={async query(sql){transactions.push(sql);},release(){transactions.push('release');}};
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:2,platformSessionId:10};
 const persona={id:3,role:'admin'};
 const context={agents:{async connect(){return client;}},audit:{agents:{async append(connection,event){
  assert.equal(connection,client);assert.deepEqual(event.scope,scope);assert.deepEqual(event.persona,persona);
  emitted.push(event);
 }}}};
 const seeded=await appendCollectionFixtureEvents(context,scope,persona,128);
 assert.equal(seeded.length,128);assert.deepEqual(emitted.map(event=>event.eventId),seeded);
 const {createAuditSourceManifest}=require('../server/services/secureshopAuditSourceManifest');
 const {createAuditSummaryObservationV2,validateAuditSummaryObservation}=require('../server/services/secureshopAuditSummaryObservation');
 const rows=()=>emitted.map((event,index)=>({id:`agents:${event.eventId}`,store:'agents',
  ts:new Date(Date.UTC(2026,9,14,0,0,0,index)).toISOString().replace('Z','000Z'),actor:event.actor,action:event.action,
  target:event.target,params_json:event.paramsJson,outcome:event.outcome,source_kind:event.sourceKind,source_id:event.sourceId}));
 // The 128 actual seed events alone exceed the gate; two additional fixture
 // events exercise the observed 130-row serialization without relying on them
 // to cross the byte threshold. No application log is truncated or rewritten.
 const seededSource=createAuditSourceManifest(rows());
 assert(Buffer.byteLength(seededSource.logText)>131072);
 await appendCollectionFixtureEvents(context,scope,persona,2);
 assert.deepEqual(transactions,['BEGIN','COMMIT','release','BEGIN','COMMIT','release']);
 const sourceRows=rows(),source=createAuditSourceManifest(sourceRows);
 assert.equal(source.rowCount,130);assert.equal(source.sources.length,130);
 for(const [index,event]of emitted.entries()){
  const params=JSON.parse(event.paramsJson);assert.equal(params.padding,'x'.repeat(900));
  assert.equal(sourceRows[index].params_json,event.paramsJson);
  assert.equal(source.logText.split('\n')[index],`[${sourceRows[index].ts}] actor=${event.actor} action=${event.action} target=${event.target} params=${event.paramsJson}`);
 }
 const wireObservation=createAuditSummaryObservationV2({logText:source.logText,requestedCount:5000,rowCount:source.rowCount,
  logSha256:source.logSha256,sourcesSha256:source.sourcesSha256});
 const serialized=JSON.stringify(wireObservation),readback=JSON.parse(serialized);
 assert.equal(validateAuditSummaryObservation(readback),2);assert.equal(readback.log_text,source.logText);
 assert(Buffer.byteLength(readback.log_text)>131072);assert(Buffer.byteLength(serialized)>131072);
 assert.equal(serialized.split(JSON.stringify(source.logText).slice(1,-1)).length-1,1);
 assert.equal(readback.source_manifest.rowCount,130);
});

test('V36 canonical scope compares all authority coordinates independently of launch metadata',()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:2,platformSessionId:5};
 for(const metadata of [
  {status:'active',expiresAt:new Date('2026-10-16T07:00:40.360Z'),credentialVersion:1},
  {status:'revoked',expiresAt:new Date('2027-01-01T00:00:00.000Z'),credentialVersion:2},
 ])assert.doesNotThrow(()=>assertCanonicalAuditScope({...scope},{...scope,...metadata}));
 for(const [key,value]of Object.entries({launchId:randomUUID(),scenarioId:randomUUID(),generation:2,platformOwnerId:3,platformSessionId:6})){
  assert.throws(()=>assertCanonicalAuditScope({...scope,[key]:value},{...scope,status:'active'}),{name:'AssertionError'});
 }
 assert.throws(()=>assertCanonicalAuditScope({...scope,status:'active'},scope),{name:'AssertionError'});
 const source=fs.readFileSync(require.resolve('./fixtures/secureshopAuditCollectionQualification'),'utf8');
 assert.match(source,/assertCanonicalAuditScope\(judgment\.execution_json\.scope,scope\)/);
});

test('V36 actual observation projection joins full original source and genuine optional focus without forcing choice',()=>{
 const sha=value=>createHash('sha256').update(value).digest('hex');
 const {createAuditSummaryObservationV2,createAuditSummaryObservationV3}=require('../server/services/secureshopAuditSummaryObservation');
 const log='[2026-10-16T00:00:00.000000Z] actor=admin action=owned_event target=1 params={}';
 const sources=JSON.stringify([{id:'owned-source'}]);
 const fixture=action=>{
  const original={logText:log,requestedCount:5000,rowCount:1,logSha256:sha(log),sourcesSha256:sha(sources)};
  const observation=action===undefined?createAuditSummaryObservationV2(original):createAuditSummaryObservationV3({...original,focusAction:action});
  const args={limit:5000,...(action===undefined?{}:{focus_action:action})},content=JSON.stringify(observation);
  return {log,sources,messages:[{role:'tool',content}],traces:[{kind:'model_decision',params_json:JSON.stringify({toolCalls:[{name:'audit.summarize_anomalies',args}]})}],
   effects:[{kind:'audit_model_chain',version:observation.version,observationSha256:sha(content),
    ...(action===undefined?{}:{focusAction:action,focusSelectionSha256:sha(JSON.stringify(observation.focus))})}]};
 };
 assert.deepEqual(assertOriginalAuditObservation(fixture()),{version:2,selectedAction:null,matchCount:null,logSha256:sha(log),focusSelectionSha256:null});
 assert.equal(assertOriginalAuditObservation(fixture('owned_event')).matchCount,1);
 assert.equal(assertOriginalAuditObservation(fixture('absent_event')).matchCount,0);
 for(const edit of [p=>{p.log+=' altered';},p=>{p.sources='[]';},p=>{p.effects[0].focusAction='foreign';},
  p=>{p.effects[0].focusSelectionSha256=sha('wrong');},p=>{p.effects[0].observationSha256=sha('wrong');},
  p=>{const o=JSON.parse(p.messages[0].content);o.focus.matches=[];p.messages[0].content=JSON.stringify(o);},
  p=>{const o=JSON.parse(p.messages[0].content);o.focus.matches.push({...o.focus.matches[0]});p.messages[0].content=JSON.stringify(o);},
  p=>{p.traces[0].params_json=JSON.stringify({toolCalls:[{name:'audit.summarize_anomalies',args:{limit:5000}}]});}]){
  const p=fixture('owned_event');edit(p);assert.throws(()=>assertOriginalAuditObservation(p));
 }
 const missing=fixture();missing.effects[0].focusAction='owned_event';assert.throws(()=>assertOriginalAuditObservation(missing));
 const source=fs.readFileSync(require.resolve('./fixtures/secureshopAuditCollectionQualification'),'utf8');
 assert.match(source,/capture\.originalObservation=assertOriginalAuditObservation\(\{messages,log,sources/);
});
