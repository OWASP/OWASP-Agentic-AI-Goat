'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {createHash}=require('node:crypto');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');
const V66=require('./fixtures/secureshopMcpManifestQualification');

test('V66 receipt admits only the distinct completed bounded cohort',()=>{
 const value={...V66.createV66Receipt(),actorCalls:4,judgeCalls:1,actualTurns:1,genuineCredit:1};
 for(const flag of V66.V66_FLAGS)value[flag]=true;
 assert.equal(V66.assertV66Receipt(value),value);
 for(const change of [{judgeCalls:0},{actorCalls:7},{actualTurns:2},{genuineCredit:0},
  {savedAssessmentGetNoEffect:false},{scope:'V43-standalone'},{errors:['cleanup failed']}]){
  assert.throws(()=>V66.assertV66Receipt({...value,...change}));
 }
 assert.throws(()=>V66.assertV66Receipt({...value,privateWire:'leaked'}));
});

test('V66 validates original Judge call metadata rather than nonexistent top-level provider fields',()=>{
 const actual={index:0,stage:'criterion',request:{method:'chat',input:[]},response:'pass',
  metadata:{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,
   tokens:36,evalCount:36}};
 assert.equal(V66.assertV66JudgeCallMetadata(actual,'llama3.1:8b'),actual.metadata);
 for(const metadata of [undefined,{...actual.metadata,provider:'mock'},
  {...actual.metadata,model:'other-model'},{...actual.metadata,mocked:true},
  {...actual.metadata,fallback:true}])
  assert.throws(()=>V66.assertV66JudgeCallMetadata({...actual,metadata},'llama3.1:8b'));
 assert.throws(()=>V66.assertV66JudgeCallMetadata({provider:'ollama',model:'llama3.1:8b'},'llama3.1:8b'));
});

test('V66 passive capture retains one original completed JSON response without rewriting it',()=>{
 const body=Buffer.from('{"sessionId":"original"}');
 const request={method:'POST',originalUrl:'/api/secureshop/agents/admin/assistant/chat'};
 const captures=[];const response=new EventEmitter();const chunks=[];
 response.statusCode=200;response.writableFinished=false;
 response.getHeader=()=> 'application/json; charset=utf-8';
 response.write=function(part){chunks.push(Buffer.from(part));return true;};
 response.end=function(part){if(part)chunks.push(Buffer.from(part));this.writableFinished=true;this.emit('finish');return this;};
 V66.captureV66Body(request,response,body);
 V66.observeV66Json(request,response,captures);
 body.fill(0);
 const output=Buffer.from('{"ok":true}');response.end(output);
 assert.equal(captures.length,1);
 assert.deepEqual(captures[0],{method:'POST',path:request.originalUrl,
  requestBody:'{"sessionId":"original"}',requestSha256:createHash('sha256').update('{"sessionId":"original"}').digest('hex'),
  status:200,contentType:'application/json; charset=utf-8',complete:true,
  responseBody:'{"ok":true}',responseSha256:createHash('sha256').update('{"ok":true}').digest('hex')});
 assert.equal(Buffer.concat(chunks).toString(),'{"ok":true}');
});

test('V66 captures the physical IDs-only role confirmation, not the manual import route',()=>{
 const body=Buffer.from('{"sessionId":"s","requestId":"r","proposalId":"p"}');
 const role={method:'POST',originalUrl:'/api/secureshop/agents/admin/assistant/mcp/confirm'};
 const manual={method:'POST',originalUrl:'/api/secureshop/admin/mcp/import-manifest'};
 V66.captureV66Body(role,null,body);V66.captureV66Body(manual,null,body);
 assert.deepEqual(role.v66Body,body);assert.equal(manual.v66Body,undefined);
 const captures=[];const response=new EventEmitter();response.statusCode=200;
 response.getHeader=()=> 'application/json';response.writableFinished=false;
 response.write=()=>true;response.end=function(){this.writableFinished=true;this.emit('finish');return this;};
 V66.observeV66Json(role,response,captures);V66.observeV66Json(manual,response,captures);
 response.end();assert.equal(captures.length,1);assert.equal(captures[0].path,role.originalUrl);
});

test('V66 native mount does not feed one confirm response to both incompatible observers',()=>{
 const native=readFileSync(join(__dirname,'postgres/secureshopOwnedMcpRegistryRendered.native.js'),'utf8');
 assert.match(native,/if \(!V66_ENABLED && !V42_ENABLED\) v43Json\.observeOriginalV43Json\(request, response, v43JsonCaptures\)/);
 assert.match(native,/if \(V66_ENABLED \|\| V42_ENABLED\) v66Contract\.observeV66Json\(request, response, v43JsonCaptures\)/);
});

test('V66 accepts the already active physical Admin assistant composer without clicking its disabled tab',async()=>{
 const active={channelGroups:1,openButtons:1,panes:1,inputs:1,openDisabled:true,
  paneVisible:true,composerVisible:true,submitVisible:true};
 const frame={evaluate:async()=>active},clicks=[],phases=[];
 const result=await V66.ensureAdminAssistantOpen({page:{},frameFor:async()=>frame,
  click:async(...args)=>clicks.push(args),record:phase=>phases.push(phase),timeoutMs:200});
 assert.equal(result,frame);assert.deepEqual(clicks,[]);
 assert.equal(phases.length,1);assert.equal(phases[0].kind,'adminAssistantReady');
 assert.equal(phases[0].alreadyActive,true);assert.equal(phases[0].physicalSwitch,false);
});

test('V66 physically switches from registered tools before using the Admin assistant composer',async()=>{
 const inactive={channelGroups:1,openButtons:1,panes:1,inputs:0,openDisabled:false,
  paneVisible:false,composerVisible:false,submitVisible:false};
 const active={...inactive,inputs:1,openDisabled:true,paneVisible:true,
  composerVisible:true,submitVisible:true};
 let state=inactive;const frame={evaluate:async()=>state},clicks=[],phases=[];
 await V66.ensureAdminAssistantOpen({page:{},frameFor:async()=>frame,
  click:async(_frame,args)=>{clicks.push(args);state=active;},
  record:phase=>phases.push(phase),timeoutMs:200});
 assert.deepEqual(clicks,[{selector:'button[aria-label="Open Admin assistant"]'}]);
 assert.equal(phases[0].kind,'adminAssistantReady');
 assert.equal(phases[0].physicalSwitch,true);assert.equal(phases[0].alreadyActive,false);
});

test('V66 records bounded UI diagnostics and denies absent Admin assistant controls',async()=>{
 const frame={evaluate:async()=>({channelGroups:0,openButtons:0,panes:0,inputs:0,
  openDisabled:null,paneVisible:false,composerVisible:false,submitVisible:false})};
 const phases=[];
 await assert.rejects(V66.ensureAdminAssistantOpen({page:{},frameFor:async()=>frame,
  click:async()=>{throw Error('unexpected click')},record:phase=>phases.push(phase),timeoutMs:120}),
 /mounted Admin assistant controls unavailable/);
 assert.deepEqual(phases,[{kind:'adminAssistantUnavailable',ui:await frame.evaluate()}]);
});

test('V66 assessment failure distinguishes no physical POST from a pending original response',async()=>{
 const path='/api/secureshop/agents/admin/assistant/mcp-manifest/assess';
 const ui={mounted:true,buttons:[{label:'Check saved MCP manifest assessment',disabled:false,visible:true}],
  alert:'Saved MCP manifest assessment unavailable.'};
 const frame={evaluate:async()=>ui};
 for(const captures of [[],[{method:'POST',path,requestSha256:'a'.repeat(64),
  status:null,complete:false,responseSha256:null}]]){
  const phases=[];
  await assert.rejects(V66.waitOriginalAssessmentPost({page:{},frameFor:async()=>frame,
   captures,start:0,record:phase=>phases.push(phase),timeoutMs:5}),
  /physical assessment POST unavailable/);
  assert.equal(phases.length,1);assert.equal(phases[0].kind,'assessmentPostUnavailable');
  assert.equal(phases[0].postSeen,captures.length===1);
  assert.equal(phases[0].observedCount,captures.length);
  assert.deepEqual(phases[0].ui,ui);
  assert.ok(!JSON.stringify(phases[0]).includes('requestBody'));
 }
});

test('V66 assessment wait requires the original complete POST without synthesizing a response',async()=>{
 const row={method:'POST',path:'/api/secureshop/agents/admin/assistant/mcp-manifest/assess',
  status:200,complete:true};const phases=[];
 assert.equal(await V66.waitOriginalAssessmentPost({page:{},frameFor:async()=>({}),captures:[row],
  start:0,record:phase=>phases.push(phase),timeoutMs:5}),row);
 assert.deepEqual(phases,[]);
});

test('V66 saved assessment retains each distinct original response and stops on explicit denial',async()=>{
 const pending={completed:false,status:'unconfirmed',modelEvaluated:false};
 for(const denied of [
  {completed:false,status:'ineligible',modelEvaluated:false},
  {completed:false,status:'disabled',modelEvaluated:false},
  {completed:false,replayed:false,judgment:{evaluationId:'a',verdict:'fail',canRetry:false}},
  {completed:false,replayed:false,judgment:{evaluationId:'a',verdict:'unavailable',canRetry:true}},
 ]){
  const responses=[{status:200,body:JSON.stringify(pending)},
   {status:200,body:JSON.stringify(denied)}];
  const phases=[];let calls=0;
  await assert.rejects(V66.waitSavedManifestAssessment({read:async()=>responses[calls++],
   record:phase=>phases.push(phase),timeoutMs:1000}),
   /saved canonical manifest assessment (ineligible|disabled|fail without credit|unavailable without credit)/);
  assert.equal(calls,2);assert.deepEqual(phases.map(phase=>phase.kind),
   ['assessmentSavedGet','assessmentSavedGet']);
  assert.deepEqual(phases.map(phase=>phase.responseBody),responses.map(row=>row.body));
 }
});

test('V66 saved assessment records HTTP failure and accepts only a pass with canonical completion',async()=>{
 const phases=[];
 await assert.rejects(V66.waitSavedManifestAssessment({read:async()=>({status:503,
  body:'{"error":"MCP manifest assessment unavailable"}'}),
 record:phase=>phases.push(phase),timeoutMs:1000}),/HTTP 503/);
 assert.equal(phases.length,1);assert.equal(phases[0].status,503);
 const judgment={evaluationId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',verdict:'pass',canRetry:false};
 const accepted={completed:true,replayed:true,judgment};const saved=[];
 assert.deepEqual(await V66.waitSavedManifestAssessment({read:async()=>({status:200,
  body:JSON.stringify(accepted)}),record:phase=>saved.push(phase),timeoutMs:1000}),accepted);
 assert.deepEqual(JSON.parse(saved[0].responseBody),accepted);
 await assert.rejects(V66.waitSavedManifestAssessment({read:async()=>({status:200,
  body:JSON.stringify({completed:true})}),record:()=>{},timeoutMs:1000}),/invalid completed response/);
});

test('V42 closed receipt cannot substitute V66 flags, mixed catalog authority or extra calls',()=>{
 const receipt={...V66.createV42Receipt(),actorCalls:4,judgeCalls:1,actualTurns:2,genuineCredit:1,
  catalogAdmission:{objectiveId:V66.V42_OBJECTIVE,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false}};
 for(const flag of V66.V42_FLAGS)receipt[flag]=true;
 assert.equal(V66.assertV42Receipt(receipt),receipt);
 for(const change of [{actorCalls:5},{judgeCalls:0},{savedReloadNoEffect:false},{fixedPhysicalDenialNoHttp:false},
  {catalogAdmission:{...receipt.catalogAdmission,fixtureLocalCandidateAdmission:false}},
  {catalogAdmission:{...receipt.catalogAdmission,productionQualification:'native-browser-judge'}},
  {scope:V66.V66_SCOPE},{extra:true}])assert.throws(()=>V66.assertV42Receipt({...receipt,...change}));
});

test('V42 disposable admission keeps the exact pending source guard and canonical admin denial/enablement',async()=>{
 const previous=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 try{
  const current=require('../server/config/secureshopCurriculum'),curriculum={...current,isQualifiedObjective:()=>false,OBJECTIVES:current.OBJECTIVES.map(row=>row.id===V66.V42_OBJECTIVE?{...row,qualification:'pending'}:row)},context=Object.freeze({admin:'owned'}),calls=[];
  const row={objectiveId:V66.V42_OBJECTIVE,qualification:'pending',enabled:false,revision:'7'};
  let admitted=false;
  const catalog={list:async input=>{assert.equal(input,context);return {objectives:[row]};},set:async(input,request)=>{
   assert.equal(input,context);assert.deepEqual(request,{objectiveId:V66.V42_OBJECTIVE,enabled:true,expectedRevision:'7'});
   calls.push(admitted?'enable':'denied');if(!admitted)throw Object.assign(Error('pending'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});return{enabled:true,qualification:'native-browser-judge'};}};
  const migration={query:async(sql,values)=>{calls.push('sql');
   for(const guard of ["qualification='pending'","is_enabled=false","catalog_active=true","configuration_source='checked_in_default'",'source_sha256=$2','source_document=$3::jsonb'])assert(sql.includes(guard));
   assert.equal(values[0],V66.V42_OBJECTIVE);assert.equal(values[1],'385ffd442a93f33fc2195329599e5d269dc04c117d9975242e04ede860db0590');
   assert.equal(createHash('sha256').update(values[2]).digest('hex'),values[1]);
   admitted=true;return{rowCount:1,rows:[{objective_id:V66.V42_OBJECTIVE,qualification:'native-browser-judge',is_enabled:false}]};}};
  assert.deepEqual(await V66.admitV42DisposableCandidate({catalog,migration,curriculum,administratorContext:context}),{
   objectiveId:V66.V42_OBJECTIVE,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});
  assert.deepEqual(calls,['denied','sql','enable']);
  for(const changed of [{...curriculum,OBJECTIVES:curriculum.OBJECTIVES.map(value=>value.id===V66.V42_OBJECTIVE?{...value,text:value.text+' changed'}:value)},
   {...curriculum,OBJECTIVES:curriculum.OBJECTIVES.map(value=>value.id===V66.V42_OBJECTIVE?{...value,defaultEnabled:true}:value)}])
   await assert.rejects(V66.admitV42DisposableCandidate({catalog,migration,curriculum:changed,administratorContext:context}));
  process.env.PG_TEST_DISPOSABLE='no';
  await assert.rejects(V66.admitV42DisposableCandidate({catalog,migration,curriculum,administratorContext:context}));
  assert.deepEqual(calls,['denied','sql','enable']);
 }finally{if(previous===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=previous;}
});

test('V42 mounted dispatch and sibling mutation resolve the current registry after fixed replacement',async t=>{
 const express=require('express');let closed=false;const calls=[];
 const first={router:(_req,res)=>{assert.equal(closed,false);res.json({instance:1});},service:{mutate:async()=>{assert.equal(closed,false);return 1;}},assertReady:async()=>{assert.equal(closed,false);return true;}};
 const second={router:(_req,res)=>{calls.push('router');res.json({instance:2});},service:{mutate:async(...args)=>{calls.push(args);return 2;},read:async()=>2},assertReady:async()=>true};
 let current=first;const mount=V66.currentRegistryMount(()=>current),app=express();app.use('/registry',mount.router);
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const endpoint=`http://127.0.0.1:${server.address().port}/registry`;
 assert.deepEqual(await(await fetch(endpoint)).json(),{instance:1});closed=true;current=second;
 assert.deepEqual(await(await fetch(endpoint)).json(),{instance:2});assert.equal(await mount.service.mutate('peer','input'),2);
 assert.equal(await mount.service.read(),2);assert.equal(await mount.assertReady(),true);assert.deepEqual(calls,['router',['peer','input']]);
});

test('V42 progress callback uses same-origin standalone cookie route and exact objective/count projection',async()=>{
 const original={principalId:'owned',objectives:[{objectiveId:V66.V42_OBJECTIVE,completed:false}],totalObjectives:1,completedObjectives:0};
 const page={evaluate:async callback=>require('node:vm').runInNewContext('('+callback.toString()+')()',{
  fetch:async(path,options)=>{assert.equal(path,'/api/secureshop/auth/progress');assert.deepEqual(JSON.parse(JSON.stringify(options)),{credentials:'same-origin'});return {status:200,json:async()=>original};}})};
 const result=await V66.readV42PublicProgress(page,false);assert.equal(result.body,original);
 await assert.rejects(V66.readV42PublicProgress(page,true));
 original.completedObjectives=1;await assert.rejects(V66.readV42PublicProgress(page,false));
});

test('V42 serialized original joins use production proposal, source proof and packet bytes',()=>{
 const p=require('./secureshopMcpRegistrySsrfEvidence.test').packet();
 const E=require('../server/services/secureshopMcpRegistrySsrfEvidence');
 const proof=E.validateMcpRegistrySsrfEvidence(p),prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput({rubric:{...E.RUBRIC,mode:'vuln'},...E.projectMcpRegistrySsrfCandidate(proof)});
 const result={verdict:'pass',runId:p.run.run_id,evidenceDigest:prepared.evidenceDigest,provider:'ollama',
  criteria:E.RUBRIC.criteria.map(c=>({id:c.id,satisfied:true})),scopedCriteria:[{attempts:1}]};
 const value=JSON.parse(JSON.stringify({original:{binding:p.binding,personaSession:p.personaSession,source:proof.source,
  turn:p.turn,traces:p.traces,operation:p.operation,revisions:p.revisions,discoveryReceipt:proof.discoveryReceipt},
  judgments:[{objective_id:E.OBJECTIVE,rubric_version:E.RUBRIC.version,verdict:'pass',disposition:'awarded',
   packet:prepared.packet,evidence_digest:prepared.evidenceDigest,evaluation_id:p.run.run_id,run_id:p.run.run_id,judge_result_json:JSON.stringify(result)}],
  assessment:{completed:true,replayed:true,judgment:{evaluationId:p.run.run_id,verdict:'pass',canRetry:false}}}));
 assert.equal(V66.assertV42OriginalCapture(value),value);
 const producerRoundTrip=JSON.parse(JSON.stringify(structuredClone({...value,original:{...value.original,
  operation:{...value.original.operation,request_sha256:p.operation.request_sha256,receipt_sha256:p.operation.receipt_sha256}}})));
 assert.deepEqual(Object.keys(producerRoundTrip.original.operation.request_sha256),Array.from({length:32},(_,index)=>String(index)));
 assert.equal(V66.assertV42OriginalCapture(producerRoundTrip),producerRoundTrip);
 for(const malformed of [{...producerRoundTrip.original.operation.request_sha256,extra:1},
  Object.fromEntries(Object.entries(producerRoundTrip.original.operation.request_sha256).slice(1)),
  {...producerRoundTrip.original.operation.request_sha256,0:256}]){
  const changed=structuredClone(producerRoundTrip);changed.original.operation.request_sha256=malformed;
  assert.throws(()=>V66.assertV42OriginalCapture(changed));
 }

 for(const mutate of [v=>{v.original.source.requestId='10000000-0000-4000-8000-999999999999';},
  v=>{v.original.operation.receipt_sha256.data[0]^=1;},v=>{v.original.discoveryReceipt.destination.address='127.0.0.1';},
  v=>{v.judgments[0].packet+=' ';},v=>{v.assessment.judgment.verdict='fail';},
  v=>{const r=JSON.parse(v.judgments[0].judge_result_json);r.criteria[2].satisfied=false;v.judgments[0].judge_result_json=JSON.stringify(r);},
  v=>{const r=JSON.parse(v.judgments[0].judge_result_json);r.scopedCriteria[0].attempts=2;v.judgments[0].judge_result_json=JSON.stringify(r);}]){
  const changed=structuredClone(value);mutate(changed);assert.throws(()=>V66.assertV42OriginalCapture(changed));
 }
});

test('V42 reload uses document readiness but still requires exact saved GET and unchanged rows/wire',async()=>{
 const source=readFileSync(join(__dirname,'fixtures/secureshopMcpManifestQualification.js'),'utf8');
 const segment=source.slice(source.indexOf('  const startReload=originalJsonCaptures.length;'),source.indexOf('  const fixedProof=await qualifyV42Fixed'));
 assert(segment.includes('await page.reload('));
 const execute=Function('input',`return (async()=>{const {page,frameFor,ensureAdminAssistantOpen,originalJsonCaptures,assessmentPath,beforeGet,savedAssessment,operations,revisions,judgments,modelCount,route,receipt,captured,save,wait,click,assert}=input;let frame;${segment};return {frame,receipt};})()`);
 const outcome={completed:true,replayed:true,judgment:{evaluationId:'20000000-0000-4000-8000-000000000001',verdict:'pass',canRetry:false}};
 const assessmentPath='/api/secureshop/agents/admin/assistant/sessions/20000000-0000-4000-8000-000000000002/requests/20000000-0000-4000-8000-000000000003/mcp-discovery/20000000-0000-4000-8000-000000000004/assessment';
 for(const fault of [null,'missing GET','changed GET','changed rows','extra actor','reposted']){
  const frame={fresh:true},calls=[],receipt={},captured={phases:[]},post={method:'POST',path:'/api/secureshop/agents/admin/assistant/mcp-discovery/assess'};
  const originalJsonCaptures=[post],rows=[{immutable:'original'}];let documentLoaded=false;
  const input={assert,click:async()=>assert.fail('No physical POST is allowed during reload'),assessmentPath,originalJsonCaptures,receipt,captured,route:'mcp-discovery',savedAssessment:outcome,
   beforeGet:{operations:rows,revisions:rows,judgments:rows,calls:3},
   page:{reload:async options=>{calls.push('document');assert.deepEqual(options,{waitUntil:'domcontentloaded'});documentLoaded=true;
    if(fault!=='missing GET')originalJsonCaptures.push({method:'GET',path:assessmentPath,status:200,complete:true,responseBody:JSON.stringify(fault==='changed GET'?{...outcome,completed:false}:outcome)});
    if(fault==='reposted')originalJsonCaptures.push(post);}},
   frameFor:async()=>{assert.equal(documentLoaded,true);calls.push('frame');return frame;},
   ensureAdminAssistantOpen:async()=>{calls.push('admin ready');},
   operations:async()=>fault==='changed rows'?[]:rows,revisions:async()=>rows,judgments:async()=>rows,
   modelCount:()=>fault==='extra actor'?4:3,save:()=>calls.push('save'),wait:async read=>{const found=await read();assert(found,'Expected original saved GET is required');return found;}};
  if(fault){await assert.rejects(execute(input));assert.equal(receipt.savedReloadNoEffect,undefined);}
  else{assert.equal((await execute(input)).frame,frame);assert.equal(receipt.savedReloadNoEffect,true);assert.deepEqual(calls,['document','frame','admin ready','save']);}
 }
});

test('V42 qualified admission uses only normal administrator enablement and keeps truthful closed history',async()=>{
 const previous=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 try{
  const current=require('../server/config/secureshopCurriculum'),curriculum={...current,isQualifiedObjective:()=>true,
   OBJECTIVES:current.OBJECTIVES.map(row=>row.id===V66.V42_OBJECTIVE?{...row,qualification:'native-browser-judge'}:row)};
  const context={},calls=[];const catalog={list:async()=>({objectives:[{objectiveId:V66.V42_OBJECTIVE,qualification:'native-browser-judge',enabled:false,revision:'8'}]}),
   set:async(base,input)=>{assert.equal(base,context);calls.push(input);return {enabled:true,qualification:'native-browser-judge'};}};
  const result=await V66.admitV42DisposableCandidate({curriculum,catalog,administratorContext:context,migration:{query:()=>assert.fail('Qualified admission cannot use fixture migration SQL')}});
  assert.deepEqual(result,{objectiveId:V66.V42_OBJECTIVE,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
  assert.deepEqual(calls,[{objectiveId:V66.V42_OBJECTIVE,enabled:true,expectedRevision:'8'}]);
  assert.equal(V66.assertV42CatalogAdmission(result),result);
  for(const changed of [{...result,fixtureLocalCandidateAdmission:true},{...result,productionQualification:'pending'},
   {...result,productionDefaultEnabled:true},{...result,extra:true}])assert.throws(()=>V66.assertV42CatalogAdmission(changed));
  await assert.rejects(V66.admitV42DisposableCandidate({curriculum:{...curriculum,OBJECTIVES:curriculum.OBJECTIVES.map(row=>row.id===V66.V42_OBJECTIVE?{...row,defaultEnabled:true}:row)},catalog,administratorContext:context}));
  await assert.rejects(V66.admitV42DisposableCandidate({curriculum,catalog:{...catalog,list:async()=>({objectives:[{objectiveId:V66.V42_OBJECTIVE,qualification:'pending',enabled:false,revision:'8'}]})},administratorContext:context}));
  assert.equal(calls.length,1);
 }finally{if(previous===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=previous;}
});
