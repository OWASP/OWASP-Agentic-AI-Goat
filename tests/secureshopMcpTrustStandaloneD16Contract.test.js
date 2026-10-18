'use strict';
// Controlled contracts only. No database, child, browser, network or model runs.
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const fixture=require('./fixtures/secureshopMcpTrustStandaloneQualification');
const {assertRegisteredJudgment,createStandaloneMcpEvidence,verifyMcpPhaseWire,physicalTrustFrame,wireOptions}=fixture._contracts;
const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
const {digestMcpValue}=require('../server/services/secureshopMcpTrustTools');
const {MODEL,DIGEST}=require('./fixtures/dpiTechniqueActualTransport');
const {STEPS,runRenderedMcpTrust}=require('./fixtures/renderedSecureShopMcpTrust');
const {buildSecureShopMcpTrustTask}=require('../server/services/secureshopMcpTrustProduction');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const sha=value=>createHash('sha256').update(value).digest('hex');
const id=n=>`${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`;
function subject(){return {binding:{launchId:id(1),scenarioId:id(2),generation:1,platformOwnerId:3,platformSessionId:4,shopUserId:1000000005,role:'admin'},tenantId:id(6),principalId:id(7),personaSessionId:id(8),personaAuthorityVersion:'1'};}
function judgment(){const s=subject(),raw={provider:'ollama',model:MODEL,runId:id(9),evidenceDigest:sha('{"controlled":true}'),verdict:'pass'};
 const row={tenant_id:s.tenantId,principal_id:s.principalId,shop_user_id:s.binding.shopUserId,objective_id:fixture.IDS[0],run_id:id(9),owner_key:'owned',owner_generation:1,mode:'vuln',evaluation_id:id(10),packet:'{"controlled":true}',evidence_digest:raw.evidenceDigest,verdict:'pass',result_json:raw,result_serialized:JSON.stringify(raw),judge_result_json:JSON.stringify(raw),credited:id(10),completed:id(10)};
 row.result_digest=sha(row.result_serialized);row.judge_observations={version:1,runId:row.run_id,evidenceDigest:row.evidence_digest,resultSha256:sha(row.judge_result_json)};
 row.execution_json={tenantId:s.tenantId,principalId:s.principalId,shopUserId:s.binding.shopUserId,role:'admin',scope:{...createLaunchScope(s.binding)},personaSessionId:s.personaSessionId,personaAuthorityVersion:'1',runId:row.run_id,ownerKey:row.owner_key,ownerGeneration:'1'};return row;}
function phaseFixture(phase='rogue'){
 const scenario=phase==='rogue'?'rogue_registration':'rug_pull',server=phase==='rogue'?'secureshop-rogue-weather-lab':'secureshop-weather-lab';
 const tools=[{name:'forecast_lookup',description:'controlled test schema',inputSchema:{type:'object',properties:{city:{type:'string'}}}}];
 const schemas=[{target_id:id(12),version:phase==='changed'?2:1,tools_json:tools}];
 const args={city:'Seattle'},inv={server_identity:server,tool_name:'forecast_lookup',call_id:'call-1',trust_scenario:scenario,target_id:id(12),schema_version:schemas[0].version,schema_sha256:Buffer.from(digestMcpValue(tools),'hex'),arguments_sha256:Buffer.from(digestMcpValue(args),'hex')};
 const expected=require('../server/services/secureshopMcpTrustExecutionConfig').createSecureShopMcpTrustExecutionConfig({serverIdentity:server,trustScenario:scenario,schema:{serverIdentity:server,version:inv.schema_version,schemaSha256:digestMcpValue(tools),tools}}).manifest.getForRole('admin');
 const response=JSON.stringify({tool_calls:[{agent:server,tool:'forecast_lookup',args}]}),messages=[{role:'user',content:'controlled test'}],format={type:'object'};
 const wireRow=(index,role,request,content)=>{const response=JSON.stringify({message:{content}})+'\n';return {index,role,caseId:phase,status:'returned',httpStatus:200,request:JSON.stringify(request),requestSha256:sha(JSON.stringify(request)),response,responseSha256:sha(response)};};
 const calls=[wireRow(0,'actor',{messages,format,options:{temperature:0,num_predict:50}},response)];
 const captures={providerCalls:[{phase,wireIndex:0,messages,options:{format,temperature:0,num_predict:50},result:{response}}],actorInvocations:[{phase,wireStart:0,wireEnd:1,input:{tools:expected},result:{provider:'ollama',model:MODEL,mocked:false,tool_uses:[{id:'call-1',name:server+'.forecast_lookup',args}]}}],transcripts:[]};
 const judgments=phase==='baseline'?[]:[judgment()];
 if(judgments.length){const row=judgments[0],input=[{role:'user',content:'controlled judge'}],reply='controlled judgment bytes';calls.push(wireRow(1,'judge',{messages:input},reply));captures.transcripts.push({phase,complete:true,header:{runId:row.run_id,packet:row.packet,evidenceDigest:row.evidence_digest},outcome:{value:JSON.parse(row.judge_result_json)},calls:[{transport:'returned',request:{input},response:reply}]});}
 return {phase,captures,wire:{model:MODEL,digest:DIGEST,failed:false,calls},invocations:[inv],schemas,judgments};
}

test('registered judgment requires exact tenant, principal, execution, immutable bytes and canonical contribution',()=>{
 assert.equal(assertRegisteredJudgment(judgment(),subject()).verdict,'pass');
 for(const change of [r=>r.tenant_id=id(99),r=>r.principal_id=id(99),r=>r.shop_user_id++,r=>r.execution_json.personaSessionId=id(99),r=>r.execution_json.personaAuthorityVersion='2',r=>r.execution_json.scope.generation++,r=>r.execution_json.runId=id(99),r=>r.packet+=' ',r=>r.result_serialized+=' ',r=>r.judge_result_json+=' ',r=>r.credited=null,r=>r.completed=null]){const row=judgment();change(row);assert.throws(()=>assertRegisteredJudgment(row,subject()));}
});

test('standalone evidence projects only the original verifier judgment read from canonical shop rows',async()=>{
 const queries=[];const identityRuntime={async query(sql,args){queries.push({sql,args});assert(sql.includes('secureshop_auth.assessment_judgments'));return {rows:[judgment()]};}};
 const agentsRuntime={async query(sql){if(sql.includes('MAX(t.id)'))return {rows:[{id:'0'}]};return {rows:[]};},connect(){throw Error('No database');}};
 const evidence=createStandaloneMcpEvidence({identityRuntime,agentsRuntime,subject:subject()});const state=await evidence.snapshot();assert.equal(state.judgments[0].evaluation_id,id(10));assert.equal(queries.length,1);
 assert.deepEqual(queries[0].args,[id(6),id(7),id(1),'1',fixture.IDS]);assert(!queries[0].sql.includes('workshop_platform.'));
});

test('raw actor serialization, exact schema and Judge transcript bind together without claiming a native run',()=>{
 assert.deepEqual(verifyMcpPhaseWire(phaseFixture()),{phase:'rogue',actorCalls:1,judgeCalls:1});
 assert.deepEqual(verifyMcpPhaseWire(phaseFixture('baseline')),{phase:'baseline',actorCalls:1,judgeCalls:0});
 const changed=phaseFixture('changed');assert.equal(verifyMcpPhaseWire(changed).phase,'changed');
});

test('actor wire binding rejects mock provenance, substituted arguments/schema, digest drift and mixed phases',()=>{
 for(const change of [f=>f.captures.actorInvocations[0].result.mocked=true,f=>f.captures.actorInvocations[0].result.model='different',f=>f.invocations[0].arguments_sha256=Buffer.alloc(32),f=>f.schemas[0].tools_json[0].description='substituted',f=>f.wire.calls[0].response+=' ',f=>f.wire.calls[0].caseId='changed',f=>f.captures.actorInvocations[0].wireEnd=0,f=>f.captures.providerCalls=[]]){const value=phaseFixture();change(value);assert.throws(()=>verifyMcpPhaseWire(value));}
});

test('Judge binding rejects forged results, missing/doubled calls and inappropriate baseline credit',()=>{
 for(const change of [f=>f.captures.transcripts[0].outcome.value.verdict='fail',f=>f.captures.transcripts[0].header.packet='other',f=>f.captures.transcripts[0].calls[0].response='invented',f=>f.wire.calls.push({...f.wire.calls[1],index:2}),f=>f.captures.transcripts=[]]){const value=phaseFixture();change(value);assert.throws(()=>verifyMcpPhaseWire(value));}
 const baseline=phaseFixture('baseline');baseline.judgments.push(judgment());assert.throws(()=>verifyMcpPhaseWire(baseline));
});

test('the existing six-control driver uses physical frame clicks, with no DOM click or mocked evidence claim',async()=>{
 const clicks=[],cleanups=[],verified=[];let step=0;
 const frame={async waitForFunction(){},async click(selector){clicks.push(selector);},async evaluate(callback){cleanups.push(String(callback));}};
 const page={async waitForResponse(){const current=STEPS[step++];return {status:()=>200,request:()=>({postData:()=>JSON.stringify({scenario:current[3],request_id:id(20)})}),json:async()=>({text:'controlled test response'})};}};
 const evidence={async snapshot(){return {};},async verify(input){verified.push(input);return {controlled:true};}};
 const result=await runRenderedMcpTrust({page,frame:physicalTrustFrame(frame),origin:'http://127.0.0.1:3000',evidence});
 assert.equal(clicks.length,6);assert(clicks.every(selector=>selector==='[data-d16-click="selected"]'));assert.equal(cleanups.length,6);assert(cleanups.every(code=>!code.includes('.click(')));
 assert.deepEqual(verified.map(v=>[v.scenario,v.protectedEffect]),[['rogue_registration',true],['rug_pull',false],['rug_pull',true]]);assert.equal(result.resetVerified,false);assert.equal(result.qualified,undefined);
});

test('recorder admits only the declared three phases and restores the actual provider without calling it',()=>{
 const phases=[],transport={model:MODEL,url:'http://127.0.0.1:12345',snapshot:()=>({calls:[]}),expect(){throw Error('No model call allowed');},beginCase:phase=>phases.push(phase),endCase(){}};
 const recorder=fixture.createMcpTrustD16Recorder({transport,record:()=>{}});assert.throws(()=>recorder.begin('changed'));recorder.begin('rogue');assert.throws(()=>recorder.begin('baseline'));recorder.end();recorder.begin('baseline');recorder.end();recorder.begin('changed');recorder.end();
 assert.deepEqual(phases,fixture.PHASES);assert.equal(recorder.snapshot().providerCalls.length,0);assert.equal(recorder.snapshot().transcripts.length,0);recorder.close();assert.throws(()=>recorder.begin('rogue'));
});

test('D16 Judge uses the configured provider path and preserves its original result',async()=>{
 const module=require('../server/agent-runtime/providers/langchainProvider');
 const originalFactory=module.createLangChainProvider;
 const keys=['JUDGE_PROVIDER','JUDGE_MODEL','OLLAMA_BASE_URL'];
 const previous=Object.fromEntries(keys.map(key=>[key,Object.hasOwn(process.env,key)?process.env[key]:undefined]));
 const result={provider:'ollama',model:MODEL,mocked:false,fallback:false,response:'controlled transport result'};
 const admitted=[];
 module.createLangChainProvider=()=>({chat:async()=>result});
 let recorder;
 try{
  const transport={model:MODEL,url:'http://127.0.0.1:12345',snapshot:()=>({calls:[]}),
   expect:(role,input)=>admitted.push({role,input}),beginCase(){},endCase(){}};
  recorder=fixture.createMcpTrustD16Recorder({transport,record:()=>{}});
  assert.deepEqual(require('../server/agent-runtime/judgeProviderConfiguration')
   .readJudgeProviderConfig(recorder.judge),
  {provider:'ollama',model:MODEL,baseURL:transport.url});
  recorder.begin('rogue');
  const configured=module.createLangChainProvider({provider:'ollama',model:MODEL,baseURL:transport.url});
  const messages=[{role:'system',content:'judge'},{role:'user',content:'evidence'}],tools=[],options={temperature:0,num_predict:900,num_ctx:32768,format:{type:'object'}};
  assert.equal(await configured.chat(messages,tools,options),result);
  assert.deepEqual(admitted,[{role:'judge',input:{messages,tools,options}}]);
  recorder.end();
 }finally{
  recorder?.close();module.createLangChainProvider=originalFactory;
  for(const [key,value] of Object.entries(previous)){
   if(value===undefined)delete process.env[key];else process.env[key]=value;
  }
 }
 assert.equal(module.createLangChainProvider,originalFactory);
 assert.deepEqual(Object.fromEntries(keys.map(key=>[key,process.env[key]])),previous);
});

test('D16 actor and configured Judge reservations match the real Ollama adapter HTTP bodies',async()=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
 const {createInboxController}=require('./postgres/secureshopMailBrowserJudgeTransport');
 const actor={messages:[{role:'system',content:'role'},{role:'user',content:'task'}],tools:[],options:{temperature:0,num_predict:2048,format:{type:'object'}}};
 const judge={messages:[{role:'system',content:'rubric'},{role:'user',content:'evidence'}],tools:[],options:{temperature:0,num_predict:900,num_ctx:32768,format:{type:'object'}}};
 const originalFetch=global.fetch;
 const captured=[];
 try{
  global.fetch=async(url,init)=>{captured.push({url:String(url),body:JSON.parse(init.body)});throw Object.assign(Error('Controlled serialization capture'),{code:'D16_CAPTURE'});};
  const provider=createLangChainProvider({provider:'ollama',model:MODEL,baseURL:'http://127.0.0.1:12345'});
  for(const input of [actor,judge])await assert.rejects(provider.chat(input.messages,input.tools,{...input.options,ownerId:3}),{code:'D16_CAPTURE'});
 }finally{global.fetch=originalFetch;}
 assert.equal(captured.length,2);
 assert.deepEqual(captured.map(row=>row.url),['http://127.0.0.1:12345/api/chat','http://127.0.0.1:12345/api/chat']);
 assert.deepEqual(captured.map(row=>row.body.options.num_ctx),[8192,32768]);
 const upstream=async url=>new Response(url.endsWith('/api/tags')
  ?JSON.stringify({models:[{name:MODEL,digest:DIGEST}]})
  :JSON.stringify({model:MODEL,done:true,done_reason:'stop',message:{content:'{}'}})+'\n',
 {status:200});
 const oldReservation=createInboxController({profile:'mcp-trust-actual',fetch:upstream});
 try{
  await oldReservation.initialize();oldReservation.beginCase('rogue');
  oldReservation.expect('actor',actor);
  await assert.rejects(oldReservation.request({method:'POST',path:'/api/chat',body:JSON.stringify(captured[0].body)}),
   {code:'INBOX_REQUEST_MISMATCH'});
  assert.equal(oldReservation.snapshot().failed,true);
 }finally{await oldReservation.close();}
 const controller=createInboxController({profile:'mcp-trust-actual',fetch:upstream});
 try{
  await controller.initialize();controller.beginCase('rogue');
  for(const [index,input] of [actor,judge].entries()){
   const expected=captured[index].body;
   assert.deepEqual(expected,{model:MODEL,format:input.options.format,
    options:{num_ctx:wireOptions(input.options).num_ctx,num_predict:input.options.num_predict,temperature:0},
    messages:input.messages,stream:true});
   controller.expect(index===0?'actor':'judge',{...input,options:wireOptions(input.options)});
   assert.equal((await controller.request({method:'POST',path:'/api/chat',body:JSON.stringify(expected)})).status,200);
  }
  controller.endCase();
  assert.equal(controller.snapshot().failed,false);
  assert.deepEqual(controller.snapshot().counts,{actor:1,judge:1,tags:1});
 }finally{await controller.close();}
});

test('a completed baseline MCP request cannot be rehashed using the rotated schema task',()=>{
 const s=subject(),requestId=id(20),sessionId=id(21);
 const original=buildSecureShopMcpTrustTask('rug_pull',1,requestId);
 const rotated=buildSecureShopMcpTrustTask('rug_pull',2,requestId);
 assert.notEqual(original,rotated);
 const input={sessionId,requestId,binding:s.binding};
 assert.notEqual(createTurnRequest({...input,message:original}).hash,
  createTurnRequest({...input,message:rotated}).hash);
});
