'use strict';
// Pure contract controls: synthetic packets never count as native qualification.
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createHash}=require('node:crypto');
const {urls,assertPhysical,assertActorWire,assertReceipt,passiveCapture,assertAssembly,finishEvidence,SCOPE,GATES}=require('./postgres/secureshopV23Original.integration.test');
const sha=s=>createHash('sha256').update(s).digest('hex');
test('native variant is explicit and rejects absence before any native resource admission',async()=>{
 const {runNative}=require('./postgres/secureshopV23Original.integration.test');
 for(const variant of [undefined,'invented'])await assert.rejects(runNative({SECURESHOP_V23_ORIGINAL_NATIVE:'1',LIVE_OLLAMA_TEST:'1',DVAIA_CURRENT_MAIN_WORKSPACE:path.resolve(__dirname,'..'),V23_REQUEST_VARIANT:variant}));
 const r=receipt();r.requestVariant='json-data-v3';r.cohort.requestVariant='json-data-v3';assertReceipt(r);
 for(const boundary of [undefined,'invented'])await assert.rejects(runNative({SECURESHOP_V23_ORIGINAL_NATIVE:'1',LIVE_OLLAMA_TEST:'1',DVAIA_CURRENT_MAIN_WORKSPACE:path.resolve(__dirname,'..'),V23_REQUEST_VARIANT:'json-data-v3',V23_BOUNDARY_CONTRACT:boundary}));
});
test('all explicit variants reach only the existing native owner fence and bind original receipt scope',async()=>{
 const {runNative}=require('./postgres/secureshopV23Original.integration.test');
 const q=require('./fixtures/secureshopV23OriginalQualification');
 for(const requestVariant of q.REQUEST_VARIANTS)for(const boundaryContract of q.BOUNDARY_CONTRACTS){
  const env={SECURESHOP_V23_ORIGINAL_NATIVE:'1',LIVE_OLLAMA_TEST:'1',DVAIA_CURRENT_MAIN_WORKSPACE:path.resolve(__dirname,'..'),
   V23_REQUEST_VARIANT:requestVariant,V23_BOUNDARY_CONTRACT:boundaryContract};
  await assert.rejects(runNative(env),{code:'ORIGINAL_COHORT_SCOPE_REQUIRED'});
  const r=receipt();r.requestVariant=requestVariant;r.cohort.requestVariant=requestVariant;
  r.boundaryContract=boundaryContract;r.cohort.boundaryContract=boundaryContract;assertReceipt(r);
  const wrong=structuredClone(r);wrong.cohort.requestVariant=q.REQUEST_VARIANTS.find(v=>v!==requestVariant);assert.throws(()=>assertReceipt(wrong));
  for(const foreign of q.BOUNDARY_CONTRACTS.filter(v=>v!==boundaryContract)){const crossed=structuredClone(r);crossed.cohort.boundaryContract=foreign;assert.throws(()=>assertReceipt(crossed));}
 }
});
function environment(){const env={PG_TEST_DISPOSABLE:'yes'};
 for(const [key,store]of Object.entries({IDENTITY:'identity',AGENTS:'secureshop_agents',COMMERCE:'secureshop',REVIEW:'secureshop_review'}))
  for(const role of ['RUNTIME','MIGRATION'])env[`PG_SECURESHOP_V23_${key}_${role}_URL`]=`postgresql://dvaia_${store}_${role.toLowerCase()}:controlled@127.0.0.1:15432/dvaia_test_agent_host_012345abcdef_${store}`;
 return env;}
function packet(content,kind='actor'){const request=JSON.stringify({model:'llama3.1:8b',messages:[{role:'user',content:'original request'}]}),
 response=JSON.stringify({model:'llama3.1:8b',message:{role:'assistant',content},done:true});
 return{kind,status:200,responseComplete:true,responseCaptureTruncated:false,model:'llama3.1:8b',request,response,requestSha256:sha(request),responseSha256:sha(response)};}
test('four-store admission requires exact disposable same-run database identities',()=>{assert.equal(Object.keys(urls(environment())).length,8);
 for(const mutate of [e=>e.PG_TEST_DISPOSABLE='no',e=>e.PG_SECURESHOP_V23_AGENTS_RUNTIME_URL=e.PG_SECURESHOP_V23_IDENTITY_RUNTIME_URL,
  e=>e.PG_SECURESHOP_V23_AGENTS_RUNTIME_URL=e.PG_SECURESHOP_V23_AGENTS_RUNTIME_URL.replace('127.0.0.1','example.invalid'),
  e=>e.PG_SECURESHOP_V23_AGENTS_RUNTIME_URL=e.PG_SECURESHOP_V23_AGENTS_RUNTIME_URL.replace('012345abcdef','112345abcdef'),
  e=>e.PG_SECURESHOP_V23_AGENTS_RUNTIME_URL+='?sslmode=disable']){const e=environment();mutate(e);assert.throws(()=>urls(e));}});
test('physical packet validates exact bytes, model and completed NDJSON',()=>{const p=packet('first');
 p.response=JSON.stringify({message:{content:'first'},done:false})+'\n'+JSON.stringify({message:{content:'second'},done:true});p.responseSha256=sha(p.response);
 assert.equal(assertPhysical(p,'actor').response.message.content,'firstsecond');
 for(const mutate of [p=>p.responseComplete=false,p=>p.responseCaptureTruncated=true,p=>p.model='other',p=>p.response+=' ',p=>p.status=500]){
  const q=structuredClone(p);mutate(q);assert.throws(()=>assertPhysical(q,'actor'));}
 const q=packet('unfinished');q.response=q.response.replace('"done":true','"done":false');q.responseSha256=sha(q.response);assert.throws(()=>assertPhysical(q,'actor'));
});
test('original actor proof binds selected args, trace call and final response',()=>{const args={name:'controlled',transport:'stdio',stdio_cmd:'exact command'},
 calls=[packet(JSON.stringify({tool_calls:[{agent:'mcp-registry',tool:'register',args}]})),packet(JSON.stringify({reply:'finished'}))],
 terminal={text:'finished',taskMetadata:{originalRegistration:{observations:[{callId:'c1',tool:'mcp-registry.register',args}],traces:[{kind:'model_decision',params_json:JSON.stringify({toolCalls:[{id:'c1',name:'mcp-registry.register',args}]})}]}}},
 spec={command:'exact command',message:'original request'};
 assertActorWire(calls,terminal,spec);
 for(const mutate of [t=>t.text='different',t=>t.taskMetadata.originalRegistration.observations[0].callId='foreign',t=>t.taskMetadata.originalRegistration.observations[0].args.stdio_cmd='different']){
  const t=structuredClone(terminal);mutate(t);assert.throws(()=>assertActorWire(calls,t,spec));}
 assert.throws(()=>assertActorWire([calls[0]],terminal,spec));assert.throws(()=>assertActorWire([...calls,calls[0]],terminal,spec));
});
function receipt(){return{version:3,boundaryContract:'hard-fail-v1',caseEvidence:['positive','benign','fixed'].map(kind=>({kind,file:kind+'-case-evidence.json',sha256:'a'.repeat(64),evidenceSha256:'b'.repeat(64),runId:kind,actorCalls:2,qualificationComplete:false,independentJudgeComplete:false})),requestVariant:'opaque-command-v2',scope:SCOPE,passed:true,canonicalCredit:false,actorCalls:6,judgeCalls:2,registrationEffects:2,
 gates:Object.fromEntries(GATES.map(k=>[k,true])),cohort:{cases:['positive','benign','fixed'].map(kind=>({kind,evidenceSha256:'b'.repeat(64),runId:kind,wire:{calls:2}})),boundaryContract:'hard-fail-v1',requestVariant:'opaque-command-v2',cohortAccepted:true,qualificationComplete:false,canonicalCredit:false},
 resources:{hostPid:123,serviceDirectory:path.resolve(__dirname,'../tasks/tmp/v23-service-012345abcdef')},errors:[]};}
test('native receipt cannot qualify without every cleanup, contrast and authority gate',()=>{assertReceipt(receipt());
 for(const key of GATES){const r=receipt();r.gates[key]=false;assert.throws(()=>assertReceipt(r));}
 for(const mutate of [r=>r.version=2,r=>delete r.boundaryContract,r=>r.cohort.boundaryContract='recoverable-denial-v1',r=>r.caseEvidence.pop(),r=>r.version=1,r=>delete r.requestVariant,r=>r.cohort.requestVariant='original-v1',r=>r.requestVariant='invented',r=>r.canonicalCredit=true,r=>r.actorCalls=13,r=>r.judgeCalls=3,r=>r.registrationEffects=1,
  r=>r.resources.serviceDirectory='/tmp/foreign',r=>r.extra=true,r=>r.errors=['uncertain'],r=>r.cohort.qualificationComplete=true]){
  const r=receipt();mutate(r);assert.throws(()=>assertReceipt(r));}
});
test('new private producer receipt is distinct from historical shared service and preserves every criterion',()=>{
 const r=receipt();r.version=4;const runId='a'.repeat(32);
 r.resources={hostPid:123,privateProducer:{version:1,runId,planSha256:'b'.repeat(64),
  artifact:path.resolve(__dirname,'../tasks/tmp/v23-build-'+runId),cleanupVerified:true,consumerCleanupVerified:true,sharedStatePreserved:true}};
 assertReceipt(r);
 for(const mutate of [x=>x.resources.privateProducer.cleanupVerified=false,x=>x.resources.privateProducer.consumerCleanupVerified=false,
  x=>x.resources.privateProducer.sharedStatePreserved=false,x=>x.resources.privateProducer.artifact='/tmp/foreign',
  x=>x.resources.serviceDirectory='old',x=>x.actorCalls=13,x=>x.judgeCalls=1,x=>x.registrationEffects=3]){
  const x=structuredClone(r);mutate(x);assert.throws(()=>assertReceipt(x));}
});
test('legacy native invocation cannot bypass private in-process producer authority',async()=>{
 const {runNative}=require('./postgres/secureshopV23Original.integration.test');
 const env={SECURESHOP_V23_ORIGINAL_NATIVE:'1',LIVE_OLLAMA_TEST:'1',DVAIA_CURRENT_MAIN_WORKSPACE:path.resolve(__dirname,'..'),
  V23_REQUEST_VARIANT:'json-data-v3',V23_BOUNDARY_CONTRACT:'hard-fail-v1'};
 for(const scope of [undefined,{}, {configuration:{baseURL:'http://127.0.0.1:1'}}])
  await assert.rejects(runNative(env,scope),{code:'ORIGINAL_COHORT_SCOPE_REQUIRED'});
});
test('unproven cohort host or transport retirement retains stores and explicit debt',async()=>{
 const {retireCohortResources}=require('./postgres/secureshopV23Original.integration.test');
 for(const failed of [true,false]){const events=[],errors=[],result={errors:[]};
  await retireCohortResources({errors,result,transports:[async()=>{events.push('host');if(failed)throw Error('unjoined host');},
   async()=>events.push('transport')],stores:[async()=>events.push('stores')]});
  assert.deepEqual(events,failed?['host','transport']:['host','transport','stores']);
  assert.equal(errors.some(e=>e.retirementUnproven),failed);}
});
test('native environment import is inert and does not auto-register an unscoped test',()=>{
 const fs=require('node:fs'),vm=require('node:vm'),filename=require.resolve('./postgres/secureshopV23Original.integration.test');let registrations=0;
 const scopedRequire=require('node:module').createRequire(filename);
 vm.runInNewContext(fs.readFileSync(filename,'utf8'),{require:id=>id==='node:test'?()=>{registrations++;}:scopedRequire(id),
  module:{exports:{}},__dirname:path.dirname(filename),process:{env:{SECURESHOP_V23_ORIGINAL_NATIVE:'1'}},Buffer});
 assert.equal(registrations,0);
});
test('file close and publication faults cannot erase retained host debt or skip the second close',async()=>{
 const {finishAndCloseEvidence}=require('./postgres/secureshopV23Original.integration.test');
 const debt=Object.assign(Error('HOST_STILL_LIVE'),{retirementUnproven:true}),errors=[debt],result={errors:['HOST_STILL_LIVE']},events=[];
 await finishAndCloseEvidence({errors,result,finish:async()=>{throw Error('STAT_OR_WRITE_FAILED');},handles:[
  {close:async()=>{events.push('result');throw Error('RESULT_CLOSE_FAILED');}},
  {close:async()=>{events.push('wire');throw Error('WIRE_CLOSE_FAILED');}}]});
 assert.equal(errors[0],debt);assert.equal(errors[0].retirementUnproven,true);
 assert.deepEqual(events,['result','wire']);assert.deepEqual(result.errors,['HOST_STILL_LIVE','STAT_OR_WRITE_FAILED','RESULT_CLOSE_FAILED','WIRE_CLOSE_FAILED']);
});
test('setup completion after cancellation cannot admit a later host or MCP effect',async()=>{
 const {activeStep}=require('./postgres/secureshopV23Original.integration.test');let expired=false,effects=0;
 const check=()=>{if(expired)throw Error('expired');};
 await assert.rejects(activeStep(check,async()=>{expired=true;}),/expired/);
 await assert.rejects(activeStep(check,async()=>effects++),/expired/);assert.equal(effects,0);
});
test('actual initial-file and actor/Judge setup callsites reject expiry before the next effect',async()=>{
 const source=require('node:fs').readFileSync(require.resolve('./postgres/secureshopV23Original.integration.test'),'utf8');
 const {activeStep,admitOwnedResource}=require('./postgres/secureshopV23Original.integration.test');
 const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
 let expired=false,effects=0;const check=()=>{if(expired)throw Error('expired');},step=fn=>activeStep(check,fn),owned={check};
 const initial=source.slice(source.indexOf(' const parent=await step(()=>fs.realpath'),source.indexOf(' const actors=[],allRelays=[]'));
 assert(initial.includes("fs.open(file,'wx'"));
 await assert.rejects(new AsyncFunction('step','fs','path','ROOT','file','owned',initial)(step,
  {realpath:async()=>{expired=true;return '/controlled';},open:async()=>{effects++;}},path,'/controlled','/controlled/v23-original-result.json',owned),/expired/);
 assert.equal(effects,0);expired=false;
 const actorStart=source.indexOf('   await step(()=>modes.setMode({userId:who.scope.platformOwnerId');
 const actor=source.slice(actorStart,source.indexOf('   assert.equal(relay.digest',actorStart));assert(actor.includes('createMailActualTransport'));
 const transport={createMailActualTransport:async()=>{effects++;return{};}};
 await assert.rejects(new AsyncFunction('step','modes','who','spec','admitOwnedResource','owned','actual','wire','actors','allRelays','saveWire',actor)(
  step,{setMode:async()=>{expired=true;}},{scope:{platformOwnerId:1}},{mode:'vuln'},admitOwnedResource,owned,transport,{},[],[],()=>{}),/expired/);
 assert.equal(effects,0);expired=false;let modes=0;
 const judgeStart=source.indexOf("  await step(()=>modes.setMode({userId:positiveOwner.scope.platformOwnerId");
 const judge=source.slice(judgeStart,source.indexOf('  const config=',judgeStart));assert(judge.includes('judgeRelay=await admitOwnedResource'));
 await assert.rejects(new AsyncFunction('step','modes','positiveOwner','assert','p','result','beforeEffects','admitOwnedResource','owned','actual','wire','allRelays','saveWire',
  'let judgeRelay;\n'+judge)(step,{setMode:async()=>{if(++modes===2)expired=true;}},{scope:{platformOwnerId:1}},assert,
  {input:{},runtime:{run:async()=>{throw Object.assign(Error('stale'),{code:'ORIGINAL_REGISTER_REPLAY_MODE_STALE'});}}},
  {gates:{},registrationEffects:0},0,admitOwnedResource,owned,transport,{},[],()=>{}),/expired/);
 assert.equal(effects,0);
 let retained=false;expired=false;
 await assert.rejects(admitOwnedResource(check,async()=>{expired=true;return{};},()=>{retained=true;}),/expired/);assert.equal(retained,true);
});
test('post-rename fsync failure or expiry leaves only explicitly unsealed false candidate evidence',async t=>{
 const fs=require('node:fs/promises'),native=require('node:fs'),vm=require('node:vm');
 const filename=require.resolve('./postgres/secureshopV23Original.integration.test'),scopedRequire=require('node:module').createRequire(filename);
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'v23-post-rename-'));t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 for(const mode of ['fsync-failure','expired']){
  const file=path.join(directory,mode+'.json');await fs.writeFile(file,'{"passed":false}',{mode:0o600});const identity=await fs.lstat(file);let renamed=false;
  const fakeNative={...native,renameSync(...args){native.renameSync(...args);renamed=true;},fsyncSync(fd){if(mode==='fsync-failure')throw Error('DIRECTORY_FSYNC_FAILED');native.fsyncSync(fd);}};
  const module={exports:{}};vm.runInNewContext(native.readFileSync(filename,'utf8'),{
   require:id=>id==='node:fs'?fakeNative:scopedRequire(id),module,__dirname:path.dirname(filename),process,Buffer});
  await assert.rejects(module.exports.publishPrivateFinal(file,identity,{passed:true},{
   io:fn=>fn(),close:fn=>fn(),check(){if(mode==='expired'&&renamed)throw Error('expired');}}),mode==='expired'?/expired/:/DIRECTORY_FSYNC_FAILED/);
  const candidate=JSON.parse(await fs.readFile(file,'utf8'));assert.equal(candidate.passed,false);assert.equal(candidate.result.passed,false);
  assert.equal(candidate.requiresOwnerTerminal,true);assert.equal(candidate.kind,'original-v23-unsealed-candidate');assert.throws(()=>assertReceipt(candidate));
 }
});
test('final private publication preserves prior record on identity mismatch and is atomic on success',async t=>{
 const fs=require('node:fs/promises'),{publishPrivateFinal}=require('./postgres/secureshopV23Original.integration.test');
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'v23-final-control-'));
 t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const file=path.join(directory,'v23-original-result.json');await fs.writeFile(file,'{"passed":false}',{mode:0o600});
 const identity=await fs.lstat(file);
 await assert.rejects(publishPrivateFinal(file,{...identity,ino:identity.ino+1},{passed:true}));
 assert.equal(await fs.readFile(file,'utf8'),'{"passed":false}');
 await publishPrivateFinal(file,identity,{passed:false,errors:['controlled cleanup failure']});
 const candidate=JSON.parse(await fs.readFile(file,'utf8'));assert.equal(candidate.passed,false);assert.equal(candidate.requiresOwnerTerminal,true);
 assert.deepEqual(candidate.result,{passed:false,errors:['controlled cleanup failure']});assert.throws(()=>assertReceipt(candidate));
 assert.equal((await fs.stat(file)).mode&0o777,0o600);assert.deepEqual(await fs.readdir(directory),['v23-original-result.json']);
});
test('physical list selection requires its distinct original trace and observation',()=>{
 const args={name:'owned',transport:'stdio',stdio_cmd:'exact'},selected=[{agent:'mcp-registry',tool:'register',args},{agent:'mcp-registry',tool:'list_servers',args:{}}];
 const calls=[...selected.map(s=>packet(JSON.stringify({tool_calls:[s]}))),packet('{"reply":"finished"}')],observations=selected.map((s,i)=>({callId:'c'+i,tool:s.agent+'.'+s.tool,args:s.args}));
 const terminal={text:'finished',taskMetadata:{originalRegistration:{observations,traces:observations.map(o=>({kind:'model_decision',params_json:JSON.stringify({toolCalls:[{id:o.callId,name:o.tool,args:o.args}]})}))}}};
 assertActorWire(calls,terminal,{command:'exact',message:'original request'});
 terminal.taskMetadata.originalRegistration.observations[1].tool='mcp-registry.describe_tools';assert.throws(()=>assertActorWire(calls,terminal,{command:'exact',message:'original request'}));
});
test('advertised denial requires exact call-linked observation in a later physical request',()=>{
 const args={name:'owned',transport:'stdio',stdio_cmd:'exact'},selected=[{agent:'mcp-registry',tool:'register',args},{agent:'audit',tool:'search_by_user',args:{username:'owned'}}];
 const calls=[...selected.map(s=>packet(JSON.stringify({tool_calls:[s]}))),packet('{"reply":"finished"}')];
 const proof={callId:'c1',step:1,tool:'audit.search_by_user',args:selected[1].args,history:{tool:{content:'{"error":"blocked-by-acl"}'}}};
 const terminal={text:'finished',taskMetadata:{originalRegistration:{observations:[{callId:'c0',tool:'mcp-registry.register',args}],denialProofs:[proof],traces:[...selected.map((s,i)=>({kind:'model_decision',step:i,params_json:JSON.stringify({toolCalls:[{id:'c'+i,name:s.agent+'.'+s.tool,args:s.args}]})})),{kind:'model_decision',step:2}]}}};
 assert.throws(()=>assertActorWire(calls,terminal,{command:'exact',message:'original request'}));
 const request=JSON.parse(calls[2].request);request.messages.push({role:'user',content:'Tool observation for completed call "c1" (tool result):\n'+proof.history.tool.content});calls[2].request=JSON.stringify(request);calls[2].requestSha256=sha(calls[2].request);
 assertActorWire(calls,terminal,{command:'exact',message:'original request'});proof.history.tool.content='changed';assert.throws(()=>assertActorWire(calls,terminal,{command:'exact',message:'original request'}));
});
test('v2 five-selection wire joins three real-shaped physical calls without relaxing v1 or unjoined denials',()=>{
 const boundaryContract='recoverable-split-budget-v2',args={name:'owned',transport:'stdio',stdio_cmd:'exact'};
 const selections=[{agent:'mcp-registry',tool:'register',args},{agent:'audit',tool:'search_by_user',args:{username:'owned'}},{agent:'mcp-registry',tool:'describe_tools',args:{name:'owned'}},{agent:'mcp-registry',tool:'list_servers',args:{}},{agent:'system',tool:'read_config',args:{}}];
 const traced=selections.map((s,i)=>({id:'c'+i,name:s.agent+'.'+s.tool,args:s.args}));
 const calls=[packet(JSON.stringify({tool_calls:[selections[0]]})),packet(JSON.stringify({tool_calls:selections.slice(1)})),packet('{"reply":"finished"}')];
 const denials=[1,4].map(i=>({boundaryContract,callId:'c'+i,step:1,tool:traced[i].name,args:traced[i].args,history:{tool:{content:'{"error":"blocked-by-acl"}'}}}));
 const req=JSON.parse(calls[2].request);for(const d of denials)req.messages.push({role:'user',content:`Tool observation for completed call ${JSON.stringify(d.callId)} (tool result):\n${d.history.tool.content}`});calls[2].request=JSON.stringify(req);calls[2].requestSha256=sha(calls[2].request);
 const terminal={text:'finished',taskMetadata:{originalRegistration:{boundaryContract,selectionBudget:{version:2,ownedReads:2,aclDenials:2,registrations:1,companions:4},denialProofs:denials,
  observations:[0,2,3].map(i=>({callId:'c'+i,tool:traced[i].name,args:traced[i].args})),traces:[{kind:'model_decision',step:0,params_json:JSON.stringify({toolCalls:[traced[0]]})},{kind:'model_decision',step:1,params_json:JSON.stringify({toolCalls:traced.slice(1)})},{kind:'model_decision',step:2}]}}};
 const spec={command:'exact',message:'original request'};assertActorWire(calls,terminal,spec);
 for(const mutate of [m=>m.boundaryContract='hard-fail-v1',m=>m.boundaryContract='recoverable-denial-v1',m=>m.denialProofs.pop(),m=>m.denialProofs[0].boundaryContract='recoverable-denial-v1',m=>m.denialProofs[0].callId='unjoined',m=>m.selectionBudget.ownedReads=3]){
  const bad=structuredClone(terminal);mutate(bad.taskMetadata.originalRegistration);assert.throws(()=>assertActorWire(calls,bad,spec));
 }
 const extra=structuredClone(calls),response=JSON.parse(extra[1].response),decision=JSON.parse(response.message.content);decision.tool_calls.push({agent:'system',tool:'restart',args:{}});response.message.content=JSON.stringify(decision);extra[1].response=JSON.stringify(response);extra[1].responseSha256=sha(extra[1].response);assert.throws(()=>assertActorWire(extra,terminal,spec));
});
test('identical denials at different steps join their own indexed physical decision, never the earlier one',()=>{
 const args={name:'owned',transport:'stdio',stdio_cmd:'exact'},audit={agent:'audit',tool:'search_by_user',args:{username:'owned'}},selected=[{agent:'mcp-registry',tool:'register',args},audit,audit];
 const calls=[...selected.map(s=>packet(JSON.stringify({tool_calls:[s]}))),packet('{"reply":"finished"}')],text=id=>`Tool observation for completed call "${id}" (tool result):\n{"error":"blocked-by-acl"}`;
 const append=(p,content)=>{const r=JSON.parse(p.request);r.messages.push({role:'user',content});p.request=JSON.stringify(r);p.requestSha256=sha(p.request);};
 append(calls[2],text('c1'));append(calls[3],text('c1'));append(calls[3],text('c2'));
 const proofs=[1,2].map(step=>({step,callId:'c'+step,tool:'audit.search_by_user',args:audit.args,history:{tool:{content:'{"error":"blocked-by-acl"}'}}}));
 const terminal={text:'finished',taskMetadata:{originalRegistration:{observations:[{callId:'c0',tool:'mcp-registry.register',args}],denialProofs:proofs,
  traces:[...selected.map((s,i)=>({kind:'model_decision',step:i,params_json:JSON.stringify({toolCalls:[{id:'c'+i,name:s.agent+'.'+s.tool,args:s.args}]})})),{kind:'model_decision',step:3}]}}};
 const spec={command:'exact',message:'original request'};assertActorWire(calls,terminal,spec);
 const wrong=structuredClone(terminal);wrong.taskMetadata.originalRegistration.denialProofs[1].step=1;assert.throws(()=>assertActorWire(calls,wrong,spec));
 const early=structuredClone(calls);append(early[2],text('c2'));assert.throws(()=>assertActorWire(early,terminal,spec));
 const missing=structuredClone(calls),r=JSON.parse(missing[3].request);r.messages=r.messages.filter(m=>m.content!==text('c2'));missing[3].request=JSON.stringify(r);missing[3].requestSha256=sha(missing[3].request);assert.throws(()=>assertActorWire(missing,terminal,spec));
});
test('offline original provider replay binds complete system, catalog, history and physical defaults',async()=>{
 const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider'),{ChatOllama}=require('@langchain/ollama');
 const provider=new OllamaProvider({baseUrl:'http://127.0.0.1:1',model:'llama3.1:8b'}),calls=[];
 provider.transport={chat:async(messages,tools,options)=>{
  const p=packet('{"reply":"controlled"}'),params=new ChatOllama({model:'llama3.1:8b',temperature:0,numPredict:1024,numCtx:8192,format:options.format}).invocationParams({});
  p.request=JSON.stringify({...params,messages,stream:true});p.requestSha256=sha(p.request);calls.push(p);
  return{response:'{"reply":"controlled"}',provider:'ollama',model:'llama3.1:8b',mocked:false};}};
 const captured=passiveCapture(provider),input={system:'full controlled original system',messages:[{role:'user',content:'original request'}],role:'admin',max_tokens:1024,
  tools:[{agent:'mcp-registry',tool:'register',description:'complete schema',inputSchema:{type:'object',properties:{name:{type:'string'}}}},
   {agent:'system',tool:'status',description:'second original catalog item',inputSchema:{type:'object',properties:{}}}]};
 const witness={system:input.system,tools:structuredClone(input.tools)};
 await provider.chat(input);await assertAssembly(captured,calls,8192,witness);
 for(const mutate of [d=>d[0].input.system+='changed',d=>d[0].input.tools[0].description='changed',d=>d[0].input.messages[0].content='changed',d=>d[0].transports[0].options.temperature=1]){
  const d=structuredClone(captured);mutate(d);await assert.rejects(assertAssembly(d,calls,8192,witness));}
 const altered=structuredClone(calls),body=JSON.parse(altered[0].request);body.options.num_ctx=32768;
 altered[0].request=JSON.stringify(body);altered[0].requestSha256=sha(altered[0].request);
 await assert.rejects(assertAssembly(captured,altered,8192,witness));
 const wrongResponse=structuredClone(calls),raw=JSON.parse(wrongResponse[0].response);raw.message.content='{"reply":"controlled","extra":true}';
 wrongResponse[0].response=JSON.stringify(raw);wrongResponse[0].responseSha256=sha(wrongResponse[0].response);
 await assert.rejects(assertAssembly(captured,wrongResponse,8192,witness));
 const matchingWrong=structuredClone(captured);matchingWrong[0].transports[0].response.response=raw.message.content;
 await assert.rejects(assertAssembly(matchingWrong,wrongResponse,8192,witness));
 for(const mutate of [r=>r.mocked=true,r=>r.fallback=true,r=>r.model='other']){const d=structuredClone(captured);mutate(d[0].transports[0].response);await assert.rejects(assertAssembly(d,calls,8192,witness));}
});
test('wire persistence failure still saves cleanup receipt and aggregates final save failure',async()=>{
 const result=receipt(),errors=[];let saved;
 await finishEvidence({writes:Promise.reject(Error('wire failed')),result,errors,save:async()=>{saved=structuredClone(result);}});
 assert.equal(saved.passed,false);assert.deepEqual(saved.errors,['wire failed']);assert.equal(errors.length,1);
 await finishEvidence({writes:Promise.resolve(),result,errors,save:async()=>{throw Error('receipt failed');}});
 assert.equal(errors.length,2);assert.deepEqual(result.errors,['wire failed','receipt failed']);
});
test('private partial case evidence is exclusive, bounded and retained without qualification on later failure',async t=>{
 const fs=require('node:fs/promises'),{saveCaseEvidence}=require('./postgres/secureshopV23Original.integration.test');
 const directory=await fs.mkdtemp(path.join(require('node:os').tmpdir(),'v23-case-control-'));t.after(()=>fs.rm(directory,{recursive:true,force:true}));
 const data={requestVariant:'json-data-v3',boundaryContract:'recoverable-denial-v1',packet:{evidenceSha256:'a'.repeat(64),evidence:{runId:'controlled',requestVariant:'json-data-v3',boundaryContract:'recoverable-denial-v1'}},terminal:{controlled:true},calls:[{},{}],assembly:{}};
 const entry=await saveCaseEvidence(directory,{kind:'positive'},data),file=path.join(directory,entry.file),bytes=await fs.readFile(file);
 assert.equal(sha(bytes),entry.sha256);assert.equal((await fs.stat(file)).mode&0o777,0o600);assert.equal(JSON.parse(bytes).canonicalCredit,false);assert.equal(JSON.parse(bytes).qualificationComplete,false);
 await assert.rejects(saveCaseEvidence(directory,{kind:'positive'},data),{code:'EEXIST'});assert.deepEqual(await fs.readFile(file),bytes);
 await assert.rejects(saveCaseEvidence(directory,{kind:'benign'},{...data,terminal:{large:'x'.repeat(4*1024*1024)}}));await assert.rejects(fs.access(path.join(directory,'benign-case-evidence.json')),{code:'ENOENT'});
 const symlink=path.join(directory,'fixed-case-evidence.json');await fs.symlink(file,symlink);await assert.rejects(saveCaseEvidence(directory,{kind:'fixed'},data));assert.deepEqual(await fs.readFile(file),bytes);
 const r=receipt();r.caseEvidence=[entry];r.errors.push('later case failed');await finishEvidence({writes:Promise.resolve(),result:r,errors:[],primary:Error('later case failed'),save:async()=>{}});assert.equal(r.passed,false);assert.equal(r.caseEvidence.length,1);assert.deepEqual(await fs.readFile(file),bytes);
});
