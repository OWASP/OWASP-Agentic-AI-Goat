'use strict';
// Controlled packets exercise replay rejection, never native/model evidence.
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const f=require('./fixtures/secureshopCustomerConsumptionActual');
const original=require('./fixtures/secureshopDirectInjectionActual');
const clone=value=>structuredClone(value);
test('V37 initializes actual canonical ACL seed transaction and refuses drift without overriding defaults',async()=>{
  const {initializeOriginalAcl}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const expected=require('../server/data/secureshopAgentSeeds').TOOLS.flatMap(([tool,matrix])=>
    ['customer','merchant','admin'].map(role=>({tool_name:tool,role,allowed:matrix[role]?1:0})));
  for(const drift of [null,'permission','enforcement','missing','extra','seed-failure']){
    const rows=[],sqls=[];let released=false,enforcement='false';
    const client={async query(sql,args){sqls.push(sql);
      if(sql.includes('SELECT EXISTS'))return{rows:[{imported:false}]};
      if(sql.includes('INSERT INTO secureshop_agents.tool_permissions')){
        if(drift==='seed-failure')throw Error('controlled seed failure');
        assert.match(sql,/ON CONFLICT DO NOTHING/);rows.push({tool_name:args[0],role:args[1],allowed:args[2]});
      }return{rows:[]};},release(){released=true;}};
    const runtime={async query(sql,args){
      if(sql.includes('ORDER BY')){const result=clone(rows);
        if(drift==='permission')result[0].allowed=1-result[0].allowed;
        if(drift==='missing')result.pop();if(drift==='extra')result.push({tool_name:'foreign.tool',role:'customer',allowed:1});
        return{rows:result};}
      if(sql.includes('SELECT allowed'))return{rows:rows.filter(r=>r.tool_name===args[0]&&r.role===args[1]).map(r=>({allowed:r.allowed}))};
      return{rows:[{value:drift==='enforcement'?'true':enforcement}]};}};
    const run=initializeOriginalAcl({migration:{connect:async()=>client},runtime});
    if(drift)await assert.rejects(run);else{
      const result=await run;assert.equal(result.permissions.length,expected.length);assert.equal(result.cartViewCustomerAllowed,true);
      assert.equal(result.enforcement,false);assert.equal(sqls.filter(sql=>sql.includes('INSERT INTO secureshop_agents.tool_permissions')).length,expected.length);
    }
    assert.equal(released,true);assert.equal(sqls[0],'BEGIN');
    assert.ok(sqls.includes(drift==='seed-failure'?'ROLLBACK':'COMMIT'));
    assert.ok(sqls.every(sql=>!/^UPDATE |^DELETE /.test(sql)));
  }
});
test('peer tenant provisioning journals exact identities before commit; shared execution owner is rejected',async()=>{
  const {provisionPeerTenant,assertDistinctOwners,fixtureCleanupComplete}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  for(const lost of [false,true]){
    const snapshots=[],queries=[];let released=false;
    const migration={connect:async()=>({async query(sql,args){queries.push({sql,args});
      if(sql.includes('RETURNING owner_id'))return{rows:[{owner_id:92}]};
      if(sql==='COMMIT'){assert.equal(snapshots.at(-1).commitAttempted,true);if(lost)throw Object.assign(Error('lost'),{code:'08006'});}
      return{rows:[]};},release(){released=true;}})};
    const operation=provisionPeerTenant({migration,principal:{principalId:randomUUID(),shopUserId:82},signal:new AbortController().signal,
      persist:async value=>snapshots.push(clone(value))});
    if(lost){await assert.rejects(operation,{code:'08006'});assert.equal(fixtureCleanupComplete({peerTenant:snapshots.at(-1)},[]),false);}
    else{const result=await operation;assert.equal(result.committed,true);assert.equal(result.ownerId,92);}
    assert.equal(released,true);assert.equal(snapshots[0].commitAttempted,false);
    assert.equal(queries.filter(row=>row.sql.startsWith('INSERT')).length,2);
    assert.ok(queries.every(row=>!/^DELETE|^UPDATE/.test(row.sql)));
    assert.ok(queries.filter(row=>row.args).every(row=>row.args[0]===snapshots[0].tenantId));
    assert.doesNotMatch(JSON.stringify(snapshots),/password|token|bearer|default/);
  }
  const owner={principalId:randomUUID(),persona:{id:81},sessionId:randomUUID(),scope:{platformOwnerId:91,platformSessionId:101,launchId:randomUUID()}};
  const sibling={principalId:randomUUID(),persona:{id:82},sessionId:randomUUID(),scope:{platformOwnerId:92,platformSessionId:102,launchId:randomUUID()}};
  assertDistinctOwners(owner,sibling);
  for(const key of ['platformOwnerId','platformSessionId','launchId']){
    const bad=clone(sibling);bad.scope[key]=owner.scope[key];assert.throws(()=>assertDistinctOwners(owner,bad));
  }
});
test('synthetic registration satisfies actual auth validation; oversized legacy username never reaches hashing or storage',async()=>{
  const {registrationInput}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
  const sentinel=Error('controlled hash boundary');let hashes=0,storage=0;
  const repository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','readCurrentSession',
    'rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll','readOrCreateDefaultExecutionSession']
    .map(name=>[name,()=>{storage++;throw Error('No storage allowed');}]));
  const auth=createSecureShopStandaloneAuthService({repository,hashPassword:async()=>{hashes++;throw sentinel;}});
  const owner=registrationInput('owner'),sibling=registrationInput('sibling');
  assert.notEqual(owner.username,sibling.username);
  for(const input of [owner,sibling]){
    assert.ok(input.username.length<=32);assert.match(input.username,/^v37_(owner|sibling)_[a-f0-9]{16}$/);
    await assert.rejects(auth.register(input),error=>error===sentinel);
  }
  assert.equal(hashes,2);assert.equal(storage,0);
  await assert.rejects(auth.register({...owner,username:`v37_owner_${'a'.repeat(32)}`}),{code:'INVALID_ARGUMENT'});
  assert.equal(hashes,2);assert.equal(storage,0);assert.throws(()=>registrationInput('foreign'));
});
test('setup diagnostics retain bounded source locations only, never messages or external paths',()=>{
  const path=require('node:path'),{safeSetupDiagnostic}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const file=path.resolve(__filename),frame=`    at secretFunction (${file}:12:3)`;
  const error={message:'password SQL secret',stack:['TypeError: password SQL secret','    at x (https://secret.invalid/a.js:1:2)',
    '    at x (/private/secret.js:1:2)',...Array(20).fill(frame)].join('\n')};
  const diagnostic=safeSetupDiagnostic(error,'grading');
  assert.equal(diagnostic.phase,'grading');assert.equal(diagnostic.frames.length,8);
  assert.deepEqual(diagnostic.frames[0],{file:'tests/secureshopCustomerConsumptionActual.test.js',line:12,column:3});
  assert.doesNotMatch(JSON.stringify(diagnostic),/password|SQL|secret|https|private|secretFunction/);
  assert.deepEqual(safeSetupDiagnostic({stack:'bad'},'untrusted secret'),{phase:'unknown',frames:[]});
  // This frame is inside 16K UTF-16 units but beyond the 16KiB UTF-8 boundary.
  assert.deepEqual(safeSetupDiagnostic({stack:'Error\n'+'é'.repeat(8200)+'\n'+frame},'grading'),{phase:'grading',frames:[]});
});
test('failed V37 prompt replay retains only closed boundary and repository assertion location',()=>{
  const {boundedDiagnosticFailure}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const frame=`    at privateFunction (${__filename}:12:3)`;
  const error={name:'AssertionError',code:'ERR_ASSERTION',message:'private model/source text',
    actual:{private:'source'},expected:{private:'model'},
    stack:['AssertionError: private model/source text','    at x (/private/source.js:1:2)',frame].join('\n')};
  assert.deepEqual(boundedDiagnosticFailure(error,'postflight-replay'),{
    name:'AssertionError',code:'ERR_ASSERTION',boundary:'postflight-replay',
    frames:[{file:'tests/secureshopCustomerConsumptionActual.test.js',line:12,column:3}]});
  const unsafe={...error,name:'private secret',code:'TOKEN_private_secret'};
  assert.deepEqual(boundedDiagnosticFailure(unsafe,'execution'),{
    name:'Error',code:null,boundary:'execution',
    frames:[{file:'tests/secureshopCustomerConsumptionActual.test.js',line:12,column:3}]});
  assert.throws(()=>boundedDiagnosticFailure(error,'caller supplied boundary'));
});
test('native setup checkpoints precede stages and host identity persists before MCP connection',()=>{
  const {runNative,SETUP_PHASES}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const source=runNative.toString();let previous=-1;
  for(const phase of SETUP_PHASES){const index=source.indexOf(`checkpoint('${phase}')`);assert.ok(index>previous,phase);previous=index;}
  for(const [phase,call]of [['migrate','await setup.migrateManualRagStores'],['grading','await setup.createManualRagGrading'],
    ['transport',"transport=await require('./secureshopMailActualTransport')"],['application','await setup.createManualRagApplication'],
    ['host-start','await host.start()'],['mcp-connect','await client.connect()'],['manifest','await manifest.refresh()']])
    assert.ok(source.indexOf(`checkpoint('${phase}')`)<source.indexOf(call));
  assert.ok(source.indexOf('await host.start()')<source.indexOf('wire.host=hostIdentity;persist();'));
  assert.ok(source.indexOf('wire.host=hostIdentity;persist();')<source.indexOf("checkpoint('mcp-connect')"));
  assert.match(source,/wire\.setupDiagnostic=safeSetupDiagnostic\(error,phase\)/);
});
async function packets(promptProfile='original',sourceArm,mixed=false){
  const diagnostic=require('./fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const message=diagnostic.messageFor(promptProfile);
  const productName=diagnostic.productNameFor(promptProfile,sourceArm);
  const tools=original.originalCustomerTools(),policy=original.expectedPolicy();
  const expectedResult={content:[{type:'text',text:JSON.stringify({items:Array.from({length:240},(_,i)=>
    ({id:i+1,product_id:1,quantity:1,added_at:'2026-01-01T00:00:00.000Z',name:productName,price:1.25})),subtotal:300})}]};
  const rows=[],sessionId=randomUUID();let physicalIndex=0;
  for(const name of ['vuln','fixed']){
    const row={name,sessionId,actorId:7,scope:{launchId:'owned',platformOwnerId:11,platformSessionId:111},executionScope:'turn',message,
      ...(promptProfile==='original'?{}:{promptProfile}),tools,policy,
      ...(sourceArm?{sourceArm}:{}),
      mode:{mode:name,featureId:'customer_consumption',policyVersion:'customer-supervisor-byte-budgets-v1'},
      expectedResult,spans:[],dispatches:[],messages:[{role:'user',content:message}],result:null,error:null};
    const hops=[];
    for(let i=0;i<(name==='vuln'?3:1);i++){
      const input={system:policy.systemPrompt,tools,messages:clone(row.messages),role:'customer',max_tokens:2048,ownerId:7};
      const decision=i===2?{reply:'The two cart observations agree.'}:{tool_calls:Array.from(
        {length:name==='fixed'?2:(mixed&&i===0?2:1)},()=>({agent:'cart',tool:'view',args:{}}))};
      const raw=JSON.stringify(decision),logical=await original.replayProviderInput(input,raw);
      assert.deepEqual(logical.tools,[]);delete logical.tools; // Installed SDK omits empty tools on the wire.
      const request=JSON.stringify({model:original.MODEL,...logical,
        stream:true,options:{temperature:0,num_predict:2048,num_ctx:f.CONTEXT_WINDOW}});
      const response=JSON.stringify({model:original.MODEL,message:{content:raw},done:true});
      const physical={index:++physicalIndex,kind:'actor',status:200,responseComplete:true,responseCaptureTruncated:false,
        request,response,requestSha256:original.sha(request),responseSha256:original.sha(response)};
      const uses=decision.tool_calls?.map(()=>({id:`ollama_${randomUUID()}`,name:'cart.view',args:{}}))||[];
      const answer={provider:'ollama',model:original.MODEL,mocked:false,...(i===2?
        {stop_reason:'end_turn',text:decision.reply}:{stop_reason:'tool_use',tool_uses:uses})};
      row.spans.push({input,response:answer,calls:[physical]});
      if(i===2){row.messages.push({role:'assistant',content:answer.text});continue;}
      row.messages.push({role:'assistant',content:'',tool_calls:uses.map(use=>
        ({id:use.id,type:'function',function:{name:use.name,arguments:'{}'}}))});
      for(const use of (name==='vuln'?uses:uses.slice(0,1))){
        row.dispatches.push({agent:'cart',tool:'view',args:{},callerId:7,result:expectedResult});
        if(name==='vuln'){
          row.messages.push({role:'tool',tool_call_id:use.id,content:expectedResult.content[0].text});
          hops.push({step:i+1,tool:'cart.view',params:{},result:expectedResult,latencyMs:1,error:null,policyViolation:null});
        }
      }
    }
    if(name==='vuln')row.result={stopReason:'end_turn',text:row.spans.at(-1).response.text,hops};
    else row.error={code:'CUSTOMER_CONSUMPTION_LIMIT',name:'Error'};
    row.traces=name==='vuln'?hops.map(hop=>({event_id:randomUUID(),session_id:row.sessionId,kind:'mcp_result',step:hop.step,
      agent_ns:'cart',tool_name:'view',result_json:JSON.stringify(hop.result),latency_ms:hop.latencyMs,policy_violation:null})):
      [{event_id:randomUUID(),session_id:row.sessionId,kind:'mcp_call',step:1,agent_ns:'cart',tool_name:'view'}];
    row.storedTraces=clone(row.traces);
    rows.push(row);
  }
  return rows;
}
test('controlled original physical request/response pair validates measurement without native credit',async()=>{
  const result=await f.validatePair(await packets());
  assert.equal(result.physicalActorCalls,4);assert.equal(result.actualJudgeCalls,0);
  assert.equal(result.nativeQualificationAccepted,false);assert.equal(result.lifecycleValidationPending,true);
});
test('versioned prompt diagnostic measures separate decisions without calling original qualification',async()=>{
  const diagnostic=require('./fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const rows=await packets(diagnostic.PROFILE),measured=await diagnostic.validateDiagnosticPair(rows);
  assert.equal(measured.diagnosticOnly,true);assert.equal(measured.originalQualificationAccepted,false);
  assert.equal(measured.canonicalCredit,false);assert.equal(measured.physicalActorCalls,4);
  assert.equal(measured.cases[0].firstDecisionOne,true);
  assert.equal(measured.cases[0].secondDecisionAfterResult,true);
  assert.equal(measured.cases[0].comparisonAfterSecond,true);
  assert.equal(measured.cases[1].terminalCode,'CUSTOMER_CONSUMPTION_LIMIT');
  await assert.rejects(f.validatePair(rows),'The original qualification cannot accept a changed user request');
  for(const mutate of [
    r=>{r[0].spans[1].input.messages[2].content='packet-only source';},
    r=>{r[0].messages[2].content='persisted source changed';},
    r=>{r[0].messages[2].tool_call_id='foreign';},
    r=>{r[0].traces[0].result_json='{}';r[0].storedTraces=clone(r[0].traces);},
    r=>{r[0].traces[1].step=1;r[0].storedTraces=clone(r[0].traces);},
    r=>{r[0].result.hops[1].result={content:[]};},
    r=>{r[0].messages[3].content='missing second result';},
  ]){
    const altered=clone(rows);mutate(altered);
    await assert.rejects(diagnostic.validateDiagnosticPair(altered));
  }
});
test('versioned cart-result source pair retains the original request and equal-byte owned SQL names',async()=>{
  const diagnostic=require('./fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const {SOURCE_PROFILE,SOURCE_NAMES}=diagnostic;
  assert.equal(Buffer.byteLength(SOURCE_NAMES.plain),Buffer.byteLength(SOURCE_NAMES.injected));
  assert.equal(Buffer.byteLength(SOURCE_NAMES.plain),140);
  assert.equal(diagnostic.messageFor(SOURCE_PROFILE),f.MESSAGE);
  assert.notEqual(SOURCE_NAMES.plain,SOURCE_NAMES.injected);
  for(const arm of ['plain','injected']){
    const rows=await packets(SOURCE_PROFILE,arm);
    const measured=await diagnostic.validateDiagnosticPair(rows);
    assert.equal(measured.profile,SOURCE_PROFILE);assert.equal(measured.sourceArm,arm);
    assert.equal(measured.originalQualificationAccepted,false);assert.equal(measured.canonicalCredit,false);
    assert.deepEqual(rows.map(row=>row.message),[f.MESSAGE,f.MESSAGE]);
    assert.deepEqual(rows.map(row=>row.sourceArm),[arm,arm]);
    const bytes=Buffer.byteLength(JSON.stringify(rows[0].expectedResult));
    assert.ok(bytes>require('../server/services/secureshopCustomerConsumptionAuthority').LIMITS.toolResultBytes);
    assert.ok(bytes<=f.LIMITS.sourceBytes);
    assert.equal(JSON.parse(rows[0].expectedResult.content[0].text).items.length,240);
    const changed=clone(rows);changed[0].expectedResult.content[0].text=
      changed[0].expectedResult.content[0].text.replaceAll(SOURCE_NAMES[arm],'unbound product');
    await assert.rejects(diagnostic.validateDiagnosticPair(changed));
  }
  assert.throws(()=>diagnostic.productNameFor(SOURCE_PROFILE,'unknown'));
  assert.throws(()=>diagnostic.productNameFor('original','injected'));
  const native=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  assert.throws(()=>native.admitNative({...process.env,SECURESHOP_CONSUMPTION_DIAGNOSTIC:SOURCE_PROFILE,
    SECURESHOP_CONSUMPTION_SOURCE_ARM:'unknown'}));
});
test('rehashed physical output cannot contradict retained selected tool or final response',async()=>{
  for(const [index,decision]of [[0,{tool_calls:[{agent:'cart',tool:'remove',args:{cart_item_id:1}}]}],[2,{reply:'different'}]]){
    const rows=await packets(),call=rows[0].spans[index].calls[0];
    call.response=JSON.stringify({model:original.MODEL,message:{content:JSON.stringify(decision)},done:true});
    call.responseSha256=original.sha(call.response);
    await assert.rejects(f.validatePair(rows));
  }
});
test('native omitted tools validate but rehashed injected tools including explicit empty array fail',async()=>{
  const cases=await packets();
  assert.equal(Object.hasOwn(JSON.parse(cases[0].spans[0].calls[0].request),'tools'),false);
  await f.validateSpan(cases[0].spans[0],cases[0].tools,cases[0].policy);
  for(const tools of [[],null,[{type:'function',function:{name:'cart.remove',parameters:{}}}]]){
    const bad=clone(cases[0]),call=bad.spans[0].calls[0],request=JSON.parse(call.request);
    request.tools=tools;call.request=JSON.stringify(request);call.requestSha256=original.sha(call.request);
    await assert.rejects(f.validateSpan(bad.spans[0],bad.tools,bad.policy));
  }
});
test('options-only physical tampering is rejected after request digest recomputation',async()=>{
  for(const [key,value]of [['temperature',0.5],['num_predict',4096],['num_ctx',32768],['seed',17]]){
    const rows=await packets(),call=rows[0].spans[0].calls[0],request=JSON.parse(call.request);
    request.options[key]=value;call.request=JSON.stringify(request);call.requestSha256=original.sha(call.request);
    await assert.rejects(f.validatePair(rows));
  }
});
test('wrong history, raw tool bytes, Fixed persistence, or counterfeit model cannot pass',async()=>{
  const changes=[r=>{r[0].spans[1].input.messages[0].content='foreign';},
    r=>{r[0].result.hops[0].result={content:[]};},
    r=>{r[1].messages.push({role:'tool',content:'oversized'});},
    r=>{r[0].spans[0].response.mocked=true;},
    r=>{r[0].result.hops[1].step=1;},
    r=>{r[0].messages[2].tool_call_id='foreign';},
    r=>{r[0].storedTraces[0].result_json='{}';},
    r=>{r[1].messages[1].tool_calls[1].id='foreign';},
    r=>{r[1].spans[0].calls[0].index=1;},
    r=>{r[0].traces[0].session_id='foreign';r[0].storedTraces=clone(r[0].traces);}];
  for(const change of changes){const rows=await packets();change(rows);await assert.rejects(f.validatePair(rows));}
});
test('dispatch guard only permits exact owned cart.view and reserves concurrent calls',async()=>{
  let calls=0,release;const wait=new Promise(resolve=>{release=resolve;});
  const expectedResult={content:[{type:'text',text:'owned'}]},dispatches=[];
  const guard=f.createDispatchGuard({pool:{async callTool(){calls++;await wait;return expectedResult;}},actorId:7,expectedResult,dispatches});
  for(const args of [{__userId:8},{_userId:8},{userId:8}])await assert.rejects(guard.callTool('cart','view',args,{callerId:7,callerRole:'customer'}),{code:'V37_DISPATCH_DENIED'});
  await assert.rejects(guard.callTool('cart','view',{}, {callerId:8,callerRole:'customer'}));
  await assert.rejects(guard.callTool('cart','remove',{}, {callerId:7,callerRole:'customer'}));
  assert.equal(calls,0);
  const pending=Array.from({length:3},()=>guard.callTool('cart','view',{}, {callerId:7,callerRole:'customer'}));
  await assert.rejects(guard.callTool('cart','view',{}, {callerId:7,callerRole:'customer'}));
  release();await Promise.all(pending);assert.equal(calls,3);
});
test('dispatch result substitution and cancellation cannot become source evidence',async()=>{
  const controller=new AbortController();let calls=0;
  const guard=f.createDispatchGuard({pool:{async callTool(){calls++;return {content:[]};}},actorId:7,
    expectedResult:{content:[{type:'text',text:'owned'}]},dispatches:[],signal:controller.signal});
  await assert.rejects(guard.callTool('cart','view',{}, {callerId:7,callerRole:'customer'}));
  controller.abort();await assert.rejects(guard.callTool('cart','view',{}, {callerId:7,callerRole:'customer'}));
  assert.equal(calls,1);
});
test('original supervisor factory preserves default prompt, policy, role and loop limits',async()=>{
  const Module=require('node:module'),fs=require('node:fs');
  const filename=require.resolve('../server/services/secureshop/supervisors/customerSupervisor');
  const compiled=new Module(filename,module);compiled.filename=filename;compiled.paths=module.paths;
  const requireActual=Module.createRequire(filename),graphs=[],runs=[];
  compiled.require=id=>id==='../../../agent-runtime/secureshopSupervisorGraph'?{
    createSupervisorGraph(dependencies){graphs.push(dependencies);return async(...args)=>{runs.push(args);return 'original-loop';};}
  }:requireActual(id);
  compiled._compile(fs.readFileSync(filename,'utf8'),filename);
  const api=compiled.exports,store={},Trace=function(){},checkToolAcl=()=>{};
  const bound=api.createCustomerSupervisor({store,Trace,checkToolAcl,
    buildBasePrompt:()=> 'not accepted',buildPolicyBlock:()=> 'not accepted'});
  assert.equal(graphs[0].store,requireActual('../sessionStore.js'));
  assert.equal(graphs[0].Trace,requireActual('../trace.js').Trace);
  assert.equal(graphs[0].checkToolAcl,requireActual('../toolAcl.js').checkToolAcl);
  assert.equal(graphs[1].store,store);assert.equal(graphs[1].Trace,Trace);assert.equal(graphs[1].checkToolAcl,checkToolAcl);
  for(const key of ['buildBasePrompt','buildPolicyBlock'])assert.equal(graphs[0][key],graphs[1][key]);
  await api.customerSupervisor.run('owned','unchanged',{callerId:7});
  await bound.run('owned','unchanged',{callerId:7});assert.deepEqual(runs[0],runs[1]);
  assert.deepEqual(runs[0],['owned','unchanged',{callerId:7,role:'customer'},
    {maxSteps:api.MAX_STEPS,maxParallelTools:api.MAX_PARALLEL_TOOLS}]);
  assert.throws(()=>api.createCustomerSupervisor({store}));
});
test('four-store admission binds exact disposable database, port, role and host aliases',()=>{
  const {STORES,disposableUrls}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const env={PG_TEST_DISPOSABLE:'yes'};
  for(const [key,name]of Object.entries(STORES))for(const role of ['RUNTIME','MIGRATION'])
    env[`PG_SECURESHOP_CONSUMPTION_${key}_${role}_URL`]=`postgresql://dvaia_${name}_${role.toLowerCase()}@127.0.0.1:54321/dvaia_test_agent_host_0123456789ab_${name}`;
  env.SECURESHOP_DATABASE_URL=env.PG_SECURESHOP_CONSUMPTION_COMMERCE_RUNTIME_URL;
  env.SECURESHOP_AGENTS_DATABASE_URL=env.PG_SECURESHOP_CONSUMPTION_AGENTS_RUNTIME_URL;
  assert.equal(Object.keys(disposableUrls(env)).length,8);
  for(const change of [e=>{e.PG_TEST_DISPOSABLE='no';},e=>{e.SECURESHOP_DATABASE_URL=e.PG_SECURESHOP_CONSUMPTION_COMMERCE_MIGRATION_URL;},
    e=>{e.PG_SECURESHOP_CONSUMPTION_REVIEW_RUNTIME_URL=e.PG_SECURESHOP_CONSUMPTION_REVIEW_RUNTIME_URL.replace('0123456789ab','0123456789ac');},
    e=>{e.PG_SECURESHOP_CONSUMPTION_IDENTITY_RUNTIME_URL=e.PG_SECURESHOP_CONSUMPTION_IDENTITY_RUNTIME_URL.replace('127.0.0.1','localhost');},
    e=>{e.PG_SECURESHOP_CONSUMPTION_IDENTITY_RUNTIME_URL=e.PG_SECURESHOP_CONSUMPTION_IDENTITY_RUNTIME_URL.replace('dvaia_test_agent_host_','dvaia_test_v37_');}]){
    const wrong={...env};change(wrong);assert.throws(()=>disposableUrls(wrong));
  }
});
test('owned SQL source seed commits exact target/sibling cardinality; cancellation rolls back',async()=>{
  const {seedSource}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  for(const abort of [false,true]){
    const controller=new AbortController(),statements=[];let id=10,released=false;
    const client={async query(sql,args){statements.push(sql);
      if(sql.includes('INSERT INTO secureshop.products'))return {rows:[{id:5}]};
      if(sql.includes('generate_series')){if(abort)controller.abort();return{rows:Array.from({length:args[2]},()=>({id:id++}))};}
      return {rows:[]};},release(){released=true;}};
    const commerce={query:async()=>({rows:[]}),connect:async()=>client};
    const operation=seedSource({commerce,actorId:1000000010,siblingId:1000000011,signal:controller.signal});
    if(abort){await assert.rejects(operation);assert.ok(statements.includes('ROLLBACK'));assert.ok(!statements.includes('COMMIT'));}
    else{const seeded=await operation;assert.deepEqual(seeded.owned.users,[1000000010,1000000011]);
      assert.equal(seeded.owned.cart.length,241);assert.ok(statements.includes('COMMIT'));}
    assert.equal(released,true);
  }
});
test('lost COMMIT acknowledgement retains precommit owned IDs and cannot claim clean without exact removal',async()=>{
  const {seedSource,fixtureCleanupComplete}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  for(const rollbackFails of [false,true]){
    let attempt,id=10,released=false;const snapshots=[],failure=Object.assign(Error('lost commit acknowledgement'),{code:'08006'});
    const client={async query(sql,args){
      if(sql==='BEGIN')assert.ok(attempt,'attempt published before transaction');
      if(sql.includes('INSERT INTO secureshop.products'))return{rows:[{id:5}]};
      if(sql.includes('generate_series'))return{rows:Array.from({length:args[2]},()=>({id:id++}))};
      if(sql==='COMMIT'){assert.equal(snapshots.at(-1).commitAttempted,true);assert.equal(snapshots.at(-1).owned.cart.length,241);throw failure;}
      if(sql==='ROLLBACK'&&rollbackFails)throw Error('connection lost');
      return{rows:[]};},release(){released=true;}};
    await assert.rejects(seedSource({commerce:{query:async()=>({rows:[]}),connect:async()=>client},actorId:1000000010,siblingId:1000000011,
      signal:new AbortController().signal,onAttempt:async value=>{attempt=value;snapshots.push(structuredClone(value));}}),error=>error===failure);
    assert.equal(released,true);assert.equal(attempt.committed,false);assert.equal(attempt.rollbackAcknowledged,!rollbackFails);
    const wire={sourceCreation:attempt};assert.equal(fixtureCleanupComplete(wire,[]),false);
    wire.cleanup={shop_users:[],products:[],cart_items:[]};assert.equal(fixtureCleanupComplete(wire,[]),true);
    wire.cleanup.cart_items=[{id:10}];assert.equal(fixtureCleanupComplete(wire,[]),false);
  }
  assert.equal(fixtureCleanupComplete({sourceCreation:{commitAttempted:false,rollbackAcknowledged:true}},[]),false);
});
test('no-credit observation hashes all three real ledgers and fails closed on truncation',async()=>{
  const {creditSnapshot}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const queries=[],identity={async query(sql){queries.push(sql);return{rows:[{row:{id:1}}]};}};
  const before=await creditSnapshot(identity);
  assert.deepEqual(Object.keys(before),['assessment_judgments','assessment_completions','assessment_contributions']);
  assert.equal(queries.length,3);for(const value of Object.values(before)){assert.equal(value.count,1);assert.match(value.sha256,/^[a-f0-9]{64}$/);}
  const changed=await creditSnapshot({query:async()=>({rows:[{row:{id:2}}]})});assert.notDeepEqual(changed,before);
  await assert.rejects(creditSnapshot({query:async()=>({rows:Array(1025).fill({row:{}})})}));
});
test('V37 physical reservation admits only six actor attempts, never Judge or shared-stage dispatch',()=>{
  const {createActualCallBudget}=require('./postgres/secureshopMailActualTransport');
  const budget=createActualCallBudget({protocol:'v37-customer-consumption-v1',maxHttpCalls:6,sharedStages:false});
  for(const kind of ['judge','unexpected',undefined])assert.equal(budget.reserve(kind),false);
  assert.deepEqual(budget.snapshot(),{total:0,actor:0,judge:0});
  for(let i=0;i<6;i++)assert.equal(budget.reserve('actor'),true);
  assert.equal(budget.reserve('actor'),false);assert.equal(budget.reserve('judge'),false);
  assert.deepEqual(budget.snapshot(),{total:6,actor:6,judge:0});
  for(const options of [{maxHttpCalls:5},{maxHttpCalls:7},{maxHttpCalls:6,sharedStages:true}])
    assert.throws(()=>createActualCallBudget({protocol:'v37-customer-consumption-v1',...options}));
  const legacy=createActualCallBudget({maxHttpCalls:6});
  assert.equal(legacy.reserve('judge'),true);assert.equal(legacy.reserve('actor'),true);
  assert.deepEqual(legacy.snapshot(),{total:2,actor:1,judge:1});
});
test('owned shutdown closes client and proxies even when host absence fails; no false cleanup credit',async()=>{
  const {quiesceOwned}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  for(const failure of ['stop','absence','endpoint',null]){
    const events=[],state={},wire={host:{pid:12345}};
    const host={port:32123,status:'running',async stop(){events.push('stop');if(failure==='stop')throw Error('controlled');this.status='stopped';}};
    const args={host,wire,state,client:{async close(){events.push('client');}},
      transport:{actorUrl:'http://127.0.0.1:12345',judgeUrl:'http://127.0.0.1:12346',async close(){events.push('proxy');}},
      processAbsent:pid=>{events.push('absence');if(failure==='absence')throw Error('controlled');return{pid,errorCode:'ESRCH'};},
      endpointClosed:async url=>{events.push(url);if(failure==='endpoint'&&url.endsWith(':32123'))throw Error('controlled');}};
    if(failure){await assert.rejects(quiesceOwned(args),AggregateError);assert.notEqual(state.hostStopped,true);}
    else{await quiesceOwned(args);assert.equal(state.hostStopped,true);assert.deepEqual(wire.hostAbsence,{pid:12345,errorCode:'ESRCH'});}
    assert.equal(state.clientClosed,true);assert.equal(state.proxyEndpointsClosed,true);
    assert.ok(events.indexOf('client')<events.indexOf('proxy'));
  }
});
test('native entrypoint rejects unadmitted invocation before any pool or host allocation',async()=>{
  const native=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  // No writes, listeners, subprocesses or database calls are needed to exercise
  // the actual entrypoint's first boundary; the current focused wrapper lacks
  // the deliberately closed native gate.
  assert.notEqual(process.env.SECURESHOP_CONSUMPTION_NATIVE,'1');
  await assert.rejects(native.runNative());
  assert.throws(()=>native.admitNative({...process.env,SECURESHOP_CONSUMPTION_DIAGNOSTIC:'unknown-profile'}));
});
test('fixture cleanup receipt cannot hide failed SQL removal behind successful outer cleanup',async()=>{
  const {removeSource,fixtureCleanupComplete}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const owned={users:[7,8],products:[1],cart:Array.from({length:241},(_,i)=>i+1)};
  const wire={source:{owned}},events=[];
  const failure=Object.assign(Error('controlled SQL cleanup failure'),{code:'CONTROLLED_SQL_FAILURE'});
  const commerce={connect:async()=>({async query(sql){events.push(sql);if(sql.startsWith('DELETE'))throw failure;return{rows:[]};},release(){events.push('released');}})};
  try{wire.cleanup=await removeSource(commerce,owned);}catch(error){assert.equal(error,failure);wire.cleanupError={name:error.name,code:error.code};}
  assert.ok(events.includes('ROLLBACK'));assert.ok(events.includes('released'));
  const status={cleanupErrors:[]};status.fixtureCleaned=fixtureCleanupComplete(wire,status.cleanupErrors);
  assert.equal(status.fixtureCleaned,false);
  assert.equal(fixtureCleanupComplete({source:{owned}},[]),false);
  assert.equal(fixtureCleanupComplete({source:{owned},cleanup:{shop_users:[],products:[],cart_items:[]}},[]),true);
});
test('native receipt replay joins original SQL source, sibling, durable traces and teardown',async()=>{
  const {validateEvidence}=require('./postgres/secureshopCustomerConsumptionActual.integration.test');
  const cases=await packets(),items=JSON.parse(cases[0].expectedResult.content[0].text).items;
  const afterSeed=[...items.map(item=>({row:{id:item.id,user_id:7,product_id:1,quantity:1,added_at:item.added_at}})),
    {row:{id:241,user_id:8,product_id:1,quantity:1,added_at:items[0].added_at}}];
  const credit=Object.fromEntries(['assessment_judgments','assessment_completions','assessment_contributions'].map(key=>[key,{count:0,sha256:'0'.repeat(64)}]));
  const wire={version:1,kind:'v37-original-customer-consumption',canonicalCredit:false,nativeQualificationAccepted:false,cases,
    originalAcl:{permissions:require('../server/data/secureshopAgentSeeds').TOOLS.flatMap(([tool,matrix])=>
      ['customer','merchant','admin'].map(role=>({tool_name:tool,role,allowed:matrix[role]?1:0})))
      .sort((a,b)=>`${a.tool_name}:${a.role}`.localeCompare(`${b.tool_name}:${b.role}`)),enforcement:false,cartViewCustomerAllowed:true},
    owner:{scope:cases[0].scope,persona:{id:7},sessionId:cases[0].sessionId,principalId:'owner'},
    sibling:{scope:{platformOwnerId:22,platformSessionId:222,launchId:randomUUID()},persona:{id:8},sessionId:randomUUID(),principalId:'sibling'},
    peerTenant:{committed:true,commitAttempted:true,ownerId:22,principalId:'sibling',shopUserId:8},
    source:{actorId:7,siblingId:8,before:[],afterSeed,afterPair:clone(afterSeed),
      owned:{users:[7,8],products:[1],cart:afterSeed.map(item=>item.row.id)},product:{id:1,name:items[0].name,price:'1.25'}},
    creditBefore:credit,creditAfter:clone(credit),siblingMessagesBefore:[],siblingMessagesAfter:[],
    lifecycle:Object.fromEntries(['oldModeRejected','siblingUnchanged','foreignConversationRejected','revokedPersonaRejected','boundaryChecksNoModel','noAward'].map(key=>[key,true])),
    cleanup:{shop_users:[],products:[],cart_items:[]},actorCalls:cases.flatMap(row=>row.spans.flatMap(span=>span.calls)),cleanupErrors:[],
    runtimeCleanup:Object.fromEntries(['hostStopped','hostEndpointClosed','proxyEndpointsClosed','clientClosed','featureTransportsClosed','auditClosed','poolsClosed','fileRootRemoved'].map(key=>[key,true])),
    hostAbsence:{errorCode:'ESRCH'},measurement:await f.validatePair(cases)};
  await validateEvidence(wire);
  const liveDateScope=clone(wire);
  liveDateScope.owner.scope={...liveDateScope.owner.scope,scenarioId:'v37',generation:3,
    status:'active',credentialVersion:2,expiresAt:new Date('2026-10-23T12:34:56.000Z')};
  for(const row of liveDateScope.cases)
    row.scope={...liveDateScope.owner.scope,expiresAt:liveDateScope.owner.scope.expiresAt.toISOString()};
  await validateEvidence(liveDateScope);
  for(const mutate of [
    w=>{w.cases[0].scope.generation++;},
    w=>{w.cases[0].scope.platformOwnerId++;},
    w=>{w.cases[0].scope.platformSessionId++;},
    w=>{w.cases[0].sessionId=randomUUID();},
  ]){
    const altered=structuredClone(liveDateScope);mutate(altered);
    await assert.rejects(validateEvidence(altered));
  }
  assert.equal(typeof items[0].price,'number');assert.equal(typeof wire.source.product.price,'string');
  for(const mutate of [w=>{w.originalAcl.enforcement=true;},w=>{w.originalAcl.permissions.pop();},w=>{w.source.product.name='substitute';},w=>{w.source.product.price='1.26';},
    w=>{const result=JSON.parse(w.cases[0].expectedResult.content[0].text);result.items[0].price='1.25';w.cases[0].expectedResult.content[0].text=JSON.stringify(result);},
    w=>{w.source.afterSeed[0].row.user_id=8;w.source.afterPair=clone(w.source.afterSeed);},
    w=>{w.runtimeCleanup.hostStopped=false;},w=>{w.cleanup.cart_items=[{id:1}];},w=>{w.creditAfter.assessment_completions.count=1;}]){
    const altered=clone(wire);mutate(altered);await assert.rejects(validateEvidence(altered));
  }
  const diagnostic=require('./fixtures/secureshopCustomerConsumptionPromptDiagnostic');
  const diagnosticCases=await packets(diagnostic.PROFILE),diagnosticWire=clone(wire);
  Object.assign(diagnosticWire,{version:2,kind:'v37-sequential-cart-request-diagnostic-v1',
    diagnosticOnly:true,promptProfile:diagnostic.PROFILE,cases:diagnosticCases,
    actorCalls:diagnosticCases.flatMap(row=>row.spans.flatMap(span=>span.calls)),
    measurement:await diagnostic.validateDiagnosticPair(diagnosticCases)});
  diagnosticWire.owner.scope=diagnosticCases[0].scope;
  diagnosticWire.owner.sessionId=diagnosticCases[0].sessionId;
  await validateEvidence(diagnosticWire);
  for(const mutate of [w=>{w.cases[0].message=f.MESSAGE;},
    w=>{w.measurement.cases[0].secondDecisionAfterResult=false;},
    w=>{w.measurement.originalQualificationAccepted=true;},
    w=>{w.cases[1].messages.push({role:'tool',content:'fabricated'});}]){
    const altered=clone(diagnosticWire);mutate(altered);await assert.rejects(validateEvidence(altered));
  }
  for(const arm of ['plain','injected']){
    const sourceCases=await packets(diagnostic.SOURCE_PROFILE,arm),sourceWire=clone(wire);
    Object.assign(sourceWire,{version:2,kind:diagnostic.kindFor(diagnostic.SOURCE_PROFILE),
      diagnosticOnly:true,promptProfile:diagnostic.SOURCE_PROFILE,sourceArm:arm,cases:sourceCases,
      actorCalls:sourceCases.flatMap(row=>row.spans.flatMap(span=>span.calls)),
      measurement:await diagnostic.validateDiagnosticPair(sourceCases)});
    sourceWire.owner.scope=sourceCases[0].scope;
    sourceWire.owner.sessionId=sourceCases[0].sessionId;
    sourceWire.source.product.name=diagnostic.SOURCE_NAMES[arm];
    sourceWire.originalOracleObservation=await require('./postgres/secureshopCustomerConsumptionActual.integration.test')
      .observeOriginalOracle(sourceCases);
    assert.equal(sourceWire.originalOracleObservation.accepted,true);
    assert.equal(sourceWire.originalOracleObservation.originalQualificationAccepted,false);
    const incomplete=clone(sourceCases);
    incomplete[0].result.hops.pop();
    const boundedFailure=await require('./postgres/secureshopCustomerConsumptionActual.integration.test')
      .observeOriginalOracle(incomplete);
    assert.equal(boundedFailure.accepted,false);
    assert.equal(boundedFailure.originalQualificationAccepted,false);
    assert.equal(boundedFailure.measurement,null);
    assert.deepEqual(Object.keys(boundedFailure.failure).sort(),['code','name']);
    await validateEvidence(sourceWire);
    const wrongArm=clone(sourceWire);
    wrongArm.sourceArm=arm==='plain'?'injected':'plain';
    await assert.rejects(validateEvidence(wrongArm));
    const fabricatedOracle=clone(sourceWire);
    fabricatedOracle.originalOracleObservation.accepted=false;
    await assert.rejects(validateEvidence(fabricatedOracle));
    const promoted=clone(sourceWire);
    promoted.version=1;
    promoted.kind='v37-original-customer-consumption';
    delete promoted.promptProfile;
    delete promoted.diagnosticOnly;
    delete promoted.sourceArm;
    for(const row of promoted.cases){delete row.promptProfile;delete row.sourceArm;}
    promoted.measurement=await f.validatePair(promoted.cases);
    await assert.rejects(validateEvidence(promoted),error=>
      error.expected===diagnostic.productNameFor('original')&&error.actual===diagnostic.SOURCE_NAMES[arm]);
  }
});

test('V37 accepts only source-bound existing token-budget termination, not fabricated completion',()=>{
  const packet=()=>({spans:[{response:{stop_reason:'tool_use'}},{response:{stop_reason:'tool_use'}},{response:{stop_reason:'tool_use'}}],
    remainingBudget:0,result:{stopReason:'budget_exhausted',text:'[max steps reached: token budget exhausted]',steps:4,hops:[{},{},{}]},
    traces:[{kind:'terminal',actor:'supervisor',step:4,result_json:JSON.stringify({stopReason:'budget_exhausted',steps:4,hops:3,model:original.MODEL,mocked:false})}]});
  assert.equal(f.assertOriginalTerminal(packet()),true);
  for(const mutate of [v=>{v.remainingBudget=1;},v=>{delete v.remainingBudget;},v=>{v.result.text='made up';},
    v=>{v.result.stopReason='cancelled';},v=>{v.traces=[];},v=>{v.traces.push(clone(v.traces[0]));},
    v=>{v.spans.at(-1).response.stop_reason='end_turn';},v=>{v.result.steps=3;},
    v=>{v.traces[0].result_json=JSON.stringify({stopReason:'budget_exhausted',steps:4,hops:3,model:original.MODEL,mocked:true});}]){
    const value=packet();mutate(value);assert.throws(()=>f.assertOriginalTerminal(value));
  }
  const normal={result:{stopReason:'end_turn',text:'original answer'},spans:[{response:{stop_reason:'end_turn',text:'original answer'}}]};
  assert.equal(f.assertOriginalTerminal(normal),false);
});

test('V37 full original validator accepts verified budget stop while retaining multi-hop and Fixed negatives',async()=>{
 const rows=await packets(),v=rows[0],last=v.spans.at(-1),id='ollama_'+randomUUID();
 const raw=JSON.stringify({tool_calls:[{agent:'cart',tool:'view',args:{}}]});
 const response=JSON.stringify({model:original.MODEL,message:{content:raw},done:true});
 last.calls[0].response=response;last.calls[0].responseSha256=original.sha(response);
 last.response={provider:'ollama',model:original.MODEL,mocked:false,stop_reason:'tool_use',tool_uses:[{id,name:'cart.view',args:{}}]};
 v.messages.pop();v.messages.push({role:'assistant',content:'',tool_calls:[{id,type:'function',function:{name:'cart.view',arguments:'{}'}}]},
   {role:'tool',tool_call_id:id,content:v.expectedResult.content[0].text});
 v.dispatches.push(clone(v.dispatches[0]));
 v.result.hops.push({...clone(v.result.hops[0]),step:3});
 v.traces.push({...clone(v.traces[0]),event_id:randomUUID(),step:3});
 v.result.stopReason='budget_exhausted';v.result.text='[max steps reached: token budget exhausted]';v.result.steps=4;v.remainingBudget=0;
 v.traces.push({event_id:randomUUID(),session_id:v.sessionId,kind:'terminal',actor:'supervisor',step:4,
   result_json:JSON.stringify({stopReason:'budget_exhausted',steps:4,hops:3,model:original.MODEL,mocked:false})});
 v.storedTraces=clone(v.traces);
 assert.equal((await f.validatePair(rows)).measuredPair,true);
 const bad=clone(rows);bad[0].remainingBudget=1;await assert.rejects(f.validatePair(bad));
 const fixed=clone(rows);fixed[1].dispatches.push(clone(fixed[1].dispatches[0]));await assert.rejects(f.validatePair(fixed));
 const parallel=clone(rows);parallel[0].result.hops.forEach(h=>{h.step=1;});await assert.rejects(f.validatePair(parallel));
});

test('mixed parallel and successive calls join distinct result events without manufacturing growth',async()=>{
 const rows=await packets('original',undefined,true);
 assert.deepEqual(rows[0].result.hops.map(h=>h.step),[1,1,2]);assert.equal(rows[0].spans.length,3);
 const measured=await f.validatePair(rows);assert.equal(measured.nativeQualificationAccepted,false);
 for(const mutate of [r=>r[0].traces.pop(),r=>r[0].traces.push(clone(r[0].traces[0])),
  r=>{r[0].traces[2].step=1;},r=>{r[0].traces[0].latency_ms=99;}]){
  const bad=clone(rows);mutate(bad);bad[0].storedTraces=clone(bad[0].traces);await assert.rejects(f.validatePair(bad));
 }
 const reordered=clone(rows);reordered[0].storedTraces.reverse();
 assert.notDeepEqual(reordered[0].storedTraces,reordered[0].traces);
 await assert.rejects(f.validatePair(reordered));
});
