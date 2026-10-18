'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createOwnedMcpRegistry}=require('../server/services/secureshopOwnedMcpRegistry');
const {createOwnedMcpRegistryRepository,assertOwnedMcpRegistryReady}=require('../server/database/postgres/secureshopOwnedMcpRegistryRepository');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const worker=require('../sidecars/sandbox-runner/owned-mcp-registry/worker');
const http=require('node:http');
const {createOwnedMcpRegistryHttpHandler}=require('../sidecars/sandbox-runner/owned-mcp-registry/http-handler');
const {createOwnedMcpRegistryClient,isOwnedMcpRegistryOutcomeUncertain}=require('../server/services/secureshopOwnedMcpRegistryClient');
const express=require('express'),{createBoundMcpRegistryRouter}=require('../server/routes/secureshop/boundMcpRegistry');
const {createOwnedMcpRegistryComposition}=require('../server/services/secureshopOwnedMcpRegistryComposition');
const {createOwnedMcpRegistryAdminReadRepository}=require('../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository');
const {createOwnedMcpRegistryAdminReadOverlay}=require('../server/services/secureshopOwnedMcpRegistryAdminReadOverlay');
const {createOwnedMcpRegistryListener}=require('../sidecars/sandbox-runner/owned-mcp-registry/http-listener');
const {createOwnedMcpRegistryExecutor}=require('../sidecars/sandbox-runner/owned-mcp-registry/executor');
const ids=Object.freeze({launch:'10000000-0000-4000-8000-000000000001',scenario:'20000000-0000-4000-8000-000000000001',personaSession:'30000000-0000-4000-8000-000000000001',operation:'40000000-0000-4000-8000-000000000001',worker:'50000000-0000-4000-8000-000000000001'});
const scope=Object.freeze({launchId:ids.launch,scenarioId:ids.scenario,generation:1,platformOwnerId:7,platformSessionId:11});
function raw(){return{scope,persona:{id:3,role:'admin'},personaSession:{sessionId:ids.personaSession,authorityVersion:'1'},request:{version:1,action:'register',operationId:ids.operation,expectedVersion:'0',name:'poisoned-catalog',transport:'sse',url:'http://127.0.0.1:8099/mcp',stdio_cmd:''}};}
test('service dispatches only a newly admitted operation and exact replay never executes',async()=>{
 const events=[],fence={assertRemoteAdmission:async()=>events.push('authority')},repository={prepare:value=>value,
  beginPrepared:async()=>({newlyAdmitted:true,fence,prepared:{request:raw().request},operation:{state:'admitted'}}),
  activeEntries:async()=>[],publish:async(_a,changes)=>{events.push(['publish',changes]);return{state:'completed'};},finish:async()=>assert.fail(),read:async()=>({})};
 const service=createOwnedMcpRegistry({repository,readMode:async()=> 'vuln',executor:{execute:async(request,{assertCurrent})=>{events.push(['execute',request.name]);await assertCurrent();return[{name:request.name,entryId:'60000000-0000-4000-8000-000000000001',action:'register',transport:'sse',endpoint:request.url,schemaSha256:'a'.repeat(64),tools:[],effect:{isolationAttested:true}}];}}});
 assert.deepEqual(await service.mutate(raw()),{state:'completed'});assert.deepEqual(events.map(v=>Array.isArray(v)?v[0]:v),['authority','execute','authority','publish']);
 repository.beginPrepared=async()=>({newlyAdmitted:false,operation:{state:'completed',replayed:true}});assert.deepEqual(await service.mutate(raw()),{state:'completed',replayed:true});assert.equal(events.filter(v=>Array.isArray(v)&&v[0]==='execute').length,1);
});
test('service distinguishes pre-effect failure from uncertain executor and publication outcomes',async()=>{
 for(const [where,expected] of [['executor-clean','failed'],['executor-unknown','unknown'],['publish','unknown']]){
  const states=[],admission={newlyAdmitted:true,fence:{assertRemoteAdmission:async()=>{}},prepared:{request:raw().request},operation:{state:'admitted'}};
  const repository={prepare:value=>value,beginPrepared:async()=>admission,activeEntries:async()=>[],finish:async(_a,state)=>states.push(state),read:async()=>({}),publish:async()=>{if(where==='publish')throw Error('lost commit');return{};}};
  const executor={execute:async()=>{if(where.startsWith('executor')){const e=Error('executor failed');if(where==='executor-clean')e.effectNotStarted=true;throw e;}return[{name:'x'}];}};
  const service=createOwnedMcpRegistry({repository,executor,readMode:async()=> 'vuln'});
  if(where==='executor-clean')await assert.rejects(service.mutate(raw()),/executor failed/);
  else await assert.rejects(service.mutate(raw()),e=>e.code==='MCP_REGISTRY_OUTCOME_UNCERTAIN'&&e.automaticRetry===false);
  assert.deepEqual(states,[expected]);
 }
});
test('repository snapshots caller data, binds the exact admin fence and returns no worker token',async()=>{
 let captured,release;const blocked=new Promise(resolve=>{release=resolve;});
 const client={query:async(sql,params)=>{if(sql.startsWith('SET LOCAL'))return{rows:[]};assert.match(sql,/admit_owned_mcp_registry_operation/);captured=params;await blocked;return{rows:[{
  operation_id:ids.operation,persona_id:3,persona_session_id:ids.personaSession,authority_version:'1',mode:'vuln',action:'register',expected_version:'0',request_sha256:Buffer.from(params[12],'hex'),binding_sha256:Buffer.from(params[13],'hex'),worker_token:ids.worker,state:'admitted',request_json:JSON.parse(params[15]),receipt_json:null,receipt_sha256:null
 }]};}};
 const binding={...scope,personaId:3,sessionId:ids.personaSession,role:'admin',authorityVersion:'1'};
 const authority={capture:input=>{assert.deepEqual(input,{scope,personaId:3,role:'admin',sessionId:ids.personaSession,authorityVersion:'1'});return{binding,withPersonaEffect:fn=>fn(client),assertRemoteAdmission:async()=>{}};}};
 const repository=createOwnedMcpRegistryRepository({pool:{query:async()=>{}},personaAuthority:authority,makeId:()=>ids.worker});const input=raw(),prepared=repository.prepare(input);const pending=repository.beginPrepared(prepared,{mode:'vuln'});input.request.name='mutated-after-call';release();const admitted=await pending;
 assert.equal(captured[9],'vuln');assert.equal(JSON.parse(captured[15]).name,'poisoned-catalog');assert.equal(admitted.newlyAdmitted,true);assert.deepEqual(admitted.operation,{version:'secureshop-owned-mcp-registry.v1',operationId:ids.operation,state:'admitted',action:'register',requestSha256:captured[12],replayed:false});assert.equal(Object.hasOwn(admitted.operation,'workerToken'),false);
});
test('repository read validates stored receipt digest and original session',async()=>{
 const receipt={version:'secureshop-owned-mcp-registry.v1',operationId:ids.operation,state:'completed',action:'register',requestSha256:'a'.repeat(64),registryVersion:'1',changes:[]};
 const row={operation_id:ids.operation,persona_id:3,persona_session_id:ids.personaSession,authority_version:'1',action:'register',request_sha256:Buffer.from('a'.repeat(64),'hex'),state:'completed',receipt_json:receipt,receipt_sha256:Buffer.from(canonicalDigest(receipt),'hex')};
 const client={query:async()=>({rows:[row]})},binding={...scope,personaId:3,sessionId:ids.personaSession,role:'admin',authorityVersion:'1'};
 const repository=createOwnedMcpRegistryRepository({pool:{query:async()=>{}},personaAuthority:{capture:()=>({binding,withPersonaEffect:fn=>fn(client),assertRemoteAdmission:async()=>{}})}});
 assert.deepEqual(await repository.read({...raw(),request:undefined,operationId:ids.operation}),{...receipt,replayed:true});row.persona_session_id='30000000-0000-4000-8000-000000000099';await assert.rejects(repository.read({...raw(),request:undefined,operationId:ids.operation}),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
});
test('assessment revision reader returns only two original same-actor immutable publications',async()=>{
 const entryId='60000000-0000-4000-8000-000000000001',operationIds=[ids.operation,'40000000-0000-4000-8000-000000000002'];
 const revisions=operationIds.map((operation_id,index)=>({operation_id,entry_id:entryId,name:'trusted-catalog',
  registry_version:String(index+1),action:'register',redacted_at:null}));
 const operations=operationIds.map(operation_id=>({operation_id,state:'completed',action:'register',persona_id:3,
  persona_session_id:ids.personaSession,authority_version:'1',redacted_at:null}));
 const calls=[],binding={...scope,personaId:3,role:'admin',sessionId:ids.personaSession,authorityVersion:'1'};
 let active=true;
 const client={query:async(sql,args)=>{calls.push({sql,args});return {rows:sql.includes('bound_mcp_registry_revisions')?revisions:operations};}};
 const repository=createOwnedMcpRegistryRepository({pool:{query:async()=>{}},personaAuthority:{capture:()=>({binding,
  withPersonaEffect:work=>work(client),assertRemoteAdmission:async()=>{if(!active)throw Error('stale');}})}});
 const input={scope,persona:{id:3,role:'admin'},personaSession:{sessionId:ids.personaSession,authorityVersion:'1'},
  entryId,registryVersion:'2'};
 const packet=await repository.readAssessmentRevisions(input);
 assert.deepEqual(packet.trusted.revision,revisions[0]);assert.deepEqual(packet.replacement.operation,operations[1]);
 assert.deepEqual(calls.map(call=>call.args.slice(0,5)),[scopeValuesForTest(scope),scopeValuesForTest(scope)]);
 assert.deepEqual(calls[0].args.slice(5),[entryId,'1','2']);assert.deepEqual(calls[1].args[5],operationIds);
 function scopeValuesForTest(value){return[value.launchId,value.scenarioId,value.generation,value.platformOwnerId,value.platformSessionId];}
 revisions[0].redacted_at='2026-01-01';
 // The real SELECT excludes redacted rows; emulate its filtered result.
 client.query=async sql=>({rows:sql.includes('bound_mcp_registry_revisions')?revisions.filter(row=>!row.redacted_at):operations});
 await assert.rejects(repository.readAssessmentRevisions(input),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
 revisions[0].redacted_at=null;operations[0].persona_session_id='30000000-0000-4000-8000-000000000099';
 await assert.rejects(repository.readAssessmentRevisions(input),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
 operations[0].persona_session_id=ids.personaSession;active=false;
 await assert.rejects(repository.readAssessmentRevisions(input),/stale/);
 for(const bad of ['1','0','01','not-a-version'])
  await assert.rejects(repository.readAssessmentRevisions({...input,registryVersion:bad}),{code:'MCP_REGISTRY_OPERATION_NOT_FOUND'});
});
test('manifest parser performs a bounded synthetic namespace file read while worker execution is host-inaccessible',async t=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'owned-mcp-registry-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));const file=path.join(root,'teaching.txt');await fs.writeFile(file,'DV-AI{owned-xxe-observation}');
 const xml=`<!DOCTYPE manifest [<!ENTITY xxe SYSTEM "file://${file}">]><manifest><label>&xxe;</label><server><name>catalog</name><transport>streamable-http</transport><url>http://127.0.0.1:8099/mcp</url><stdio_cmd></stdio_cmd></server></manifest>`;
 const parsed=await worker.parseManifest(xml,{root});assert.equal(parsed.parsed.manifest.label,'DV-AI{owned-xxe-observation}');assert.equal(parsed.reads[0].value,'DV-AI{owned-xxe-observation}');assert.equal(parsed.reads[0].bytes,Buffer.byteLength('DV-AI{owned-xxe-observation}'));assert.match(parsed.reads[0].sha256,/^[0-9a-f]{64}$/);
 await assert.rejects(worker.parseManifest(xml.replace(file,'/etc/passwd'),{root}),{code:'MCP_REGISTRY_ENTITY_OUTSIDE_NAMESPACE'});
 await assert.rejects(worker.operation({}),e=>e.code==='MCP_REGISTRY_EXECUTOR_UNATTESTED'&&e.effectNotStarted===true);
});
test('authenticated private transport performs exact execution and brands a lost POST response unknown',async t=>{
 const token='a'.repeat(43),change={name:'catalog',entryId:'60000000-0000-4000-8000-000000000001',action:'register',transport:'sse',endpoint:'http://127.0.0.1:8099/mcp',schemaSha256:'b'.repeat(64),tools:[],effect:{isolation:'owned-mcp-registry-v1'}};
 let nativeProbes=0;const handler=createOwnedMcpRegistryHttpHandler({token,executor:{checkReadiness:async()=>({runtimeDigest:'c'.repeat(64)}),assertReady:async()=>{nativeProbes++;return{ready:true};},execute:async input=>{assert.equal(input.mode,'vuln');return[change];}}});
 const server=http.createServer((req,res)=>handler.handle(req,res).then(ok=>{if(!ok){res.writeHead(404);res.end();}},()=>{res.writeHead(503);res.end();}));await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(async()=>{await handler.close();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
 const baseURL=`http://127.0.0.1:${server.address().port}`,client=createOwnedMcpRegistryClient({baseURL,token});let checks=0;assert.deepEqual(await client.execute(raw().request,{activeEntries:[],mode:'vuln',assertCurrent:async()=>checks++}),[change]);assert.equal(checks,3);assert.equal(nativeProbes,1);
 let posts=0;const dropped=createOwnedMcpRegistryClient({baseURL,token,fetchImpl:async(url,options)=>{const response=await fetch(url,options);if(options.method==='POST'){posts++;await response.body.cancel();throw Error('lost');}return response;}});await assert.rejects(dropped.execute(raw().request,{activeEntries:[],mode:'vuln',assertCurrent:async()=>{}}),error=>isOwnedMcpRegistryOutcomeUncertain(error)&&error.automaticRetry===false);assert.equal(posts,1);
 const denied=await fetch(baseURL+'/secureshop/mcp-registry/health');assert.equal(denied.status,401);
});
test('bound routes require the closed versioned request and recover by operation id only',async t=>{
 const calls=[],service={mutate:async value=>{calls.push(value);return{version:'secureshop-owned-mcp-registry.v1',operationId:value.request.operationId,state:'completed',action:value.request.action,requestSha256:'a'.repeat(64),registryVersion:'1',changes:[],replayed:false};},read:async value=>{calls.push(value);return{version:'secureshop-owned-mcp-registry.v1',operationId:value.operationId,state:'unknown',action:'register',requestSha256:'a'.repeat(64),replayed:true};}};
 const app=express();app.use(express.json());app.use((req,_res,next)=>{req.ssLaunch=scope;req.ssUser={id:3,role:'admin'};req.ssPersonaSession={sessionId:ids.personaSession,authorityVersion:'1'};next();});app.use(createBoundMcpRegistryRouter({service,authenticatePersona:(_req,_res,next)=>next()}));const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));const origin=`http://127.0.0.1:${server.address().port}`;
 const response=await fetch(origin+'/admin/mcp/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(raw().request)});assert.equal(response.status,200);assert.equal((await response.json()).ok,true);assert.equal(calls[0].request.name,'poisoned-catalog');
 const old=await fetch(origin+'/admin/mcp/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'legacy'})});assert.equal(old.status,400);
 const recovered=await fetch(origin+'/admin/mcp/operations/'+ids.operation);assert.equal(recovered.status,200);assert.deepEqual(await recovered.json(),{version:'secureshop-owned-mcp-registry.v1',operationId:ids.operation,state:'unknown',action:'register',requestSha256:'a'.repeat(64),replayed:true,ok:false,automaticRetry:false});assert.equal(Object.hasOwn(calls[1],'request'),false);
});
test('readiness requires exact database, narrow grants, functions and enabled canonical triggers',async()=>{
 let row={database:'agents_owned',tables_present:true,table_grants:true,function_grants:true,cleanup_denied:true,guard_denied:true,actor_guard_denied:true,actor_guard_current:true,admission_guard_current:true,request_digest_denied:true,triggers_ready:true};const pool={query:async(sql,args)=>{assert.match(sql,/t\.tgenabled IN \('O','A'\)/);assert.match(sql,/t\.tgfoid=to_regprocedure\('secureshop_agents\.cleanup_owned_mcp_registry\(\)'\)/);assert.match(sql,/t\.tgrelid='secureshop_agents\.bound_mcp_registry_revisions'::regclass/);assert.equal(args[0].length,5);assert.equal(args[1].length,3);return{rows:[row]};}};
 assert.deepEqual(await assertOwnedMcpRegistryReady({pool,expectedDatabase:'agents_owned'}),{ready:true,database:'agents_owned'});
 for(const key of ['tables_present','table_grants','function_grants','cleanup_denied','guard_denied','actor_guard_denied','actor_guard_current','admission_guard_current','request_digest_denied','triggers_ready']){const before=row;row={...before,[key]:false};await assert.rejects(assertOwnedMcpRegistryReady({pool,expectedDatabase:'agents_owned'}),{code:'MCP_REGISTRY_NOT_READY'});row=before;}
});
test('candidate SQL binds the public receipt to exact published changes and grants no table writes',()=>{
 const sql=require('node:fs').readFileSync(require('node:path').join(__dirname,'../docs/modernization/drafts/secureshop-owned-mcp-registry/0035_owned_mcp_registry.sql'),'utf8');
 assert.match(sql,/requested_receipt->'changes' IS DISTINCT FROM expected_receipt_changes/);
 assert.match(sql,/requested_request IS DISTINCT FROM secureshop_agents\.owned_mcp_registry_request_digest\(requested_json\)/);
 assert.match(sql,/REVOKE ALL ON secureshop_agents\.bound_mcp_registry_heads,[\s\S]*FROM PUBLIC,dvaia_secureshop_agents_runtime;/);
 assert.doesNotMatch(sql,/GRANT (?:INSERT|UPDATE|DELETE|ALL)[\s\S]*bound_mcp_registry/i);
});
test('composition is inert by default and enabled only after database and executor readiness',async()=>{
 let calls=[];assert.equal(await createOwnedMcpRegistryComposition({readiness:()=>calls.push('bad')}),undefined);assert.deepEqual(calls,[]);
 const pool={query:async()=>{}},personaAuthority={capture:()=>{}},executorClient={health:async()=>calls.push('health'),execute:async()=>{}},repository={},service={},router=()=>{},readMode=async()=> 'vuln';
 const value=await createOwnedMcpRegistryComposition({enabled:true,agentsPool:pool,personaAuthority,authenticatePersona:()=>{},executorClient,readMode,expectedDatabase:'agents_owned',
  readiness:async input=>{assert.deepEqual(input,{pool,expectedDatabase:'agents_owned'});calls.push('database');},repositoryFactory:input=>{assert.deepEqual(input,{pool,personaAuthority});calls.push('repository');return repository;},
  serviceFactory:input=>{assert.deepEqual(input,{repository,executor:executorClient,readMode});calls.push('service');return service;},routerFactory:input=>{assert.equal(input.service,service);calls.push('router');return router;}});
 assert.deepEqual(calls,['database','health','repository','service','router']);assert.equal(value.capability,'secureshop-owned-mcp-registry.v1');assert.equal(value.router,router);
 await assert.rejects(createOwnedMcpRegistryComposition({enabled:'true'}),TypeError);
});
test('admin read overlay appends the general namespace and preserves trust fallback',async()=>{
 const queries=[];const repository=createOwnedMcpRegistryAdminReadRepository({pool:{query:async(sql,args)=>{queries.push({sql,args});if(sql.includes('FROM secureshop_agents.bound_mcp_registry_entries WHERE'))return{rows:[{id:'general-id',name:'poisoned',provenance:'owned_registry'}]};if(sql.includes('FROM secureshop_agents.bound_mcp_registry_revisions WHERE'))return{rows:[{name:'poisoned',version:'1',schema_hash:'a'.repeat(64),ts:'2026-01-02',provenance:'owned_registry'}]};if(args[5]==='missing')return{rows:[]};return{rows:[{version:'1',schema_hash:'a'.repeat(64),tools_json:[{name:'search',description:'poisoned description',inputSchema:{type:'object'}}]}]};}}});
 const base={mcpServers:async()=>({basis:'persisted_launch_discovery',servers:[{id:'trust-id',name:'trust'}]}),mcpHistory:async()=>({basis:'persisted_launch_discovery',history:[{name:'trust',ts:'2026-01-01'}]}),mcpTools:async(_s,name)=>({name,tools:[{tool_name:'trust'}]})};
 const overlay=createOwnedMcpRegistryAdminReadOverlay({base,repository,enabled:true});const servers=await overlay.mcpServers(scope);assert.deepEqual(servers.servers.map(row=>row.name),['trust','poisoned']);const history=await overlay.mcpHistory(scope);assert.deepEqual(history.history.map(row=>row.name),['trust','poisoned']);const general=await overlay.mcpTools(scope,'poisoned');assert.deepEqual(general.tools,[{tool_name:'search',description:'poisoned description',input_schema_json:'{"type":"object"}'}]);
 const trust=await overlay.mcpTools(scope,'missing');assert.deepEqual(trust,{name:'missing',tools:[{tool_name:'trust'}]});assert.ok(queries.every(query=>query.args.slice(0,5).join(',')===scopeValuesForTest(scope).join(',')));
 function scopeValuesForTest(value){return[value.launchId,value.scenarioId,value.generation,value.platformOwnerId,value.platformSessionId];}
 let disabledRepositoryCalls=0;
 const disabledRepository={head:async()=>{disabledRepositoryCalls++;},servers:async()=>{disabledRepositoryCalls++;},history:async()=>{disabledRepositoryCalls++;},tools:async()=>{disabledRepositoryCalls++;}};
 const disabled=createOwnedMcpRegistryAdminReadOverlay({base,repository:disabledRepository,enabled:false});
 assert.notEqual(disabled,base);
 assert.deepEqual(await disabled.mcpServers(scope),{basis:'persisted_launch_discovery',servers:[{id:'trust-id',name:'trust'}],registry_administration:{ready:false}});
 assert.equal(disabledRepositoryCalls,0);
 assert.equal(servers.registry_discovery_assessment,undefined,'existing registry flows acquire no new assessment latch');
 for(const readiness of [false,true,'true']){
  let reads=0;
  const candidate=createOwnedMcpRegistryAdminReadOverlay({base,repository,enabled:true,
   readDiscoveryAssessment:async actual=>{assert.deepEqual(actual,scope);reads++;return readiness;}});
  const result=await candidate.mcpServers(scope);
  assert.deepEqual(result.registry_discovery_assessment,{ready:readiness===true});
  assert.deepEqual(result.registry_administration,servers.registry_administration);
  assert.equal(reads,1);
 }

});
test('listener gates bind on actual executor readiness and drains authenticated work',async()=>{
 const token='z'.repeat(43),calls=[];const executor={checkReadiness:async()=>{calls.push('assets');return{ready:true,runtimeDigest:'d'.repeat(64)};},assertReady:async()=>{calls.push('namespace');return{ready:true};},execute:async()=>[]};
 const listener=createOwnedMcpRegistryListener({enabled:true,token,host:'127.0.0.1',port:0,executor});const address=await listener.start();const response=await fetch(`http://127.0.0.1:${address.port}/secureshop/mcp-registry/health`,{headers:{authorization:'Bearer '+token}});assert.equal(response.status,200);assert.deepEqual(calls,['assets','assets','namespace']);await listener.close();assert.equal(listener.address(),null);
 assert.throws(()=>createOwnedMcpRegistryListener({enabled:false}),{code:'MCP_REGISTRY_LISTENER_DISABLED'});assert.throws(()=>createOwnedMcpRegistryExecutor({expectedProfile:'not-qualified'}),TypeError);
});

test('mounted admission maps only exact database conflicts to 409 before executor work', async t => {
 let databaseError, executions=0, admissions=0;
 const client={query:async sql=>{if(sql.startsWith('SET LOCAL'))return {rows:[]};assert.match(sql,/admit_owned_mcp_registry_operation/);admissions++;throw databaseError;}};
 const personaAuthority={capture:()=>({binding:{...scope,personaId:3,role:'admin',sessionId:ids.personaSession,authorityVersion:'1'},assertRemoteAdmission:async()=>{},withPersonaEffect:work=>work(client)})};
 const repository=createOwnedMcpRegistryRepository({pool:client,personaAuthority});
 const service=createOwnedMcpRegistry({repository,readMode:async()=> 'vuln',executor:{execute:async()=>{executions++;assert.fail('Rejected admission must not execute');}}});
 const app=express();app.use(express.json());app.use((req,_res,next)=>{req.ssLaunch=scope;req.ssUser={id:3,role:'admin'};req.ssPersonaSession={sessionId:ids.personaSession,authorityVersion:'1'};next();});
 app.use(createBoundMcpRegistryRouter({service,authenticatePersona:(_req,_res,next)=>next()}));
 const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 for(const [code,message,status] of [
  ['55000','Owned MCP registry version conflict',409],['55000','Owned MCP operation conflict',409],
  ['55000','Owned MCP authority unavailable',503],['55000','Owned MCP registry quota exceeded',503],
  ['55000','Owned MCP registry version conflict extra',503],['08006','Owned MCP registry version conflict',503]
 ]){
  databaseError=Object.assign(Error(message),{code});
  const response=await fetch(`http://127.0.0.1:${server.address().port}/admin/mcp/register`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(raw().request)});
  assert.equal(response.status,status);const body=await response.json();
  assert.deepEqual(body,status===409?{ok:false,error:'Owned MCP registry conflict',code:'MCP_REGISTRY_OPERATION_CONFLICT',automaticRetry:false}:{ok:false,error:'Owned MCP registry unavailable'});
 }
 assert.equal(admissions,6);assert.equal(executions,0);
});

test('fixed network registration admits only the attested benign peer before discovery; other lesson paths retain their gates',()=>{
 const registration={...raw().request,transport:'streamable-http',url:'http://metadata.training/mcp'};
 for(const url of ['http://metadata.training/mcp','http://169.254.169.254/mcp','http://attacker.training:8080/mcp','http://10.0.2.10/mcp','http://127.0.0.1/mcp','https://benign.training/mcp','http://benign.training:8080/mcp','http://benign.training/manifest.xml','http://benign.training/mcp?x=1','http://benign.training/mcp#x','http://user@benign.training/mcp'])assert.throws(()=>worker.assertRegistrationDestination({...registration,url},'fixed'),error=>error.code==='MCP_REGISTRY_FIXED_DESTINATION_DENIED'&&error.effectNotStarted===true);
 for(const url of ['http://benign.training/mcp','http://192.0.2.10/mcp','http://benign.training:80/mcp'])assert.doesNotThrow(()=>worker.assertRegistrationDestination({...registration,url},'fixed'));
 assert.doesNotThrow(()=>worker.assertRegistrationDestination(registration,'vuln'));
 assert.doesNotThrow(()=>worker.assertRegistrationDestination({action:'import',xml_url:'http://metadata.training/manifest.xml'},'fixed'));
 assert.doesNotThrow(()=>worker.assertRegistrationDestination({...registration,transport:'stdio',url:'',stdio_cmd:'owned command'},'fixed'));
});

function discoveryControl(){
 const request={...raw().request,transport:'streamable-http',url:'http://metadata.training/mcp'},witness=worker.createDiscoveryWitness(),nonce=witness.begin(request,request.url);
 const tools=[{name:'metadata-catalog',description:'Namespace-only synthetic metadata',inputSchema:{type:'object',properties:{query:{type:'string'}}}}];
 const body=JSON.stringify({jsonrpc:'2.0',id:1,method:'tools/list',params:{}}),headers={'x-dvaia-registry-discovery':nonce};
 const receiving={headers,socket:{localAddress:'169.254.169.254',localPort:80}},extra={requestId:1,requestInfo:{headers}};
 return{request,witness,nonce,tools,body,receiving,extra,peer:worker.PEERS[0]};
}

test('discovery receipt binds original receiving socket/body and SDK result to exact normalized operation',()=>{
 const c=discoveryControl(),originalOperation=c.request.operationId;
 c.witness.capture(c.peer,c.receiving,c.body);c.witness.complete(c.peer,{method:'tools/list'},{tools:c.tools},c.extra);
 c.request.operationId=crypto.randomUUID(); // begin owns an immutable normalized snapshot.
 const receipt=c.witness.finish(c.nonce,{pages:1,tools:c.tools});
 assert.equal(receipt.operationId,originalOperation);assert.deepEqual(receipt.destination,{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true});
 assert.equal(receipt.toolsListRequestBody,c.body);assert.equal(receipt.toolsListRequestSha256,crypto.createHash('sha256').update(c.body).digest('hex'));
 assert.deepEqual(receipt.toolsListResponse,{tools:c.tools});assert.equal(receipt.toolsListResponseSha256,canonicalDigest({tools:c.tools}));
 assert.equal(receipt.schemaSha256,require('../server/services/secureshopMcpSchemaDigest').mcpSchemaDigest(c.tools));
 assert.throws(()=>c.witness.finish(c.nonce,{pages:1,tools:c.tools}),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
});

test('discovery witness rejects foreign socket, absent receiving request, mismatched RPC and changed discovered schema',()=>{
 let c=discoveryControl();assert.throws(()=>c.witness.capture(c.peer,{...c.receiving,socket:{localAddress:'10.0.1.100',localPort:80}},c.body),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
 c=discoveryControl();assert.throws(()=>c.witness.finish(c.nonce,{pages:1,tools:c.tools}),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
 c=discoveryControl();c.witness.capture(c.peer,c.receiving,c.body);assert.throws(()=>c.witness.complete(c.peer,{method:'tools/list'},{tools:c.tools},{...c.extra,requestId:2}),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
 c=discoveryControl();c.witness.capture(c.peer,c.receiving,c.body);c.witness.complete(c.peer,{method:'tools/list'},{tools:c.tools},c.extra);
 assert.throws(()=>c.witness.complete(c.peer,{method:'tools/list'},{tools:c.tools},c.extra),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
 assert.throws(()=>c.witness.finish(c.nonce,{pages:1,tools:[{...c.tools[0],description:'foreign'}]}),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
});

test('SDK discovery observation preserves the actual registered peer handler and complete original result',async()=>{
 const {Client}=await import('@modelcontextprotocol/sdk/client/index.js'),{InMemoryTransport}=await import('@modelcontextprotocol/sdk/inMemory.js');
 const observations=[],server=worker.mcpServer(worker.PEERS[0],{observeToolsList:(peer,request,result,extra)=>observations.push({peer,request:structuredClone(request),result:JSON.parse(JSON.stringify(result)),requestId:extra.requestId})});
 const [a,b]=InMemoryTransport.createLinkedPair(),client=new Client({name:'controlled-discovery-observer',version:'1.0.0'});
 try{await server.connect(b);await client.connect(a);const result=await client.listTools();assert.equal(observations.length,1);assert.equal(observations[0].request.method,'tools/list');assert.equal(observations[0].peer,worker.PEERS[0]);assert.deepEqual(observations[0].result,JSON.parse(JSON.stringify(result)));assert.equal(result.tools[0].name,'metadata-catalog');}
 finally{await Promise.allSettled([client.close(),server.close(),a.close(),b.close()]);}
});

test('only exact joined fixed-destination worker denial is classified pre-effect; generic and foreign output never is',()=>{
 const {readWorkerOutput}=require('../sidecars/sandbox-runner/owned-mcp-registry/executor'),{DISCOVERY_POLICY_SHA256}=require('../server/services/secureshopMcpRegistryDiscoveryContract');
 const input={mode:'fixed',activeEntries:[],request:{...raw().request,url:'http://metadata.training/mcp'}},denial={version:1,type:'registration-destination-denied',operationId:input.request.operationId,registryRequestSha256:require('../server/services/secureshopMcpRegistryContract').registryRequestDigest(input.request),policySha256:DISCOVERY_POLICY_SHA256,effectNotStarted:true};
 assert.throws(()=>readWorkerOutput(JSON.stringify(denial),input,{drained:true}),error=>error.code==='MCP_REGISTRY_FIXED_DESTINATION_DENIED'&&error.effectNotStarted===true&&error.drained===true&&error.operationId===input.request.operationId);
 for(const value of [{...denial,operationId:ids.launch},{...denial,policySha256:'a'.repeat(64)},{...denial,registryRequestSha256:'b'.repeat(64)},{...denial,effectNotStarted:false},{...denial,extra:true},{error:'MCP_REGISTRY_CHILD_FAILED'}])assert.throws(()=>readWorkerOutput(JSON.stringify(value),input,{drained:true}),error=>error.code==='MCP_REGISTRY_WORKER_OUTPUT_INVALID'&&error.effectNotStarted!==true);
 assert.throws(()=>readWorkerOutput(JSON.stringify(denial),input),error=>error.effectNotStarted!==true);
 assert.throws(()=>readWorkerOutput(JSON.stringify(denial),{...input,mode:'vuln'},{drained:true}),error=>error.effectNotStarted!==true);
 assert.deepEqual(readWorkerOutput('[]',input,{drained:true}),[]);
});

test('persisted discovery receipt survives JSONB key ordering but never body or response substitution',()=>{
 const c=discoveryControl();
 c.tools[0]={inputSchema:c.tools[0].inputSchema,description:c.tools[0].description,name:c.tools[0].name};
 c.witness.capture(c.peer,c.receiving,c.body);
 c.witness.complete(c.peer,{method:'tools/list'},{tools:c.tools},c.extra);
 const original=c.witness.finish(c.nonce,{pages:1,tools:c.tools});
 const jsonb=value=>Array.isArray(value)?value.map(jsonb):value&&typeof value==='object'
  ?Object.fromEntries(Object.keys(value).sort((a,b)=>a.length-b.length||a.localeCompare(b)).map(key=>[key,jsonb(value[key])])):value;
 const stored=JSON.parse(JSON.stringify(jsonb(original)));
 assert.notEqual(JSON.stringify(stored.toolsListResponse),JSON.stringify(original.toolsListResponse));
 const {validateDiscoveryReceipt}=require('../server/services/secureshopMcpRegistryDiscoveryContract');
 const input={request:c.request,tools:jsonb(c.tools),endpoint:c.request.url};
 assert.deepEqual(validateDiscoveryReceipt(stored,input),stored);
 assert.equal(stored.toolsListResponseSha256,canonicalDigest(original.toolsListResponse));
 assert.equal(stored.toolsListRequestSha256,crypto.createHash('sha256').update(c.body).digest('hex'));
 for(const mutate of [r=>{r.toolsListResponse.tools[0].description+=' changed';},
  r=>{r.toolsListResponseSha256='0'.repeat(64);},r=>{r.toolsListRequestBody+=' ';},
  r=>{r.toolsListResponse.tools[0].inputSchema.properties.query.type='number';}]){
  const changed=structuredClone(stored);mutate(changed);
  assert.throws(()=>validateDiscoveryReceipt(changed,input),{code:'MCP_REGISTRY_DISCOVERY_RECEIPT_INVALID'});
 }
});

test('worker stdout decoder preserves exact real SDK invocation receipt and rejects foreign or malformed output',async()=>{
 const {InMemoryTransport}=require('@modelcontextprotocol/sdk/inMemory.js'),{Client}=require('@modelcontextprotocol/sdk/client/index.js');
 const {readWorkerOutput}=require('../sidecars/sandbox-runner/owned-mcp-registry/executor'),protocol=require('../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'registry-stdout-control-')),file=path.join(root,'catalog.json'),catalog=[{id:'owned-decoder-value',title:'Original file-backed SDK result'}];
 await fs.writeFile(file,JSON.stringify(catalog),{mode:0o600});
 const server=worker.mcpServer(worker.PEERS[1],{readCatalog:()=>worker.readOwnedCatalog(file)}),client=new Client({name:'worker-stdout-control',version:'1.0.0'},{capabilities:{}}),[a,b]=InMemoryTransport.createLinkedPair();
 try{
  await server.connect(a);await client.connect(b);const found=await client.listTools(),tools=JSON.parse(JSON.stringify(found.tools));
  const invocation={version:1,instanceId:ids.launch,operationId:ids.operation,
   entry:{entryId:ids.worker,registryVersion:'1',transport:'sse',endpoint:'http://attacker.training:8080/mcp',
    schemaSha256:require('../server/services/secureshopMcpSchemaDigest').mcpSchemaDigest(tools),tools},toolName:'search_catalog',args:{query:'owned'}};
  const receipt=await protocol.callCapturedTool(invocation,client),stdout=JSON.stringify(receipt)+'\n';
  assert.deepEqual(JSON.parse(receipt.result.content[0].text).catalog,catalog);
  assert.deepEqual(readWorkerOutput(stdout,{invocation},{drained:true}),receipt);
  for(const output of [{...receipt,operationId:ids.launch},{...receipt,requestSha256:'a'.repeat(64)},
   {...receipt,resultSha256:'b'.repeat(64)},{...receipt,extra:true},{...receipt,result:{content:[]}},[],{},
   {version:1,type:'registration-destination-denied',operationId:invocation.operationId,effectNotStarted:true}])
   assert.throws(()=>readWorkerOutput(JSON.stringify(output),{invocation},{drained:true}),error=>error.code==='MCP_REGISTRY_INVOCATION_INVALID'&&error.effectNotStarted!==true);
 }finally{await Promise.allSettled([client.close(),server.close(),a.close(),b.close()]);await fs.rm(root,{recursive:true,force:true});}
});
