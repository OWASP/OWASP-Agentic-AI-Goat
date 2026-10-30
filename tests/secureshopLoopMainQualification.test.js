'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { validateUrls, budget, validateRequest, validateResponse, validateTimedResponse, closeOwned, MODEL, DIGEST } = require('./postgres/secureshopLoopMainQualification');
const makeUrls = () => Object.fromEntries([['IDENTITY','identity','identity'],['REVIEW','review','secureshop_review'],['AGENTS','agents','secureshop_agents']].flatMap(([key,label,store]) => ['MIGRATION','RUNTIME'].map(kind => [`PG_SECURESHOP_LOOP_ASSESSMENT_${key}_${kind}_URL`,`postgresql://dvaia_${store}_${kind.toLowerCase()}@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_${label}`])));
test('six exact owned URLs reject installed endpoint, wrong role, aliases and URL options', () => {
  validateUrls(makeUrls(),6543);
  for (const altered of ['postgresql://dvaia_identity_runtime@127.0.0.1:5432/owasp_ai_goat_test_secureshop_loop_identity','postgresql://postgres@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_identity','postgresql://dvaia_identity_runtime@localhost:6543/owasp_ai_goat_test_secureshop_loop_identity','postgresql://dvaia_identity_runtime@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_identity?sslmode=disable']) {
    assert.throws(() => validateUrls({...makeUrls(),PG_SECURESHOP_LOOP_ASSESSMENT_IDENTITY_RUNTIME_URL:altered},6543));
  }
});
test('wire reservation consumes failed attempts and rejects every role/aggregate overflow', () => {
  const b=budget(); for(let i=0;i<24;i++)b.reserve('actor'); assert.throws(()=>b.reserve('actor'));
  for(let i=0;i<12;i++)b.reserve('judge'); for(let i=0;i<9;i++)b.reserve('metadata');
  assert.equal(b.counts.external,45);assert.throws(()=>b.reserve('metadata'));
  for(let i=0;i<45;i++)b.incoming();assert.throws(()=>b.incoming());
});
test('only exact chat and tags allowed; arbitrary model, oversized, redirect/path and invalid JSON deny', () => {
  const body=Buffer.from(JSON.stringify({model:MODEL,messages:[{role:'user',content:'controlled'}],stream:true}));
  assert.equal(validateRequest('POST','/api/chat',body),'chat');assert.equal(validateRequest('GET','/api/tags',Buffer.alloc(0)),'metadata');
  for(const [method,url,value] of [['POST','/api/generate',body],['POST','/api/chat',Buffer.alloc(262145)],['POST','/api/chat',Buffer.from('{}')],['GET','/api/tags',body]])assert.throws(()=>validateRequest(method,url,value));
});
const returned = () => ({kind:'actor',status:200,responseComplete:true,responseCaptureTruncated:false,response:JSON.stringify({model:MODEL,done:true,done_reason:'stop',message:{content:'controlled'}})});
test('complete actual model/termination and metadata digest required', () => {
  validateResponse(returned());validateResponse({...returned(),kind:'metadata',response:JSON.stringify({models:[{name:MODEL,digest:DIGEST}]})});
  for(const delta of [{status:503},{responseComplete:false},{responseCaptureTruncated:true},{response:JSON.stringify({model:MODEL,done:true,done_reason:'length'})},{kind:'metadata',response:JSON.stringify({models:[{name:MODEL,digest:'wrong'}]})}])assert.throws(()=>validateResponse({...returned(),...delta}));
});
test('absolute deadline rejects completion before and after parsing despite delayed timer', () => {
  assert.throws(()=>validateTimedResponse(returned(),100,()=>100));
  let calls=0;assert.throws(()=>validateTimedResponse(returned(),100,()=>++calls===1?90:101));
  validateTimedResponse(returned(),100,()=>99);
});
test('physical close awaits request and socket events after server close', async () => {
  const request=new EventEmitter(),socket=new EventEmitter();let ended=0;
  request.destroy=()=>setTimeout(()=>{ended++;request.emit('close');},10);
  socket.destroy=()=>setTimeout(()=>{ended++;socket.emit('close');},20);
  await closeOwned([request,socket],[{close:cb=>cb()}],100);assert.equal(ended,2);
  const hung=new EventEmitter();hung.destroy=()=>{};await assert.rejects(closeOwned([hung],[{close:cb=>cb()}],5),/Physical close/);
});

test('persisted retrieval binds exact decoded newline body and review identity to prior selected call', () => {
  const { assertPersistedReviewObservation } = require('./postgres/secureshopLoopMainQualification');
  const expected={id:3,body:'First line\nSecond line'};
  const selected={role:'assistant',content:'',tool_calls:[{id:'read-1',type:'function',function:{name:'review-moderator.moderate_pending',arguments:'{"limit":10}'}}]};
  const result={role:'tool',tool_call_id:'read-1',content:JSON.stringify({ok:true,reviews:[expected]})};
  assert.equal(result.content.includes(expected.body),false);
  assertPersistedReviewObservation([selected,result],expected);
  const reject = messages => assert.throws(()=>assertPersistedReviewObservation(messages,expected));
  reject([{role:'user',content:expected.body}]);
  reject([selected,{...result,tool_call_id:'unselected'}]);
  reject([{...selected,tool_calls:[{...selected.tool_calls[0],function:{name:'review-moderator.approve'}}]},result]);
  reject([result,selected]);
  reject([selected,{...result,content:JSON.stringify({ok:true,reviews:[{id:4,body:expected.body}]})}]);
  reject([selected,{...result,content:JSON.stringify({ok:true,reviews:[{id:3,body:'changed'}]})}]);
  reject([selected,{...result,content:'not JSON'}]);
  reject([selected,result,result]);
});

test('frozen ad outcome distinguishes attack success from correct resistance without credit relaxation', () => {
  const { frozenAdOutcome, assertOutcomeJudgments } = require('./postgres/secureshopLoopMainQualification');
  for (const status of ['approved','rejected']) {
    const outcome=frozenAdOutcome(status);
    assert.equal(outcome.attackSucceeded,status==='approved');
    assert.equal(outcome.creditObjectives.includes('ss_content_followed'),status==='approved');
    const rows=['ss_loop_observation','ss_content_persist','ss_content_followed'].map(objective_id=>({objective_id,
      verdict:objective_id==='ss_content_followed'?outcome.followedVerdict:'pass',
      disposition:objective_id==='ss_content_followed'&&status==='rejected'?'not_pass':'awarded',result_json:{provider:'ollama'}}));
    assertOutcomeJudgments(rows,outcome);
    const wrong=structuredClone(rows);wrong[2].verdict=status==='approved'?'fail':'pass';assert.throws(()=>assertOutcomeJudgments(wrong,outcome));
    const badCredit=structuredClone(rows);badCredit[2].disposition=status==='approved'?'not_pass':'awarded';assert.throws(()=>assertOutcomeJudgments(badCredit,outcome));
  }
  assert.throws(()=>frozenAdOutcome('pending'));
});

test('registry identity initialization includes supported catalog seed before agents and lifecycle',async()=>{
  const fs=require('node:fs'),vm=require('node:vm');
  const source=fs.readFileSync(require.resolve('./postgres/secureshopLoopMainQualification'),'utf8');
  const start=source.indexOf("    await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,im);");
  const end=source.indexOf("    const templates=",start);assert.ok(start>0&&end>start);
  const calls=[],identity={},im={},agents={},am={},review={},rm={};
  const modules={
    '../../server/database/postgres/identityRepository':{initializeIdentityRepository:async(r,m)=>{assert.equal(r,identity);assert.equal(m,im);calls.push('identity');}},
    '../../server/database/postgres/workshopPlatformSeed':{seedWorkshopPlatform:async(m,...options)=>{assert.equal(m,im);assert.deepEqual(options,[]);calls.push('canonical-seed');}},
    '../../server/database/postgres/secureshopAgentsDb':{initializeSecureShopAgentsDb:async()=>calls.push('agents')},
    '../../server/database/postgres/secureshopReviewDb':{initializeSecureShopReviewDb:async()=>calls.push('review')}
  };
  await vm.runInNewContext('(async()=>{'+source.slice(start,end)+'})()',{require:id=>{assert.ok(modules[id],id);return modules[id];},identity,im,agents,am,review,rm,rendered:false});
  assert.deepEqual(calls,['identity','canonical-seed','agents','review']);
});


test('rendered profile alone requires exact fourth commerce URL pair',()=>{
 const env={...makeUrls(),PG_SECURESHOP_REGISTRY_RENDERED:'1'};
 assert.throws(()=>validateUrls(env,6543));
 for(const kind of ['RUNTIME','MIGRATION'])env['PG_SECURESHOP_LOOP_ASSESSMENT_COMMERCE_'+kind+'_URL']='postgresql://dvaia_secureshop_'+kind.toLowerCase()+'@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_commerce';
 validateUrls(env,6543);
 assert.throws(()=>validateUrls({...env,PG_SECURESHOP_LOOP_ASSESSMENT_COMMERCE_RUNTIME_URL:env.PG_SECURESHOP_LOOP_ASSESSMENT_IDENTITY_RUNTIME_URL},6543));
 validateUrls(makeUrls(),6543);
});

test('rendered registry SSE URL matches the packaged attacker listener',()=>{
 const fs=require('node:fs');
 const source=fs.readFileSync(require.resolve('./helpers/secureshopBoundAdminReadRendered'),'utf8');
 const urls=[...source.matchAll(/http:\/\/attacker\.training(?::\d+)?\/mcp/g)].map(x=>new URL(x[0]));assert(urls.length>=1);
 const listener=require('../sidecars/sandbox-runner/owned-mcp-registry/network-manifest.json').listeners.find(x=>x.id==='attacker');
 for(const url of urls){assert.equal(url.hostname,listener.hostname);assert.equal(Number(url.port||80),listener.port);assert.equal(url.pathname,'/mcp');}
});

 test('registry rendered static assets permit the opaque sandbox module bootstrap',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const source=fs.readFileSync(require.resolve('./helpers/secureshopBoundAdminReadRendered'),'utf8');
 const branch=source.slice(source.indexOf('async function qualifyRegistryControlPlaneRendered'));
 const statement=branch.match(/app\.use\(express\.static\(build[^;]+;/)[0];
 let options;const middleware={};
 vm.runInNewContext(statement,{build:'/owned/build',express:{static:(root,opts)=>{assert.equal(root,'/owned/build');options=opts;return middleware;}},app:{use:value=>assert.equal(value,middleware)}});
 const headers={};assert.equal(typeof options?.setHeaders,'function');options.setHeaders({set:(name,value)=>headers[name]=value});
 assert.deepEqual(headers,{'Access-Control-Allow-Origin':'*'});
 // Compiled module output is asserted by the owned production-build browser suite.
 const html=fs.readFileSync('client/secureshop-frame.html','utf8');assert.match(html,/<script type="module" src="\/src\/pages\/secureshop\/frameEntry\.jsx"><\/script>/);
 });

test('registry pointer action denies occlusion and performs one physical click only',async()=>{
 const {registryPhysicalClick}=require('./helpers/secureshopBoundAdminReadRendered');
 for(const hit of [true,false]){let evaluations=0,clicks=0,disposed=0;const diagnostic={};const button={evaluate:async()=>++evaluations===3?{hitTarget:hit,contains:hit}:undefined,click:async()=>{clicks++;},dispose:async()=>{disposed++;}};
 if(hit)await registryPhysicalClick(button,diagnostic);else await assert.rejects(registryPhysicalClick(button,diagnostic),/pointer hit target/);
 assert.equal(clicks,hit?1:0);assert.equal(disposed,1);assert.equal(diagnostic.hitTarget,hit);}
});


test('registered invocation result oracle follows actual HTTP/SSE and stdio peer shapes',()=>{
 const {assertRegistryInvocationResult:verify}=require('./postgres/secureshopLoopMainQualification');
 const catalog=[{id:'owned-product-42',title:'Synthetic training item',priceCents:4200}];
 const sdk=body=>({content:[{type:'text',text:JSON.stringify(body)}]});
 for(const transport of ['sse','streamable-http']){
  verify(transport,{query:'owned'},sdk({peer:'attacker',query:'owned',catalog}));
  assert.throws(()=>verify(transport,{query:'owned'},sdk({peer:'attacker',query:'foreign',catalog})));
  assert.throws(()=>verify(transport,{query:'owned'},sdk({peer:'benign',query:'owned',catalog})));
 }
 verify('stdio',{},sdk(catalog));assert.throws(()=>verify('stdio',{},sdk({catalog})));
 assert.throws(()=>verify('stdio',{},sdk([{...catalog[0],id:'foreign'}])));
});

test('registered admin wire profile admits only bounded actual structured decisions',()=>{
 const T=require('./postgres/finflowBackupBrowserActualTransport'),p=T.transportProfile('secureshop-registry-admin-chat');
 assert.equal(p.chat,4);assert.equal(p.external,5);assert.equal(p.generate,0);
 const body={model:T.MODEL,stream:true,options:{temperature:0,num_predict:2048},format:require('../server/services/secureshop/providers/ollamaProvider').DECISION_SCHEMA,messages:[{role:'user',content:'owned'}]};
 assert.equal(T.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(body)),p),'chat');
 for(const change of [x=>x.model='other',x=>x.options.num_predict=2049,x=>x.options.temperature=1,x=>x.format={type:'object'}]){const x=structuredClone(body);change(x);assert.throws(()=>T.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(x)),p));}
 assert.throws(()=>T.validateRequest('POST','/api/generate',Buffer.from(JSON.stringify(body)),p));
 const b=T.budget(p);b.reserve('tags');for(let i=0;i<4;i++)b.reserve('chat');assert.throws(()=>b.reserve('chat'));assert.throws(()=>b.reserve('generate'));
 assert.equal(T.transportProfile('mcp-mounted-http').chat,30);
});
test('registry role wire admits actual closed tool and answer-only provider serialization without widening historical chat',async t=>{
 const http=require('node:http'),T=require('./postgres/finflowBackupBrowserActualTransport');
 const metadata=T.transportProfile('secureshop-registry-role-chat');
 assert.equal(metadata.ids.length,11);assert.equal(metadata.ids[8],'registry-role-9');
 assert.equal(metadata.chat,53);assert.equal(metadata.tags,359);assert.equal(metadata.metadata,359);
 assert.equal(metadata.external,412);assert.equal(metadata.tags,1+(1+Math.ceil(metadata.overallMs/5000))+metadata.chat+4);
 const budget=T.budget(metadata);
 for(let i=0;i<metadata.tags;i++)budget.reserve('tags');
 assert.throws(()=>budget.reserve('tags'));assert.throws(()=>budget.reserve('version'));
 for(let i=0;i<metadata.chat;i++)budget.reserve('chat');
 assert.throws(()=>budget.reserve('chat'));assert.throws(()=>budget.reserve('generate'));
 assert.equal(T.transportProfile('secureshop-registry-admin-chat').tags,1);
 const {OllamaProvider,DECISION_SCHEMA,FINAL_RESPONSE_SCHEMA}=require('../server/services/secureshop/providers/ollamaProvider');
 const {WORKFLOW_ROUTE_SCHEMA}=require('../server/agent-runtime/providers/workflowRouteContract');
 const requests=[],expected=[];
 const server=http.createServer(async(request,response)=>{
  let body='';for await(const chunk of request)body+=chunk;
  requests.push(Buffer.from(body));
  response.writeHead(200,{'content-type':'application/x-ndjson'});
  response.end(JSON.stringify({model:T.MODEL,message:{role:'assistant',content:JSON.stringify(requests.length===1
   ?{route:'management'}:requests.length===2
    ?{tool_calls:[{agent:'admin',tool:'policies_search',args:{search:'owned'}}]}
    :requests.length===3?{answer:'Observed result.'}:{reply:'Registered answer.'})},
   done:true,prompt_eval_count:8,eval_count:4})+'\n');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const provider=new OllamaProvider({baseUrl:`http://127.0.0.1:${server.address().port}`});
 const original=provider.transport.chat.bind(provider.transport);
 provider.transport.chat=async(messages,tools,options)=>{
  expected.push({phase:['routeWorkflow','chat','finalResponse','chat'][expected.length],
   format:structuredClone(options.format),numPredict:options.num_predict,
   messages:messages.map(({role,content})=>({role,content})),accepted:0});
  return original(messages,tools,options);
 };
 const tools=[{agent:'admin',tool:'policies_search',inputSchema:{type:'object',properties:{search:{type:'string'}},required:['search'],additionalProperties:false}}];
 const route=await provider.routeWorkflow({system:'Classify current admin request',
  messages:[{role:'user',content:'Find owned'}],max_tokens:128});
 assert.equal(route.decision.route,'management');assert.equal(route.usage.attempts,1);
 await provider.chat({system:'Role task',messages:[{role:'user',content:'Find owned'}],tools,
  closedToolCatalog:true,maxToolCalls:1,max_tokens:256});
 await provider.finalResponse({system:'Role task',messages:[{role:'user',content:'Answer'}],max_tokens:128});
 await provider.chat({system:'Registered task',messages:[{role:'user',content:'Answer'}],tools:[],max_tokens:256});
 const profile=T.transportProfile('secureshop-registry-role-chat');
 assert.equal(requests.length,4);
 assert.deepEqual(expected[0].format,WORKFLOW_ROUTE_SCHEMA);
 assert.equal(expected[0].numPredict,128);
 assert.deepEqual(expected[1].format.oneOf[1].properties.tool_calls.items.oneOf[0].properties.args,tools[0].inputSchema);
 assert.equal(expected[1].format.oneOf[1].properties.tool_calls.maxItems,1);
 assert.deepEqual(expected[2].format,FINAL_RESPONSE_SCHEMA);
 assert.deepEqual(expected[3].format,DECISION_SCHEMA);
 for(let i=0;i<4;i++)assert.equal(T.validateRequest('POST','/api/chat',requests[i],
  {...profile,roleWire:i<3?expected[i]:null}),'chat');
 assert.equal(expected[0].accepted,1);assert.equal(expected[1].accepted,1);assert.equal(expected[2].accepted,1);
 for(const change of [body=>{body.format=DECISION_SCHEMA},body=>{body.options.num_ctx=4096},
  body=>{body.options.num_predict=257},body=>{body.messages[0].content='different'}]){
  const changed=JSON.parse(requests[0]);change(changed);
  assert.throws(()=>T.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(changed)),
   {...profile,roleWire:{...expected[0],accepted:0}}));
 }
 assert.throws(()=>T.validateRequest('POST','/api/chat',requests[0],
  T.transportProfile('secureshop-registry-admin-chat')));
});
test('registry role fixture wrapper sends its captured closed schema through actual SDK HTTP serialization',async t=>{
 const fs=require('node:fs'),http=require('node:http');
 const {createRequire}=require('node:module'),T=require('./postgres/finflowBackupBrowserActualTransport');
 const fixture=require.resolve('./helpers/secureshopBoundAdminReadRendered');
 const source=fs.readFileSync(fixture,'utf8');
 const start=source.indexOf(' const roleCalls=[];',source.indexOf('async function qualifyRegistryRoleChatRendered'));
 const end=source.indexOf(' const registered=',start);assert(start>0&&end>start);
 const bodies=[],expected=[],denied=[];const server=http.createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;bodies.push(Buffer.from(body));
  try{T.validateRequest(req.method,req.url,bodies.at(-1),
   {...T.transportProfile('secureshop-registry-role-chat'),roleWire:expected.at(-1)})}
  catch(error){denied.push(error);res.writeHead(503).end();return}
  res.writeHead(200,{'content-type':'application/x-ndjson'});
  res.end(JSON.stringify({model:T.MODEL,message:{role:'assistant',content:JSON.stringify(bodies.length===1
   ?{route:'management'}:bodies.length===2
    ?{tool_calls:[{agent:'admin',tool:'policies_search',args:{search:'owned'}}]}
    :{answer:'Grounded final response.'})},done:true,prompt_eval_count:8,eval_count:4})+'\n');
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>new Promise(resolve=>server.close(resolve)));
 const modelTransport={actorUrl:`http://127.0.0.1:${server.address().port}`,
  beginRoleWire(value){const item={...structuredClone(value),accepted:0};expected.push(item);return item},
  endRoleWire(item){assert.equal(item.accepted,1)}};
 const wireRequire=createRequire(fixture);
 const instantiate=new Function('require','assert','modelTransport','AbortSignal','structuredClone','Buffer',
  'return (async()=>{'+source.slice(start,end)+' return {provider,roleCalls};})()');
 const {provider,roleCalls}=await instantiate(wireRequire,assert,modelTransport,AbortSignal,structuredClone,Buffer);
 const tools=[{agent:'admin',tool:'policies_search',inputSchema:{type:'object',properties:{search:{type:'string'}},required:['search'],additionalProperties:false}}];
 await provider.routeWorkflow({system:'Classify current admin request',
  messages:[{role:'user',content:'Find owned'}],max_tokens:128});
 await provider.chat({system:'Role task',messages:[{role:'user',content:'Find owned'}],tools,
  closedToolCatalog:true,maxToolCalls:1,max_tokens:256});
 await provider.finalResponse({system:'Role task',messages:[{role:'user',content:'Answer'}],max_tokens:128});
 assert.deepEqual(denied,[]);assert.equal(bodies.length,3);
 assert.deepEqual(roleCalls.map(item=>item.method),['routeWorkflow','chat','finalResponse']);
});
test('registry transport rejection diagnostic records structural hashes and assertion location only',()=>{
 const T=require('./postgres/finflowBackupBrowserActualTransport');
 const error=Object.assign(Error('private-secret'),{code:'ERR_ASSERTION'});
 error.stack='Error: private-secret\n    at validateRequest (/private/path/finflowBackupBrowserActualTransport.js:81:4)';
 const body=Buffer.from(JSON.stringify({model:T.MODEL,format:{private:'private-secret'},
  options:{num_ctx:8192,num_predict:256,temperature:0,'private-secret-option':1},
  messages:[{role:'user',content:'private-secret'}],stream:true,'private-secret-key':1}));
 const row=T.registryRoleRejection(error,{method:'POST',url:'/api/chat?private-secret',body,
  roleWire:{format:{private:'other-secret'},messages:[{role:'user',content:'other-secret'}],numPredict:256,accepted:0},activeCase:'registry-role-1'});
 assert.deepEqual(row.assertionFrame,{file:'finflowBackupBrowserActualTransport.js',line:81,column:4});
 assert.equal(row.request.path,'other');assert.equal(row.request.numCtx,8192);
 assert.equal(row.request.unknownKeys,1);assert.equal(row.request.unknownOptionKeys,1);
 assert.equal(row.request.formatSha256.length,64);assert.equal(row.expected.messagesSha256.length,64);
 assert(!JSON.stringify(row).includes('secret'));
});
test('registry rendered wait fails promptly on captured transport rejection without inventing completion',async()=>{
 const fs=require('node:fs'),source=fs.readFileSync(require.resolve('./helpers/secureshopBoundAdminReadRendered'),'utf8');
 const start=source.indexOf('  const wait=async(predicate,label,timeout=120000)',
  source.indexOf('async function qualifyRegistryRoleChatRendered'));
 const end=source.indexOf('  const latestRole=',start);assert(start>0&&end>start);
 const modelTransport={snapshot:()=>({failures:[{code:'REQUEST_DENIED_OR_INCOMPLETE'}]})};
 const wait=new Function('modelTransport',source.slice(start,end)+' return wait;')(modelTransport);
 let read=false;await assert.rejects(wait(async()=>{read=true;return true},'controlled',10000),
  {code:'REGISTRY_ROLE_WIRE_REJECTED'});
 assert.equal(read,false);
});

test('actual registry opt-in registers only registry hook; never the review/Judge assessment',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const source=fs.readFileSync(require.resolve('./postgres/secureshopLoopAssessment.integration.test'),'utf8');
 const env={PG_TEST_DISPOSABLE:'yes',PG_SECURESHOP_REGISTRY_CONTROL_PLANE:'1',PG_SECURESHOP_REGISTRY_RENDERED:'1',PG_SECURESHOP_REGISTRY_ACTUAL_CHAT:'1',LIVE_OLLAMA_TEST:'0',...makeUrls()};
 for(const live of ['0','1']){
  const registered=[];vm.runInNewContext(source,{process:{env:{...env,LIVE_OLLAMA_TEST:live}},require:id=>id==='node:test'?(name,options,callback)=>registered.push({name,options,callback}):{},module:{exports:{}},Buffer});
  assert.deepEqual(registered.map(x=>x.name),[
   'historical loop cohort selector is closed and exact',
   'actual SecureShop review loop records attack outcome, canonical credit and provenance negatives',
   'main owned registry control plane uses real isolated SDK transport and canonical authority',
   'standalone admin prepares and confirms owned MCP registry changes, then uses the registered tools assistant with real local llama3.1:8b'
  ]);
  const review=registered[1],registry=registered[2];
  assert.equal(typeof registered[0].options,'function'); // Pure selector unit test, no native hook.
  assert.equal(review.options.skip,live==='0');assert.equal(registry.options.skip,false);
  assert.equal(registered[3].options.skip,true);
  if(live==='0')assert.deepEqual(registered.filter(x=>typeof x.options==='object'&&!x.options.skip).map(x=>x.name),['main owned registry control plane uses real isolated SDK transport and canonical authority']);
 }
 const parent=fs.readFileSync('tests/postgres/run-secureshop-loop-assessment-isolated.py','utf8');
 const optin=parent.match(/if args.registry_actual_chat:env\.update\(([^\n]+)\)/)[1];assert.equal(optin,"PG_SECURESHOP_REGISTRY_ACTUAL_CHAT='1'");
});

test('registry failure request diagnostics exclude query credentials and unrelated routes',()=>{
 const {registryRequestDiagnostic:d}=require('./helpers/secureshopBoundAdminReadRendered');
 assert.deepEqual(d('POST','http://owned/api/secureshop/admin/mcp/register?token=secret',403),{method:'POST',path:'/api/secureshop/admin/mcp/register',status:403});
 assert.equal(d('GET','http://owned/api/auth/login?token=secret',200),null);
 assert.equal(d('GET','http://owned/api/secureshop/admin/mcp/arbitrary-secret',200),null);
 assert.equal(d('POST','invalid',200),null);
 assert.deepEqual(d('POST','http://owned/api/secureshop/agents/admin/chat?secret=hidden',200),{method:'POST',path:'/api/secureshop/agents/admin/chat',status:200});
});

test('actual chat waits for real toast retirement before reserving case or physical Send',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),source=fs.readFileSync(require.resolve('./helpers/secureshopBoundAdminReadRendered'),'utf8');
 const start=source.indexOf("   await frame.waitForSelector('.ss-toast-stack .ss-toast'");const end=source.indexOf('   await frame.waitForFunction',start);assert(start>0&&end>start);
 let retire;const events=[];const work=vm.runInNewContext('(async()=>{'+source.slice(start,end)+'})()',{frame:{waitForSelector:async(selector,options)=>{assert.equal(selector,'.ss-toast-stack .ss-toast');assert.equal(options.hidden,true);events.push('wait');await new Promise(resolve=>retire=resolve);}},actualChat:{begin:()=>events.push('begin')},clickSelector:async selector=>{assert.equal(selector,'[data-testid="agent-lane"] button[type="submit"]');events.push('physical-click');}});
 await Promise.resolve();assert.deepEqual(events,['wait']);retire();await work;assert.deepEqual(events,['wait','begin','physical-click']);
});

test('actual provider capture omits signal and serializes with the real bounded writer',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),source=fs.readFileSync(require.resolve('./postgres/secureshopLoopMainQualification'),'utf8');
 const begin=source.indexOf('async chat(input){const output=await provider.chat(input);');
 const end=source.indexOf('}},',begin);assert(begin>0&&end>begin);
 const body=source.slice(begin+'async chat(input){'.length,end),output={provider:'ollama',mocked:false,response:'owned'},calls=[];
 const input={system:'owned',messages:[{role:'user',content:'owned'}],tools:[],role:'admin',max_tokens:2048,signal:new AbortController().signal,ownerId:7};
 const directory=fs.mkdtempSync(require('node:path').join(require('node:os').tmpdir(),'registry-capture-control-')),file=require('node:path').join(directory,'capture.json');
 try{
  const value=await vm.runInNewContext('(async()=>{'+body+'})()',{input,provider:{chat:async actual=>{assert.equal(actual,input);return output;}},calls,observations:[],structuredClone,checkpoint:data=>require('./fixtures/boundedJsonArtifact').saveBounded(file,data)});
  assert.equal(value,output);assert.equal(Object.hasOwn(calls[0].input,'signal'),false);
  const parsed=JSON.parse(fs.readFileSync(file,'utf8'));assert.equal(parsed.calls[0].input.max_tokens,2048);assert.deepEqual(parsed.calls[0].output,output);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('populated upgrade URLs admit only extra owned database and canonical role pair',()=>{
 const env={...makeUrls(),PG_SECURESHOP_REGISTRY_INVOCATION_UPGRADE:'1'};
 assert.throws(()=>validateUrls(env,6543));
 for(const kind of ['RUNTIME','MIGRATION'])env['PG_SECURESHOP_LOOP_ASSESSMENT_UPGRADE_'+kind+'_URL']='postgresql://dvaia_secureshop_agents_'+kind.toLowerCase()+'@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_agents_upgrade';
 validateUrls(env,6543);
 for(const value of ['postgresql://dvaia_secureshop_agents_runtime@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_agents','postgresql://dvaia_upgrade_runtime@127.0.0.1:6543/owasp_ai_goat_test_secureshop_loop_agents_upgrade'])assert.throws(()=>validateUrls({...env,PG_SECURESHOP_LOOP_ASSESSMENT_UPGRADE_RUNTIME_URL:value},6543));
});

test('replacement publication changes only attested digest and preserves disabled configuration',()=>{
 const {assertReplacementPublication}=require('./postgres/secureshopLoopMainQualification');
 const before={version:1,workspace:'owned',enabled:false,baseURL:'http://127.0.0.1:12345',token:'private-token',runtimeDigest:'a'.repeat(64),mode:'vuln'};
 const next={...before,runtimeDigest:'b'.repeat(64)};assertReplacementPublication(before,next,next.runtimeDigest);
 for(const delta of [{enabled:true},{token:'replaced'},{baseURL:'http://127.0.0.1:8095'},{mode:'fixed'},{runtimeDigest:'c'.repeat(64)}])assert.throws(()=>assertReplacementPublication(before,{...next,...delta},next.runtimeDigest));
});
