'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const{randomUUID}=require('node:crypto');
const{createV11ReferenceTracker,createV11HttpCounters,createV11ActualAssembler}=require('./secureshopMailAgentReadRenderedAssembler');
function fixture(overrides={}){const sql=[];const pool={query:async(text,args)=>{sql.push({text,args});return{rows:[{n:0}]};}};const frame={};const value={page:{waitForRequest(){},waitForResponse(){}},reacquireFrame:()=>frame,requestFrame:frame,origin:'http://127.0.0.1:8081',scope:{platformOwnerId:41,platformSessionId:42,launchId:randomUUID(),scenarioId:randomUUID(),generation:0},principal:{tenantId:randomUUID(),principalId:randomUUID()},persona:{id:3},personaSession:{id:randomUUID()},pools:{IDENTITY_RUNTIME:pool,AGENTS_RUNTIME:pool,AGENTS_MIGRATION:pool},composition:{roleAssistants:{merchant:{mailAgentReadAssessment:{assertRetainedPacket(){}},runtime:{readRequest(){}}}}},transport:{calls:[]},judgeResults:new Map(),capture:{transcripts:[]},requestLog:[],headers:{authorization:'Bearer owner','x-owasp-ai-goat-secureshop-launch':'opaque-owner-capability'},siblingHeaders:{authorization:'Bearer sibling','x-owasp-ai-goat-secureshop-launch':'opaque-sibling-capability'},targetId:randomUUID(),siblingScope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1},siblingPersona:{id:9},siblingPersonaSession:{sessionId:randomUUID(),authorityVersion:'1'},readAssessmentReference:async()=>null,fixtureLocalCandidateAdmission:true,recoveryAuthority:{arm:()=>true,authorize:async()=>({authorization:'Bearer owner','x-owasp-ai-goat-secureshop-launch':'opaque-owner-capability'})},...overrides};return{value,sql};}
test('assembler constructs against installed composition and initializes exact real count schema',async()=>{const f=fixture();const assembled=createV11ActualAssembler(f.value);let supplied=null;await assembled.run(async input=>{supplied=input.v11;});assert.equal(supplied,assembled.lifecycle);assert(f.sql.some(row=>row.text.includes("agent_trace WHERE kind='local_tool_call'")));assert(f.sql.some(row=>row.text.includes('graph_runtime.effects')));assert(f.sql.some(row=>row.text.includes('assessment_judgments')));const contributionQueries=f.sql.filter(row=>row.text.includes('assessment_contributions'));assert(contributionQueries.length>=1);for(const row of contributionQueries){assert(!/c\.(?:objective_id|generation)/.test(row.text));assert(row.text.includes('assessment_judgments j'));assert(row.text.includes('j.objective_id'));}assert(f.sql.some(row=>row.text.includes('assessment_completions')));assert(f.sql.some(row=>row.text.includes("lab_mail_operation_receipts WHERE action='read'")));assert(f.sql.every(row=>!row.text.includes('lab_mail_messages')));assert(f.sql.every(row=>!row.text.includes('INSERT ')&&!row.text.includes('UPDATE ')&&!row.text.includes('DELETE ')));});
test('assembler rejects non-UUID or scope-derived principal and requires UUID mail target',()=>{let f=fixture();assert.throws(()=>createV11ActualAssembler({...f.value,principal:{tenantId:String(f.value.scope.platformOwnerId),principalId:randomUUID()}}));f=fixture();assert.throws(()=>createV11ActualAssembler({...f.value,targetId:1}));});
test('assembler requires real installed assessment and runtime APIs',()=>{const f=fixture();assert.throws(()=>createV11ActualAssembler({...f.value,composition:{roleAssistants:{merchant:{}}}}));});

test('assembler binds sibling evidence to exact UUID persona session rather than shared target content',()=>{const source=require('node:fs').readFileSync(require.resolve('./secureshopMailAgentReadRenderedAssembler'),'utf8');assert.match(source,/bound_persona_sessions s WHERE session_id=\$1 AND platform_launch_id=\$2/);assert.match(source,/sharedTargetMessages/);assert.doesNotMatch(source,/siblingTargetId/);});

test('all raw contribution queries join judgment for objective instead of reading absent raw columns',()=>{const source=require('node:fs').readFileSync(require.resolve('./secureshopMailAgentReadRenderedAssembler'),'utf8');for(const fragment of source.split('assessment_contributions').slice(1)){const query=fragment.slice(0,fragment.indexOf('`'));assert(!/c\.(?:objective_id|generation)/.test(query));}assert.match(source,/assessment_contributions c JOIN secureshop_auth\.assessment_judgments j/);});

test('request-time persisted reference becomes the sole assembler counter and owner-query identity',async()=>{const first={version:1,shopUserId:7,sessionId:randomUUID(),requestId:randomUUID(),startedAt:12},values=[null,first,{...first}],tracker=createV11ReferenceTracker(async()=>values.shift());assert.equal(await tracker.read(),null);assert.equal(tracker.ids(),null);assert.deepEqual(await tracker.read(),first);assert.deepEqual(tracker.ids(),{sessionId:first.sessionId,requestId:first.requestId});assert.deepEqual(await tracker.read(),first);const source=require('node:fs').readFileSync(require.resolve('./secureshopMailAgentReadRenderedAssembler'),'utf8');assert.match(source,/createV11AssessmentActions\(\{[^}]*readAssessmentReference:trackedReference\.read/);assert.match(source,/readReference:trackedReference\.read/);assert.ok((source.match(/trackedReference\.ids\(\)/g)||[]).length>=1);assert.match(source,/getIds:trackedReference\.ids/);const changed={...first,requestId:randomUUID()};const drift=createV11ReferenceTracker(async()=>changed);await drift.read();changed.requestId=randomUUID();await assert.rejects(()=>drift.read(),/identity changed/);});


test('HTTP counters bind exact opaque launch capabilities and reject wrong token or launch',()=>{const ids={sessionId:randomUUID(),requestId:randomUUID()},scope={launchId:randomUUID()},siblingScope={launchId:randomUUID()},ownerLaunch=`opaque-owner-${randomUUID()}`,siblingLaunch=`opaque-sibling-${randomUUID()}`,headers={authorization:'Bearer owner','x-owasp-ai-goat-secureshop-launch':ownerLaunch},siblingHeaders={authorization:'Bearer sibling','x-owasp-ai-goat-secureshop-launch':siblingLaunch},assess='/agents/merchant/assistant/mail-read/assess',source=`/agents/merchant/assistant/operations/${ids.sessionId}/${ids.requestId}`,saved=`/agents/merchant/assistant/mail-read/assessment/${ids.sessionId}/${ids.requestId}`,row=(method,path,status,auth,launch,body)=>({method,path,status,authorization:auth,launch,...(body?{body}:{})}),body={sessionId:ids.sessionId,requestId:ids.requestId},requestLog=[row('POST',assess,200,headers.authorization,ownerLaunch,body),row('GET',saved,200,headers.authorization,ownerLaunch),row('GET',source,401,siblingHeaders.authorization,siblingLaunch),row('GET',source,403,siblingHeaders.authorization,siblingLaunch),row('POST',assess,401,siblingHeaders.authorization,siblingLaunch,body),row('GET',source,401,headers.authorization,ownerLaunch),row('GET',saved,401,headers.authorization,ownerLaunch),row('POST',assess,200,'Bearer wrong',ownerLaunch,body),row('GET',saved,200,headers.authorization,`wrong-${ownerLaunch}`),row('GET',saved,200,'Bearer wrong',ownerLaunch)];const args={requestLog,headers,siblingHeaders,scope,siblingScope,getIds:()=>ids},read=createV11HttpCounters(args),expected={assessmentPosts:1,savedAssessmentGets:1,deniedAssessmentPosts:1,deniedSourceGets:3,deniedSavedAssessmentGets:1};assert.deepEqual(read(),expected);const renewed={authorization:'Bearer renewed','x-owasp-ai-goat-secureshop-launch':'opaque-renewed'};assert.equal(read.registerOwner(renewed),true);requestLog.push(row('GET',saved,200,renewed.authorization,renewed['x-owasp-ai-goat-secureshop-launch']));assert.equal(read().savedAssessmentGets,2);requestLog.pop();assert.equal(read.registerOwner(renewed),true);assert.equal(read.registerOwner(headers),true);assert.deepEqual(read(),expected);assert.throws(()=>createV11HttpCounters({...args,headers:{authorization:'Bearer owner'}}));requestLog.push(row('POST',assess,401,siblingHeaders.authorization,siblingLaunch,{...body,extra:true}));assert.deepEqual(read(),expected);requestLog.pop();for(const failure of [row('GET',source,500,siblingHeaders.authorization,siblingLaunch),row('POST',assess,503,siblingHeaders.authorization,siblingLaunch,body),row('GET',saved,500,headers.authorization,ownerLaunch)]){requestLog.push(failure);assert.throws(read,/server error/);requestLog.pop();}});

function renewalFixture() {
  const { createV11RecoveryAuthority } = require('./secureshopMailAgentReadRenderedScenario');
  const scope = { launchId:randomUUID(), scenarioId:randomUUID(), generation:2, platformOwnerId:41, platformSessionId:42 };
  const principal = { tenantId:randomUUID(), principalId:randomUUID() };
  const persona = { id:3, role:'merchant' };
  const personaSession = { sessionId:randomUUID(), authorityVersion:7 };
  const headers = { authorization:'Bearer original-token', 'x-owasp-ai-goat-secureshop-launch':'opaque-capability' };
  const state = {
    scope:{...scope}, actor:{user:{...persona},sessionId:personaSession.sessionId,authorityVersion:7},
    canonical:{...principal,ownerId:41,shopUserId:3}, browserBootstraps:[], calls:[]
  };
  const composition = {
    launches:{resolveCapability:async value => (state.calls.push(['launch',value]),state.scope)},
    personaAuth:{authenticateBoundToken:async value => (state.calls.push(['persona',value]),state.actor)}
  };
  const auth = { establishTenantContext:async value => (state.calls.push(['principal',value]),state.canonical) };
  const authority = createV11RecoveryAuthority({composition,auth,systemAuthByLaunch:new Map([[scope.launchId,{trusted:true}]]),
    browserBootstraps:state.browserBootstraps,username:'merchant',scope,persona,personaSession,principal});
  return {scope,headers,state,authority,addBootstrap(value=headers){
    state.browserBootstraps.push({username:'merchant',authorization:value.authorization,launch:value['x-owasp-ai-goat-secureshop-launch']});
  }};
}
for (const refreshed of [false,true]) test(`same-session recovery accepts ${refreshed?'refreshed':'identical'} JWT bytes and counts each physical GET once`,async()=>{
  const f=renewalFixture(), ids={sessionId:randomUUID(),requestId:randomUUID()}, requestLog=[];
  const siblingHeaders={authorization:'Bearer sibling','x-owasp-ai-goat-secureshop-launch':'opaque-sibling'};
  const read=createV11HttpCounters({requestLog,headers:f.headers,siblingHeaders,scope:f.scope,siblingScope:{launchId:randomUUID()},getIds:()=>ids});
  const renewed={...f.headers,authorization:refreshed?'Bearer refreshed-token':f.headers.authorization};
  // A prior bootstrap cannot satisfy the single post-reload observation.
  f.addBootstrap(); f.authority.arm(); f.addBootstrap(renewed);
  const validated=await f.authority.authorize({headers:()=>renewed});
  assert.deepEqual(validated,renewed);
  assert.deepEqual(f.state.calls.map(row=>row[0]),['launch','persona','principal']);
  assert.equal(read.registerOwner(validated),true);
  assert.equal(read.registerOwner(validated),true);
  requestLog.push({method:'GET',path:`/agents/merchant/assistant/mail-read/assessment/${ids.sessionId}/${ids.requestId}`,
    status:200,authorization:renewed.authorization,launch:renewed['x-owasp-ai-goat-secureshop-launch']});
  assert.equal(read().savedAssessmentGets,1);
  assert.equal(read.registerOwner(f.headers),true);
  assert.equal(read().savedAssessmentGets,1);
});
for (const [name,mutate] of [
  ['launch',f=>f.state.scope.launchId=randomUUID()],
  ['scenario',f=>f.state.scope.scenarioId=randomUUID()],
  ['generation',f=>f.state.scope.generation++],
  ['zero launch generation',f=>f.state.scope.generation=0],
  ['platform owner',f=>f.state.scope.platformOwnerId++],
  ['platform session',f=>f.state.scope.platformSessionId++],
  ['persona',f=>f.state.actor.user.id++],
  ['role',f=>f.state.actor.user.role='admin'],
  ['authority version',f=>f.state.actor.authorityVersion++],
  ['different persona session',f=>f.state.actor.sessionId=randomUUID()],
  ['principal',f=>f.state.canonical.principalId=randomUUID()],
  ['tenant',f=>f.state.canonical.tenantId=randomUUID()],
  ['canonical owner',f=>f.state.canonical.ownerId++],
  ['canonical persona',f=>f.state.canonical.shopUserId++],
  ['absent bootstrap',f=>f.state.browserBootstraps.length=0],
  ['duplicate bootstrap',f=>f.addBootstrap()],
  ['wrong bootstrap credential',f=>f.state.browserBootstraps[0].authorization='Bearer other'],
  ['wrong bootstrap launch',f=>f.state.browserBootstraps[0].launch='opaque-other']
]) test(`recovery rejects ${name} before credential registration`,async()=>{
  const f=renewalFixture();f.authority.arm();f.addBootstrap();mutate(f);
  let registered=false;
  await assert.rejects(async()=>{await f.authority.authorize({headers:()=>f.headers});registered=true;});
  assert.equal(registered,false);
});

test('assembler requires and propagates exact candidate-admission boolean',async()=>{
 const missing=fixture();delete missing.value.fixtureLocalCandidateAdmission;assert.throws(()=>createV11ActualAssembler(missing.value));
 for(const value of [true,false]){const f=fixture({fixtureLocalCandidateAdmission:value}),assembled=createV11ActualAssembler(f.value);assert.equal(assembled.lifecycle.fixtureLocalCandidateAdmission,value);}
});
