'use strict';
// Controlled graph/authority regression only; never actual-model qualification.
const test=require('node:test'),assert=require('node:assert/strict');
const {createOriginalRegistrationRuntime}=require('../server/services/secureshopOriginalRegistrationRuntime');
const {createBoundTurns}=require('../server/services/secureshopBoundTurns');
const {withEffectAdmission,currentEffectAdmission}=require('../server/agent-runtime/effectAdmissionContext');
const {buildBasePrompt}=require('../server/services/secureshop/supervisors/basePrompt');
const {createAdminSupervisor,adminSupervisor,MAX_STEPS}=require('../server/services/secureshop/supervisors/adminSupervisor');
const scope={launchId:'11111111-1111-4111-8111-111111111111',scenarioId:'22222222-2222-4222-8222-222222222222',generation:1,platformOwnerId:1,platformSessionId:2};
const sessionId='33333333-3333-4333-8333-333333333333',requestId='44444444-4444-4444-8444-444444444444',runId='55555555-5555-4555-8555-555555555555';
const persona={id:3,role:'admin'},personaSession={sessionId:'66666666-6666-4666-8666-666666666666',authorityVersion:'1'};
const args={name:'owned-fixture',transport:'stdio',stdio_cmd:'original exact command --test'};
function policies(t){const pools=require('../server/database/postgres/secureshopPools'),original=pools.getCommercePool;
 pools.getCommercePool=()=>({async query(){return{rows:[{name:'Original policy',markdown_source:'literal policy text',injected_into_json:'["admin"]'}]};}});
 t.after(()=>{pools.getCommercePool=original;});}
function setup(t,fault={}){
 policies(t);const calls=[],messages=[],traces=[],claims=new Map(),records=new Map();let tokens=0;
 const conversations={async assertOwned(id,binding,p){if(fault.revoked||id!==sessionId||binding.platformOwnerId!==1||binding.platformSessionId!==2||binding.generation!==1||p.id!==3)throw Error('owner/session retired');},async getMessages(){return structuredClone(messages);}};
 const repository={async appendMessage(_id,_binding,m){messages.push(structuredClone(m));},async getTokens(){return tokens;},async addTokens(_id,_binding,n){tokens+=n;},async appendTraces(_id,_binding,rows){traces.push(...rows);}};
 const identity={runId,ownerKey:'owned-original-registration',generation:1,durableGeneration:'1'};
 const coordinator={async run(_id,options,work){const admitted=await options.admit();if(admitted.skip)return admitted.value;
  return work({...identity,async check(){if(fault.revoked)throw Error('retired');},async effectWithReceipt(key,callback){const effectKey=requestId+':'+key;
   const value=await withEffectAdmission(identity,effectKey,callback);return{value,receipt:{version:1,...identity,generation:'1',effectKey,status:'completed'}};}});}};
 const turns=createBoundTurns({conversations,coordinator});
 const journal={async claim({requestId}){if(claims.has(requestId))return claims.get(requestId);const r={status:'claimed',claimId:requestId};claims.set(requestId,{status:'started',claimId:requestId});return r;},
  async complete({requestId,result}){calls.push('complete');claims.set(requestId,{status:'completed',result:structuredClone(result)});},async markUncertain({requestId}){if(claims.get(requestId)?.status!=='completed')claims.set(requestId,{status:'uncertain'});}};
 const registrationJournal={prepare(envelope,execution){calls.push('prepare');const record={envelope:{...envelope,effectKey:currentEffectAdmission(execution).ledgerEffectKey}};records.set(envelope.request.operationId,record);return record;},
  identity(h){return{instanceId:h.envelope.instanceId,operationId:h.envelope.request.operationId,requestSha256:h.envelope.requestSha256};},async admitPrepared(){},
  async settlePrepared(h,{receipt,status,notDispatched}){h.receipt=receipt||status;return{drained:notDispatched||h.receipt?.drained===true};},
  async readCompleted({operationId}){const r=records.get(operationId);if(fault.badEvidence)r.envelope.callId='foreign';return r;}};
 const provider={provider:'mock',model:'controlled-only',async chat(input){calls.push('model');if(fault.revokeOnModel)fault.revoked=true;
  assert.equal(input.system,buildBasePrompt('admin',{extra:'--- ACTIVE POLICIES (1) ---\n\n## Policy: Original policy\n\nliteral policy text\n\n--- END POLICIES ---',externalMcpBlock:'original external descriptions'}));
  assert.deepEqual(input.tools,descriptor);
  const n=calls.filter(x=>x==='model').length;
  if(fault.sequence){const tool_uses=fault.sequence[n-1]||[];return{provider:'mock',model:'controlled-only',mocked:true,stop_reason:tool_uses.length?'tool_use':'end_turn',text:'Observed bounded results',tool_uses};}
  if(fault.denial&&n===2)return{provider:'mock',model:'controlled-only',mocked:true,stop_reason:'tool_use',tool_uses:fault.batch||[{id:'denial-1',name:fault.denialName||'audit.search_by_user',args:{username:'owned'}}]};
  if(fault.reads&&n>1&&n<=1+fault.reads){const list=fault.list||fault.mixed&&n===3;return{provider:'mock',model:'controlled-only',mocked:true,stop_reason:'tool_use',tool_uses:[{id:'read-'+n,name:list?'mcp-registry.list_servers':'mcp-registry.describe_tools',args:list?(fault.listArgs||{}):{name:fault.readName||args.name}}]};}
  return {provider:'mock',model:'controlled-only',mocked:true,stop_reason:calls.filter(x=>x==='model').length===1?'tool_use':'end_turn',text:'Observed registry response',
   tool_uses:calls.filter(x=>x==='model').length===1?[{id:'call-1',name:fault.otherTool?'system.restart':'mcp-registry.register',args:fault.args||args}]:[]};}};
 const descriptor=[{agent:'mcp-registry',tool:'register',description:'controlled original-shape descriptor',inputSchema:{type:'object'}}];
 if(fault.denial)descriptor.push({agent:'audit',tool:'search_by_user',description:'original advertised audit',inputSchema:{type:'object'}});
 if(fault.extraCatalog)descriptor.push(...fault.extraCatalog);
 const manifest={getForRole:()=>descriptor,async buildExternalMcpPromptBlock(){return'original external descriptions';}};
 const dependencies={turns,conversations,repository,journal,provider,manifest,boundaryContract:fault.boundaryContract||'hard-fail-v1',
  capturePersonaAuthority:async()=>({binding:{...scope,personaId:3,role:'admin',...personaSession},async assertRemoteAdmission(){if(fault.badPersona)throw Error('persona revoked');}}),
  captureMode:async()=>({mode:{version:1,mode:fault.fixed?'fixed':'vuln',generation:fault.modeGeneration||0,modeStamp:fault.modeStamp||'original'},async assertCurrent(){if(fault.badMode)throw Error('mode stale');}}),
  toolPolicyAdmission:async q=>({admissionId:'77777777-7777-4777-8777-777777777777',runId,invocationId:q.invocationId,toolKey:q.agent+'.'+q.tool,policyVersion:'1',registrySha256:'a'.repeat(64),enforcement:true,allowed:true,action:'dispatch',policyViolation:null}),
  readRegistryTools:async q=>{calls.push('read');assert.deepEqual(q,{scope,name:args.name});if(fault.revokeOnRead)fault.revoked=true;return fault.missingRead?null:{version:'1',schema_hash:'c'.repeat(64),tools_json:[{name:'echo',description:'literal untrusted description',inputSchema:{type:'object'}}]};},
  readRegistryServers:async q=>{calls.push('list');assert.deepEqual(q,{scope});if(fault.revokeOnRead)fault.revoked=true;return fault.overflow?Array(33).fill({name:'owned'}):fault.fixed?[]:[{name:args.name,stdio_cmd:args.stdio_cmd}];},
  readRegistryVersion:async()=> '0',registrationJournal,launches:{async admitOwnedMcpRegistration(){calls.push('admit');}},
  client:{async registrationHealth(){return{instanceId:'88888888-8888-4888-8888-888888888888',runtimeDigest:'b'.repeat(64)};},async registrationState(){calls.push('drain');throw Error('unknown');}},
  ownedMcpRegistry:{async mutate({request},options){calls.push('mutate');if(fault.lostReply)throw Error('reply lost');
   const receipt={version:1,...options.registrationIdentity,state:'completed',drained:true,changes:[]};await options.onRegistrationReceipt(receipt);
   return {...receipt,registryVersion:'1',operationId:request.operationId};}}};const runtime=createOriginalRegistrationRuntime(dependencies);
 const input={sessionId,requestId,scope,persona,personaSession,message:'Register the exact supplied command.'};
 return {runtime,input,calls,messages,traces,claims,records,withBoundary:boundaryContract=>createOriginalRegistrationRuntime({...dependencies,boundaryContract})};
}
test('original graph uses bound authority and immutable registration/effect links; replay has no second actor or effect',async t=>{
 const f=setup(t),first=await f.runtime.run(f.input);assert.equal(first.replayed,false);assert.equal(first.taskMetadata.originalRegistration.links.length,1);
 assert.equal(first.taskMetadata.originalRegistration.canonicalCredit,false);assert.equal(first.taskMetadata.originalRegistration.observations[0].args.stdio_cmd,args.stdio_cmd);
 assert(f.calls.indexOf('admit')<f.calls.indexOf('mutate'));assert(f.calls.indexOf('mutate')<f.calls.indexOf('complete'));
 const count=f.calls.length,again=await f.runtime.run(f.input);assert.equal(again.replayed,true);assert.equal(f.calls.length,count);
 assert(f.traces.some(row=>row.kind==='model_decision'));
});
const splitContract='recoverable-split-budget-v2';
const splitCatalog=[{agent:'audit',tool:'search_by_user'},{agent:'system',tool:'read_config'},{agent:'system',tool:'restart'},...['describe_tools','list_servers'].map(tool=>({agent:'mcp-registry',tool}))].map(x=>({...x,inputSchema:{type:'object'}}));
const selectedRegister={id:'register',name:'mcp-registry.register',args};
const splitCompanions=[{id:'denied-audit',name:'audit.search_by_user',args:{username:'owned'}},{id:'describe',name:'mcp-registry.describe_tools',args:{name:args.name}},{id:'list',name:'mcp-registry.list_servers',args:{}},{id:'denied-config',name:'system.read_config',args:{}}];
test('v2 admits actual two registry reads and two ACL denials atomically without changing catalog, effect or replay budgets',async t=>{
 const f=setup(t,{boundaryContract:splitContract,extraCatalog:splitCatalog,sequence:[[selectedRegister],splitCompanions]}),r=await f.runtime.run(f.input),m=r.taskMetadata.originalRegistration;
 assert.deepEqual(m.selectionBudget,{version:2,ownedReads:2,aclDenials:2,registrations:1,companions:4});
 assert.equal(m.denialProofs.length,2);assert.equal(m.readLinks.length,2);assert.equal(m.observations.length,3);
 assert.equal(f.calls.filter(x=>x==='mutate').length,1);assert.equal(f.calls.filter(x=>x==='read').length,1);assert.equal(f.calls.filter(x=>x==='list').length,1);
 assert(m.denialProofs.every(p=>p.boundaryContract===splitContract&&p.effectNotStarted&&p.consumed));
 assert.equal(r.hops.filter(h=>h.error?.message==='blocked-by-acl').length,2);
 const count=f.calls.length,again=await f.runtime.run(f.input);assert(again.replayed);assert.equal(f.calls.length,count);assert.deepEqual(again.taskMetadata.originalRegistration.selectionBudget,m.selectionBudget);
 for(const contract of ['hard-fail-v1','recoverable-denial-v1'])await assert.rejects(f.withBoundary(contract).run(f.input),{code:'ORIGINAL_REGISTER_REPLAY_BOUNDARY_STALE'});
 assert.equal(f.calls.length,count);
});
for(const [label,sequence,code]of [
 ['third read',[[selectedRegister],[splitCompanions[1],splitCompanions[2]],[{...splitCompanions[1],id:'third-read'}]],'ORIGINAL_REGISTER_SELECTION_LIMIT'],
 ['third denial',[[selectedRegister],[splitCompanions[0],splitCompanions[3]],[{id:'third-denial',name:'system.restart',args:{}}]],'ORIGINAL_REGISTER_SELECTION_LIMIT'],
 ['second register',[[selectedRegister],[{...selectedRegister,id:'second-register'},splitCompanions[1]]],'ORIGINAL_REGISTER_SELECTION_LIMIT'],
 ['unknown whole batch',[[selectedRegister,{id:'unknown',name:'foreign.unknown',args:{}}]],'ORIGINAL_REGISTER_RAW_SELECTION_INVALID'],
 ['duplicate name',[[selectedRegister],[splitCompanions[1],{...splitCompanions[1],id:'duplicate-name'}]],'ORIGINAL_REGISTER_RAW_SELECTION_INVALID'],
 ['duplicate ID',[[selectedRegister],[splitCompanions[0],{...splitCompanions[1],id:splitCompanions[0].id}]],'ORIGINAL_REGISTER_RAW_SELECTION_INVALID'],
 ['reused ID across calls',[[selectedRegister],[{...splitCompanions[0],id:'register'}]],'ORIGINAL_REGISTER_RAW_SELECTION_INVALID'],
 ['five parallel selections',[[selectedRegister,...splitCompanions]],'ORIGINAL_REGISTER_SELECTION_LIMIT']
])test('v2 rejects '+label+' before any effect from that batch',async t=>{
 const f=setup(t,{boundaryContract:splitContract,extraCatalog:splitCatalog,sequence});await assert.rejects(f.runtime.run(f.input),{code});
 assert.equal(f.calls.filter(x=>x==='mutate').length,sequence.length===1?0:1);assert(!f.calls.includes('complete'));
 if(!['third read','third denial'].includes(label)){assert(!f.calls.includes('read'));assert(!f.calls.includes('list'));assert(!f.traces.some(x=>x.kind==='tool_blocked'));}
 const before=f.calls.length;await assert.rejects(f.runtime.run(f.input),{code:'TURN_RECOVERY_REQUIRED'});assert.equal(f.calls.length,before);
});
test('v2 independently newly claimed request gets its own counters, never a shared model-call reset',async t=>{
 const f=setup(t,{boundaryContract:splitContract,extraCatalog:splitCatalog,sequence:[[selectedRegister],splitCompanions]});await f.runtime.run(f.input);
 const g=setup(t,{boundaryContract:splitContract,extraCatalog:splitCatalog,sequence:[[selectedRegister],splitCompanions]});const next=await g.runtime.run({...g.input,requestId:'99999999-9999-4999-8999-999999999999'});
 assert.equal(next.taskMetadata.originalRegistration.selectionBudget.companions,4);assert.equal(g.calls.filter(x=>x==='mutate').length,1);
});
test('Fixed preserves original selected command but denies before registration admission',async t=>{
 const f=setup(t,{fixed:true}),r=await f.runtime.run(f.input),m=r.taskMetadata.originalRegistration;
 assert.equal(m.links.length,0);assert.equal(m.observations[0].result.error,'V23_FIXED_STDIO_DENIED');assert(!f.calls.includes('mutate'));assert(!f.calls.includes('prepare'));
});
test('owned describe companion returns persisted schemas with separate ACL/evidence and no second registration',async t=>{
 const f=setup(t,{reads:2}),r=await f.runtime.run(f.input),m=r.taskMetadata.originalRegistration;
 assert.equal(m.links.length,1);assert.equal(m.readLinks.length,2);assert.equal(m.observations.length,3);assert.equal(f.calls.filter(x=>x==='mutate').length,1);
 assert.equal(f.calls.filter(x=>x==='read').length,2);assert.equal(m.observations[1].result.tools[0].description,'literal untrusted description');
 assert.equal(m.readLinks[0].admission.toolKey,'mcp-registry.describe_tools');
});
test('Fixed listing reads actual scoped empty rows; combined describe/list share two-read cap',async t=>{
 const f=setup(t,{fixed:true,reads:2,mixed:true}),r=await f.runtime.run(f.input),m=r.taskMetadata.originalRegistration;
 assert.equal(f.calls.filter(x=>x==='list').length,1);assert(!f.calls.includes('mutate'));assert.deepEqual(m.observations[2].result,{ok:true,count:0,servers:[]});assert.equal(m.readLinks[1].admission.toolKey,'mcp-registry.list_servers');
});
test('prospective denial returns unchanged graph block, joins immutable history, and executes no external tool',async t=>{
 const f=setup(t,{denial:true,boundaryContract:'recoverable-denial-v1'}),r=await f.runtime.run(f.input),m=r.taskMetadata.originalRegistration;
 assert.equal(m.denialProofs.length,1);assert.equal(m.denialProofs[0].effectNotStarted,true);assert.equal(m.observations.length,1);assert.equal(m.links.length,1);assert.equal(m.denialProofs[0].history.tool.tool_call_id,'denial-1');
 assert.equal(f.calls.filter(x=>x==='mutate').length,1);assert(!f.calls.includes('read'));assert(r.hops.some(h=>h.error?.message==='blocked-by-acl'));
 const {validateDenial}=require('../server/services/secureshopOriginalRegistrationRuntime');
 for(const mutate of [p=>p.args.username='foreign',p=>p.consumed.content='invented',p=>p.history.tool.tool_call_id='foreign',p=>p.catalogDigest='0'.repeat(64)]){
  const proof=structuredClone(m.denialProofs[0]);mutate(proof);assert.throws(()=>validateDenial(proof,{...m,hops:r.hops}));}
});
test('hard-fail historical contract still throws on advertised unsupported tool',async t=>{
 const f=setup(t,{denial:true});await assert.rejects(f.runtime.run(f.input),{code:'ORIGINAL_REGISTER_TOOL_UNAVAILABLE'});
});
test('completed replay cannot cross boundary contracts or reinterpret missing historical metadata',async t=>{
 const f=setup(t);await f.runtime.run(f.input);const count=f.calls.length;
 await assert.rejects(f.withBoundary('recoverable-denial-v1').run(f.input),{code:'ORIGINAL_REGISTER_REPLAY_BOUNDARY_STALE'});assert.equal(f.calls.length,count);
 delete f.claims.get(requestId).result.taskMetadata.originalRegistration.boundaryContract;
 await assert.rejects(f.runtime.run(f.input),{code:'ORIGINAL_REGISTER_REPLAY_BOUNDARY_STALE'});assert.equal(f.calls.length,count);
});
test('whole concurrent batch reserves combined read/denial budget before any companion dispatch',async t=>{
 const extraCatalog=['describe_tools','list_servers'].map(tool=>({agent:'mcp-registry',tool,inputSchema:{type:'object'}}));
 const batch=[{id:'a',name:'audit.search_by_user',args:{}},{id:'b',name:'mcp-registry.describe_tools',args:{name:args.name}},{id:'c',name:'mcp-registry.list_servers',args:{}}];
 const f=setup(t,{denial:true,boundaryContract:'recoverable-denial-v1',extraCatalog,batch});await assert.rejects(f.runtime.run(f.input),{code:'ORIGINAL_REGISTER_SELECTION_LIMIT'});
 assert(!f.calls.includes('read'));assert(!f.calls.includes('list'));assert(!f.traces.some(t=>t.kind==='tool_blocked'));assert.equal(f.calls.filter(x=>x==='mutate').length,1);
});
for(const fault of [{denialName:'audit.search_by_user.extra'},{denialName:'foreign.tool'},
 {batch:[{id:'x',name:'audit.search_by_user',args:{}},{id:'x',name:'audit.search_by_user',args:{}}]},
 {batch:[{id:'x',name:'audit.search_by_user',args:{}},{id:'y',name:'audit.search_by_user',args:{}}]}])test('prospective whole-batch validation rejects raw aliases and ambiguous identities: '+JSON.stringify(fault),async t=>{
 const f=setup(t,{denial:true,boundaryContract:'recoverable-denial-v1',...fault});await assert.rejects(f.runtime.run(f.input),{code:'ORIGINAL_REGISTER_RAW_SELECTION_INVALID'});assert(!f.traces.some(t=>t.kind==='tool_blocked'));
});
for(const fault of [{list:true,reads:3},{list:true,reads:1,overflow:true},{list:true,reads:1,revokeOnRead:true},{list:true,reads:1,listArgs:{owner:9}}])test('listing rejects overflow/arguments/stale authority/shared cap: '+JSON.stringify(fault),async t=>{
 const f=setup(t,fault);await assert.rejects(f.runtime.run(f.input));assert(!f.calls.includes('complete'));assert.equal(f.calls.filter(x=>x==='mutate').length,1);
});
for(const fault of [{fixed:true,reads:1},{reads:1,readName:'foreign'}])test('unpublished or foreign-name companion never reads registry: '+JSON.stringify(fault),async t=>{
 const f=setup(t,fault),r=await f.runtime.run(f.input);assert(!f.calls.includes('read'));assert.equal(r.taskMetadata.originalRegistration.observations[1].result.error,'ORIGINAL_REGISTER_READ_UNAVAILABLE');
});
for(const fault of [{reads:3},{reads:1,revokeOnRead:true},{reads:1,missingRead:true}])test('read limit and post-read stale/missing state fail closed: '+JSON.stringify(fault),async t=>{
 const f=setup(t,fault);await assert.rejects(f.runtime.run(f.input));assert.equal(f.calls.filter(x=>x==='mutate').length,1);assert(!f.calls.includes('complete'));
});
for(const fault of [{args:{...args,transport:'sse',url:'http://foreign.invalid'}},{otherTool:true},{badPersona:true},{badMode:true},{revokeOnModel:true}])test('authority/transport/tool rejection never reaches executor: '+JSON.stringify(fault),async t=>{
 const f=setup(t,fault);await assert.rejects(f.runtime.run(f.input));assert(!f.calls.includes('mutate'));
});
test('foreign owner/session and reset generation cannot reuse completed turn',async t=>{
 const f=setup(t);await f.runtime.run(f.input);const count=f.calls.length;
 for(const change of [{platformOwnerId:9},{platformSessionId:9},{generation:2}])await assert.rejects(f.runtime.run({...f.input,scope:{...scope,...change}}));
 assert.equal(f.calls.length,count);
});
for(const change of [{fixed:true},{modeStamp:'changed'},{modeGeneration:2,modeStamp:'after-vuln-fixed-vuln'}])test('completed replay rejects changed canonical mode revision without a second effect: '+JSON.stringify(change),async t=>{
 const fault={},f=setup(t,fault);await f.runtime.run(f.input);const count=f.calls.length;Object.assign(fault,change);
 await assert.rejects(f.runtime.run(f.input),{code:'ORIGINAL_REGISTER_REPLAY_MODE_STALE'});assert.equal(f.calls.length,count);
 assert.equal(f.claims.get(requestId).status,'completed');
});
for(const fault of ['badEvidence','lostReply'])test('uncertain/evidence failure never completes or automatically replays: '+fault,async t=>{
 const f=setup(t,{[fault]:true});await assert.rejects(f.runtime.run(f.input));assert.equal(f.claims.get(requestId).status,'uncertain');
 const count=f.calls.length;await assert.rejects(f.runtime.run(f.input),{code:'TURN_RECOVERY_REQUIRED'});assert.equal(f.calls.length,count);
});
test('trusted factory and unchanged default singleton produce identical original prompt/catalog/final graph result',async t=>{
 policies(t);const db=require('../server/database/postgres/secureshopAgentsDb'),old=db.getSecureShopAgentsDb;
 const messages=[],store={async appendMessage(_id,m){messages.push(m);},async getMessages(){return messages;},async getTokens(){return 0;},async addTokens(){},async appendTraces(){}};
 db.getSecureShopAgentsDb=()=>store;t.after(()=>{db.getSecureShopAgentsDb=old;});
 const seen=[],provider={provider:'mock',model:'controlled-only',async chat(input){seen.push(structuredClone({...input,signal:null}));return{stop_reason:'end_turn',text:'original final',mocked:true};}};
 const manifest={getForRole:()=>[],buildExternalMcpPromptBlock:async()=> 'literal external'};
 const factory=createAdminSupervisor({store:require('../server/services/secureshop/sessionStore'),Trace:require('../server/services/secureshop/trace').Trace,checkToolAcl:async()=>{throw Error('no tool');}});
 const opts={provider,manifest,pool:{callTool:async()=>{}},role:'admin'};
 const a=await adminSupervisor.run(sessionId,'same original input',opts);messages.length=0;
 const b=await factory.run(sessionId,'same original input',opts);assert.deepEqual(a,b);assert.deepEqual(seen[0],seen[1]);assert.equal(MAX_STEPS,8);
});
