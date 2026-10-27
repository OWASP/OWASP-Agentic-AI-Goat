'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {withEffectAdmission,currentEffectAdmission}=require('../server/agent-runtime/effectAdmissionContext');
const {createV23RegisterAdapter}=require('../server/services/secureshopV23RegisterAdapter');

const RUN='33333333-3333-4333-8333-333333333333',INSTANCE='22222222-2222-4222-8222-222222222222';
const args={name:'fixture',transport:'stdio',stdio_cmd:'original-selected-command --token exact'};
const selection={callId:'call-1',step:1,tool:'mcp-registry.register'};
function setup(mode='vuln',override={}){
 const calls=[],context={ownerKey:'owner-fixture',runId:RUN,durableGeneration:1};let admitted=false;
 const execution={...context,check:async()=>calls.push('check')};let identity;
 const journal={prepare(envelope,run){assert.equal(currentEffectAdmission(run).ledgerEffectKey,'effect-1');
   assert.equal(envelope.args.stdio_cmd,args.stdio_cmd);assert.equal(envelope.runId,RUN);identity={instanceId:INSTANCE,
    operationId:envelope.request.operationId,requestSha256:envelope.requestSha256};calls.push('prepare');return{};},
  identity:()=>identity,admitPrepared:async()=>{},settlePrepared:async(_handle,value)=>{calls.push(value.notDispatched?'settle-none':value.receipt?'settle-receipt':'settle-status');
   return{drained:value.notDispatched===true||value.receipt?.drained===true||value.status?.drained===true};}};
 const launches={admitOwnedMcpRegistration:async()=>{admitted=true;calls.push('admit');
  if(override.failAdmitAfterCommit)throw Error('identity ACK lost');}};
 const client={registrationHealth:async()=>({version:1,instanceId:INSTANCE,runtimeDigest:'a'.repeat(64),registrationCapability:'owned-mcp-registration-v1'}),
  registrationState:async()=>{calls.push('drain');return{version:1,...identity,state:'unknown',drained:false};}};
 const ownedMcpRegistry={mutate:async(_raw,options)=>{calls.push('mutate');assert.equal(options.expectedRegistrationMode,'vuln');
  await options.onRegistrationReceipt({version:1,...identity,state:'completed',drained:true,changes:[]});
  return{version:'secureshop-owned-mcp-registry.v1',...identity,state:'completed',registryVersion:'1'};}};
 const adapter=createV23RegisterAdapter({mode,scope:{owner:'fixture'},persona:{id:1,role:'admin'},personaSession:{sessionId:RUN,authorityVersion:'1'},
  execution,readRegistryVersion:async()=>{calls.push('version');return'0';},assertRunCurrent:async()=>{
   calls.push('current');if(admitted&&override.failAfterAdmission)throw Error('owner retired before transport');},
  registrationJournal:journal,launches,
  client:typeof override.client==='function'?override.client({calls,getIdentity:()=>identity}):client,
  ownedMcpRegistry:typeof override.ownedMcpRegistry==='function'?override.ownedMcpRegistry({calls,getIdentity:()=>identity}):ownedMcpRegistry});
 return {adapter,calls,context};
}

test('original selected command joins current effect, pre-effect journal, tracked receipt and publication',async()=>{
 const {adapter,calls,context}=setup();
 const result=await withEffectAdmission(context,'effect-1',()=>adapter.invoke(args,selection));
 assert.equal(result.ok,true);assert.equal(result.command,args.stdio_cmd);
 assert.equal(result.receipt.state,'completed');assert.equal(adapter.readProvenance().length,1);
 assert.ok(calls.indexOf('admit')<calls.indexOf('mutate'));
 assert.ok(calls.indexOf('settle-receipt')>calls.indexOf('mutate'));
 await adapter.close();
});

test('Fixed original command is denied before journal, executor, and registry mutation',async()=>{
 const {adapter,calls,context}=setup('fixed');
 const result=await withEffectAdmission(context,'effect-1',()=>adapter.invoke(args,selection));
 assert.equal(result.ok,false);assert.equal(result.effectNotStarted,true);
 assert.equal(adapter.readProvenance().length,0);
 assert.equal(calls.includes('prepare'),false);assert.equal(calls.includes('mutate'),false);
 await adapter.close();
});

test('after-admission lost ACK drains exact identity and never reports command success',async()=>{
 const {adapter,calls,context}=setup('vuln',{
  ownedMcpRegistry:({calls})=>({mutate:async()=>{calls.push('mutate');
   throw Object.assign(Error('lost ACK'),{code:'MCP_REGISTRY_OUTCOME_UNCERTAIN'});}}),
  client:({calls,getIdentity})=>({registrationHealth:async()=>({version:1,instanceId:INSTANCE,runtimeDigest:'a'.repeat(64)}),
   registrationState:async(q,{drain})=>{assert.equal(drain,true);assert.deepEqual(q,getIdentity());calls.push('drain');
    return{version:1,...q,state:'unknown',drained:false};}}),
 });
 await assert.rejects(withEffectAdmission(context,'effect-1',()=>adapter.invoke(args,selection)),error=>
  error.code==='V23_EXECUTION_OUTCOME_UNCERTAIN'&&error.automaticRetry===false);
 assert.ok(calls.includes('settle-status'));assert.equal(adapter.readProvenance().length,1);
 await assert.rejects(adapter.close(),{code:'V23_REGISTRATION_DRAIN_REQUIRED'});
});

test('authority loss after durable admission but before mutate settles proven no-dispatch',async()=>{
 const {adapter,calls,context}=setup('vuln',{failAfterAdmission:true});
 await assert.rejects(withEffectAdmission(context,'effect-1',()=>adapter.invoke(args,selection)),error=>
  error.code==='V23_EXECUTION_OUTCOME_UNCERTAIN'&&error.automaticRetry===false);
 assert.ok(calls.includes('settle-none'));assert.equal(calls.includes('mutate'),false);
 assert.equal(calls.includes('drain'),false);await adapter.close();
});

test('service pretransport callback can prove no dispatch without consulting unknown status',async()=>{
 const {adapter,calls,context}=setup('vuln',{ownedMcpRegistry:({calls})=>({mutate:async(_raw,options)=>{
  calls.push('mutate');await options.onRegistrationNotDispatched();throw Error('mode changed before transport');}})});
 await assert.rejects(withEffectAdmission(context,'effect-1',()=>adapter.invoke(args,selection)),error=>
  error.code==='V23_EXECUTION_OUTCOME_UNCERTAIN'&&error.automaticRetry===false);
 assert.ok(calls.includes('settle-none'));assert.equal(calls.includes('drain'),false);await adapter.close();
});

test('lost pre-effect admission ACK retains an unresolved shutdown obligation',async()=>{
 const {adapter,calls,context}=setup('vuln',{failAdmitAfterCommit:true});
 await assert.rejects(withEffectAdmission(context,'effect-1',()=>adapter.invoke(args,selection)),error=>
  error.code==='V23_EXECUTION_OUTCOME_UNCERTAIN'&&error.automaticRetry===false);
 assert.equal(calls.includes('mutate'),false);assert.equal(calls.includes('settle-none'),false);
 await assert.rejects(adapter.close(),{code:'V23_REGISTRATION_DRAIN_REQUIRED'});
});
