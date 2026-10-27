'use strict';
// Server-only original V23 composition. No HTTP mount, canonical objective,
// provider substitution, legacy session copy, or prepare/confirm replacement.
const {isDeepStrictEqual}=require('node:util');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createBoundGraphStore}=require('./secureshopBoundGraphStore');
const {createAdminSupervisor}=require('./secureshop/supervisors/adminSupervisor');
const {createV23RegisterAdapter}=require('./secureshopV23RegisterAdapter');
const {canonicalDigest}=require('./mcp/protocolContext');
const {originalCommand}=require('./secureshopV23RegisterCapability');
const {checkedMode}=require('./secureshopAnalyticsModeAuthority');
const PURPOSE='general',TOOL='mcp-registry.register';
const READ='mcp-registry.describe_tools',ORIGINAL_DESCRIBE_TOOL=Object.freeze({agent:'mcp-registry',tool:'describe_tools'});
const LIST='mcp-registry.list_servers',ORIGINAL_LIST_TOOL=Object.freeze({agent:'mcp-registry',tool:'list_servers'});
const BOUNDARY_CONTRACTS=Object.freeze(['hard-fail-v1','recoverable-denial-v1','recoverable-split-budget-v2']);
const denialText=tool=>JSON.stringify({error:'blocked-by-acl',message:`Policy denied ${tool} for role=admin`});
function validateDenial(proof,{traces,hops,run,binding,modeSnapshot,catalog,boundaryContract}){
 const assert=require('node:assert/strict');assert.equal(proof.version,1);assert(['recoverable-denial-v1','recoverable-split-budget-v2'].includes(proof.boundaryContract));
 assert.equal(proof.boundaryContract,boundaryContract);
 assert.deepEqual(Object.keys(proof).sort(),['args','argsDigest','binding','boundaryContract','callId','catalogDigest','consumed','effectNotStarted','history','modeSnapshot','reason','run','step','tool','version']);
 assert.deepEqual(proof.run,run);assert.deepEqual(proof.binding,binding);assert.deepEqual(proof.modeSnapshot,modeSnapshot);
 assert.equal(proof.catalogDigest,canonicalDigest(catalog));assert(catalog.some(t=>t.agent+'.'+t.tool===proof.tool));assert(![TOOL,READ,LIST].includes(proof.tool));
 assert.equal(proof.argsDigest,canonicalDigest(proof.args));assert.equal(proof.effectNotStarted,true);assert.equal(proof.reason,'not-admitted-by-registration-boundary');
 const decisions=traces.filter(t=>t.kind==='model_decision'&&t.step===proof.step).flatMap(t=>JSON.parse(t.params_json||'{}').toolCalls||[]).filter(t=>t.id===proof.callId);
 assert.deepEqual(decisions,[{id:proof.callId,name:proof.tool,args:proof.args}]);
 const plans=traces.filter(t=>t.kind==='dispatch_plan'&&t.step===proof.step);assert.equal(plans.length,1);
 for(const entries of [JSON.parse(plans[0].params_json).selected,JSON.parse(plans[0].result_json).execute])assert.deepEqual(entries.filter(x=>x.id===proof.callId),[{id:proof.callId,name:proof.tool}]);
 const blocked=traces.filter(t=>t.kind==='tool_blocked'&&t.step===proof.step&&t.agent_ns+'.'+t.tool_name===proof.tool);assert.equal(blocked.length,1);
 const text=denialText(proof.tool),result={content:[{type:'text',text}],isError:true};assert.deepEqual(JSON.parse(blocked[0].result_json),result);
 const matching=hops.filter(h=>h.step===proof.step&&h.tool===proof.tool);assert.equal(matching.length,1);assert.deepEqual(matching[0].params,proof.args);assert.deepEqual(matching[0].result,result);assert.equal(matching[0].error.message,'blocked-by-acl');
 assert.deepEqual(proof.history.tool,{role:'tool',tool_call_id:proof.callId,content:text});assert.deepEqual(proof.consumed,proof.history.tool);
 const calls=proof.history.assistant.tool_calls.filter(c=>c.id===proof.callId);assert.equal(calls.length,1);assert.equal(calls[0].function.name,proof.tool);assert.deepEqual(JSON.parse(calls[0].function.arguments),proof.args);
}
const fail=code=>Object.assign(Error(code),{code,executionBoundary:true});
function createOriginalRegistrationRuntime({turns,conversations,repository,journal,provider,manifest,
 capturePersonaAuthority,captureMode,toolPolicyAdmission,readRegistryVersion,readRegistryTools,readRegistryServers,
 registrationJournal,launches,ownedMcpRegistry,client,boundaryContract='hard-fail-v1'}={}){
 if(!BOUNDARY_CONTRACTS.includes(boundaryContract))throw TypeError('Explicit supported registration boundary required');
 for(const fn of [turns?.run,conversations?.assertOwned,conversations?.getMessages,
  repository?.appendMessage,repository?.getTokens,repository?.addTokens,repository?.appendTraces,
  provider?.chat,manifest?.getForRole,capturePersonaAuthority,captureMode,toolPolicyAdmission,
  readRegistryVersion,readRegistryTools,readRegistryServers,registrationJournal?.readCompleted])if(typeof fn!=='function')throw TypeError('Original registration dependencies required');
 const admission=createTurnAdmission({journal});
 return Object.freeze({async run({sessionId,requestId,scope,persona,personaSession,message,signal}){
  const binding=createConversationBinding(scope,persona);
  scope=Object.freeze(Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,binding[k]])));
  if(binding.role!=='admin')throw fail('ORIGINAL_REGISTER_ADMIN_REQUIRED');
  const request=createTurnRequest({sessionId,requestId,binding,message});sessionId=request.sessionId;
  const trustedPersona=Object.freeze({id:binding.shopUserId,role:'admin'});
  const trustedSession=Object.freeze({...personaSession});
  const fence=await capturePersonaAuthority({binding,sessionId,requestId:request.requestId,personaSession:trustedSession});
  const expected={...Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,binding[k]])),
   personaId:trustedPersona.id,role:'admin',sessionId:trustedSession.sessionId,authorityVersion:trustedSession.authorityVersion};
  if(!isDeepStrictEqual(fence?.binding,expected)||typeof fence.assertRemoteAdmission!=='function')throw fail('SHOP_AUTH_INVALID');
  const mode=await captureMode(scope);
  if(typeof mode?.assertCurrent!=='function')throw fail('ORIGINAL_REGISTER_MODE_REQUIRED');
  const modeSnapshot=checkedMode(mode.mode);
  const checkOutside=async()=>{signal?.throwIfAborted();await mode.assertCurrent();await fence.assertRemoteAdmission();
   await conversations.assertOwned(sessionId,binding,trustedPersona,PURPOSE);signal?.throwIfAborted();};
  await checkOutside();let prepared;
  try{
   const outcome=await turns.run(sessionId,binding,trustedPersona,{signal,idempotencyKey:request.requestId,conversationPurpose:PURPOSE,
    admit:async()=>{await checkOutside();prepared=await admission.prepare({sessionId,requestId:request.requestId,binding,message});
     return prepared.status==='completed'?{skip:true,value:prepared.outcome}:{skip:false,value:prepared};}},async boundary=>{
    if(!prepared||prepared.status!=='claimed'||!boundary.identity?.runId||!boundary.identity?.ownerKey
     ||boundary.identity.durableGeneration==null||typeof boundary.effectWithReceipt!=='function')throw fail('ORIGINAL_REGISTER_ADMISSION_REQUIRED');
    const check=async()=>{await boundary.check();await checkOutside();await boundary.check();};
    return admission.execute(prepared,{...boundary,check},async()=>{
     const execution=Object.freeze({...boundary.identity,signal:boundary.signal,check});
     const adapter=createV23RegisterAdapter({mode:modeSnapshot.mode,scope,persona:trustedPersona,personaSession:trustedSession,execution,
      readRegistryVersion:()=>readRegistryVersion({scope,persona:trustedPersona,personaSession:trustedSession}),assertRunCurrent:check,
      registrationJournal,launches,ownedMcpRegistry,client});
     const observations=[],traces=[],readLinks=[],readAdmissions=new Map(),denialProofs=[],selections=new Map();let selected=false,attemptComplete=false,primary,result,publishedName=null,publishedVersion=null,readCount=0;
     const catalog=structuredClone(manifest.getForRole('admin')),splitBudget=boundaryContract==='recoverable-split-budget-v2',recoverable=boundaryContract!=='hard-fail-v1';
     let reservedReads=0,reservedDenials=0,reservedRegisters=0;const actualProvider=Object.create(provider);
     Object.defineProperty(actualProvider,'chat',{value:async input=>{
      await check();for(const proof of denialProofs){if(!proof.consumed){const found=input.messages.filter(m=>m.role==='tool'&&m.tool_call_id===proof.callId);if(found.length===1)proof.consumed=structuredClone(found[0]);}}
      const response=await provider.chat(input);await check();if(!recoverable)return response;
      const batch=response.tool_uses||[],names=new Set(),ids=new Set();let reads=0,denials=0,registers=0;
      if(splitBudget&&(!Array.isArray(batch)||batch.length>4))throw fail('ORIGINAL_REGISTER_SELECTION_LIMIT');
      for(const call of batch){if(typeof call.name!=='string'||call.name.split('.').length!==2||!catalog.some(t=>t.agent+'.'+t.tool===call.name)
       ||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(call.id||'')||selections.has(call.id)||ids.has(call.id)||names.has(call.name))throw fail('ORIGINAL_REGISTER_RAW_SELECTION_INVALID');
       ids.add(call.id);names.add(call.name);if(call.name===TOOL)registers++;else if(!splitBudget||[READ,LIST].includes(call.name))reads++;else denials++;}
      if(reservedReads+reads>2||reservedDenials+denials>2||reservedReads+reads+reservedDenials+denials>(splitBudget?4:2)||reservedRegisters+registers>1)throw fail('ORIGINAL_REGISTER_SELECTION_LIMIT');
      // Reserve the complete validated batch before any graph dispatch. These
      // counters belong to this newly claimed durable request, never a model call.
      const captured=batch.map(call=>structuredClone(call));
      reservedReads+=reads;reservedDenials+=denials;reservedRegisters+=registers;for(const call of captured)selections.set(call.id,call);return response;
     }});
     try{
      const {store,Trace}=createBoundGraphStore({sessionId,scope:binding,persona:trustedPersona,service:conversations,
       repository,check,conversationPurpose:PURPOSE,onTracesPersisted:rows=>{if(traces.length+rows.length>4096)throw fail('ORIGINAL_REGISTER_TRACE_LIMIT');traces.push(...rows);}});
      const checkToolAcl=async(role,agent,tool,invocation)=>{
       if(role!=='admin')throw fail('ORIGINAL_REGISTER_TOOL_UNAVAILABLE');
       if(recoverable){const selection=selections.get(invocation.callId);if(!selection||selection.name!==agent+'.'+tool||!isDeepStrictEqual(selection.args||{},invocation.args))throw fail('ORIGINAL_REGISTER_RAW_SELECTION_INVALID');}
       if(![TOOL,READ,LIST].includes(agent+'.'+tool)){
        if(!recoverable)throw fail('ORIGINAL_REGISTER_TOOL_UNAVAILABLE');await check();
        denialProofs.push({version:1,boundaryContract,run:structuredClone(boundary.identity),binding,modeSnapshot,callId:invocation.callId,step:invocation.step,tool:agent+'.'+tool,
         args:structuredClone(invocation.args),argsDigest:canonicalDigest(invocation.args),catalogDigest:canonicalDigest(catalog),reason:'not-admitted-by-registration-boundary',effectNotStarted:true});
        await check();return{allowed:false,action:'block',enforcement:true,policyViolation:'blocked'};
       }
       await check();const proof=await toolPolicyAdmission({scope,persona:trustedPersona,personaSession:trustedSession,
        runId:execution.runId,invocationId:`${invocation.step}:${invocation.callId}`,agent,tool,args:invocation.args});await check();
       if([READ,LIST].includes(agent+'.'+tool))readAdmissions.set(invocation.callId,structuredClone(proof));
       return {allowed:proof.allowed,action:proof.action,policyViolation:proof.policyViolation,enforcement:proof.enforcement,admission:proof};
      };
      const supervisor=createAdminSupervisor({store,Trace,checkToolAcl});
      result=await supervisor.run(sessionId,message,{provider:recoverable?actualProvider:provider,manifest,role:'admin',callerRole:'admin',callerId:trustedPersona.id,ownerId:sessionId,
       signal:boundary.signal,check,effectWithReceipt:boundary.effectWithReceipt,
       pool:{async callTool(){throw fail('ORIGINAL_REGISTER_TOOL_UNAVAILABLE');}},
       localTools:new Map([[TOOL,async(args,selection)=>{if(selected)throw fail('ORIGINAL_REGISTER_SELECTION_LIMIT');selected=true;
        // The original SSE branch has a different unconfined fetch sink. This
        // composition admits only the approved stdio lesson, never that branch.
        if(args?.transport!=='stdio')throw fail('ORIGINAL_REGISTER_TRANSPORT_UNAVAILABLE');
        await check();const value=await adapter.invoke(args,selection);await check();attemptComplete=true;if(value.ok===true){publishedName=args.name;publishedVersion=value.registryVersion;}return value;}],
        [READ,async(args,selection)=>{if(++readCount>2)throw fail('ORIGINAL_REGISTER_READ_LIMIT');await check();
         const admission=readAdmissions.get(selection.callId);if(!admission||admission.allowed!==true)throw fail('ORIGINAL_REGISTER_READ_ADMISSION');
         if(Object.keys(args||{}).join()!=='name'||typeof args.name!=='string')throw fail('ORIGINAL_REGISTER_READ_ARGUMENTS');
         if(!publishedName||args.name!==publishedName){readLinks.push({callId:selection.callId,step:selection.step,admission,record:null});return{ok:false,error:'ORIGINAL_REGISTER_READ_UNAVAILABLE'};}
         const record=await readRegistryTools({scope,name:args.name});await check();
         if(!record||record.version!==publishedVersion||!Array.isArray(record.tools_json)||record.tools_json.length>64)throw fail('ORIGINAL_REGISTER_READ_UNAVAILABLE');
         const tools=record.tools_json.map(tool=>{if(typeof tool?.name!=='string'||typeof tool.description!=='string'||!tool.inputSchema||typeof tool.inputSchema!=='object'||Array.isArray(tool.inputSchema))throw fail('ORIGINAL_REGISTER_READ_SCHEMA');
          return{server_name:args.name,tool_name:tool.name,description:tool.description,input_schema_json:JSON.stringify(tool.inputSchema)};});
         readLinks.push({callId:selection.callId,step:selection.step,admission,record:structuredClone(record)});
         return{ok:true,name:args.name,tool_count:tools.length,tools};}],
        [LIST,async(args,selection)=>{if(++readCount>2)throw fail('ORIGINAL_REGISTER_READ_LIMIT');await check();
         const admission=readAdmissions.get(selection.callId);if(!admission||admission.allowed!==true)throw fail('ORIGINAL_REGISTER_READ_ADMISSION');
         if(!args||Array.isArray(args)||Object.keys(args).length)throw fail('ORIGINAL_REGISTER_READ_ARGUMENTS');
         if(!attemptComplete)throw fail('ORIGINAL_REGISTER_READ_UNAVAILABLE');
         const version=await readRegistryVersion({scope,persona:trustedPersona,personaSession:trustedSession});await check();
         const servers=await readRegistryServers({scope});await check();
         const after=await readRegistryVersion({scope,persona:trustedPersona,personaSession:trustedSession});await check();
         if(version!==after||!Array.isArray(servers)||servers.length>32)throw fail('ORIGINAL_REGISTER_READ_UNAVAILABLE');
         readLinks.push({callId:selection.callId,step:selection.step,admission,record:{version,servers:structuredClone(servers)}});
         return{ok:true,count:servers.length,servers};}]]),
       onLocalToolObservation:async observation=>{if(observations.length>=3)throw fail('ORIGINAL_REGISTER_SELECTION_LIMIT');observations.push(structuredClone(observation));}});
      await check();
      if(recoverable){const history=await store.getMessages(sessionId);await check();for(const proof of denialProofs){
       const assistants=history.filter(m=>m.role==='assistant'&&m.tool_calls?.some(c=>c.id===proof.callId)),tools=history.filter(m=>m.role==='tool'&&m.tool_call_id===proof.callId);
       if(assistants.length!==1||tools.length!==1)throw fail('ORIGINAL_REGISTER_DENIAL_EVIDENCE');proof.history={assistant:assistants[0],tool:tools[0]};
       validateDenial(proof,{traces,hops:result.hops,run:boundary.identity,binding,modeSnapshot,catalog,boundaryContract});}}
     }catch(error){primary=error;}
     try{await adapter.close();}catch(error){if(primary)throw new AggregateError([primary,error],'Original registration and cleanup failed');throw error;}
     if(primary)throw primary;
     const provenance=adapter.readProvenance(),links=[];
     for(const source of provenance){
      const observation=observations.find(o=>o.callId===source.callId&&o.step===source.step&&o.tool===TOOL);
      const record=await registrationJournal.readCompleted({scope,operationId:source.operationId});
      const normalized=observation&&originalCommand({name:observation.args.name,transport:observation.args.transport,
       url:observation.args.url??null,stdio_cmd:observation.args.stdio_cmd??null});
      if(!observation||canonicalDigest(normalized)!==source.argsSha256||record.envelope.runId!==execution.runId
       ||record.envelope.callId!==source.callId||record.envelope.step!==source.step||record.envelope.argsSha256!==source.argsSha256
       ||record.envelope.requestSha256!==source.requestSha256||record.envelope.instanceId!==source.instanceId
       ||observation.effectReceipt?.status!=='completed'||observation.effectReceipt.runId!==execution.runId
       ||observation.effectReceipt.ownerKey!==execution.ownerKey
       ||String(observation.effectReceipt.generation)!==String(execution.durableGeneration)
       ||observation.effectReceipt.effectKey!==record.envelope.effectKey)throw fail('ORIGINAL_REGISTER_EVIDENCE_MISMATCH');
      links.push({source,record});
     }
     const taskMetadata={originalRegistration:{version:1,boundaryContract,mode:modeSnapshot.mode,modeSnapshot,binding,sessionId,requestId:request.requestId,
      run:boundary.identity,observations,traces,links,readLinks,denialProofs,...(recoverable?{catalog}:{}),
      ...(splitBudget?{selectionBudget:{version:2,ownedReads:reservedReads,aclDenials:reservedDenials,registrations:reservedRegisters,companions:reservedReads+reservedDenials}}:{}),canonicalCredit:false}};
     if(Buffer.byteLength(JSON.stringify(taskMetadata))>65536)throw fail('ORIGINAL_REGISTER_EVIDENCE_LIMIT');
     return {...result,taskMetadata};
    },fence);
   });
   await checkOutside();
   if(!isDeepStrictEqual(outcome.result?.taskMetadata?.originalRegistration?.modeSnapshot,modeSnapshot))throw fail('ORIGINAL_REGISTER_REPLAY_MODE_STALE');
   if(outcome.result?.taskMetadata?.originalRegistration?.boundaryContract!==boundaryContract)throw fail('ORIGINAL_REGISTER_REPLAY_BOUNDARY_STALE');
   return {...outcome.result,replayed:outcome.replayed};
  }catch(error){await admission.abandon(prepared);throw error;}
 }});
}
module.exports={createOriginalRegistrationRuntime,ORIGINAL_DESCRIBE_TOOL,ORIGINAL_LIST_TOOL,BOUNDARY_CONTRACTS,validateDenial};
