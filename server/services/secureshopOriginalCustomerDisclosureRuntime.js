'use strict';
// Unmounted original-customer composition. This is not the separate four-step
// bound customer assistant, a Judge, or an objective completion service.
const {isDeepStrictEqual}=require('node:util');
const {createConversationBinding}=require('./secureshopConversationBinding');
const {createTurnRequest}=require('./secureshopTurnRequest');
const {createTurnAdmission}=require('./secureshopTurnAdmission');
const {createBoundGraphStore}=require('./secureshopBoundGraphStore');
const {createCustomerSupervisor}=require('./secureshop/supervisors/customerSupervisor');
const {createCustomerDisclosureAuthority,disclosureFor}=require('./secureshopCustomerDisclosureAuthority');
const fail=code=>Object.assign(new Error(code),{code,executionBoundary:true});
const copy=value=>JSON.parse(JSON.stringify(value));
const PURPOSE='general';
function createOriginalCustomerDisclosureRuntime({turns,conversations,repository,journal,provider,pool,manifest,
  modeAuthority,launches,personaAuthority,checkToolAcl,observePrivateEvidence}){
  if(observePrivateEvidence!==undefined&&typeof observePrivateEvidence!=='function')throw TypeError('Private evidence observer must be a function');
  for(const fn of [turns?.run,conversations?.assertOwned,conversations?.getMessages,repository?.appendMessage,
    repository?.getTokens,repository?.addTokens,repository?.appendTraces,provider?.chat,pool?.callTool,checkToolAcl])
    if(typeof fn!=='function')throw TypeError('Original customer disclosure dependencies required');
  const observe=async event=>{if(observePrivateEvidence){try{await observePrivateEvidence(copy(event));}
    catch{throw fail('CUSTOMER_DISCLOSURE_EVIDENCE_UNAVAILABLE');}}};
  const authority=createCustomerDisclosureAuthority({modeAuthority,launches,personaAuthority,conversations,manifest,
    ...(observePrivateEvidence?{observePrivateSource:source=>observe({kind:'source',source})}:{})});
  const admission=createTurnAdmission({journal});
  return Object.freeze({async run({sessionId,requestId,scope,persona,personaSession,message,signal}){
    const binding=createConversationBinding(scope,persona);
    if(binding.role!=='customer')throw fail('CUSTOMER_DISCLOSURE_AUTHORITY');
    const request=createTurnRequest({sessionId,requestId,binding,message});sessionId=request.sessionId;
    const trustedPersona=Object.freeze({id:binding.shopUserId,role:'customer'});
    let prepared,cap,protection,stamp;
    try{
      const outcome=await turns.run(sessionId,binding,trustedPersona,{signal,idempotencyKey:request.requestId,conversationPurpose:PURPOSE,
        admit:async()=>{
          // Capture only after the shared coordinator acquires the turn lease;
          // a queued request must not retain a pre-queue mode/source snapshot.
          cap=await authority.capture({scope:binding,persona:trustedPersona,personaSession,sessionId,signal});
          protection=disclosureFor(cap,{sessionId,role:'customer',callerId:binding.shopUserId});stamp=protection.metadata;
          await protection.check();prepared=await admission.prepare({sessionId,requestId:request.requestId,binding,message});
          if(prepared.status==='completed'){
            if(!isDeepStrictEqual(prepared.outcome.result?.taskMetadata?.customerDisclosure?.authority,stamp))throw fail('CUSTOMER_DISCLOSURE_REPLAY_STALE');
            return{skip:true,value:prepared.outcome};
          }
          return{skip:false,value:prepared};}},async execution=>{
        if(!prepared||prepared.status!=='claimed'||!execution.identity?.runId||!execution.identity?.ownerKey||execution.identity.durableGeneration==null)throw fail('CUSTOMER_DISCLOSURE_RUN_REQUIRED');
        const check=async()=>{await execution.check();await protection.check();execution.signal?.throwIfAborted();await execution.check();};
        return admission.execute(prepared,{...execution,check},async()=>{
          await observe({kind:'run',sessionId,requestId:request.requestId,run:copy(execution.identity),authority:stamp});
          await check();
          // Private message metadata never enters the provider transcript. Only
          // Fixed reads filter historical rows; vulnerable conversational memory
          // remains unchanged. Source/mode/session changes retire unsafe history.
          const scopedRepository={...repository,appendMessage:async(id,b,m,p)=>{
            await check();return repository.appendMessage(id,b,{...m,customerDisclosure:copy(stamp)},p);
          }};
          const scopedConversations={...conversations,getMessages:async(...args)=>{
            const rows=await conversations.getMessages(...args);await check();
            return rows.filter(row=>!protection.fixed||isDeepStrictEqual(row.customerDisclosure,stamp))
              .map(({customerDisclosure:_private,...row})=>row);
          }};
          const {store,Trace}=createBoundGraphStore({sessionId,scope:binding,persona:trustedPersona,
            service:scopedConversations,repository:scopedRepository,check,conversationPurpose:PURPOSE});
          const guardedPool=Object.create(pool);
          Object.defineProperty(guardedPool,'callTool',{value:async(...args)=>{
            await check();let result;
            try{result=await pool.callTool(...args);}catch(error){await check();if(!protection.fixed)throw error;throw fail('CUSTOMER_DISCLOSURE_TOOL_UNAVAILABLE');}
            await check();return protection.inspect(result);
          }});
          const supervisor=createCustomerSupervisor({store,Trace,checkToolAcl:async(...args)=>{
            await check();const result=await checkToolAcl(...args);await check();return result;
          },disclosureCapability:cap});
          const result=await supervisor.run(sessionId,message,{provider,pool:guardedPool,manifest,
            role:'customer',callerRole:'customer',callerId:binding.shopUserId,ownerId:binding.shopUserId,
            signal:execution.signal,check,effectWithReceipt:execution.effectWithReceipt});
          await check();
          return{...result,taskMetadata:{customerDisclosure:{version:1,authority:stamp,run:copy(execution.identity),
            canonicalCredit:false,semanticProtectionClaimed:false}}};
        },protection.fence);
      });
      await protection.check();
      if(!isDeepStrictEqual(outcome.result?.taskMetadata?.customerDisclosure?.authority,stamp))throw fail('CUSTOMER_DISCLOSURE_REPLAY_STALE');
      return{...outcome.result,replayed:outcome.replayed};
    }catch(error){await admission.abandon(prepared);throw error;}
  }});
}
module.exports={createOriginalCustomerDisclosureRuntime};
