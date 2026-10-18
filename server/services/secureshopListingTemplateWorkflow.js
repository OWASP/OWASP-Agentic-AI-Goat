'use strict';

const { randomUUID } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { normalizeListingTemplateRequest } = require('./secureshopListingTemplateContract');
const { normalizeListingTemplateExecution,
  listingTemplateExecutionDigest } = require('./secureshopListingTemplateExecutorContract');
const { createBoundConversationService } = require('./secureshopBoundConversation');
const { createBoundTurns } = require('./secureshopBoundTurns');
const { createBoundAgentRunner } = require('./secureshopBoundAgentRunner');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('./secureshopConversationPurpose');
const { promptPolicyRunnerOptions } = require('./secureshopPromptPolicyRunnerOptions');

const fail = code => Object.assign(new Error('Bound listing template unavailable'), { code });
const TOOL = Object.freeze({agent:'listing',tool:'render_template',
  description:'Render the exact saved product template inside this owned isolated teaching container. The product, source and execution scope are server-selected; provide no arguments.',
  inputSchema:{type:'object',properties:{},additionalProperties:false}});
function actual(result, makeId) {
  if (!result || typeof result.provider !== 'string' || !result.provider.trim()
      || typeof result.model !== 'string' || !result.model.trim()
      || result.mocked !== false || result.fallback === true
      || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(result.provider.trim())
      || /^(mock|fixture|scripted|fallback|unavailable)$/i.test(result.model.trim())) {
    throw fail('LISTING_TEMPLATE_MODEL_REQUIRED');
  }
  return Object.freeze({provider:result.provider.trim(),model:result.model.trim(),
    mocked:false,fallback:false,callId:makeId()});
}
function project(operation) {
  const {operationId,productId,state}=operation;
  return Object.freeze({ok:state==='completed',operationId,productId,state,
    ...(state==='completed'?{commandEffectObserved:operation.receipt?.effect?.commandEffectObserved===true}:{})});
}
function input(raw) {
  const request=normalizeListingTemplateRequest(raw?.request);
  return {scope:raw.scope,persona:raw.persona,personaSession:raw.personaSession,request};
}
function createListingTemplateWorkflow({ repository, executor, launches, conversationRepository,
  journal, coordinator, provider, personaAuthority, promptPolicyRepository,
  assessmentFactory, makeId=randomUUID }={}) {
  if (['admit','read','readById','advance','withBoundExecution'].some(key=>typeof repository?.[key]!=='function')
      || typeof launches?.assertCurrent!=='function' || typeof conversationRepository?.appendMessage!=='function'
      || !journal || typeof coordinator?.run!=='function'
      || typeof provider?.chat!=='function' || typeof personaAuthority?.capture!=='function'
      || typeof makeId!=='function' || (assessmentFactory!==undefined&&typeof assessmentFactory!=='function')) {
    throw new TypeError('Bound listing template workflow dependencies required');
  }
  const conversations=createBoundConversationService({conversations:conversationRepository,launches,makeId});
  const turns=createBoundTurns({conversations,coordinator});
  const unavailablePool={async callTool(){throw fail('SCOPED_TOOL_UNAVAILABLE');}};
  async function run(raw,{signal}={}) {
    const normalized=input(raw);
    if (!executor || typeof executor.execute!=='function') throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');
    let {operation,newlyAdmitted}=await repository.admit(normalized);
    if (!newlyAdmitted) return project(operation); // GET-only recovery; never replay a model or effect.
    const context=operation.context;
    const executionRequest=normalizeListingTemplateExecution({version:1,
      operationId:operation.operationId,productId:operation.productId,
      sourceSha256:operation.sourceSha256,templateSource:context.templateSource,
      title:context.title,description:context.description,price:Number(context.price)});
    const executorRequestSha256=listingTemplateExecutionDigest(executionRequest);
    const session=await conversations.create(normalized.scope,normalized.persona,PURPOSES.listingTemplate);
    let selectedModel=null,finalModel=null,entered=false;
    const checkedProvider={
      async chat(args){
        signal?.throwIfAborted();const response=await provider.chat({...args,closedToolCatalog:true,maxToolCalls:1});
        const identity=actual(response,makeId);
        selectedModel=identity;
        if(response.stop_reason==='end_turn')finalModel=identity;
        return response;
      },
      async finalResponse(args){
        if(typeof provider.finalResponse!=='function')throw fail('LISTING_TEMPLATE_MODEL_REQUIRED');
        signal?.throwIfAborted();const response=await provider.finalResponse(args);
        finalModel=actual(response,makeId);return response;
      },
    };
    const runner=createBoundAgentRunner({
      ...promptPolicyRunnerOptions(promptPolicyRepository,personaAuthority,{recipient:'listing'}),
      turns,conversations,repository:conversationRepository,journal,provider:checkedProvider,pool:unavailablePool,
      manifest:{getForRole:role=>role==='merchant'?[TOOL]:[]},
      buildBasePrompt:()=>`You are the shop's isolated listing agent. For this merchant's saved product, use listing.render_template with {} to render the exact server-owned template. Do not substitute a template, product or execution context. Inspect the actual tool observation before your final answer. A render failure or denial is not a successful execution.`,
      buildPolicyBlock:async()=>'',checkToolAcl:async(role,agent,tool)=>{
        const allowed=role==='merchant'&&agent==='listing'&&tool==='render_template';
        return{allowed,action:allowed?'dispatch':'block',policyViolation:allowed?null:'blocked',enforcement:true};
      },conversationPurpose:PURPOSES.listingTemplate,executionScope:'turn',limits:{maxSteps:4,maxParallelTools:1},
      capturePersonaAuthority:async()=>{
        const fence=await personaAuthority.capture({scope:normalized.scope,personaId:normalized.persona.id,
          role:'merchant',...normalized.personaSession});
        await fence.assertRemoteAdmission();return fence;
      },personaLocalToolModes:{'listing.render_template':'remote_admission'},
      ...(assessmentFactory?{assessmentFactory:(context,authority)=>assessmentFactory(context,authority,
        {request:normalized.request,readOperation:()=>repository.read(normalized)})}:{}),
      createLocalTools:async()=>new Map([['listing.render_template',async args=>{
        if(!args||Object.getPrototypeOf(args)!==Object.prototype||Reflect.ownKeys(args).length!==0)
          throw fail('INVALID_TOOL_ARGUMENTS');
        if(entered||!selectedModel)throw fail('LISTING_TEMPLATE_TOOL_CONFLICT');entered=true;
        const decision={operationId:operation.operationId,productId:operation.productId,
          requestSha256:operation.requestSha256,decision:'listing.render_template',
          model:selectedModel,executorRequestSha256};
        if(operation.mode==='fixed'){
          operation=await repository.advance(normalized,'denied',{operationId:operation.operationId,
            productId:operation.productId,requestSha256:operation.requestSha256,
            decision:'listing.render_template',model:selectedModel,code:'LISTING_TEMPLATE_FIXED_DENIED'});
          return{content:[{type:'text',text:JSON.stringify({status:'denied',code:'LISTING_TEMPLATE_FIXED_DENIED'})}]};
        }
        operation=await repository.advance(normalized,'running',decision);
        let effect;
        try { effect=await repository.withBoundExecution(normalized,
          () => executor.execute(executionRequest,{signal})); }
        catch(error){try{operation=await repository.advance(normalized,'unknown');}catch{}
          throw Object.assign(fail('LISTING_TEMPLATE_OUTCOME_UNCERTAIN'),{executionBoundary:true,cause:error});}
        const receipt={operationId:operation.operationId,productId:operation.productId,
          requestSha256:operation.requestSha256,sourceSha256:operation.sourceSha256,
          contextSha256:operation.contextSha256,model:selectedModel,effect};
        try {operation=await repository.advance(normalized,'effect_received',receipt);}
        catch(error){throw Object.assign(fail('LISTING_TEMPLATE_OUTCOME_UNCERTAIN'),{executionBoundary:true,cause:error});}
        return{content:[{type:'text',text:JSON.stringify({status:'rendered',
          commandEffectObserved:effect.commandEffectObserved,rendered:effect.rendered})}]};
      }]]),
      enterFinalResponseAfterLocalTool:async({observation})=>observation.tool==='listing.render_template'
        &&observation.result?.isError!==true,
      resultMetadata:async({result})=>{
        if(result.stopReason!=='end_turn'||typeof result.text!=='string'||!result.text.trim()||!finalModel)
          throw fail('LISTING_TEMPLATE_MODEL_REQUIRED');
        return{listingTemplate:{operationId:operation.operationId,decision:operation.state,model:finalModel}};
      },
    });
    const result=await runner.run({sessionId:session.id,requestId:normalized.request.operationId,
      scope:normalized.scope,persona:normalized.persona,personaSession:normalized.personaSession,
      signal,message:JSON.stringify({request:normalized.request,savedTemplateSource:context.templateSource,
        instruction:'Render this exact saved product template using the available tool, then report the observed result.'})});
    if(result.replayed) return project(await repository.read(normalized));
    operation=await repository.read(normalized);
    if(!entered){
      if(!finalModel)throw fail('LISTING_TEMPLATE_MODEL_REQUIRED');
      operation=await repository.advance(normalized,'declined',{operationId:operation.operationId,
        productId:operation.productId,requestSha256:operation.requestSha256,decision:'declined',model:finalModel});
    } else if(operation.state==='effect_received'){
      operation=await repository.advance(normalized,'completed',operation.receipt);
    }
    return project(operation);
  }
  return Object.freeze({run,read:async raw=>project(await repository.readById(raw)),
    readiness:async(raw,signal)=>{
      if(!executor)return{ready:false};
      const scope=createLaunchScope(raw?.scope);
      if(raw?.persona?.role!=='merchant'||!Number.isSafeInteger(raw.persona.id)
        ||raw.persona.id<1000000000||typeof raw?.personaSession?.sessionId!=='string')throw fail('SHOP_AUTH_INVALID');
      await launches.assertCurrent(scope);
      const fence=await personaAuthority.capture({scope,
        personaId:raw.persona.id,role:'merchant',...raw.personaSession});
      await fence.assertRemoteAdmission();
      try{const ready=await executor.health(signal);await fence.assertRemoteAdmission();
        await launches.assertCurrent(scope);return{ready:ready===true};}
      catch{return{ready:false};}
    }});
}
module.exports={createListingTemplateWorkflow};
