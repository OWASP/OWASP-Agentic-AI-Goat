'use strict';
const {createHash}=require('node:crypto');
const {projectRecentWorkshopHistory}=require('./workshopHistoryProjection');
const compiledGraphs=new Map();
const MAX_TOOL_STEPS=4,MAX_RESPONSE_PROMPT_CHARS=24000,TRUNCATION_MARKER='...[TRUNCATED FOR MODEL CONTEXT]';
const MUTATING_TOOLS={ARIA:new Set(['add_to_cart','remove_from_cart','checkout','return_refund','update_address']),NOVA:new Set(['add_to_reading_list','remove_from_reading_list'])};
function stableJson(value){if(Array.isArray(value))return `[${value.map(stableJson).join(',')}]`;if(value&&typeof value==='object')return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;return JSON.stringify(value);}
function decisionKey(tool,params){return `${tool}:${createHash('sha256').update(stableJson(params||{})).digest('hex')}`;}
function effectKey(step,tool,params){return `tool:${step}:${decisionKey(tool,params)}`;}
function boundedProjection(value,max=8000){const text=JSON.stringify(value);if(typeof text!=='string'||text.length<=max)return value;return {boundedExcerpt:text.slice(0,max-TRUNCATION_MARKER.length)+TRUNCATION_MARKER};}
function boundedHistory(history,max=5000){return projectRecentWorkshopHistory(history,{maxChars:max});}

function terminationData(state) {
  if (state.decisionSource === 'scripted') return {};
  if (state.blocked) return { errorCode: 'REQUEST_BLOCKED', toolSteps: state.toolSteps || 0 };
  const terminationReason = ['duplicate_observation', 'duplicate_mutation'].includes(state.stopReason) ? 'duplicate_action'
      : state.stopReason === 'decision_unavailable' ? 'decision_unavailable'
        : state.toolSteps >= MAX_TOOL_STEPS ? 'tool_budget'
          : state.intent?.tool === 'general_chat' ? 'model_finished' : null;
  return terminationReason ? { terminationReason, toolSteps: state.toolSteps || 0 } : {};
}

/**
 * Stateless pilot graph. Database history remains authoritative; there is no
 * checkpoint/replay of mutating tools. Scripted/mock runs execute one selected
 * tool; real-provider runs may execute a bounded observation-driven sequence.
 * Provider credentials remain in the existing provider adapter, outside state.
 */
function createWorkshopGraph(adapter) {
  const { createRunCoordinator } = require('./runCoordinator');
  const coordinator = createRunCoordinator({ family: adapter.name, ledger: adapter.runLedger,
    defaultTimeoutMs: adapter.defaultTimeoutMs });
  const node = (name, fn) => async (state, config) => {
    const execution = config.configurable.execution;
    await execution.check();
    const started=Date.now();
    await execution.trace({node:name,type:'node_start'});
    try {
      const result = await fn(state, config);
      await execution.checkpoint(name);
      await execution.trace({node:name,type:'node_end',data:{durationMs:Date.now()-started,...(name === 'persist' ? terminationData(state) : {})}});
      return result;
    } catch(error) {
      try { await execution.trace({node:name,type:'error',data:{errorCode:error.code||error.name,durationMs:Date.now()-started}}); } catch {}
      throw error;
    }
  };
  const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
  const { RunnableLambda } = require('@langchain/core/runnables');
  const fields = ['userId', 'message', 'mode', 'history', 'intent', 'blocked',
    'toolUsed', 'toolResult', 'toolObservations', 'toolSteps', 'stopReason', 'prompt', 'response', 'responseSource', 'responseErrorCode', 'rawDecision', 'decisionError', 'decisionAttempt', 'decisionSource', 'preparedPresentation', 'presentation'];
  const State = Annotation.Root(Object.fromEntries(fields.map(key => [key, Annotation()])));
  const model = RunnableLambda.from((prompt, config) => adapter.model.generateResponse(prompt,
    { temperature: 0.7, num_predict: 1500, signal: config.signal, ownerId: config.configurable?.ownerId }));
  const fallback = state => state.toolUsed === adapter.searchTool && state.mode === 'vuln'
    ? adapter.formatSearchResult(state.toolResult)
    : adapter.generateFallbackResponse(state.intent.tool, state.toolResult);

  const graph = new StateGraph(State)
    .addNode('load_history', node('load_history', async state => ({ history: await adapter.store.getHistory(state.userId, 12) })))
    .addNode('decide', node('decide', async(state,config)=>{
      const execution=config.configurable.execution;
      const scripted=adapter.decisionMode==='scripted' || adapter.model.provider==='mock';
      if(scripted){
        const intent=adapter.detectIntent(state.message);
        await execution.trace({node:'decide',type:'decision',data:{decisionSource:'scripted',tool:intent.tool,attempt:1}});
        return {rawDecision:intent,decisionAttempt:1,decisionSource:'scripted',decisionError:null};
      }
      const attempt=(state.decisionAttempt||0)+1;
      try{
        const decision=await require('./workshopDecisions').requestDecision(adapter,state,execution);
        await execution.trace({node:'decide',type:'decision',data:{decisionSource:'model',tool:decision.value?.tool,attempt,provider:decision.provider,model:decision.model,tokens:decision.tokens,durationMs:decision.durationMs}});
        return {rawDecision:decision.value,decisionAttempt:attempt,decisionSource:'model',decisionError:null};
      }catch(error){
        if(error.name==='AbortError'||['WORKSHOP_REQUEST_INVALID','WORKSHOP_REQUEST_TOO_LARGE','WORKSHOP_CONTEXT_TOO_LARGE'].includes(error.code))throw error;
        await execution.trace({node:'decide',type:'error',data:{decisionSource:'unavailable',attempt,errorCode:'DECISION_UNAVAILABLE'}});
        return {rawDecision:null,decisionAttempt:attempt,decisionSource:'unavailable',decisionError:'Return one valid JSON tool decision.'};
      }
    }))
    .addNode('validate',node('validate',state=>{
      try{
        if(state.decisionError)throw Error(state.decisionError);
        const intent=state.decisionSource==='scripted'?state.rawDecision:require('./workshopDecisions').validateDecision(adapter.name,state.rawDecision);
        adapter.validateDecision?.(state.message,intent);
        const blocked=adapter.blockedResponse(state.message,state.mode,intent);
        const duplicate=new Set((state.toolObservations||[]).map(item=>decisionKey(item.toolUsed,item.invocation?.params))).has(decisionKey(intent.tool,intent.params));
        const stopReason=duplicate?(MUTATING_TOOLS[adapter.name]?.has(intent.tool)?'duplicate_mutation':'duplicate_observation'):null;
        return {intent,blocked,response:blocked||'',decisionError:null,stopReason};
      }catch(error){return {decisionError:error?.code==='WORKSHOP_EXACT_SEARCH_MISMATCH'
        ? error.message : 'Tool or parameters do not match the catalog.'};}
    }))
    .addNode('decision_failed',node('decision_failed',state=>({intent:{tool:'general_chat',params:{}},decisionSource:'unavailable',blocked:false,stopReason:'decision_unavailable',response:(state.toolObservations||[]).length?'':'I could not validate a model tool decision. Please rephrase your request and try again.'})))
    .addNode('tool', node('tool', async (state, config) => {
      const toolUsed = state.intent.tool;
      const params=state.intent.params||{};
      try {
        const toolResult=await config.configurable.execution.effect(effectKey(state.toolSteps||0,toolUsed,params), async () => {
          const definition=require('./workshopDecisions').catalogFor(adapter.name)[toolUsed];
          const {DynamicStructuredTool}=require('@langchain/core/tools');
          const tool=new DynamicStructuredTool({name:toolUsed,description:definition.description,schema:state.decisionSource==='scripted'?require('zod').z.object({}).passthrough():definition.schema,func:params=>adapter.executeTool(toolUsed,params,state.userId,state.mode)});
          await config.configurable.execution.trace({node:'tool',type:'tool',data:{tool:toolUsed,decisionSource:state.decisionSource}});
          return tool.invoke(params);
        });
        const observation={index:state.toolSteps||0,effectKey:`${config.configurable.effectPrefix}:${effectKey(state.toolSteps||0,toolUsed,params)}`,toolUsed,toolResult,invocation:{tool:toolUsed,params,decisionSource:state.decisionSource}};
        return {toolUsed,toolResult,toolObservations:[...(state.toolObservations||[]),observation],toolSteps:(state.toolSteps||0)+1,decisionAttempt:0};
      } catch (error) {
        if (error.name === 'AbortError' || error.code === 'GRAPH_EFFECT_REPLAY_BLOCKED') throw error;
        const toolResult={error:error.message};
        const observation={index:state.toolSteps||0,effectKey:`${config.configurable.effectPrefix}:${effectKey(state.toolSteps||0,toolUsed,params)}`,toolUsed,toolResult,invocation:{tool:toolUsed,params,decisionSource:state.decisionSource}};
        return {toolUsed,toolResult,toolObservations:[...(state.toolObservations||[]),observation],toolSteps:(state.toolSteps||0)+1,decisionAttempt:0};
      }
    }))
    .addNode('build_prompt', node('build_prompt', async (state,config) => {
      if(adapter.formatObservation&&state.toolObservations?.length){
        const helper=require('./workshopResultPresentation');
        const preparedPresentation=helper.preparePresentation({family:adapter.name,runId:config.configurable.execution.runId,observations:state.toolObservations,formatObservation:adapter.formatObservation});
        return {preparedPresentation,prompt:helper.narrativePrompt({presentation:preparedPresentation,request:state.message,history:boundedHistory(state.history)})};
      }
      const history=boundedHistory(state.history),last=state.toolObservations?.at(-1);
      const lastResult=last?boundedProjection(last.toolResult):null;
      const observationExcerpt=boundedProjection(state.toolObservations);
      const prompt=last
        ? lastResult&&typeof lastResult==='object'&&Object.hasOwn(lastResult,'boundedExcerpt')
          ? `You are ${adapter.name}, a database-result formatter for an authorized security workshop. Present only the actual bounded tool observations below. State that the display is truncated; do not invent omitted rows, fields, or effects.\nUser request: ${JSON.stringify(state.message)}\nOrdered tool observations: ${JSON.stringify(observationExcerpt)}`
          : `${adapter.buildResponsePrompt(last.toolUsed,lastResult,state.message,history,state.mode)}\n\nOrdered tool observations (bounded for response model): ${JSON.stringify(observationExcerpt)}`
        : await adapter.buildGeneralChatPrompt(state.message,history);
      if(typeof prompt!=='string'||prompt.length>MAX_RESPONSE_PROMPT_CHARS){const error=new Error('Workshop response context exceeds the model input ceiling.');error.name='WorkshopContextError';error.code='WORKSHOP_CONTEXT_TOO_LARGE';throw error;}
      return {prompt};
    }))
    .addNode('model', node('model', async (state, config) => {
      try {
        const signal = config.configurable.execution.signal;
        const result = await new Promise((resolve, reject) => {
          const abort = () => reject(signal.reason);
          signal.addEventListener('abort', abort, { once: true });
          if (signal.aborted) return abort();
          model.invoke(state.prompt, { signal, configurable: { ownerId: state.userId } }).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
        });
        const responseText=typeof result?.response==='string'?result.response.trim():'';
        const unavailable=!result||result.fallback===true||!responseText;
        if(unavailable){
          await config.configurable.execution.trace({node:'model',type:'error',data:{errorCode:'MODEL_RESPONSE_UNAVAILABLE',responseSource:'fallback'}});
          return {response:fallback(state),responseSource:'fallback',responseErrorCode:'MODEL_RESPONSE_UNAVAILABLE'};
        }
        const resultProvider=String(result.provider||'').toLowerCase(),adapterProvider=String(adapter.model.provider||'').toLowerCase();
        const fixtureProvider=value=>/^(mock|fixture|controlled)(?:$|-)/.test(value);
        const fixture=result.mocked===true||fixtureProvider(resultProvider)||fixtureProvider(adapterProvider)||(!resultProvider&&!adapterProvider);
        const responseSource=fixture?'fixture':'model';
        const responseErrorCode=result.metadata?.done_reason==='length'?'MODEL_OUTPUT_LIMIT':null;
        await config.configurable.execution.trace({node:'model',type:'node_end',data:{provider:result.provider,model:result.model,tokens:result.tokens>0?result.tokens:undefined,responseSource,...(responseErrorCode?{errorCode:responseErrorCode}:{})}});
        return {response:responseText,responseSource,responseErrorCode};
      } catch (error) {
        await config.configurable.execution.trace({node:'model',type:'error',data:{errorCode:'MODEL_RESPONSE_ERROR',responseSource:'fallback'}});
        return {response:fallback(state),responseSource:'fallback',responseErrorCode:'MODEL_RESPONSE_ERROR'};
      }
    }))
    .addNode('persist', node('persist', async (state, config) => {
      const composed=state.preparedPresentation?require('./workshopResultPresentation').composePresentation(state.preparedPresentation,{text:state.responseSource==='fallback'?'':state.response,source:state.responseSource==='fallback'?'unavailable':state.responseSource,errorCode:state.responseErrorCode||null}):null;
      for (const [role, message] of [['user', state.message], ['assistant', composed?.response??state.response]]) {
        await config.configurable.execution.check();
        try { await config.configurable.execution.effect(`persist:${role}`, () => adapter.store.saveMessage(state.userId, role, message)); }
        catch (error) { if (!state.blocked) throw error; }
      }
      if(composed){const p=composed.presentation;await config.configurable.execution.trace({node:'presentation',type:'node_end',data:{presentationSnapshot:{version:p.version,narrativeSource:p.narrative.source,errorCode:p.narrative.errorCode,narrativeSha256:p.narrative.sha256,responseSha256:p.responseSha256,blocks:p.blocks}}});}
      return composed||{};
    }))
    .addEdge(START, 'load_history')
    .addEdge('load_history', 'decide')
    .addEdge('decide','validate')
    .addConditionalEdges('validate', state => state.decisionError ? (state.decisionAttempt<2?'decide':'decision_failed') : state.blocked ? 'persist'
      : state.stopReason||state.intent.tool === 'general_chat' ? 'build_prompt' : 'tool', ['decide','decision_failed','persist', 'build_prompt', 'tool'])
    .addConditionalEdges('decision_failed',state=>(state.toolObservations||[]).length?'build_prompt':'persist',['build_prompt','persist'])
    .addConditionalEdges('tool',state=>state.decisionSource==='scripted'||state.toolSteps>=MAX_TOOL_STEPS?'build_prompt':'decide',['build_prompt','decide'])
    .addEdge('build_prompt', 'model')
    .addEdge('model', 'persist')
    .addEdge('persist', END)
    .compile();
  compiledGraphs.set(adapter.name,graph);

  const invoke = (userId, message, mode = 'fixed', options = {}) => coordinator.run(userId, options, async originalExecution => {
    let execution=originalExecution;
    if(options.wrapExecution!==undefined){
      if(typeof options.wrapExecution!=='function')throw new TypeError('Execution wrapper must be a function');
      execution=options.wrapExecution(originalExecution);
      const identities=['runId','ownerKey','generation','durableGeneration','signal'];
      const methods=['check','effect','effectWithReceipt','checkpoint','trace'];
      if(!execution||identities.some(key=>execution[key]!==originalExecution[key])
        ||methods.some(key=>typeof originalExecution[key]==='function'&&typeof execution[key]!=='function'))
        throw new TypeError('Execution wrapper must preserve run authority and methods');
    }
    await options.onStart?.(execution);
    await execution.check();
    const result = await graph.invoke({ userId, message, mode, toolObservations:[], toolSteps:0, decisionAttempt:0 }, {
      recursionLimit: 40, configurable: { execution, effectPrefix:options.idempotencyKey||execution.runId },
    });
    const dto = { response: result.response, toolUsed: result.toolUsed||null, toolResult: result.toolResult??null, toolObservations:result.toolObservations||[],...(result.presentation?{presentation:result.presentation}:{}) };
    // Blocked and decision-failed paths bypass the formatter, so response
    // provenance is intentionally absent for those already-authored responses.
    if(options.includeRunMetadata)dto.run={runId:execution.runId,decisionSource:result.decisionSource,...(result.presentation?{responseComposition:result.presentation.version}:{}),
      ...(result.responseSource?{responseSource:result.responseSource}:{}),...(result.responseErrorCode?{responseErrorCode:result.responseErrorCode}:{})};
    if (options.onResult) {
      await execution.check();
      const lastObservation=result.toolObservations?.at(-1);
      await options.onResult(dto, execution.check, execution, {
        tool: lastObservation?.toolUsed||result.toolUsed||null,
        params:lastObservation?.invocation?.params||{},
        decisionSource:lastObservation?.invocation?.decisionSource||result.decisionSource,
      });
      await execution.check();
    }
    return dto;
  });
  return {
    // Client history is deliberately ignored, matching the workshop contract.
    chat: (userId, message, conversationHistory = [], mode = 'fixed') => invoke(userId, message, mode),
    invoke,
    cancel: userId => coordinator.cancel(userId),
    reset: (userId, resetStore) => coordinator.reset(userId, resetStore),
  };
}

function getWorkshopGraphDefinition(name='ARIA'){
 if(!['ARIA','NOVA'].includes(name))return null;
 if(!compiledGraphs.has(name))createWorkshopGraph({name,store:{},model:{provider:'mock'},decisionMode:'scripted'});
 return compiledGraphs.get(name).getGraph().toJSON();
}

module.exports = { createWorkshopGraph,getWorkshopGraphDefinition,decisionKey,effectKey,boundedProjection,boundedHistory,MAX_RESPONSE_PROMPT_CHARS };
