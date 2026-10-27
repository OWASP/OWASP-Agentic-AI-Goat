'use strict';
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { DynamicStructuredTool } = require('@langchain/core/tools');
const { z } = require('zod');
const { parseWorkflowRoute } = require('./providers/workflowRouteContract');
const FINAL_RESPONSE_INSTRUCTION = 'The requested server observation is complete. Answer the current request using the latest tool result, do not request another tool, and do not add facts absent from that result.';
const VALID_PROVIDER_CALL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RECOVERABLE_EXTERNAL_TOOL_ERRORS = Object.freeze({
  INVALID_TOOL_ARGUMENTS: 'Selected tool arguments were rejected before execution.',
  INVALID_TOOL_SELECTION: 'Selected tool was rejected before execution.',
});

const POLICY_RECEIPT_FIELDS = Object.freeze(['admissionId', 'runId', 'invocationId', 'toolKey',
  'policyVersion', 'registrySha256', 'enforcement', 'allowed', 'action', 'policyViolation']);
function snapshotPolicyArgs(value) {
  const seen = new Set();
  let nodes = 0;
  function clone(item, depth) {
    if (depth > 24 || ++nodes > 4096) throw new TypeError('Tool arguments exceed policy bounds');
    if (item === null || typeof item === 'string' || typeof item === 'boolean') return item;
    if (typeof item === 'number' && Number.isFinite(item)) return item;
    if (!item || typeof item !== 'object' || seen.has(item)) throw new TypeError('Invalid policy tool arguments');
    seen.add(item);
    let result;
    if (Array.isArray(item)) result = item.map(child => clone(child, depth + 1));
    else if (Object.getPrototypeOf(item) === Object.prototype) {
      result = Object.fromEntries(Object.entries(item).map(([key, child]) => [key, clone(child, depth + 1)]));
    } else throw new TypeError('Invalid policy tool arguments');
    seen.delete(item);
    return Object.freeze(result);
  }
  const result = clone(value, 0);
  if (Buffer.byteLength(JSON.stringify(result)) > 65536) throw new TypeError('Tool arguments exceed policy bounds');
  return result;
}
function policyReceipt(decision, context) {
  if (decision.admission === undefined) return null;
  const receipt = structuredClone(decision.admission);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const invalid = () => { throw Object.assign(new Error('Invalid policy admission receipt'), { code: 'SECURESHOP_INVALID_POLICY_ADMISSION', executionBoundary: true }); };
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)
    || Object.keys(receipt).sort().join(',') !== [...POLICY_RECEIPT_FIELDS].sort().join(',')
    || typeof receipt.admissionId !== 'string' || !uuid.test(receipt.admissionId)
    || typeof receipt.runId !== 'string' || !uuid.test(receipt.runId)
    || typeof receipt.invocationId !== 'string' || receipt.invocationId !== `${context.step}:${context.callId}`
    || !VALID_PROVIDER_CALL_ID.test(context.callId || '') || receipt.invocationId.length > 256
    || typeof receipt.toolKey !== 'string' || receipt.toolKey.length > 160
    || !/^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/.test(receipt.toolKey)
    || typeof receipt.policyVersion !== 'string' || !/^[1-9]\d{0,18}$/.test(receipt.policyVersion)
    || BigInt(receipt.policyVersion) > 9223372036854775807n
    || typeof receipt.registrySha256 !== 'string' || !/^[0-9a-f]{64}$/.test(receipt.registrySha256)
    || typeof receipt.enforcement !== 'boolean' || typeof receipt.allowed !== 'boolean'
    || receipt.action !== (receipt.allowed || !receipt.enforcement ? 'dispatch' : 'block')
    || receipt.policyViolation !== (receipt.allowed ? null : 'denied-by-acl')
    || receipt.action !== (decision.action === 'log' ? 'dispatch' : decision.action)
    || decision.allowed !== receipt.allowed || decision.enforcement !== receipt.enforcement
    || decision.policyViolation !== receipt.policyViolation) invalid();
  return Object.freeze(receipt);
}

// Shared supervisor graph. Verbatim tool results and advisory ACL behavior are
// deliberate SecureShop teaching sinks; never sanitize or enforce them here.
function createSupervisorGraph({ store, Trace, buildBasePrompt, buildPolicyBlock, checkToolAcl }) {
  const { appendUserMessage, appendAssistantMessage, appendAssistantToolCalls, appendToolResult, getMessages,
    remainingBudget, addUsedTokens } = store;
  const estimateTokens = value => value ? Math.ceil((typeof value === 'string' ? value : JSON.stringify(value)).length / 4) : 0;
  const freezeTree = value => {
    if (value && typeof value === 'object') {
      for (const child of Object.values(value)) freezeTree(child);
      Object.freeze(value);
    }
    return value;
  };
  const extractToolText = value => !value ? '' : typeof value === 'string' ? value
    : Array.isArray(value.content) ? value.content.filter(p => p && p.type === 'text').map(p => p.text || '').join('\n') : JSON.stringify(value);
  const configuredIdentity = provider => ({
    provider: provider?.config?.provider || provider?.provider || null,
    model: provider?.config?.model || provider?.model || provider?.modelId || null,
    mocked: provider?.config?.provider === 'mock' || provider?.provider === 'mock' ? true : null,
  });
  return async function run(sessionId, userMessage, opts, limits) {
    const { provider, pool, manifest, stream = null, role, policyDbPath, callerRole = null, callerId = null,
      signal = null, ownerId = callerId } = opts;
    if (!provider || !pool || !manifest) throw new Error(`${role}Supervisor.run requires provider, pool and manifest`);
    const consumption = opts.consumptionCapability !== undefined || opts.consumptionRequired !== undefined
      ? require('../services/secureshopCustomerConsumptionAuthority').consumptionFor(opts.consumptionCapability,
        {sessionId,role,callerId}) : null;
    const reservedToolResults=new Set();
    const persist = async (method,args,message) => {
      if(consumption){await consumption.check();
        if(method!=='appendToolResult'||!reservedToolResults.delete(args[0]))consumption.append(message);}
      return store[method](sessionId,...args);
    };
    const appendUserMessage=(_id,text)=>persist('appendUserMessage',[text],{role:'user',content:text});
    const appendAssistantMessage=(_id,text)=>persist('appendAssistantMessage',[text],{role:'assistant',content:text});
    const appendToolResult=(_id,id,text)=>persist('appendToolResult',[id,text],{role:'tool',tool_call_id:id,content:text});
    const appendAssistantToolCalls=(_id,calls)=>persist('appendAssistantToolCalls',[calls],{role:'assistant',content:'',
      tool_calls:calls.map(call=>({id:call.id,type:'function',function:{name:call.name,arguments:JSON.stringify(call.args||{})}}))});
    const check = opts.check;
    const effect = opts.effect;
    const effectWithReceipt = opts.effectWithReceipt;
    const onLocalToolObservation = opts.onLocalToolObservation;
    const onExternalToolObservation = opts.onExternalToolObservation;
    const enterFinalResponseAfterExternalTool = opts.enterFinalResponseAfterExternalTool;
    const shouldEnterFinalResponse = opts.shouldEnterFinalResponse;
    const finalResponseAfterBlockedLocalTool = opts.finalResponseAfterBlockedLocalTool === true;
    const finalResponseAfterBlockedUnknownTool = opts.finalResponseAfterBlockedUnknownTool === true;
    const terminalAfterLocalTool=opts.terminalAfterLocalTool;
    const onFinalDecision=opts.onFinalDecision;
    const decisionRouting=opts.decisionRouting;
    if ((check !== undefined && typeof check !== 'function') || (effect !== undefined && typeof effect !== 'function')
      || (effectWithReceipt !== undefined && typeof effectWithReceipt !== 'function')
      || (onLocalToolObservation !== undefined && typeof onLocalToolObservation !== 'function')
      || (onExternalToolObservation !== undefined && typeof onExternalToolObservation !== 'function')
      || (enterFinalResponseAfterExternalTool !== undefined && typeof enterFinalResponseAfterExternalTool !== 'function')
      || (terminalAfterLocalTool !== undefined && typeof terminalAfterLocalTool !== 'function')
      || (onFinalDecision !== undefined && typeof onFinalDecision !== 'function')
      || (shouldEnterFinalResponse !== undefined && typeof shouldEnterFinalResponse !== 'function')
      || (opts.finalResponseAfterBlockedLocalTool !== undefined
        && (typeof opts.finalResponseAfterBlockedLocalTool !== 'boolean'
          || (finalResponseAfterBlockedLocalTool && typeof shouldEnterFinalResponse !== 'function')))
      || (decisionRouting !== undefined && (typeof provider.routeWorkflow !== 'function'
        || !decisionRouting || Object.getPrototypeOf(decisionRouting)!==Object.prototype
        || Object.keys(decisionRouting).sort().join(',')!=='families,system,version'
        || decisionRouting.version!==1 || typeof decisionRouting.system!=='string'
        || !decisionRouting.system.trim() || Buffer.byteLength(decisionRouting.system,'utf8')>4096
        || !decisionRouting.families || Object.getPrototypeOf(decisionRouting.families)!==Object.prototype
        || Object.keys(decisionRouting.families).sort().join(',')!=='management,registered_tools'
        || Object.values(decisionRouting.families).some(names=>!Array.isArray(names)||!names.length
          ||names.length>64||names.some(name=>typeof name!=='string'||!/^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/.test(name)))))
      || (opts.finalResponseAfterBlockedUnknownTool !== undefined
        && (typeof opts.finalResponseAfterBlockedUnknownTool !== 'boolean'
          || (finalResponseAfterBlockedUnknownTool && typeof shouldEnterFinalResponse !== 'function')))) {
      throw new TypeError('Invalid server execution boundary');
    }
    const assertExecution = async () => {
      signal?.throwIfAborted();
      if(consumption)await consumption.check();
      if (check) {
        try { await check(); }
        catch (cause) {
          const error = new Error('Execution authority unavailable', { cause });
          error.name = cause?.name || 'Error';
          error.code = cause?.code;
          error.executionBoundary = true;
          throw error;
        }
      }
      signal?.throwIfAborted();
    };
    // Server-created closures capture authority outside model messages/state.
    // Snapshot the registry so asynchronous callers cannot swap executors.
    const localTools = new Map(opts.localTools instanceof Map ? opts.localTools : Object.entries(opts.localTools || {}));
    const externalToolErrorProjector = typeof pool.projectRecoverableToolError === 'function'
      ? pool.projectRecoverableToolError.bind(pool) : null;
    for (const [name, execute] of localTools) {
      if (!/^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/.test(name) || typeof execute !== 'function') {
        throw new TypeError('Invalid local tool executor');
      }
    }
    const { maxSteps, maxParallelTools } = limits;
    let localObservationIndex = 0;let externalObservationIndex=0;
    const effectiveCallerRole = callerRole || role;
    const trace = new Trace(sessionId);
    let normalTraceFlushStarted = false;
    const State = Annotation.Root(Object.fromEntries(['step', 'remaining', 'routePending', 'llmResp', 'latency', 'finalText', 'stopReason', 'hops', 'modelProvider', 'modelName', 'modelMocked', 'modelFallback', 'finalResponseRequired', 'continueAfterFinal'].map(key => [key, Annotation()])));
    let systemPrompt, tools, routedTools;
    const graph = new StateGraph(State)
      .addNode('initialize', async () => {
        if (check) await check();
        if(!consumption?.fixed)await appendUserMessage(sessionId, userMessage);
        const externalMcpBlock = typeof manifest.buildExternalMcpPromptBlock === 'function' ? await manifest.buildExternalMcpPromptBlock() : '';
        systemPrompt = buildBasePrompt(role, { extra: await buildPolicyBlock(role, { dbPath: policyDbPath }), externalMcpBlock });
        tools = manifest.getForRole(role);
        if(consumption?.fixed){await consumption.check();
          consumption.input({system:systemPrompt,messages:await getMessages(sessionId),tools,role,max_tokens:2048,ownerId});
          await appendUserMessage(sessionId,userMessage);}
        if(decisionRouting){
          if(!Array.isArray(tools)||!tools.length)throw new TypeError('Routed task catalog required');
          const byName=new Map();
          for(const tool of tools){
            const name=`${tool?.agent}.${tool?.tool}`;
            if(!/^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/.test(name)||byName.has(name))
              throw new TypeError('Invalid routed task catalog');
            byName.set(name,freezeTree(structuredClone(tool)));
          }
          const claimed=new Set();routedTools={};
          for(const family of ['management','registered_tools']){
            routedTools[family]=Object.freeze(decisionRouting.families[family].map(name=>{
              if(!byName.has(name)||claimed.has(name))throw new TypeError('Invalid routed task family');
              claimed.add(name);return byName.get(name);
            }));
          }
          if(claimed.size!==byName.size)throw new TypeError('Incomplete routed task catalog');
          Object.freeze(routedTools);
        }
        return { step: 0, finalText: '', stopReason: null, hops: [], modelProvider: null,
          modelName: null, modelMocked: null, modelFallback: false, finalResponseRequired: false,
          routePending:!!decisionRouting, continueAfterFinal: false };
      })
      .addNode('budget', async state => {
        // A configured task reserves the last bounded model step for a real
        // tools-empty response after its authoritative observation completes.
        const toolStepLimit = (shouldEnterFinalResponse || enterFinalResponseAfterExternalTool)
          ? maxSteps - 1 : maxSteps;
        if ((state.finalResponseRequired !== true && state.step >= toolStepLimit)
            || (state.finalResponseRequired === true && state.step >= maxSteps)) {
          const finalText = '[max steps reached]';
          await appendAssistantMessage(sessionId, finalText);
          return { finalText, stopReason: 'max_steps' };
        }
        const remaining = await remainingBudget(sessionId);
        return { step: state.step + 1, remaining, continueAfterFinal: false,
          ...(remaining <= 0 ? { finalText: '[max steps reached: token budget exhausted]', stopReason: 'budget_exhausted' } : {}) };
      })
      .addNode('route_model', async state => {
        const step=state.step,configured=configuredIdentity(provider);
        trace.record({step,actor:'supervisor',kind:'llm_call_start',provider:configured.provider,
          result_json:configured.model?JSON.stringify({model:configured.model,mocked:configured.mocked,phase:'workflow_route'}):null});
        let response,usageDebited=false;
        try {
          await assertExecution();
          const routeInput={system:decisionRouting.system,
            messages:[{role:'user',content:userMessage}],role,max_tokens:Math.min(state.remaining,256),signal,ownerId};
          if(consumption)consumption.input(routeInput);
          response=await provider.routeWorkflow(routeInput);
          await assertExecution();
          const decision=response?.decision&&Object.getPrototypeOf(response.decision)===Object.prototype
            ?parseWorkflowRoute(response.decision):null;
          const usage=response?.usage;
          const tokenCount=value=>value===null||(Number.isSafeInteger(value)&&value>=0);
          if(response?.responseMode!=='decision_routing_v1'||!decision
            ||typeof response.provider!=='string'||!response.provider
            ||typeof response.model!=='string'||!response.model
            ||typeof response.mocked!=='boolean'||response.fallback!==undefined&&typeof response.fallback!=='boolean'
            ||!usage||Object.keys(usage).sort().join(',')!=='attempts,inputTokens,outputTokens,totalTokens'
            ||!['inputTokens','outputTokens','totalTokens'].every(key=>tokenCount(usage[key]))
            ||usage.attempts!==1)throw Object.assign(new Error('Invalid workflow route decision'),
              {code:'SECURESHOP_INVALID_DECISION',usage});
          if(decision.route!=='clarification')tools=routedTools[decision.route];
          trace.record({step,actor:'supervisor',kind:'model_route',provider:response.provider,
            result_json:JSON.stringify({decision:decision.route,...(decision.route==='clarification'?{text:decision.message}:{}),
              model:response.model,mocked:response.mocked,...(response.fallback?{fallback:true}:{})}),
            tokens_in:usage.inputTokens,tokens_out:usage.outputTokens});
          usageDebited=true;
          await addUsedTokens(sessionId,usage.outputTokens===null?estimateTokens(decision):usage.outputTokens);
          if(decision.route==='clarification'){
            await appendAssistantMessage(sessionId,decision.message);
            trace.record({step,actor:'supervisor',kind:'final'});
          }
          return{routePending:false,modelProvider:response.provider,modelName:response.model,
            modelMocked:response.mocked,modelFallback:response.fallback===true,
            ...(decision.route==='clarification'?{finalText:decision.message,stopReason:'end_turn'}:{})};
        } catch(error) {
          const usage=error?.usage||response?.usage;
          const outputTokens=Number.isSafeInteger(usage?.outputTokens)&&usage.outputTokens>=0?usage.outputTokens:null;
          const inputTokens=Number.isSafeInteger(usage?.inputTokens)&&usage.inputTokens>=0?usage.inputTokens:null;
          if(outputTokens!==null&&!usageDebited)await addUsedTokens(sessionId,outputTokens);
          const actualProvider=typeof error?.provider==='string'&&error.provider?error.provider
            :typeof response?.provider==='string'&&response.provider?response.provider:configured.provider;
          const actualModel=typeof error?.model==='string'&&error.model?error.model
            :typeof response?.model==='string'&&response.model?response.model:configured.model;
          const actualMocked=typeof error?.mocked==='boolean'?error.mocked
            :typeof response?.mocked==='boolean'?response.mocked:configured.mocked;
          trace.record({step,actor:'supervisor',kind:'error',provider:actualProvider,
            tokens_in:inputTokens,tokens_out:outputTokens,
            result_json:JSON.stringify({errorCode:error?.name==='AbortError'||signal?.aborted?'ABORTED'
              :error?.executionBoundary?'EXECUTION_AUTHORITY_UNAVAILABLE'
                :error?.code==='SECURESHOP_INVALID_DECISION'?'SECURESHOP_INVALID_DECISION'
                  :error?.code==='SECURESHOP_ROUTE_UNSUPPORTED'?'SECURESHOP_ROUTE_UNSUPPORTED':'PROVIDER_ERROR',
              phase:'workflow_route',model:actualModel,mocked:actualMocked})});
          throw error;
        }
      })
      .addNode('model', async state => {
        const step = state.step;
        const finalResponseRequired = state.finalResponseRequired === true;
        const configured = configuredIdentity(provider);
        trace.record({ step, actor: 'supervisor', kind: 'llm_call_start', tokens_in: null,
          provider: configured.provider,
          result_json: configured.model ? JSON.stringify({ model: configured.model, mocked: configured.mocked }) : null });
        const messages = await getMessages(sessionId), started = Date.now();
        try {
          await assertExecution();
          const modelInput = { system: finalResponseRequired
            ? `${systemPrompt}\n\n${FINAL_RESPONSE_INSTRUCTION}` : systemPrompt,
          messages, role, max_tokens: Math.min(state.remaining, 2048), signal, ownerId };
          if(consumption)consumption.input(finalResponseRequired?modelInput:{...modelInput,tools});
          if (finalResponseRequired && typeof provider.finalResponse !== 'function') {
            throw Object.assign(new Error('Structured final response capability unavailable'), {
              code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED',
            });
          }
          const llmResp = finalResponseRequired
            ? await provider.finalResponse(modelInput)
            : await provider.chat({ ...modelInput, tools });
          // A provider may resolve at the same moment its owner is cancelled.
          // Never route that stale decision into dispatch.
          await assertExecution();
          // A router may select a different backend from its configured
          // preference. The identity on the successful response is the actual
          // backend; configured identity is only a fallback for direct adapters.
          const modelProvider = llmResp.provider || configured.provider || null;
          const modelName = llmResp.model || configured.model || null;
          const modelMocked = typeof llmResp.mocked === 'boolean' ? llmResp.mocked : configured.mocked;
          const modelFallback = llmResp.fallback === true;
          const toolUses = Array.isArray(llmResp.tool_uses) ? llmResp.tool_uses : [];
          const isToolDecision = llmResp.stop_reason === 'tool_use';
          trace.record({
            step,
            actor: 'supervisor',
            kind: 'model_decision',
            provider: modelProvider,
            ...(isToolDecision ? {
              params_json: JSON.stringify({ decision: 'tool_use', toolCalls: toolUses.map(call => ({
                id: call.id || null, name: call.name || null, args: call.args || {},
              })) }),
            } : {
              result_json: JSON.stringify({ decision: 'final', text: llmResp.text || '',
                stopReason: llmResp.stop_reason || 'unknown', model: modelName, mocked: modelMocked, ...(modelFallback ? { fallback: true } : {}),
                ...(finalResponseRequired && Number.isSafeInteger(llmResp.usage?.attempts)
                  ? { providerAttempts: llmResp.usage.attempts } : {}),
                ...(finalResponseRequired && llmResp.usage?.complete === false
                  ? { usageComplete: false } : {}) }),
            }),
            ...(!isToolDecision ? {} : { result_json: JSON.stringify({ model: modelName, mocked: modelMocked, ...(modelFallback ? { fallback: true } : {}) }) }),
            ...(finalResponseRequired && Number.isSafeInteger(llmResp.usage?.inputTokens)
              ? { tokens_in: llmResp.usage.inputTokens } : {}),
            ...(finalResponseRequired && Number.isSafeInteger(llmResp.usage?.outputTokens)
              ? { tokens_out: llmResp.usage.outputTokens } : {}),
          });
          await addUsedTokens(sessionId, finalResponseRequired && Number.isSafeInteger(llmResp.usage?.outputTokens)
            ? llmResp.usage.outputTokens : estimateTokens(llmResp.text || JSON.stringify(llmResp)));
          if (finalResponseRequired && (llmResp.stop_reason !== 'end_turn'
              || llmResp.responseMode !== 'structured_final' || toolUses.length !== 0
              || typeof llmResp.text !== 'string' || !llmResp.text.trim())) {
            throw Object.assign(new Error('Final response decision is invalid'), { code: 'SECURESHOP_INVALID_DECISION' });
          }
          return { llmResp, latency: Date.now() - started, modelProvider, modelName, modelMocked, modelFallback };
        } catch (error) {
          // Current-authority failures must never become a normal model stop.
          if (error?.executionBoundary === true) throw error;
          const cancelled = error?.name === 'AbortError' || signal?.aborted;
          const failedOutputTokens = finalResponseRequired
            && Number.isSafeInteger(error?.usage?.outputTokens) && error.usage.outputTokens >= 0
            ? error.usage.outputTokens : null;
          const failedInputTokens = finalResponseRequired
            && Number.isSafeInteger(error?.usage?.inputTokens) && error.usage.inputTokens >= 0
            ? error.usage.inputTokens : null;
          const failedAttempts = finalResponseRequired
            && Number.isSafeInteger(error?.usage?.attempts) && error.usage.attempts >= 1
            ? error.usage.attempts : null;
          if (failedOutputTokens !== null) await addUsedTokens(sessionId, failedOutputTokens);
          // Provider SDK failures can contain request URLs, local paths or
          // credentials. These traces and terminal messages are learner-visible.
          // Preserve deliberate raw *tool* observations, but project platform
          // failures to a stable public category instead of SDK exception text.
          const errorCode = cancelled ? 'ABORTED'
            : error?.executionBoundary ? 'EXECUTION_AUTHORITY_UNAVAILABLE'
              : error?.code === 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED' ? 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED'
              : error?.code === 'SECURESHOP_INVALID_DECISION' ? 'SECURESHOP_INVALID_DECISION' : 'PROVIDER_ERROR';
          const publicMessage = cancelled ? 'request cancelled'
            : errorCode === 'EXECUTION_AUTHORITY_UNAVAILABLE' ? 'Execution authority unavailable'
              : errorCode === 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED' ? 'AI provider final response unavailable'
              : errorCode === 'SECURESHOP_INVALID_DECISION' ? 'AI provider returned an invalid decision'
                : 'AI provider unavailable';
          trace.record({ step, actor: 'supervisor', kind: 'error', provider: configured.provider,
            ...(failedInputTokens !== null ? { tokens_in: failedInputTokens } : {}),
            ...(failedOutputTokens !== null ? { tokens_out: failedOutputTokens } : {}),
            result_json: JSON.stringify({ message: publicMessage,
              errorCode, model: configured.model, mocked: configured.mocked,
              ...(failedAttempts !== null ? { providerAttempts: failedAttempts } : {}),
              ...(finalResponseRequired && error?.usage?.complete === false
                ? { usageComplete: false } : {}) }) });
          return { finalText: `[${publicMessage}]`, stopReason: cancelled ? 'cancelled' : 'error',
            modelProvider: configured.provider, modelName: configured.model, modelMocked: configured.mocked };
        }
      })
      .addNode('dispatch_tools', async state => {
        const { step, latency } = state;
        const hops = [];
        const selectedCalls = Array.isArray(state.llmResp.tool_uses) ? state.llmResp.tool_uses : [];
        if(decisionRouting&&selectedCalls.some(call=>!tools.some(tool=>call?.name===`${tool.agent}.${tool.tool}`)))
          throw Object.assign(new Error('Tool outside selected workflow route'),{code:'SECURESHOP_INVALID_DECISION'});
        const calls = selectedCalls.slice(0, maxParallelTools).map(call => Object.freeze({ ...call,
          args: snapshotPolicyArgs(call.args || {}) }));
        const omittedCalls = selectedCalls.slice(maxParallelTools);
        let cancelledBeforeEffect = false;
        let finalResponseRequired = false;
        const identity = call => ({ id: call.id || null, name: call.name || null });
        trace.record({
          step,
          actor: 'supervisor',
          kind: 'dispatch_plan',
          params_json: JSON.stringify({ selected: selectedCalls.map(identity) }),
          result_json: JSON.stringify({
            execute: calls.map(identity),
            omitted: omittedCalls.map(identity),
            omissionReason: omittedCalls.length ? 'max_parallel_tools' : null,
            maxParallelTools,
          }),
        });
        await appendAssistantToolCalls(sessionId, calls);
        let terminalToolOutcome=null;
        const dispatchOne = async call => {
        const [namespace, toolName] = String(call.name).includes('.')
          ? String(call.name).split('.', 2)
          : [call.name, ''];
        const ns = namespace;
        const tn = toolName || call.tool || '';
        const localExecute = call.name === `${ns}.${tn}` ? localTools.get(call.name) : undefined;
        const executionKind = localExecute ? 'local_tool' : 'mcp';

        // External effects require a stable provider-issued identity so their
        // durable receipt can be joined to exactly one model decision. Keep
        // this opt-in: existing local callbacks retain their prior semantics.
        if (!localExecute && onExternalToolObservation && !VALID_PROVIDER_CALL_ID.test(call.id || '')) {
          throw Object.assign(new Error('External tool call identity is invalid'), {
            code: 'SECURESHOP_INVALID_DECISION',
          });
        }

        const cancelCall = async (phase, policyViolation = null) => {
          cancelledBeforeEffect = true;
          const cancellationText = JSON.stringify({ error: 'request-cancelled', code: 'ABORTED', phase });
          const toolResult = { content: [{ type: 'text', text: cancellationText }], isError: true };
          trace.record({ step, actor: 'supervisor→task', kind: 'tool_cancelled', agent_ns: ns, tool_name: tn,
            params_json: JSON.stringify(call.args || {}), result_json: JSON.stringify({ errorCode: 'ABORTED', phase }) });
          await appendToolResult(sessionId, call.id, cancellationText);
          const hop = { step, tool: `${ns}.${tn}`, params: call.args || {}, result: toolResult,
            latencyMs: 0, error: { message: 'request-cancelled', code: 'ABORTED' }, policyViolation };
          hops.push(hop);
          if (stream) stream.send('tool_result', { id: call.id, tool: `${ns}.${tn}`, result: toolResult,
            latencyMs: 0, step, policyViolation });
          return hop;
        };

        if (signal?.aborted) return cancelCall('before_acl');

        // M14 Layer B — ACL check BEFORE dispatch. Returns one of:
        //   { action:'dispatch', policyViolation:null }         → normal
        //   { action:'log',      policyViolation:'denied-by-acl'} → LLM06 sink,
        //     runtime still calls the tool but the trace is annotated.
        //   { action:'block',    policyViolation:'blocked' }    → enforcement
        //     enabled; the tool is NOT called and a synthetic error result is
        //     returned to the LLM.
        let aclDecision;
        try {
          const context = Object.freeze({ callId: call.id, step, args: call.args });
          aclDecision = await checkToolAcl(effectiveCallerRole, ns, tn, context);
          const admission = policyReceipt(aclDecision, context);
          if (admission) {
            trace.record({ step, actor: 'supervisor', kind: 'policy_decision', agent_ns: ns, tool_name: tn,
              params_json: JSON.stringify({ callId: context.callId, step, admission }),
              policy_violation: admission.policyViolation });
          }
        } catch (error) {
          if (error?.name === 'AbortError' || signal?.aborted) return cancelCall('during_acl');
          throw error;
        }
        if (signal?.aborted) return cancelCall('after_acl', aclDecision.policyViolation);
        try { await assertExecution(); }
        catch (error) {
          if (error?.name === 'AbortError' || signal?.aborted) return cancelCall('after_acl', aclDecision.policyViolation);
          throw error;
        }
        if (stream) {
          stream.send('tool_call', {
            id: call.id, tool: `${ns}.${tn}`, params: call.args, step,
            policyViolation: aclDecision.policyViolation,
          });
        }
        if (signal?.aborted) return cancelCall('before_effect', aclDecision.policyViolation);

        if (aclDecision.action === 'block') {
          // Enforcement mode — refuse the call outright. Return a synthetic
          // error result so the LLM sees the denial and can respond.
          const denialText = JSON.stringify({
            error: 'blocked-by-acl',
            message: `Policy denied ${ns}.${tn} for role=${effectiveCallerRole}`,
          });
          const toolResult = { content: [{ type: 'text', text: denialText }], isError: true };
          trace.record({
            step,
            actor: 'task→supervisor',
            kind: 'tool_blocked',
            agent_ns: ns,
            tool_name: tn,
            result_json: JSON.stringify(toolResult),
            latency_ms: 0,
            policy_violation: 'blocked',
          });
          await appendToolResult(sessionId, call.id, denialText);
          const hop = {
            step, tool: `${ns}.${tn}`, params: call.args || {},
            result: toolResult, latencyMs: 0, error: { message: 'blocked-by-acl' },
            policyViolation: 'blocked',
          };
          hops.push(hop);
          // An opted-in local workflow can reserve its last model call to
          // explain this real denial. This is routing only: no local executor,
          // effect receipt, evidence observer, or success terminal is invoked.
          const unknownTool = !tools.some(tool => `${tool.agent}.${tool.tool}` === `${ns}.${tn}`);
          if (((localExecute && finalResponseAfterBlockedLocalTool)
            || (unknownTool && finalResponseAfterBlockedUnknownTool)) && shouldEnterFinalResponse) {
            await assertExecution();
            const observation = Object.freeze({ index: localObservationIndex++, step,
              callId: call.id, tool: `${ns}.${tn}`,
              args: freezeTree(JSON.parse(JSON.stringify(call.args || {}))),
              result: freezeTree(JSON.parse(JSON.stringify(toolResult))), effectReceipt: null });
            finalResponseRequired = await shouldEnterFinalResponse(observation) === true || finalResponseRequired;
            await assertExecution();
          }
          if (stream) {
            stream.send('tool_result', {
              id: call.id, tool: `${ns}.${tn}`, result: toolResult, latencyMs: 0, step,
              policyViolation: 'blocked',
            });
          }
          return hop;
        }



        // Dispatch (allowed OR denied-by-acl-but-not-enforced — see LLM06).
        const ct0 = Date.now();
        let toolResult;
        let toolError = null;
        let toolInvocationError;
        let effectReceipt = null;
        let recoverableExternalError = false;
        try {
          const tool = new DynamicStructuredTool({
            name: `${ns}.${tn}`, description: 'Invoke the selected teaching tool without changing its arguments.',
            schema: z.any(),
            func: async args => {
              const invoke = async () => {
                await assertExecution();
                trace.record({
                  step,
                  actor: 'supervisor→task',
                  kind: `${executionKind}_call`,
                  agent_ns: ns,
                  tool_name: tn,
                  params_json: JSON.stringify(call.args || {}),
                  latency_ms: latency,
                  policy_violation: aclDecision.policyViolation,
                });
                try {
                  return await (localExecute ? localExecute(args, Object.freeze({callId:call.id,step,tool:call.name})) : pool.callTool(ns, tn, args, {
                    callerRole: effectiveCallerRole, callerId,policyViolation:aclDecision.policyViolation,
                    callId:call.id,
                  }));
                } catch (error) { toolInvocationError = error; throw error; }
              };
              await assertExecution();
              const key = JSON.stringify([step, call.id, `${ns}.${tn}`]);
              if (effectWithReceipt) {
                const outcome = await effectWithReceipt(key, invoke);
                effectReceipt = outcome?.receipt || null;
                return outcome?.value;
              }
              return effect ? effect(key, invoke) : invoke();
            },
          });
          toolResult = await tool.invoke(call.args || {});
        } catch (e) {
          if (e?.name === 'AbortError' || e?.executionBoundary || e?.code === 'GRAPH_EFFECT_REPLAY_BLOCKED'
            || ((effect || effectWithReceipt) && e !== toolInvocationError)) throw e;
          const projectedCode = !localExecute && e === toolInvocationError && effectReceipt === null
            && externalToolErrorProjector ? externalToolErrorProjector(e) : null;
          if (projectedCode !== null) {
            if (typeof projectedCode !== 'string'
              || !Object.hasOwn(RECOVERABLE_EXTERNAL_TOOL_ERRORS, projectedCode)) {
              throw new TypeError('Invalid recoverable external tool error projection');
            }
            const publicMessage = RECOVERABLE_EXTERNAL_TOOL_ERRORS[projectedCode];
            recoverableExternalError = true;
            toolError = { message: publicMessage, code: projectedCode };
            toolResult = { content: [{ type: 'text', text: JSON.stringify({
              ok: false, code: projectedCode, error: publicMessage,
            }) }], isError: true };
          } else {
            toolError = { message: e.message };
            toolResult = { content: [{ type: 'text', text: `ERROR: ${e.message}` }], isError: true };
          }
        }
        if (recoverableExternalError) await assertExecution();
        const clat = Date.now() - ct0;
        const resultJson = JSON.stringify(toolResult);
        if(consumption){await consumption.check();consumption.tool(resultJson);
          const text=extractToolText(toolResult);consumption.tool(text);
          consumption.append({role:'tool',tool_call_id:call.id,content:text});reservedToolResults.add(call.id);}
        trace.record({
          step,
          actor: 'task→supervisor',
          kind: `${executionKind}_result`,
          agent_ns: ns,
          tool_name: tn,
          result_json: resultJson,
          latency_ms: clat,
          policy_violation: aclDecision.policyViolation,
        });
        if (!localExecute&&!recoverableExternalError&&onExternalToolObservation&&typeof call.id==='string'&&call.id.length>0) {
          await assertExecution();
          const externalRecord = await onExternalToolObservation(Object.freeze({index:externalObservationIndex++,step,callId:call.id,
            tool:`${ns}.${tn}`,args:freezeTree(JSON.parse(JSON.stringify(call.args||{}))),
            result:freezeTree(JSON.parse(resultJson)),effectReceipt}));
          if (enterFinalResponseAfterExternalTool && !toolError && toolResult?.isError !== true) {
            await assertExecution();
            finalResponseRequired = await enterFinalResponseAfterExternalTool(Object.freeze({
              observation: Object.freeze({ step, callId: call.id, tool: `${ns}.${tn}`, args: call.args || {},
                result: toolResult, effectReceipt }), externalRecord,
            })) === true || finalResponseRequired;
          }
          await assertExecution();
        }
        if (recoverableExternalError) await assertExecution();
        // Invalid/missing provider call IDs cannot form an evidentiary link.
        if (localExecute && (onLocalToolObservation || shouldEnterFinalResponse || terminalAfterLocalTool)
            && typeof call.id === 'string' && call.id.length > 0) {
          await assertExecution();
          const observation = Object.freeze({
            index: localObservationIndex++, step, callId: call.id, tool: `${ns}.${tn}`,
            args: freezeTree(JSON.parse(JSON.stringify(call.args || {}))),
            result: freezeTree(JSON.parse(resultJson)), effectReceipt,
          });
          if (onLocalToolObservation) await onLocalToolObservation(observation);
          if(terminalAfterLocalTool){const terminal=await terminalAfterLocalTool(observation);if(terminal!==null&&terminal!==undefined){if(calls.length!==1||terminalToolOutcome||Object.keys(terminal).sort().join(',')!=='source,stopReason,text'||terminal.source!=='server'||terminal.stopReason!=='tool_denied'||typeof terminal.text!=='string'||!terminal.text||Buffer.byteLength(terminal.text)>1024)throw TypeError('Invalid terminal tool outcome');terminalToolOutcome=terminal;trace.record({step,actor:'server',kind:'local_tool_terminal',result_json:JSON.stringify(terminal)});}}
          if (!terminalToolOutcome && shouldEnterFinalResponse) {
            finalResponseRequired = await shouldEnterFinalResponse(observation) === true || finalResponseRequired;
          }
          await assertExecution();
        }
        // Append tool result VERBATIM — see JSDoc header, this is the MCP-05 sink.
        await appendToolResult(sessionId, call.id, extractToolText(toolResult));
        await addUsedTokens(sessionId, estimateTokens(resultJson));

        const hop = {
          step,
          tool: `${ns}.${tn}`,
          params: call.args || {},
          result: toolResult,
          latencyMs: clat,
          error: toolError,
          policyViolation: aclDecision.policyViolation, // null | 'denied-by-acl'
        };
        hops.push(hop);
        if (stream) {
          stream.send('tool_result', {
            id: call.id, tool: `${ns}.${tn}`, result: toolResult, latencyMs: clat, step,
            policyViolation: aclDecision.policyViolation,
          });
        }
        return hop;
        };
        if (consumption?.fixed) {
          // Finish validation and persistence before admitting another Fixed
          // effect. Promise.all can otherwise leave a sibling writing after
          // the graph has rejected a result that exceeds the byte budget.
          for (const call of calls) await dispatchOne(call);
        } else {
          // Preserve concurrent dispatch for the original teaching path.
          await Promise.all(calls.map(dispatchOne));
        }
        const cancelled = cancelledBeforeEffect || signal?.aborted;
        return { hops: [...state.hops, ...hops],
          ...(terminalToolOutcome?{finalText:terminalToolOutcome.text,stopReason:terminalToolOutcome.stopReason}:{}),
          finalResponseRequired: state.finalResponseRequired === true || finalResponseRequired,
          ...(cancelled
          ? { finalText: '[request cancelled]', stopReason: 'cancelled' } : {}) };
      })
      .addNode('finalize', async state => {
        const finalText = state.llmResp.text || '', stopReason = state.llmResp.stop_reason || 'unknown';
        if (onFinalDecision && stopReason === 'end_turn' && state.finalResponseRequired !== true) {
          await assertExecution();
          const admission = await onFinalDecision(Object.freeze({ step: state.step,
            text: finalText, stopReason, hops: Object.freeze([...state.hops]) }));
          await assertExecution();
          if (admission !== null && admission !== undefined) {
            const keys = Object.keys(admission).sort().join(',');
            if (!admission || Object.getPrototypeOf(admission) !== Object.prototype
              || !['continue','incomplete'].includes(admission.action)
              || typeof admission.reason !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(admission.reason)
              || !Number.isSafeInteger(admission.completedCount) || admission.completedCount < 0
              || admission.completedCount > 32 || !Number.isSafeInteger(admission.remainingCount)
              || admission.remainingCount < 0 || admission.remainingCount > 32
              || keys !== (admission.action === 'continue'
                ? 'action,completedCount,feedback,reason,remainingCount'
                : 'action,completedCount,reason,remainingCount,text')
              || (admission.action === 'continue' && (typeof admission.feedback !== 'string'
                || !admission.feedback.trim() || Buffer.byteLength(admission.feedback) > 1024))
              || (admission.action === 'incomplete' && (typeof admission.text !== 'string'
                || !admission.text.trim() || Buffer.byteLength(admission.text) > 1024))) {
              throw new TypeError('Invalid final decision admission');
            }
            trace.record({ step: state.step, actor: 'supervisor', kind: 'final_admission',
              result_json: JSON.stringify({ version: 1, action: admission.action,
                reason: admission.reason, completedCount: admission.completedCount,
                remainingCount: admission.remainingCount }) });
            if (admission.action === 'continue') {
              await appendUserMessage(sessionId, admission.feedback);
              return { continueAfterFinal: true, finalText: '', stopReason: null };
            }
            const incomplete = admission.text;
            await appendAssistantMessage(sessionId, incomplete);
            return { continueAfterFinal: false, finalText: incomplete, stopReason: 'incomplete' };
          }
        }
        await appendAssistantMessage(sessionId, finalText);
        if (stopReason === 'end_turn') trace.record({ step: state.step, actor: 'supervisor', kind: 'final' });
        return { finalText, stopReason, continueAfterFinal: false };
      })
      .addNode('emit', async state => {
        trace.record({
          step: state.step,
          actor: 'supervisor',
          kind: 'terminal',
          provider: state.modelProvider || null,
          result_json: JSON.stringify({ stopReason: state.stopReason || 'unknown', steps: state.step,
            hops: state.hops.length, model: state.modelName || null,
            mocked: typeof state.modelMocked === 'boolean' ? state.modelMocked : null,
            ...(state.modelFallback === true ? { fallback: true } : {}) }),
        });
        normalTraceFlushStarted = true;
        await trace.flush();
        if (stream) {
          stream.send('assistant_message', { text: state.finalText, stopReason: state.stopReason, hops: state.hops.length });
          stream.send('done', { sessionId, stopReason: state.stopReason, steps: state.step });
        }
        return {};
      })
      .addEdge(START, 'initialize').addEdge('initialize', 'budget')
      .addConditionalEdges('budget', state => state.stopReason ? 'emit' : state.routePending?'route_model':'model', ['emit','route_model','model'])
      .addConditionalEdges('route_model',state=>state.stopReason?'emit':'budget',['emit','budget'])
      .addConditionalEdges('model', state => state.stopReason ? 'emit' : state.llmResp.stop_reason === 'tool_use' ? 'dispatch_tools' : 'finalize', ['emit', 'dispatch_tools', 'finalize'])
      .addConditionalEdges('dispatch_tools', state => state.stopReason ? 'emit' : 'budget', ['emit', 'budget'])
      .addConditionalEdges('finalize', state => state.continueAfterFinal ? 'budget' : 'emit', ['budget', 'emit'])
      .addEdge('emit', END).compile();
    let result;
    try {
      result = await graph.invoke({}, { recursionLimit: maxSteps * 3 + 6 });
    } catch (error) {
      if (!normalTraceFlushStarted) {
        try {
          await assertExecution();
          await trace.flush();
        } catch {
          // Preserve the graph failure. Trace persistence is best effort here,
          // and its own authority checks must fail closed after reset/revocation.
        }
      }
      throw error;
    }
    return { sessionId, text: result.finalText, stopReason: result.stopReason, hops: result.hops, steps: result.step };
  };
}
module.exports = { createSupervisorGraph, FINAL_RESPONSE_INSTRUCTION,
  validatePolicyAdmissionReceipt: policyReceipt };
