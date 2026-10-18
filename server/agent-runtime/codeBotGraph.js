'use strict';
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { runToolLoop } = require('./toolLoopGraph');
async function runCodeBotGraph({ userMessage, conversationHistory, mode, userId }, {
  aiService, executeCodeBotTool, CODEBOT_TOOL_SCHEMAS, FIXED_SYSTEM_PROMPT, VULNERABLE_SYSTEM_PROMPT,
  tryParseTextToolCall, extractJsonFromMessage, logger, execution,
}) {
  const check = execution?.check || (async () => {});
  let rawModelResponse='',toolInvocations=[],modelIsReal=true,lastModelSource='model',repairContinuationAttempted=false;
  const observedModel={chatWithTools:async(...args)=>{const response=await aiService.chatWithTools(...args);lastModelSource=response?.mocked?'scripted':response?.fallback?'fallback':'model';if(lastModelSource!=='model')modelIsReal=false;const history=args[0],content=typeof response?.content==='string'?response.content.trim():'';if(Array.isArray(history)&&history.at(-1)?.role==='tool')for(const pending of toolInvocations.filter(call=>!call.continuation))pending.continuation={source:lastModelSource,kind:'tool_loop',observed:true,available:lastModelSource==='model'&&Boolean(content||response?.tool_calls?.length)};return response;}};
  const execute=async(name,params,mode,decision={source:lastModelSource,kind:'structured_tool_call',validated:lastModelSource==='model'})=>{await check();await execution?.trace?.({node:'codebot_tool',type:'node_start',data:{tool:name}});try{if(name==='check_dependencies'){params=require('./codeBotManifestBinding').bindManifest(userMessage,params);if(calledToolName===name)calledParams=params;}const result=await executeCodeBotTool(name,params,mode,{ownerId:userId,executeTransform:execution?.executeCodeBotTransform,adoptEffect:execution?.adoptCodeBotEffect});const invocation=JSON.parse(JSON.stringify({name,params,result,decision}));execution?.adoptCodeBotEffect?.(result,invocation.result);toolInvocations.push(invocation);await check();await execution?.trace?.({node:'codebot_tool',type:'node_end',data:{tool:name,decisionSource:decision.source}});return result;}catch(error){await execution?.trace?.({node:'codebot_tool',type:'error',data:{tool:name,errorCode:error.code||'TOOL_FAILED'}});throw error;}};
  let finalResponse = '', toolResult = null, calledToolName = null, calledParams = null;
    const systemPrompt = mode === 'fixed' ? FIXED_SYSTEM_PROMPT : VULNERABLE_SYSTEM_PROMPT;

    // Build messages array for /api/chat
    const messages = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.slice(-8).map(m => ({ role: m.role, content: m.content })),
      { role: 'user', content: userMessage }
    ];

  const continueAfterRepair=async(kind)=>{
    repairContinuationAttempted=true;
    const invocation=toolInvocations.at(-1);
    const callId=`codebot_repair_${toolInvocations.length}`;
    messages.push({role:'assistant',content:'',tool_calls:[{id:callId,type:'function',function:{name:calledToolName,arguments:JSON.stringify(calledParams||{})}}]});
    messages.push({role:'tool',tool_call_id:callId,content:JSON.stringify(toolResult)});
    await check();
    await execution?.trace?.({node:'repair_continuation',type:'node_start',data:{tool:calledToolName,decisionSource:invocation?.decision?.source||'unavailable'}});
    try{
      const answer=await observedModel.chatWithTools(messages,[],{temperature:0.3,signal:execution?.signal,trace:execution?.trace});
      await check();
      const continuationSource=lastModelSource;
      const content=typeof answer?.content==='string'?answer.content.trim():'';
      const repeatedToolCall=Array.isArray(answer?.tool_calls)&&answer.tool_calls.length>0;
      invocation.continuation={source:continuationSource,kind,observed:true,available:continuationSource==='model'&&Boolean(content)&&!repeatedToolCall};
      if(continuationSource!=='model'||!content||repeatedToolCall){
        modelIsReal=false;
        finalResponse='CodeBot completed the tool execution, but the model continuation is unavailable.';
        await execution?.trace?.({node:'repair_continuation',type:'error',data:{tool:calledToolName,decisionSource:continuationSource,errorCode:repeatedToolCall?'REPEATED_TOOL_CALL_REJECTED':'MODEL_CONTINUATION_UNAVAILABLE'}});
        return;
      }
      finalResponse=content;
      rawModelResponse=content;
      await execution?.trace?.({node:'repair_continuation',type:'node_end',data:{tool:calledToolName,decisionSource:'model'}});
    }catch(error){
      if(error?.name==='AbortError'||execution?.signal?.aborted)throw error;
      modelIsReal=false;
      invocation.continuation={source:'unavailable',kind,observed:true,available:false};
      finalResponse='CodeBot completed the tool execution, but the model continuation is unavailable.';
      await execution?.trace?.({node:'repair_continuation',type:'error',data:{tool:calledToolName,decisionSource:'unavailable',errorCode:error.code||'MODEL_CONTINUATION_FAILED'}});
    }
  };


  const snapshot = () => ({ finalResponse, toolResult, calledToolName, calledParams, rawModelResponse, toolInvocations,modelIsReal });
  const State = Annotation.Root(Object.fromEntries(['finalResponse', 'toolResult', 'calledToolName', 'calledParams','rawModelResponse','toolInvocations','modelIsReal'].map(key => [key, Annotation()])));
  const graph = new StateGraph(State)
    .addNode('tool_loop', async () => {
      const loop = await runToolLoop({ messages, tools: CODEBOT_TOOL_SCHEMAS, model: observedModel, maxIterations: 3, check, signal: execution?.signal, trace: execution?.trace,
        summaryPrompt: 'Please summarize the result for me.',
        executeCall: async (tc, messages) => {
          calledToolName = tc.function.name;
          calledParams = typeof tc.function.arguments === 'string' ? JSON.parse(tc.function.arguments) : tc.function.arguments || {};
          toolResult = await execute(calledToolName, calledParams, mode, {source:lastModelSource,kind:'structured_tool_call',validated:lastModelSource==='model'});
          logger.info('tool_call', { workshop: 'supply_chain', userId, tool: calledToolName, security: toolResult && toolResult.security, mode, via: 'agentic_loop' });
          messages.push({ role: 'tool', content: JSON.stringify(toolResult).substring(0, 1500) });
        },
      });
      finalResponse = loop.finalResponse;
      rawModelResponse=loop.finalResponse||'';
      return snapshot();
    })
    .addNode('text_parse', async () => {
      await check();
    // ── Detect if LLM returned a tool call as raw JSON text ───────────────────
    // Llama 3.1:8b sometimes returns {"name":"check_dependencies","parameters":{...}}
    // instead of a proper tool_calls object. Parse and execute when detected.
    if (finalResponse && !calledToolName) {
      const textCall = tryParseTextToolCall(finalResponse, userMessage);
      if (textCall) {
        calledToolName = textCall.name;
        calledParams = textCall.params || {};
        toolResult = await execute(calledToolName, calledParams, mode, {source:lastModelSource,kind:'text_tool_call_repair',validated:lastModelSource==='model'});
        logger.info('tool_call', { workshop: 'supply_chain', userId, tool: calledToolName, security: toolResult && toolResult.security, mode, via: 'text_parse_fallback' });
        await continueAfterRepair('text_tool_call_repair');
      }
    }


      return snapshot();
    })
    .addNode('manifest_retry', async () => {
      await check();
    // Ask the model to explicitly authorize repair of a missing/malformed tool call.
    // LLM may respond without calling the tool, OR it may call check_dependencies
    // but pass a malformed manifest (Llama 3.1:8b sometimes mis-escapes JSON strings).
    // In either case, re-run with the manifest extracted directly from the user message.
    const shouldRetryWithManifest = !calledToolName ||
      (calledToolName === 'check_dependencies' && toolResult && toolResult.security === 'error' && /^Failed to parse manifest:/.test(toolResult.error || ''));

    if (shouldRetryWithManifest) {
      const parsedManifest = extractJsonFromMessage(userMessage);
      const looksLikeManifest = parsedManifest && (
        parsedManifest.name || parsedManifest.version || parsedManifest.dependencies
      );
      let repairDecision=null;
      if (looksLikeManifest && await approveManifestRepair({ aiService, execution, messages, onNonModel:()=>{modelIsReal=false;},onDecision:value=>{repairDecision=value;} })) {
        calledToolName = 'check_dependencies';
        calledParams = { manifest: JSON.stringify(parsedManifest) };
        const source=repairDecision?.source||'unavailable';
        toolResult = await execute('check_dependencies', calledParams, mode, {source,kind:'manifest_repair_authorization',validated:source==='model'&&repairDecision?.action==='check_dependencies'});
        logger.info('tool_call', { workshop: 'supply_chain', userId, tool: 'check_dependencies', security: toolResult && toolResult.security, mode, via: aiService.provider==='mock'?'mock_manifest_decision':'model_manifest_repair' });
        await continueAfterRepair('manifest_repair_authorization');
      }
    }


      return snapshot();
    })
    .addNode('fallback', () => {
    // ── Fallback: Ollama unavailable or no response for non-manifest messages ──
    if (toolResult?.security === 'unavailable') {
      finalResponse = toolResult.message;
    } else if (toolResult?.security === 'error' && toolResult.execution_attempted) {
      finalResponse = `CodeBot attempted the transform in the isolated lab, but execution failed: ${toolResult.error || 'execution failed'}`;
    } else if (!finalResponse) {
      if (
        /what\s+(tools|capabilities|functions|commands|can\s+you\s+do)/i.test(userMessage) ||
        /list\s+(tools|capabilities|your\s+tools)/i.test(userMessage) ||
        /what\s+can\s+you\s+do/i.test(userMessage)
      ) {
        finalResponse = `I have **3 tools** available:\n\n1. **\`review_code(code, language)\`**\n   Review source code for bugs, style issues, and best practices.\n\n2. **\`check_dependencies(manifest)\`**\n   Analyze a \`package.json\` manifest for dependency health.\n\n3. **\`explain_error(error_message)\`**\n   Explain runtime errors with common causes and suggested fixes.\n\nSend me a \`package.json\` to analyze, a code snippet to review, or an error message to explain.`;
      } else if (
        /(internal|internally)\s*(lib|package|depend|module|version)/i.test(userMessage) ||
        /(check_depend|dep.*check).*(use|using|package|lib|internal)/i.test(userMessage) ||
        /what\s+(packages|libraries|deps|dependencies|modules)\s+(does|do|are|is)\s+(check_depend|internal|used|it\s+use)/i.test(userMessage)
      ) {
        if (mode === 'vulnerable') {
          finalResponse = `The \`check_dependencies\` tool uses the following internal packages for manifest parsing and validation:\n\n| Package | Version | Purpose |\n|---------|---------|----------|\n| **pkg-parse** | **1.2.0** | Fictional training parser — reads and normalizes \`package.json\` fields |\n| semver | 7.5.0 | Semantic version range validation |\n| validate-npm-package-name | 5.0.0 | Package name conformance checking |\n| json-schema | 0.4.0 | JSON Schema validation for manifest structure |\n\n\`pkg-parse@1.2.0\` is curriculum data, and its vulnerable transform behavior runs only in the disposable lab.`;
        } else {
          finalResponse = 'I cannot share implementation details. Please try again.';
        }
      } else {
        finalResponse = mode === 'fixed'
          ? 'An error occurred. Please try again.'
          : `Hi! I'm CodeBot. Send me a \`package.json\` to analyze dependencies, a code snippet for review, or an error message to explain.`;
      }
    }

    // ── In vulnerable mode, ensure RCE output appears in the response ─────────
    if (!repairContinuationAttempted && mode === 'vulnerable' && toolResult && toolResult.security === 'rce_executed') {
      const probe = toolResult.transform_output.substring(0, 30).toLowerCase().replace(/\s+/g, ' ').trim();
      if (probe && !finalResponse.toLowerCase().includes(probe)) {
        finalResponse += `\n\n${toolResult.transform_output}`;
      }
    }


      return snapshot();
    })
    .addEdge(START, 'tool_loop')
    .addConditionalEdges('tool_loop', state => state.finalResponse && !state.calledToolName ? 'text_parse' : 'manifest_retry', ['text_parse', 'manifest_retry'])
    .addEdge('text_parse', 'manifest_retry').addEdge('manifest_retry', 'fallback').addEdge('fallback', END).compile();
  return graph.invoke({}, { recursionLimit: 6 });
}
async function approveManifestRepair({aiService,execution,messages,onNonModel,onDecision}) {
  if(aiService.provider==='mock'){onNonModel?.();onDecision?.({source:'scripted',action:'check_dependencies',attempt:1});await execution?.trace?.({node:'manifest_decision',type:'decision',data:{decisionSource:'scripted',tool:'check_dependencies'}});return true;}
  for(let attempt=1;attempt<=2;attempt++){
    await execution?.check?.();
    await execution?.trace?.({node:'manifest_decision',type:'node_start',data:{attempt}});
    const response=await aiService.chatWithTools([...messages,{role:'system',content:'You are selecting an action, not answering the user. Decide whether this request requires check_dependencies. Return only JSON {"action":"check_dependencies"} or {"action":"none"}. Select none if declining the request. Do not include arguments; the original manifest is preserved by the server.'}],[],{temperature:0,signal:execution?.signal,format:{type:'object',properties:{action:{type:'string',enum:['check_dependencies','none']}},required:['action'],additionalProperties:false}});
    await execution?.check?.();
    let action;try{const value=JSON.parse(response.content);if(Object.keys(value).length===1&&['none','check_dependencies'].includes(value.action))action=value.action;}catch{}
    const nonModel=Boolean(response.mocked||response.fallback);
    if(nonModel){onNonModel?.();action='none';}
    const source=nonModel?'fallback':'model';
    await execution?.trace?.({node:'manifest_decision',type:action?'decision':'error',data:{attempt,decisionSource:source,action:action||'invalid'}});
    if(action)onDecision?.({source,action,attempt});
    if(action)return action==='check_dependencies';
  }
  return false;
}
module.exports = { runCodeBotGraph, approveManifestRepair };
