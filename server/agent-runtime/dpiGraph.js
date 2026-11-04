'use strict';
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
function compileDpiGraph(handlers) {
  const State = Annotation.Root({ needsJudge: Annotation() });
  return new StateGraph(State)
    .addNode('prepare', handlers.prepare).addNode('model', handlers.model)
    .addNode('detect', handlers.detect).addNode('judge', handlers.judge)
    .addNode('publication', handlers.publication)
    .addEdge(START, 'prepare').addEdge('prepare', 'model').addEdge('model', 'detect')
    .addConditionalEdges('detect', state => state.needsJudge ? 'publication' : END, ['publication', END])
    .addEdge('publication', 'judge').addEdge('judge', END).compile();
}
function getDpiGraphDefinition() {
  const deny = () => { throw new Error('Topology callbacks cannot execute'); };
  const graph = compileDpiGraph({prepare:deny,model:deny,detect:deny,judge:deny,publication:deny}).getGraph().toJSON();
  return { nodes: graph.nodes.map(({id}) => ({id})), edges: graph.edges.map(({source,target,conditional}) => ({source,target,conditional:conditional===true})) };
}
async function runDpiGraph(userMessage, conversationHistory, completedObjectives, activeObjectiveId, {
  SYSTEM_PROMPTS, OBJECTIVE_IDS, filterRejectedExchanges, buildMessages,
  aiService, isValidPracticeInteraction, detectCompletedObjective, messageCouldBeAttack, looksLikeRejection, judgeAttack, evaluateDpiObjective, execution, judge,
  completionService, attempt, userId,
}) {
  if(attempt?.mode==='fixed'&&activeObjectiveId!==OBJECTIVE_IDS.OBFUSCATION&&!require('./dpiPolicyContract').TEXT_OBJECTIVES.includes(activeObjectiveId))throw Object.assign(Error('Fixed mode requires a supported DPI objective.'),{code:'DPI_OBJECTIVE_MODE_UNSUPPORTED',statusCode:409});
  let actorProof, decoderProof, publication, privateDraft, publicationResult;
  let selectedPolicy, selectedLesson, messages, result, responseText, completedId = null, validInteraction = false, judgment, durableGrading = false;
  const graph = compileDpiGraph({
    prepare: () => {
  const systemPrompt = attempt?.mode==='fixed' && activeObjectiveId!==OBJECTIVE_IDS.OBFUSCATION
    ? require('./dpiPolicyContract').textSystemPrompt(activeObjectiveId,attempt.mode)
    : SYSTEM_PROMPTS[activeObjectiveId] || SYSTEM_PROMPTS[OBJECTIVE_IDS.INTERACT];
  // For practice mode, use no history — each message is independent and history causes
  // the model to mimic rejection patterns from prior non-AWS questions.
  const historyForModel = activeObjectiveId === OBJECTIVE_IDS.INTERACT
    ? []
    : filterRejectedExchanges(conversationHistory);
  messages = buildMessages(systemPrompt, historyForModel);

  // Preserve the learner's payload exactly. Obfuscation delegates any decoding
  // to its explicit owned tool graph.
  messages.push({ role: 'user', content: userMessage });
  if(attempt&&activeObjectiveId!=='obfuscation'){const contract=require('./dpiPolicyContract');selectedPolicy=contract.selectPolicy({objectiveId:activeObjectiveId,mode:attempt.mode});selectedLesson=contract.selectedLesson(selectedPolicy);}
  if(attempt&&activeObjectiveId!=='obfuscation'){const contract=require('./dpiPolicyContract');contract.validateActorMessages(messages,userMessage,selectedPolicy);messages.forEach(Object.freeze);Object.freeze(messages);}


      return {};
    },
    model: async () => {
  if(activeObjectiveId===OBJECTIVE_IDS.OBFUSCATION){result=await require('./dpiObfuscationGraph').runDpiObfuscationGraph({request:userMessage,execution,attempt,aiService});decoderProof=result.proof;selectedLesson=result.selectedLesson;responseText=result.response;return {};}

  await execution?.check?.();
  const started = Date.now();
  await execution?.trace?.({node:'actor_model',type:'node_start',data:{}});
  try {
    result = await aiService.chatWithMessages(messages, {
      // Keep obfuscation attempts repeatable without rewriting the learner's input.
      temperature: activeObjectiveId === OBJECTIVE_IDS.OBFUSCATION ? 0.2 : 0.6,
      max_tokens: 1024,
      signal: execution?.signal,
      timeout: 120000
    });
  } catch (error) {
    if (error?.name !== 'AbortError' && !execution?.signal?.aborted) {
      await execution?.trace?.({node:'actor_model',type:'error',data:{errorCode:'MODEL_UNAVAILABLE',durationMs:Date.now()-started}});
    }
    throw error;
  }
  // Keep authority failures outside the provider catch. A reset that lands
  // after inference is stale execution, not evidence that the model failed.
  await execution?.check?.();
  if (!result || typeof result.response !== 'string' || !result.response.trim()) {
    await execution?.trace?.({node:'actor_model',type:'error',data:{errorCode:'MODEL_RESPONSE_INVALID',durationMs:Date.now()-started}});
    const error = new Error('The AI provider returned no usable text response.');
    error.code = 'MODEL_RESPONSE_INVALID';
    throw error;
  }
  const decisionSource = result.mocked === true || String(result.provider || '').toLowerCase() === 'mock' ? 'scripted'
    : result.fallback === true ? 'unavailable' : 'model';
  await execution?.trace?.({node:'actor_model',type:'node_end',data:{
    decisionSource, provider:result.provider || null, model:result.model || null,
    ...(result.tokens > 0 ? {tokens:result.tokens} : {}), durationMs:Date.now()-started,
  }});


      responseText = result.response;
      return {};
    },
    detect: () => {
  // Strip any marker or evaluation text the LLM may have leaked (belt-and-suspenders)
  if(!decoderProof && !require('../config/dpiBoundedCurriculum').IDS.includes(activeObjectiveId))responseText = responseText
    .replace(/---\s*\r?\nINTERNAL EVALUATION:[\s\S]*?(?=\|\|SUCCESS\|\||$)/g, '')
    .replace(/INTERNAL EVALUATION:\s*[\s\S]*?(?=\|\|SUCCESS\|\||$)/g, '')
    .replace(/Did (?:I|user) [^\n]+\? (?:YES|NO)\r?\n?/g, '')
    .replace(/If (?:ANY|ALL|BOTH) [^\n]+\r?\n?/g, '')
    .replace(/\|\|VALID_INTERACTION\|\|/g, '')
    .replace(/\|\|SUCCESS\|\|/g, '')
    .trim();


      return { needsJudge: true };
    },
    judge: async () => {
      await execution?.check?.();
      if(require('./dpiPolicyContract').TEXT_OBJECTIVES.includes(activeObjectiveId)&&require('./dpiActorProof').canCaptureModel(result)&&execution&&attempt)actorProof=require('./dpiActorProof').createActorProof({request:userMessage,response:responseText,result,execution,attempt,objective:activeObjectiveId,messages,selectedPolicy});
      const evaluated = await evaluateDpiObjective(userMessage,privateDraft??responseText,activeObjectiveId,
        {execution,judge,completionService,attempt,userId,decoderProof,actorProof,publicationResult,mode:attempt?.mode});
      const {completionAccepted=false,durableGrading:durable=false,...publicJudgment}=evaluated;
      if(publicationResult && (!completionService||durable!==true))throw Error('Durable publication grading record required');
      judgment=publicJudgment;
      durableGrading=durable;
      await execution?.check?.();
      if(judgment.verdict==='pass' && (attempt?.mode!=='fixed'||activeObjectiveId===OBJECTIVE_IDS.INTERACT)) {
        if(activeObjectiveId===OBJECTIVE_IDS.INTERACT)validInteraction=true;
        else if((!durableGrading||completionAccepted)&&!completedObjectives[activeObjectiveId])completedId=activeObjectiveId;
      }
      return {};
    },
    publication: async () => {
      if(decoderProof && attempt?.mode==='fixed'){
        privateDraft=responseText;
        const published=await require('./dpiPublicationDefense').defend({request:userMessage,draft:responseText,proof:decoderProof,execution,attempt,aiService});
        publicationResult=published;responseText=published.response;publication=published.publication;
      }
      return {};
    }
  });
  try { await graph.invoke({}, { recursionLimit: 8 }); }
  catch (error) {
    if (decoderProof) require('./dpiToolActivity').recordToolActivityFailure(error, result.toolActivity || []);
    throw error;
  }
  return { response: responseText, model: result.model, provider: result.provider,
    toolActivity: decoderProof ? result.toolActivity : [],
    ...(selectedLesson?{selectedLesson}:{}), completedObjectiveId: completedId || undefined, validInteraction: validInteraction || undefined, judgment, durableGrading, ...(publication?{publication}:{}) };
}
module.exports = { runDpiGraph, compileDpiGraph, getDpiGraphDefinition };
