'use strict';
const {checkOwnerRun,getOwnerExecution}=require('./ownerWorkflowRoutes');
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { applyCsrfSelectedEffect, withCsrfTeachingEffect } = require('./csrfSelectedEffect');
async function runCsrfAgentGraph(sessionId, tabId, message, opts, {
  sandboxMod, detectIntent, detectAction, extractParams, resolveObjectives, reconObjectives, reconNudge,
  INJECTION_RE, GUARDED_ACTIONS, deterministicAttackBody, phraseRecon, phraseAttack, phraseDefense, phraseQuery, model, execution=getOwnerExecution(),
}) {
  const sandbox = sandboxMod.getOrCreateSandbox(sessionId);
  const t = sandbox.tab(tabId);
  const forgedVia = opts.forgedVia && sandboxMod.VECTORS[opts.forgedVia] ? opts.forgedVia : null;
  const mode=opts.mode??'vuln';
  if(!['vuln','fixed'].includes(mode))throw new TypeError('Canonical CSRF mode required');
  let plan;
  const scripted=model?.provider==='mock';


  const State = Annotation.Root({ branch: Annotation(), result: Annotation() });
  const graph = new StateGraph(State);
  const addNode=graph.addNode.bind(graph);
  graph.addNode=(name,fn)=>addNode(name,async state=>{await checkOwnerRun();await execution?.check?.();await opts.assertMode?.();await execution?.trace?.({node:name,type:'node_start',data:{}});try{const result=await fn(state);await opts.assertMode?.();await execution?.check?.();await checkOwnerRun();await execution?.trace?.({node:name,type:'node_end',data:{}});return result;}catch(error){await execution?.trace?.({node:name,type:'error',data:{errorCode:'CSRF_NODE_FAILED'}});throw error;}});
  graph.addNode('classify',async()=>{
    plan=scripted?detectIntent(message):await require('./csrfDecision').decideCsrf({model,message,document:opts.document,actions:sandboxMod.ACTIONS,vectors:sandboxMod.VECTORS,execution});
    if(scripted)await execution?.trace?.({node:'classify',type:'decision',data:{decisionSource:'scripted'}});
    return {branch:scripted?(opts.document?'document':forgedVia||plan.intent==='attack'?'attack':['recon','defense','query'].includes(plan.intent)?plan.intent:'chitchat'):
      plan.intent==='attack'?(opts.document?'document':'attack'):['recon','defense','query'].includes(plan.intent)?plan.intent:'no_action'};
  });
  graph.addNode('no_action',async()=>({result:{response:plan.intent==='unavailable'?'The action decision is unavailable; no action was taken.':'No action was taken.',intent:plan.intent,toolResult:null,objectivesHit:[],victimState:sandbox.getTabState(tabId)}})).addEdge('no_action',END);
  graph.addNode('document', async () => ({ result: await (async () => {
    const docLower = String(opts.document).toLowerCase();
    const docAction = scripted?(detectAction(docLower)||'disable_mfa'):plan.action;
    const effect = await applyCsrfSelectedEffect({ sandbox, sandboxMod, tabId, message,
      document: opts.document, chain: null, inputVector: null,
      selected: { intent: 'attack', action: docAction,
        vector: plan.vector, params: scripted ? extractParams(opts.document, docAction) : plan.params },
      resolveObjectives, injectionPattern: INJECTION_RE, guardedActions: GUARDED_ACTIONS, execution,mode,assertMode:opts.assertMode });
    return { ...effect.result,
      responseSpec: { kind: 'attack', args: [effect.phraseMessage, effect.phraseResult] } };

  })() })).addEdge('document', 'phrase');
  graph.addNode('recon', async () => ({ result: await withCsrfTeachingEffect(execution, sandbox, async () => {
    const surface = sandbox.describeSurface(tabId);
    const hit = reconObjectives(t, tabId);
    await sandbox.flush?.();
    if(tabId==='get')await execution?.trace?.({node:'csrf_recon_get',type:'tool',data:{tool:'recon'}});
    return {
      responseSpec: { kind: 'recon', args: [surface] },
      intent: 'recon', toolResult: { kind: 'recon', surface },
      objectivesHit: hit, reconCount: t.reconCount,
      victimState: sandbox.getTabState(tabId),
    };

  }) })).addEdge('recon', 'phrase');
  graph.addNode('defense', async () => ({ result: await withCsrfTeachingEffect(execution, sandbox, async () => {
    const toggle = sandbox.setDefenses(tabId, plan.defenseOn);
    await sandbox.flush?.();
    return {
      responseSpec: { kind: 'defense', args: [toggle] },
      intent: 'defense', toolResult: { kind: 'defense', ...toggle },
      objectivesHit: [], victimState: sandbox.getTabState(tabId),
    };

  }) })).addEdge('defense', 'phrase');
  graph.addNode('query', async () => ({ result: await (async () => {
    const state = sandbox.getTabState(tabId);
    return {
      responseSpec: { kind: 'query', args: [message, state] },
      intent: 'query', toolResult: { kind: 'query' },
      objectivesHit: [], victimState: state,
    };

  })() })).addEdge('query', 'phrase');
  graph.addNode('attack', async () => ({ result: await (async () => {
    const lower = String(message).toLowerCase();
    const action = (plan.intent === 'attack' ? plan.action : detectAction(lower)) || 'change_email';
    const params = plan.intent === 'attack' ? plan.params : extractParams(message, action);
    const effect = await applyCsrfSelectedEffect({ sandbox, sandboxMod, tabId, message,
      document: null, chain: opts.chain, inputVector: forgedVia,
      selected: { intent: 'attack', action, vector: plan.vector, params },
      resolveObjectives, injectionPattern: INJECTION_RE, guardedActions: GUARDED_ACTIONS, execution,mode,assertMode:opts.assertMode });
    if (effect.refused) return { ...effect.result, response: deterministicAttackBody(effect.phraseResult) };
    return { ...effect.result,
      responseSpec: { kind: 'attack', args: [effect.phraseMessage, effect.phraseResult] } };

  })() })).addEdge('attack', 'phrase');
  graph.addNode('chitchat', async () => ({ result: await withCsrfTeachingEffect(execution, sandbox, async () => {
  // Chit-chat → recon.
  const surface = sandbox.describeSurface(tabId);
  const hit = reconObjectives(t, tabId);
    await sandbox.flush?.();
  return {
    responseSpec: { kind: 'recon', args: [surface] },
    intent: 'chitchat', toolResult: { kind: 'recon', surface },
    objectivesHit: hit, reconCount: t.reconCount,
    victimState: sandbox.getTabState(tabId),
  };
  }) })).addEdge('chitchat', 'phrase');
  graph.addNode('phrase', async state => {
    const { responseSpec, ...result } = state.result;
    if (!responseSpec) return { result };
    const phrases = { recon: phraseRecon, attack: phraseAttack, defense: phraseDefense, query: phraseQuery };
    const text = await phrases[responseSpec.kind](...responseSpec.args);
    return { result: { ...result,
      ...(responseSpec.kind !== 'query' ? { victimState: sandbox.getTabState(tabId) } : {}),
      ...(responseSpec.kind === 'recon' ? { reconCount: t.reconCount } : {}),
      response: responseSpec.kind === 'recon' ? reconNudge(t, text) : text } };
  }).addEdge('phrase', END).addEdge(START, 'classify')
    .addConditionalEdges('classify', state => state.branch, ['document', 'recon', 'defense', 'query', 'attack', 'chitchat','no_action']);
  return (await graph.compile().invoke({}, { recursionLimit: 5 })).result;
}
module.exports = { runCsrfAgentGraph };
