'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module=require('node:module');
const { EventEmitter } = require('node:events');

function installModuleStub(request, exports) {
  const filename = require.resolve(request);
  require.cache[filename] = {
    id: filename,
    filename,
    loaded: true,
    exports,
    children: [],
    paths: [],
  };
}

// Controlled PostgreSQL-shaped stores and actor boundaries; no legacy startup.
const progress={syncObjectiveComplete:async()=>{},syncWorkshopStarted:async()=>{},checkAndMarkWorkshopComplete:async()=>false,resetWorkshopProgress:async()=>{},getUserWorkshopProgress:async()=>[],getCanonicalWorkshopCompletions:async()=>({objectiveIds:[],generation:0})};
for(const family of ['sql','nosql'])installModuleStub('../server/database/'+family+'WorkshopDb',{clearHistory:async()=>{},clearCart:async()=>{},clearReadingList:async()=>{}});
for(const family of ['sensitiveInfo','supplyChain'])installModuleStub('../server/database/'+family+'WorkshopDb',{engine:'postgres',ensureObjectives:async()=>{},getProgress:async()=>[],completeObjective:async()=>({changed:false}),logToolCall:async()=>{},resetUser:async()=>{},runAsync:async()=>({changes:0}),getAsync:async()=>null,allAsync:async()=>[]});
installModuleStub('../server/utils/progressSync',progress);
installModuleStub('../server/utils/logger',{error(){},info(){},warn(){}});
installModuleStub('../server/utils/contextLogger',{error(){},info(){},warn(){}});
const providerFixture={};
const guardedLoad=Module._load;Module._load=function(request,parent,isMain){if(request.endsWith('/multiProviderAIService'))return providerFixture;return guardedLoad.call(this,request,parent,isMain);};
const actualCoordinator=require('../server/agent-runtime/runCoordinator');
installModuleStub('../server/agent-runtime/runCoordinator',{...actualCoordinator,createRunCoordinator:options=>actualCoordinator.createRunCoordinator({...options,ledger:null})});
for(const name of ['aria','nova'])installModuleStub('../server/services/'+name+'AgentService',{invoke:async()=>{throw Error('Fixture actor not installed');},reset:async(owner,work)=>work({check:async()=>{}})});
installModuleStub('../server/services/workshopObjectiveGrader',{createWorkshopObjectiveGrader:()=>({begin:async()=>({generation:0}),observe:async()=>{},evaluate:async()=>({completed:false})})});
const sensitiveRuns=actualCoordinator.createRunCoordinator({family:'ControlledSensitiveModes',ledger:null});
class ControlledSensitiveAgent{
 constructor({stateStore}){this.stateStore=stateStore;}
 runUserExclusive(owner,work){return sensitiveRuns.run(owner,{},execution=>work({},execution));}
 resetUserExclusive(owner,work){return sensitiveRuns.reset(owner,()=>work());}
}
installModuleStub('../server/services/sensitiveInfoWorkshopAgent',{SensitiveInfoWorkshopAgent:ControlledSensitiveAgent,OBJECTIVES:[],createSensitiveInfoWorkshopStateStore:()=>({resetUser(){}}),getConfiguredSsrfExamples:()=>[]});
installModuleStub('../server/services/sensitiveInfoResetComposition',{createConfiguredFinflowTraversalManager:()=>({}),getSensitiveInfoResetComposition:()=>({reset:{reset:async()=>({status:'completed'})}})});
const eaState={conversations:new Map(),toolRouter:{executeTool:async()=>({success:true}),getToolDefinitions:()=>[]},database:{getUserProgress:()=>({objectives:{},completedAt:{}}),getStats:()=>({}),resetUser:async()=>{}}};
installModuleStub('../server/services/excessiveAgencyAttendeeLabStore',{excessiveAgencyAttendeeLabStore:{getOrCreate:async()=>eaState,resetAttendee:async()=>eaState}});
installModuleStub('../server/middleware/adminAuth',{authenticateToken(req,res,next){if(!req.user)return res.status(401).json({error:'Authentication required'});next();}});
// These mode-routing tests inject available lab resources and instructor
// admission. Native resource, visibility and JWT proofs live in their own suites.
let finflowAdmissionError;
installModuleStub('../server/services/finflowObjectiveAdmission', {
  createWorkshopObjectiveAdmission: () => ({ admit: async objectiveId => {
    if (finflowAdmissionError) throw finflowAdmissionError;
    return { objectiveId, generalChat: !objectiveId };
  } }),
});
installModuleStub('../server/services/postgresPlatformStores', {
  getPostgresPlatformStores: () => ({ pool: {},progress,config:{getSnapshot:async()=>({revision:0,exercises:{}}),getSolutionVisibilityMap:async()=>({}),isObjectiveEnabled:async()=>true} }),
});
installModuleStub('../server/services/finflowAgentResourceComposition', {
  configuredFinflowAgentResources: () => ({ assertReady: async () => true,
    readDataset: async () => {}, deleteDataset: async () => {},
    createBackup: async () => {}, downloadBackup: async () => {}, listBackups: async () => [],
    readLogOverlay: async () => null, writeLogOverlay: async () => {},
  }),
});

// Controlled canonical session validator; no live database or authentication bypass.
installModuleStub('../server/services/postgresIdentityAdapter', {
  getPostgresIdentityAdapter: () => ({validateSession: async token => {
    const match = /^controlled-owner-([0-9]+)$/.exec(token);
    if (!match) return null;
    const id = Number(match[1]); return {user:{id},session:{id:700,user_id:id}};
  }}),
});

const {createAdmittedPlatformSessionFence}=require('../server/agent-runtime/admittedPlatformSession');
installModuleStub('../server/services/supplyChain/codeBotExecutionBoundary',{getConfiguredCodeBotExecutionBoundary:()=>({async resolveRequest(req){const fence=createAdmittedPlatformSessionFence(req,{validateSession:token=>require('../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token)});await fence.check();return{platformOwnerId:req.user.id,platformSessionId:700,fence,assertCurrent:fence.check};},bind(authority,execution){return authority.fence.wrap(execution);}})});
installModuleStub('../server/agent-runtime/codeBotRequestJournal',{getConfiguredCodeBotRequestJournal:()=>({assertReady:async()=>{},replay:async()=>({replayed:false}),claim:async()=>({replayed:false}),complete:async()=>{},markUncertain:async()=>{}}),requestFingerprint:()=> 'controlled'});
const productionPath=require.resolve('../server/services/supplyChain/codeBotProduction');const production=require(productionPath);
installModuleStub('../server/services/supplyChain/codeBotProduction',{...production,getCodeBotProductionActivation:()=>({assertEffectReady:async()=>{},requireReady(_req,_res,next){next();},requireConfigured(_req,_res,next){next();}})});
installModuleStub('../server/agent-runtime/codeBotJudge',{beginCodeBotEvaluation:async()=>async()=>({completed:false})});
installModuleStub('../server/agent-runtime/excessiveAgencyJudge',{beginEAEvaluation:async()=>async()=>({completed:false})});
const actualRouteFactory = require('../server/agent-runtime/workshopRouteHandlers');
installModuleStub('../server/agent-runtime/workshopRouteHandlers', {
  createWorkshopRouteHandlers: options => actualRouteFactory.createWorkshopRouteHandlers({
    ...options, validateSession: token => require('../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter().validateSession(token),
  }),
});
const modeService = require('../server/services/workshopModeService');
const ariaAgent = require('../server/services/ariaAgentService');
const novaAgent = require('../server/services/novaAgentService');
const aiService = require('../server/services/multiProviderAIService');
const { SensitiveInfoWorkshopAgent } = require('../server/services/sensitiveInfoWorkshopAgent');
const codeBotSandboxRuntime = require('../server/services/supplyChain/codeBotSandboxRuntime');

const routers = {
  sql: require('../server/routes/sqlWorkshop'),
  nosql: require('../server/routes/nosqlWorkshop'),
  sensitive: require('../server/routes/sensitiveInfoWorkshop'),
  supply: require('../server/routes/supplyChainWorkshop'),
  ea: require('../server/routes/excessiveAgencyLab'),
};

function handlers(router, path, method) {
  const layer = router.stack.find((candidate) => candidate.route?.path === path && candidate.route.methods?.[method]);
  if (!layer) throw new Error(`Missing ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map((entry) => entry.handle);
}

function responseRecorder() {
  return Object.assign(new EventEmitter(), {
    statusCode: 200,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    set() { return this; },
    cookie() { return this; },
    clearCookie() { return this; },
  });
}

async function invoke(handler, req) {
  const request = typeof req.once === 'function' ? req : Object.assign(new EventEmitter(), req.user ? {get(name){return this.headers?.[String(name).toLowerCase()];},identitySession:{id:700},headers:{authorization:`Bearer controlled-owner-${req.user.id}`}} : {}, req);
  const res = responseRecorder();
  await handler(request, res, () => {});
  return res;
}

async function invokeSupply(path, req) {
  const stack = handlers(routers.supply, path, 'post');
  const request = Object.assign(new EventEmitter(), { ...req,
    identitySession:{id:700}, headers: { authorization: `Bearer controlled-owner-${req.user.id}`, 'idempotency-key':'controlled-request-key', ...(req.headers || {}) },
    get(name) { return this.headers[String(name).toLowerCase()]; } });
  const res = responseRecorder();
  const dispatch = index => new Promise((resolve, reject) => {
    let nextCalled = false;
    const next = () => { nextCalled = true;Promise.resolve(dispatch(index + 1)).then(resolve, reject); };
    Promise.resolve(stack[index]?.(request, res, next)).then(() => { if (!nextCalled) resolve(); }, reject);
  });
  await dispatch(1);
  return res;
}

test('Supply chat rejects malformed idempotency keys before model or store work', async () => {
  const res = await invokeSupply('/chat', { user: { id: 104 }, headers: { 'idempotency-key': 'short' },
    body: { userMessage: 'hello' } });
  assert.equal(res.statusCode, 400);assert.match(res.body.error, /Idempotency-Key/);
});

test('all five chat routes reject missing platform authentication', async () => {
  for (const router of Object.values(routers)) {
    const authenticate = handlers(router, '/chat', 'post')[0];
    const res = await invoke(authenticate, { headers: {}, body: {} });
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'Authentication required');
  }
});

test('actual chat handlers use authenticated owner mode and ignore body authority', async (t) => {
  const original = {
    getMode: modeService.getMode,
    ariaInvoke: ariaAgent.invoke,
    novaInvoke: novaAgent.invoke,
    aiChatWithTools: aiService.chatWithTools,
    aiChatWithMessages: aiService.chatWithMessages,
    sensitiveProcess: SensitiveInfoWorkshopAgent.prototype.processMessage,
  };
  t.after(() => {
    modeService.getMode = original.getMode;
    ariaAgent.invoke = original.ariaInvoke;
    novaAgent.invoke = original.novaInvoke;
    aiService.chatWithTools = original.aiChatWithTools;
    aiService.chatWithMessages = original.aiChatWithMessages;
    SensitiveInfoWorkshopAgent.prototype.processMessage = original.sensitiveProcess;
  });

  const reads = [];
  const execution = [];
  modeService.getMode = async ({ userId, workshopKey }) => {
    reads.push([String(userId), workshopKey]);
    return workshopKey === 'sensitive_info_disclosure' || workshopKey === 'supply_chain_rce'
      ? 'fixed'
      : 'vuln';
  };
  ariaAgent.invoke = async (userId, message, mode, options) => {
    execution.push(['sql', userId, mode]);
    const result = { response: 'sql ok', toolUsed: null, toolResult: null };
    await options?.onResult?.(result, async () => {});
    return result;
  };
  novaAgent.invoke = async (userId, message, mode, options) => {
    execution.push(['nosql', userId, mode]);
    const result = { response: 'nosql ok', toolUsed: null, toolResult: null };
    await options?.onResult?.(result, async () => {});
    return result;
  };
  SensitiveInfoWorkshopAgent.prototype.processMessage = async function processMessage(message, history, mode) {
    execution.push(['sensitive', message, mode]);
    return { success: true, response: `sensitive ${mode}`, toolCalls: [], completedObjectiveIds: [] };
  };
  aiService.chatWithTools = async (messages) => {
    execution.push(['supply', messages[0].content, messages.at(-1).content]);
    return { content: 'supply ok', tool_calls: [] };
  };
  aiService.chatWithMessages = async (messages) => {
    execution.push(['ea', messages[0].content]);
    return { response: 'ea ok' };
  };

  const hostileBody = { userId: 'attacker-selected', mode: 'vulnerable', userMessage: 'hello', message: 'hello', conversationHistory: [] };
  const sql = await invoke(handlers(routers.sql, '/chat', 'post').at(-1), { user: { id: 101 }, body: hostileBody });
  const nosql = await invoke(handlers(routers.nosql, '/chat', 'post').at(-1), { user: { id: 102 }, body: hostileBody });
  const sensitive = await invoke(handlers(routers.sensitive, '/chat', 'post').at(-1), { user: { id: 103 }, body: hostileBody });
  const supply = await invokeSupply('/chat', { user: { id: 104 }, body: hostileBody });
  const ea = await invoke(handlers(routers.ea, '/chat', 'post').at(-1), {
    user: { id: 105 },
    labUser: { userId: 'user_001' },
    labState: {
      conversations: new Map(),
      toolRouter: { executeTool: async () => ({ success: true }) },
      database: { getUserProgress: () => ({ objectives: {}, completedAt: {} }) },
    },
    body: hostileBody,
  });

  assert.equal(sensitive.statusCode, 200, JSON.stringify(sensitive.body));
  assert.deepEqual([sql.body.mode, nosql.body.mode, sensitive.body.mode, supply.body.mode, ea.body.labMode],
    ['vuln', 'vuln', 'fixed', 'fixed', 'vuln']);
  assert.deepEqual(reads, [
    ['101', 'sql_injection_workshop'],
    ['102', 'nosql_injection_workshop'],
    ['103', 'sensitive_info_disclosure'],
    ['104', 'supply_chain_rce'],
    ['105', 'excessive_agency'],
  ]);
  assert.deepEqual(execution.slice(0, 3), [
    ['sql', '101', 'vuln'],
    ['nosql', '102', 'vuln'],
    ['sensitive', 'hello', 'fixed'],
  ]);
  assert.match(execution[3][1], /strictly validates|blocked|secure/i);
  assert.match(execution[4][1], /"bob's notes" or "notes from bob" → use userId "bob"/i);
  assert.doesNotMatch(execution[4][1], /CRITICAL AUTHORIZATION RULES/);
});

test('Sensitive chat keeps concurrent owners in their persisted modes', async (t) => {
  const originalGetMode = modeService.getMode;
  const originalProcess = SensitiveInfoWorkshopAgent.prototype.processMessage;
  t.after(() => {
    modeService.getMode = originalGetMode;
    SensitiveInfoWorkshopAgent.prototype.processMessage = originalProcess;
  });

  modeService.getMode = async ({ userId }) => String(userId) === '201' ? 'vulnerable' : 'fixed';
  SensitiveInfoWorkshopAgent.prototype.processMessage = async function processMessage(message, history, mode) {
    await new Promise((resolve) => setTimeout(resolve, mode === 'vulnerable' ? 10 : 1));
    return { success: true, response: mode, toolCalls: [], completedObjectiveIds: [] };
  };

  const chat = handlers(routers.sensitive, '/chat', 'post').at(-1);
  const [vulnerable, fixed] = await Promise.all([
    invoke(chat, { user: { id: 201 }, body: { userMessage: 'A', mode: 'fixed', userId: '202' } }),
    invoke(chat, { user: { id: 202 }, body: { userMessage: 'B', mode: 'vulnerable', userId: '201' } }),
  ]);
  assert.deepEqual([vulnerable.body.mode, vulnerable.body.response, fixed.body.mode, fixed.body.response],
    ['vulnerable', 'vulnerable', 'fixed', 'fixed']);
});

test('EA mode-reading endpoints and Supply chat convert mode-store rejection to 500', async (t) => {
  const originalGetMode = modeService.getMode;
  const originalConsoleError = console.error;
  t.after(() => {
    modeService.getMode = originalGetMode;
    console.error = originalConsoleError;
  });
  modeService.getMode = async () => { throw new Error('temporary mode store failure'); };
  console.error = () => {};

  for (const [path, req] of [
    ['/auth/me', { user: { id: 301 }, labUser: { userId: 'user_001' }, body: {} }],
    ['/welcome', { user: { id: 301 }, labUser: { userId: 'user_001' }, body: {} }],
    ['/stats', { user: { id: 301 }, body: {} }],
    ['/tools', { user: { id: 301 }, query: {}, body: {} }],
    ['/chat', { user: { id: 301 }, labUser: { userId: 'user_001' }, body: { message: 'hello' } }],
  ]) {
    const res = await invoke(handlers(routers.ea, path, path === '/chat' ? 'post' : 'get').at(-1), req);
    assert.equal(res.statusCode, 500, `EA ${path}`);
    assert.match(res.body.error, /failed|internal/i);
  }

  const supply = await invokeSupply('/chat', {
    user: { id: 302 },
    body: { userMessage: 'hello' },
  });
  assert.equal(supply.statusCode, 500);
  assert.equal(supply.body.error, 'Internal server error');
});

test('ordinary reset handlers complete without changing persisted mode', async (t) => {
  const originalSetMode = modeService.setMode;
  const originalCodeBotReset = codeBotSandboxRuntime.resetOwnerBeforeProgress;
  let writes = 0;
  modeService.setMode = async () => { writes += 1; };
  // This test covers mode preservation. Backend reset failure semantics are
  // exercised separately by codeBotSandboxRuntime.test.js.
  codeBotSandboxRuntime.resetOwnerBeforeProgress = async (_ownerId, resetProgress) => {
    await resetProgress();
    return { ok: true };
  };
  t.after(() => {
    modeService.setMode = originalSetMode;
    codeBotSandboxRuntime.resetOwnerBeforeProgress = originalCodeBotReset;
  });

  const unique = '501';
  const cases = [
    [routers.sql, '/reset', { user: { id: Number(unique)+1 }, body: { mode: 'fixed', userId: 'other' } }],
    [routers.nosql, '/reset', { user: { id: Number(unique)+2 }, body: { mode: 'fixed', userId: 'other' } }],
    [routers.sensitive, '/progress/reset', { user: { id: Number(unique)+3 }, body: { mode: 'fixed', userId: 'other' } }],
    [routers.supply, '/progress/reset', { user: { id: Number(unique) }, body: { mode: 'fixed', userId: 'other' } }],
    [routers.ea, '/reset', { user: { id: Number(unique)+4 }, body: { mode: 'vuln', userId: 'other' } }],
  ];
  for (const [router, path, req] of cases) {
    const res = router === routers.supply ? await invokeSupply(path, req) : await invoke(handlers(router, path, 'post').at(-1), req);
    assert.equal(res.statusCode, 200, path);
  }
  assert.equal(writes, 0);
});

test('Sensitive admission failure stops before persisted-mode lookup', async t => {
  const original = modeService.getMode;
  let modeReads = 0;
  modeService.getMode = async () => { modeReads++; return 'fixed'; };
  finflowAdmissionError = Object.assign(new Error('Unavailable'), { code: 'EXERCISE_AVAILABILITY_UNAVAILABLE', statusCode: 503 });
  t.after(() => { modeService.getMode = original; finflowAdmissionError = undefined; });
  const result = await invoke(handlers(routers.sensitive, '/chat', 'post').at(-1), {
    user: { id: 201 }, body: { userMessage: 'hello', userId: 202, mode: 'vulnerable' },
  });
  assert.equal(result.statusCode, 503);
  assert.equal(result.body.code, 'EXERCISE_AVAILABILITY_UNAVAILABLE');
  assert.equal(modeReads, 0);
});
