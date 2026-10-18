'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const previousPlatformEngine=process.env.PLATFORM_DATABASE_ENGINE;
process.env.PLATFORM_DATABASE_ENGINE='test';
test.after(()=>{if(previousPlatformEngine===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;
 else process.env.PLATFORM_DATABASE_ENGINE=previousPlatformEngine;});
const originalLoad = Module._load;
Module._load = function guardedLoad(request, parent, isMain) {
  if (/(?:^|\/)authDb(?:\.js)?$/.test(request)) throw new Error('Test isolation violation: live authDb import');
  return originalLoad.call(this, request, parent, isMain);
};
test.after(()=>{Module._load=originalLoad;});

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

// Route-ordering tests supply req.user directly; never import the live auth DB.
installModuleStub('../server/middleware/adminAuth', { authenticateToken: (_req, _res, next) => next() });
installModuleStub('../server/services/postgresIdentityAdapter',{getPostgresIdentityAdapter:()=>({validateSession:async token=>({user:{id:Number(token)},session:{id:11,user_id:Number(token)}})})});
let aggregateResetComposition=null;
const traversalManager=Object.freeze({read:async()=>{},readAdminConfig:async()=>{},listAdminDirectory:async()=>{}});
installModuleStub('../server/services/sensitiveInfoResetComposition', {
  getSensitiveInfoResetComposition:async()=>aggregateResetComposition,
  createConfiguredFinflowTraversalManager:()=>traversalManager,
});
const durableResources=Object.freeze({assertReady:async()=>true,readDataset:async()=>{},deleteDataset:async()=>{},
 createBackup:async()=>{},downloadBackup:async()=>{},listBackups:async()=>[],readLogOverlay:async()=>null,writeLogOverlay:async()=>{}});
installModuleStub('../server/services/finflowAgentResourceComposition',{
 configuredFinflowAgentResources:()=>durableResources,
});
installModuleStub('../server/services/finflowObjectiveAdmission',{
 createWorkshopObjectiveAdmission:()=>({admit:async objectiveId=>({objectiveId,generalChat:!objectiveId})}),
});
installModuleStub('../server/services/postgresPlatformStores',{
 getPostgresPlatformStores:()=>({pool:{}}),
});
const realAgentModule=require('../server/services/sensitiveInfoWorkshopAgent');
let routeStateStore;
installModuleStub('../server/services/sensitiveInfoWorkshopAgent',{
 ...realAgentModule,
 createSensitiveInfoWorkshopStateStore(options){
  routeStateStore=realAgentModule.createSensitiveInfoWorkshopStateStore(options);
  return routeStateStore;
 },
});

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => { resolve = resolvePromise; });
  return { promise, resolve };
}

function handlers(router, path, method) {
  const layer = router.stack.find((candidate) =>
    candidate.route?.path === path && candidate.route.methods?.[method]);
  if (!layer) throw new Error(`Missing ${method.toUpperCase()} ${path}`);
  return layer.route.stack.map((entry) => entry.handle);
}

function responseRecorder() {
  return {
    statusCode: 200,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

async function invoke(handler, req) {
  req.headers={authorization:`Bearer ${req.user.id}`};req.identitySession={id:11};
  const res = responseRecorder();
  await handler(req, res, () => {});
  return res;
}

test('a reset requested during agent execution waits for the older chat ordering unit', {timeout:5000}, async (t) => {
  const sqlCalls = [];
  const progressSyncCalls = [];
  installModuleStub('../server/database/sensitiveInfoWorkshopDb', {
    ensureObjectives: async () => {},
    completeObjective: async (owner,id) => {sqlCalls.push({method:'complete',owner,id});return {changes:1};},
    logToolCall: async owner => sqlCalls.push({method:'log',owner}),
    resetUser: async owner => sqlCalls.push({method:'reset',owner}),
  });
  installModuleStub('../server/services/workshopModeService', {
    getMode: async () => 'vulnerable',
  });
  installModuleStub('../server/services/workshopModeHandlers', {
    createWorkshopModeHandlers: () => ({ get() {}, set() {} }),
  });
  installModuleStub('../server/utils/progressSync', {
    syncObjectiveComplete: async (...args) => progressSyncCalls.push(['objective', ...args]),
    syncWorkshopStarted: async () => {},
    checkAndMarkWorkshopComplete: async (...args) => progressSyncCalls.push(['complete', ...args]),
    resetWorkshopProgress: async (...args) => progressSyncCalls.push(['reset', ...args]),
  });

  const agentModule = require('../server/services/sensitiveInfoWorkshopAgent');
  const originalProcessMessage = agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage;
  const chatStarted = deferred();
  const chatResult = deferred();
  let chatState;
  agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage = async function processMessage(
    _message, _history, _mode, _objectiveId, _userId, requestState
  ) {
    chatState=requestState;
    chatStarted.resolve();
    return chatResult.promise;
  };
  t.after(() => {
    agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage = originalProcessMessage;
    return routeStateStore?.resetAll();
  });

  const routePath = require.resolve('../server/routes/sensitiveInfoWorkshop');
  delete require.cache[routePath];
  const router = require(routePath);
  const chat = handlers(router, '/chat', 'post').at(-1);
  const reset = handlers(router, '/progress/reset', 'post').at(-1);

  const completionOrder = [];
  const pendingChat = invoke(chat, {
    user: { id: 41 },
    body: { userMessage: 'create a backup after this delayed response' },
  }).then((response) => {
    completionOrder.push('chat');
    return response;
  });
  await chatStarted.promise;

  let resetFinished = false;
  const resetRequest = invoke(reset, { user: { id: 41 }, body: {} }).then((response) => {
    resetFinished = true;
    completionOrder.push('reset');
    return response;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(resetFinished, false);

  chatResult.resolve({
    success: true,
    response: 'stale backup created',
    completedObjectiveIds: ['admin_backup'],
    toolCalls: [{
      name: 'admin_create_backup',
      params: { backup_name: 'stale' },
      result: 'stale backup created',
      securityFlag: 'vulnerability_exploited',
    }],
  });
  const chatResponse = await pendingChat;
  const resetResponse = await resetRequest;

  assert.equal(chatResponse.statusCode, 409);
  assert.equal(resetResponse.statusCode, 200);
  assert.deepEqual(completionOrder, ['chat', 'reset']);
  assert.equal(sqlCalls.some(call=>call.method==='log'),false, 'cancelled chat must not persist tool logs');
  assert.equal(progressSyncCalls.at(-1)?.[0], 'reset');
  assert.notEqual(routeStateStore.getUserState('41'),chatState,
    'the completed reset must replace the exact route-owned state used by the cancelled chat');
});

test('student reset waits for older same-user chat persistence and remains independent across users', {timeout:5000}, async (t) => {
  const sqlCalls = [];
  const completed = new Set();
  const toolLogs = [];
  const persistenceReached = deferred();
  const releasePersistence = deferred();
  let holdFirstChatWrite = true;

  installModuleStub('../server/database/sensitiveInfoWorkshopDb', {
    ensureObjectives: async () => {},
    completeObjective: async (owner,id) => {
      sqlCalls.push({method:'complete',owner,id});
      if(holdFirstChatWrite && owner==='41' && id==='admin_backup'){
        holdFirstChatWrite=false;persistenceReached.resolve();await releasePersistence.promise;
      }
      completed.add(`${owner}:${id}`);return {changes:1};
    },
    logToolCall: async owner => toolLogs.push(owner),
    resetUser: async owner => {
      for(const key of [...completed])if(key.startsWith(`${owner}:`))completed.delete(key);
      for(let index=toolLogs.length-1;index>=0;index--)if(toolLogs[index]===owner)toolLogs.splice(index,1);
    },
  });
  installModuleStub('../server/services/workshopModeService', {
    getMode: async () => 'vulnerable',
  });
  installModuleStub('../server/services/workshopModeHandlers', {
    createWorkshopModeHandlers: () => ({ get() {}, set() {} }),
  });
  installModuleStub('../server/utils/progressSync', {
    syncObjectiveComplete: async () => {},
    syncWorkshopStarted: async () => {},
    checkAndMarkWorkshopComplete: async () => {},
    resetWorkshopProgress: async () => {},
  });

  const agentModule = require('../server/services/sensitiveInfoWorkshopAgent');
  const originalProcessMessage = agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage;
  agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage = async function processMessage(
    _message, _history, _mode, _objectiveId, _userId, requestState
  ) {
    requestState.testBackups ||= new Set();
    requestState.testBackups.add('older_chat.bak');
    return {
      success: true,
      response: 'older chat result',
      completedObjectiveIds: ['admin_backup'],
      toolCalls: [{
        name: 'admin_create_backup',
        params: { backup_name: 'older_chat' },
        result: 'older chat result',
        securityFlag: 'vulnerability_exploited',
      }],
    };
  };
  t.after(async () => {
    agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage = originalProcessMessage;
    await routeStateStore?.resetAll();
  });

  const routePath = require.resolve('../server/routes/sensitiveInfoWorkshop');
  delete require.cache[routePath];
  const router = require(routePath);
  const chat = handlers(router, '/chat', 'post').at(-1);
  const reset = handlers(router, '/progress/reset', 'post').at(-1);

  const completionOrder = [];
  const pendingChat = invoke(chat, {
    user: { id: 41 },
    body: { userMessage: 'create delayed backup' },
  }).then((response) => { completionOrder.push('chat-41'); return response; });
  await persistenceReached.promise;

  let sameUserResetFinished = false;
  const sameUserReset = invoke(reset, { user: { id: 41 }, body: {} })
    .then((response) => {
      sameUserResetFinished = true;
      completionOrder.push('reset-41');
      return response;
    });
  const otherUserReset = invoke(reset, { user: { id: 42 }, body: {} });
  await new Promise((resolve) => setImmediate(resolve));
  const resetFinishedBeforeRelease = sameUserResetFinished;
  const otherUserResponse = await otherUserReset;
  assert.equal(routeStateStore.getUserState('41').testBackups.has('older_chat.bak'),true,
    'a sibling owner reset must not delete the active owner state');

  releasePersistence.resolve();
  const [chatResponse, resetResponse] = await Promise.all([pendingChat, sameUserReset]);

  assert.equal(resetFinishedBeforeRelease, false, 'same-user reset must wait for older persistence');
  assert.equal(otherUserResponse.statusCode, 200, 'different-user reset must not share the lock');
  assert.equal(chatResponse.statusCode, 409);
  assert.equal(resetResponse.statusCode, 200);
  assert.deepEqual(completionOrder, ['chat-41', 'reset-41']);
  assert.equal(completed.has('41:admin_backup'), false);
  assert.equal(toolLogs.includes('41'), false);

  const freshState = routeStateStore.getUserState('41');
  assert.equal(freshState.testBackups?.has('older_chat.bak')||false,false,
    'route reset must delete the state containing the older backup artifact');
});

test('student reset cannot overtake an older chat waiting for its workshop mode', {timeout:5000}, async (t) => {
  const completed = new Set();
  const toolLogs = [];
  const modeLookupStarted = deferred();
  const releaseModeLookup = deferred();

  installModuleStub('../server/database/sensitiveInfoWorkshopDb', {
    ensureObjectives: async () => {},
    completeObjective: async (owner,id) => {completed.add(`${owner}:${id}`);return {changes:1};},
    logToolCall: async owner => toolLogs.push(owner),
    resetUser: async owner => {
      for(const key of [...completed])if(key.startsWith(`${owner}:`))completed.delete(key);
      for(let index=toolLogs.length-1;index>=0;index--)if(toolLogs[index]===owner)toolLogs.splice(index,1);
    },
  });
  installModuleStub('../server/services/workshopModeService', {
    getMode: async ({ userId }) => {
      if (String(userId) === '41') {
        modeLookupStarted.resolve();
        await releaseModeLookup.promise;
      }
      return 'vulnerable';
    },
  });
  installModuleStub('../server/services/workshopModeHandlers', {
    createWorkshopModeHandlers: () => ({ get() {}, set() {} }),
  });
  installModuleStub('../server/utils/progressSync', {
    syncObjectiveComplete: async () => {},
    syncWorkshopStarted: async () => {},
    checkAndMarkWorkshopComplete: async () => {},
    resetWorkshopProgress: async () => {},
  });

  const agentModule = require('../server/services/sensitiveInfoWorkshopAgent');
  const originalProcessMessage = agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage;
  agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage = async function processMessage(
    _message, _history, _mode, _objectiveId, _userId, requestState
  ) {
    requestState.testBackups ||= new Set();
    requestState.testBackups.add('older_mode_chat.bak');
    return {
      success: true,
      response: 'older chat result',
      completedObjectiveIds: ['admin_backup'],
      toolCalls: [{
        name: 'admin_create_backup',
        params: { backup_name: 'older_chat' },
        result: 'older chat result',
        securityFlag: 'vulnerability_exploited',
      }],
    };
  };
  t.after(async () => {
    agentModule.SensitiveInfoWorkshopAgent.prototype.processMessage = originalProcessMessage;
    await routeStateStore?.resetAll();
  });

  const routePath = require.resolve('../server/routes/sensitiveInfoWorkshop');
  delete require.cache[routePath];
  const router = require(routePath);
  const chat = handlers(router, '/chat', 'post').at(-1);
  const reset = handlers(router, '/progress/reset', 'post').at(-1);

  const completionOrder = [];
  const pendingChat = invoke(chat, {
    user: { id: 41 },
    body: { userMessage: 'complete after delayed mode lookup' },
  }).then((response) => { completionOrder.push('chat'); return response; });
  await modeLookupStarted.promise;

  let resetFinished = false;
  const pendingReset = invoke(reset, { user: { id: 41 }, body: {} })
    .then((response) => {
      resetFinished = true;
      completionOrder.push('reset');
      return response;
    });
  await new Promise((resolve) => setImmediate(resolve));
  const resetFinishedBeforeMode = resetFinished;

  releaseModeLookup.resolve();
  const [chatResponse, resetResponse] = await Promise.all([pendingChat, pendingReset]);

  assert.equal(resetFinishedBeforeMode, false, 'reset must queue behind a chat that arrived before mode lookup completed');
  assert.equal(chatResponse.statusCode, 409);
  assert.equal(resetResponse.statusCode, 200);
  assert.deepEqual(completionOrder, ['chat', 'reset']);
  assert.equal(completed.has('41:admin_backup'), false);
  assert.equal(toolLogs.includes('41'), false);
  const freshState = routeStateStore.getUserState('41');
  assert.equal(freshState.testBackups?.has('older_mode_chat.bak')||false,false,
    'route reset must delete state created after the delayed mode lookup');
});

test('FinFlow parent reset forwards the mocked-auth owner and idempotency key on replay', async t => {
  const operationId='44444444-4444-4444-8444-444444444444';const seen=[];
  aggregateResetComposition={reset:{async reset(owner,options){seen.push({owner,options});return{
    operationId,fromGeneration:8,toGeneration:9,status:'completed'};}}};
  t.after(()=>{aggregateResetComposition=null;});
  installModuleStub('../server/database/sensitiveInfoWorkshopDb', {
    ensureObjectives:async()=>{},getProgress:async()=>[],resetUser:async()=>{},
  });
  installModuleStub('../server/services/workshopModeHandlers', {
    createWorkshopModeHandlers:()=>({get(){},set(){}}),
  });
  const routePath=require.resolve('../server/routes/sensitiveInfoWorkshop');
  delete require.cache[routePath];const router=require(routePath);
  const reset=handlers(router,'/progress/reset','post').at(-1);
  const request={user:{id:41},body:{},get:name=>name.toLowerCase()==='x-reset-operation-id'?operationId:undefined};
  const first=await invoke(reset,request),replay=await invoke(reset,request);
  assert.equal(first.statusCode,200);assert.equal(replay.statusCode,200);
  assert.deepEqual(seen,[{owner:41,options:{operationId}},{owner:41,options:{operationId}}]);
  assert.deepEqual(first.body.reset,{operationId,fromGeneration:8,toGeneration:9,status:'completed'});
  assert.deepEqual(replay.body.reset,first.body.reset);
});

test('FinFlow PostgreSQL reset maintenance opt-out fails closed without local cleanup',async()=>{
 aggregateResetComposition=null;let localResets=0;
 installModuleStub('../server/database/sensitiveInfoWorkshopDb',{
  engine:'postgres',ensureObjectives:async()=>{},getProgress:async()=>[],resetUser:async()=>{localResets+=1;},
 });
 installModuleStub('../server/services/workshopModeHandlers',{
  createWorkshopModeHandlers:()=>({get(){},set(){}}),
 });
 const routePath=require.resolve('../server/routes/sensitiveInfoWorkshop');
 delete require.cache[routePath];const router=require(routePath);
 const reset=handlers(router,'/progress/reset','post').at(-1);
 const res=await invoke(reset,{user:{id:41},body:{},get:()=>undefined});
 assert.equal(res.statusCode,503);assert.equal(res.body.unavailable,true);assert.equal(localResets,0);
});
