'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');

function loadRoute(helpers) {
  const routePath = path.resolve(__dirname, '../server/routes/ctf.js');
  const original = Module._load;
  Module._load = function(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../agent-runtime/ctfStageJudge') return { stageDigest: () => 'unused', judgeCtfStage: async () => { throw new Error('judge forbidden'); } };
      if (request === '../agent-runtime/ctfAttemptCommit' || request === '../agent-runtime/ctfReset') assert.fail('SQLite CTF runtime import forbidden');
      if (request === '../agent-runtime/ownerWorkflowRoutes') return { ownerWorkflowRoute: (_c, _o, handler, options) => { assert.equal(typeof options?.withAdmission, 'function'); return handler; }, getOwnerExecution: () => null };
      if (request === '../agent-runtime/runCoordinator') return { createRunCoordinator: () => ({ reset: async (owner, work) => { helpers.ownerEvents?.push(['reset',owner]); return work(); }, cancel(owner) { helpers.ownerEvents?.push(['cancel',owner]); } }) };
      if (request === '../database/ctfDb') return { CTFHelpers: helpers };
      if (request === '../services/promptInjectionCTF') return { classifyTechnique() {}, hashPayload() {}, isNearDuplicate() {}, TECHNIQUE_TAGS: { OTHER: 'other' } };
      if (request === '../services/ctfDefenseLayers') return { runDefenseLayers() {}, runOutputDefenses() {}, normalizedContains() {} };
      if (request === '../agent-runtime/ctfGuardianResult') return { requireCtfGuardianResult() {} };
      if (request === '../middleware/ctfAttemptInput') return { ctfAttemptInput: () => (_q, _s, next) => next(), ctfStageIdInput: () => (_q, _s, next) => next(), ctfStageSecretInput: () => (_q, _s, next) => next() };
      if (request === '../services/multiProviderAIService') return {};
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../data/ctfSolutions') return { levels: [] };
      if (request === '../services/ctfLeaderboardRefreshCoordinator') return { createLeaderboardRefreshCoordinator: () => ({ requestRefresh() {}, flush: async () => {} }) };
    }
    return original.call(this, request, parent, isMain);
  };
  try { delete require.cache[routePath]; return { router: require(routePath).router, routePath }; }
  finally { Module._load = original; }
}

test('mounted PostgreSQL registration recovers at capacity and retains closed/cap responses', async t => {
  let outcome = { admitted: true, participantId: 7, recovered: true };
  const admissions = [], writes = [];
  const helpers = {
    getConfig: async () => 'true', updateLeaderboard: async () => true,
    admitParticipant: async (...args) => { admissions.push(args); return outcome; },
    countParticipants: async () => { throw new Error('racy pre-count forbidden'); },
    registerParticipant: async () => { throw new Error('non-atomic registration forbidden'); },
    createSession: async (...args) => { writes.push(['session', ...args]); return 1; },
    recordRegistration: async (...args) => { writes.push(['event', ...args]); return 1; },
  };
  const express = require('express'); const { router, routePath } = loadRoute(helpers);
  const app = express(); app.use(express.json());
  app.use((req, _res, next) => { req.user = { id: 202, username: 'existing', email: 'existing@fixture.invalid', role: 'student' }; next(); });
  app.use(router);
  const server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
  t.after(async () => { await new Promise(resolve => server.close(resolve)); delete require.cache[routePath]; });
  const send = displayName => fetch(`http://127.0.0.1:${server.address().port}/register`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ displayName }),
  });

  const recovered = await send('Existing learner');
  assert.equal(recovered.status, 200);
  assert.deepEqual(admissions, [[202, 'Existing learner', 'existing@fixture.invalid', null]]);
  assert.deepEqual(writes.map(row => row[0]), ['session', 'event']);

  const writesBeforeDenials = writes.length;
  outcome = { admitted: false, reason: 'registration_closed' };
  const closed = await send('Closed learner');
  assert.equal(closed.status, 403); assert.deepEqual(await closed.json(), { error: 'CTF registration is currently closed' });
  outcome = { admitted: false, reason: 'capacity_reached' };
  const full = await send('Full learner');
  assert.equal(full.status, 403); assert.deepEqual(await full.json(), { error: 'CTF participant limit reached' });
  assert.equal(writes.length, writesBeforeDenials);
});

test('CTF database entry binds PostgreSQL regardless of obsolete engine or SQLite path settings', () => {
  const databasePath=path.resolve(__dirname,'../server/database/ctfDb.js'),original=Module._load;
  const previousEngine=process.env.WORKSHOP_DATABASE_ENGINE,previousPath=process.env.CTF_DB_PATH;
  const postgres=Object.freeze({engine:'postgres',CTFHelpers:Object.freeze({})});let loads=0;
  Module._load=function(request,parent,isMain){
    if(parent?.filename===databasePath){assert.equal(request,'./postgres/ctfDb');loads++;return postgres;}
    return original.call(this,request,parent,isMain);
  };
  try{
    process.env.CTF_DB_PATH='/forbidden/obsolete-ctf.db';
    for(const engine of [undefined,'sqlite','postgres']){
      if(engine===undefined)delete process.env.WORKSHOP_DATABASE_ENGINE;else process.env.WORKSHOP_DATABASE_ENGINE=engine;
      delete require.cache[databasePath];assert.equal(require(databasePath),postgres);
    }
    assert.equal(loads,3);
  }finally{
    Module._load=original;delete require.cache[databasePath];
    if(previousEngine===undefined)delete process.env.WORKSHOP_DATABASE_ENGINE;else process.env.WORKSHOP_DATABASE_ENGINE=previousEngine;
    if(previousPath===undefined)delete process.env.CTF_DB_PATH;else process.env.CTF_DB_PATH=previousPath;
  }
});

test('mounted CTF resets use PostgreSQL owner scopes and cancel every owner before global reset', async t => {
  const ownerEvents=[],resets=[];
  const helpers={ownerEvents,findParticipant:async id=>({id:20,user_id:id,username:'Owner'}),
    reset:async scope=>{resets.push(scope);ownerEvents.push(['store',scope]);},
    resetParticipant:async id=>{resets.push({participantId:id});},listOwners:async()=>[{user_id:202},{user_id:303}]};
  const express=require('express'),{router,routePath}=loadRoute(helpers),app=express();app.use(express.json());
  app.use((req,_res,next)=>{req.user={id:202,role:req.get('x-test-admin')==='yes'?'admin':'student'};next();});app.use(router);
  const server=await new Promise(resolve=>{const listener=app.listen(0,'127.0.0.1',()=>resolve(listener));});
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));delete require.cache[routePath];});
  const send=(route,body={},admin=true)=>fetch(`http://127.0.0.1:${server.address().port}${route}`,{
    method:'POST',headers:{'content-type':'application/json','x-test-admin':admin?'yes':'no'},body:JSON.stringify(body)});
  assert.equal((await send('/admin/participants/202/remove',{},false)).status,403);assert.equal(resets.length,0);
  assert.equal((await send('/admin/participants/202/reset')).status,200);
  assert.equal((await send('/admin/participants/202/remove')).status,200);
  assert.deepEqual(resets,[{participantId:20},{participantId:20,userId:202,remove:true}]);
  assert.equal((await send('/admin/reset',{confirm:'wrong'})).status,400);assert.equal(resets.length,2);
  ownerEvents.length=0;
  assert.equal((await send('/admin/reset',{confirm:'RESET_CTF_CONFIRM'})).status,200);
  assert.deepEqual(ownerEvents,[['cancel',202],['cancel',303],['store',{all:true}]]);
});

test('hidden or nonconsecutive levels cannot bypass the previous active CTF prerequisite',async t=>{
 let previous={id:5},completed=false,started=0;
 const helpers={getConfig:async key=>key==='ctf_time_limit'?'-1':'true',findActiveParticipant:async()=>({id:20}),isBanned:async()=>false,
  getActiveStage:async()=>({id:7,stage_order:7,stage_name:'Test'}),getPreviousActiveStage:async order=>{assert.equal(order,7);return previous;},
  getStageByOrder:async()=>assert.fail('Exact preceding order can be hidden'),getProgressStatus:async(participant,id)=>{assert.equal(participant,20);assert.equal(id,5);return completed?{status:'completed'}:undefined;},
  getProgress:async()=>null,startStage:async()=>{started++;},updateParticipantActivity:async()=>{},recordStageStart:async()=>{}};
 const express=require('express'),{router,routePath}=loadRoute(helpers),app=express();app.use(express.json());app.use((req,_res,next)=>{req.user={id:202,role:'student'};next();});app.use(router);
 const server=await new Promise(resolve=>{const listener=app.listen(0,'127.0.0.1',()=>resolve(listener));});t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));delete require.cache[routePath];});
 const send=()=>fetch(`http://127.0.0.1:${server.address().port}/stage/7/start`,{method:'POST'});
 assert.equal((await send()).status,403);assert.equal(started,0);
 completed=true;assert.equal((await send()).status,200);assert.equal(started,1);
 previous=null;completed=false;assert.equal((await send()).status,200);assert.equal(started,2);
});
