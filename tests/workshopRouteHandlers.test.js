'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createWorkshopRouteHandlers } = require('../server/agent-runtime/workshopRouteHandlers');
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function request() { return Object.assign(new EventEmitter(), { user: { id: 7 }, body: { userMessage: 'hello', userId: 999 } }); }
function response() { return Object.assign(new EventEmitter(), { statusCode: 200,
  status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; this.writableEnded = true; return this; } }); }
for (const name of ['aria', 'nova']) {
  const { createAgent } = require(`../server/services/${name}AgentService`);
  function fixture({ model, sync, resetProgress } = {}) {
    const events = [];
    const store = { async getHistory() { return []; }, async saveMessage(id, role) { events.push([id, role]); },
      async clearHistory(id) { events.push([id, 'clearHistory']); }, async clearCart() {}, async clearReadingList() {} };
    const agent = createAgent({ store, decisionMode: 'scripted', runLedger: null, model: model || { async generateResponse() { return { response: 'hello' }; } } });
    const handlers = createWorkshopRouteHandlers({legacyFixture:true, agent, store, workshopKey: name,
      challengeKey: name, modeService: { async getMode() { return 'vuln'; } },
      syncObjectiveComplete: sync || (async id => events.push([id, 'credit'])),
      resetWorkshopProgress: resetProgress || (async id => events.push([id, 'clearProgress'])),
      grading: { begin: async () => null, evaluate: async ({ userId }) => { await (sync || (async id => events.push([id, 'credit'])))(userId); return { completed: true, judgment: { verdict: 'pass', provider: 'fixture' } }; } },
      detectCompletedObjectives: () => ['one'], objectiveLabels: { one: 'One' },
      clearState: name === 'aria' ? 'clearCart' : 'clearReadingList', resetMessage: 'cleared', logger: { error() {} },
    });
    return { handlers, events };
  }
  test(`${name} actual chat handler preserves DTO and authenticated ownership`, async () => {
    const { handlers, events } = fixture(); const res = response();
    await handlers.chat(request(), res);
    assert.match(res.body.run.runId, /^[a-f0-9-]{36}$/);
    assert.equal(res.body.run.decisionSource, 'scripted');
    const { run, ...body } = res.body;
    assert.deepEqual(body, { success: true, response: 'hello', toolUsed: null, toolResult: null, toolObservations: [], completedObjectives: ['one'], judgments: [{ verdict: 'pass', provider: 'fixture' }], mode: 'vuln' });
    assert.deepEqual(events, [['7', 'user'], ['7', 'assistant'], [7, 'credit']]);
  });
  test(`${name} reset waits for canonical credit then clears it`, { timeout: 2000 }, async () => {
    const entered = deferred(), resume = deferred(); const order = [];
    const { handlers } = fixture({ sync: async () => { entered.resolve(); await resume.promise; order.push('credit'); },
      resetProgress: async () => order.push('clear') });
    const chatRes = response(), resetRes = response();
    const chat = handlers.chat(request(), chatRes); await entered.promise;
    const reset = handlers.reset(request(), resetRes);
    await new Promise(r => setImmediate(r)); assert.deepEqual(order, []);
    resume.resolve(); await Promise.all([chat, reset]);
    assert.deepEqual(order, ['credit', 'clear']);
    assert.equal(chatRes.statusCode, 409); assert.equal(resetRes.body.success, true);
  });
  test(`${name} disconnected request cannot save model output or credit`, { timeout: 2000 }, async () => {
    const entered = deferred(), resume = deferred();
    const { handlers, events } = fixture({ model: { async generateResponse() { entered.resolve(); await resume.promise; return { response: 'late' }; } } });
    const req = request(), res = response(); const pending = handlers.chat(req, res);
    await entered.promise; res.emit('close'); await pending; resume.resolve();
    assert.deepEqual(events, []); assert.equal(res.body, undefined);
  });
  test(`${name} reset reports canonical progress failure`, async () => {
    const { handlers } = fixture({ resetProgress: async () => { throw new Error('unavailable'); } });
    const res = response(); await handlers.reset(request(), res);
    assert.equal(res.statusCode, 500); assert.equal(res.body.success, false);
  });
}

test('route grades every ordered tool observation under one run attempt',async()=>{
 const observed=[],evaluated=[],detected=[];const agent={invoke:async(_owner,_message,_mode,options)=>{const execution={runId:'11111111-1111-4111-8111-111111111111',generation:3,check:async()=>{},trace:async()=>{}};await options.onStart(execution);const dto={response:'final summary',toolUsed:'search_products',toolResult:[{id:2}],toolObservations:[{index:0,toolUsed:'search_products',toolResult:[{id:1}],invocation:{tool:'search_products',params:{searchTerm:'first'}}},{index:1,toolUsed:'search_products',toolResult:[{id:2}],invocation:{tool:'search_products',params:{searchTerm:'second'}}}],run:{runId:execution.runId,decisionSource:'model'}};await options.onResult(dto,execution.check,execution,{tool:'search_products',params:{searchTerm:'second'}});return dto;}};
 const handlers=createWorkshopRouteHandlers({legacyFixture:true,agent,store:{},workshopKey:'sql_injection_workshop',challengeKey:'sql_injection',modeService:{getMode:async()=> 'vuln'},syncObjectiveComplete:async()=>{},resetWorkshopProgress:async()=>{},detectCompletedObjectives:(message,_t,result)=>{detected.push(message);return [`objective_${result[0].id}`];},objectiveLabels:{objective_1:'one',objective_2:'two'},clearState:'clearCart',resetMessage:'clear',grading:{begin:async()=>({generation:3}),observe:async packet=>observed.push(packet),evaluate:async packet=>{evaluated.push(packet);return {completed:true,judgment:{objectiveId:packet.objectiveId,verdict:'pass'}};}},logger:{error(){}}});
 const res=response();await handlers.chat(request(),res);
 assert.deepEqual(observed.map(x=>x.observationIndex),[0,1]);assert.deepEqual(evaluated.map(x=>x.observationIndex),[0,1]);assert.deepEqual(detected,['first','second']);assert.deepEqual(evaluated.map(x=>x.objectiveId),['objective_1','objective_2']);assert.ok(evaluated.every(x=>x.attempt.generation===3&&x.execution.runId==='11111111-1111-4111-8111-111111111111'));assert.deepEqual(res.body.completedObjectives,['objective_1','objective_2']);
});

test('later successful observation can complete an objective after an earlier failed attempt', async () => {
 const evaluated = [], observed = [];
 const execution = { runId: '11111111-1111-4111-8111-111111111111', generation: 3, check: async () => {}, trace: async () => {} };
 const dto = { response: 'Final result', toolObservations: [false, true, true].map((success, index) => ({
  index, toolUsed: 'search_products', toolResult: { success },
  invocation: { tool: 'search_products', params: { searchTerm: `attempt-${index}` } },
 })) };
 const handlers = createWorkshopRouteHandlers({legacyFixture:true,
  agent: { async invoke(_owner, _message, _mode, hooks) {
   await hooks.onStart(execution); await hooks.onResult(dto, execution.check, execution); return dto;
  } }, store: {}, workshopKey: 'sql_injection_workshop',
  modeService: { getMode: async () => 'vuln' }, detectCompletedObjectives: () => ['sqli_5'],
  grading: { begin: async () => ({ generation: 3 }), observe: async p => observed.push(p),
   evaluate: async p => {
    evaluated.push(p.result.toolInvocation.params.searchTerm);
    const completed = p.result.toolResult.success;
    return { completed, judgment: { objectiveId: p.objectiveId, verdict: completed ? 'pass' : 'fail', evaluationId: evaluated.length } };
   } }, logger: { error() {} },
 });
 const res = response(); await handlers.chat(request(), res);
 assert.equal(res.statusCode, 200);
 assert.equal(observed.length, 3, 'all actual tool effects are retained');
 assert.deepEqual(evaluated, ['attempt-0', 'attempt-1'], 'grade until success without redundant post-success calls');
 assert.deepEqual(res.body.completedObjectives, ['sqli_5']);
 assert.deepEqual(res.body.judgments, [{ objectiveId: 'sqli_5', verdict: 'pass', evaluationId: 2 }]);
});
for(const workshopKey of ['sql_injection','nosql_injection'])test(`${workshopKey} mounted chat/reset capacity projects503 without changing cancel/auth/errors`,async t=>{
 const express=require('express'),app=express();app.use(express.json());app.use((req,res,next)=>{if(!req.headers.authorization)return res.status(401).end();req.user={id:7};req.identitySession={id:9};next();});
 let error=Object.assign(Error('private busy details'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503}),calls=0;
 const handlers=createWorkshopRouteHandlers({agent:{invoke:async()=>{calls++;throw error;},reset:async()=>{calls++;throw error;}},store:{},workshopKey,modeService:{getMode:async()=> 'vuln'},grading:{},validateSession:async()=>({user:{id:7},session:{id:9,user_id:7}}),logger:{error(){}}});app.post('/chat',handlers.chat);app.post('/reset',handlers.reset);
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));t.after(()=>new Promise(r=>server.close(r)));
 const post=route=>fetch('http://127.0.0.1:'+server.address().port+route,{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer controlled'},body:JSON.stringify({userMessage:'hello'})});
 for(const route of ['/chat','/reset']){const response=await post(route);assert.equal(response.status,503);assert.deepEqual(await response.json(),{success:false,code:'GRAPH_RUN_CAPACITY_EXCEEDED',message:'Agent capacity is unavailable.'});}
 error=Object.assign(Error('cancel'),{name:'AbortError'});assert.equal((await post('/chat')).status,409);error=Object.assign(Error('revoked'),{code:'SESSION_REVOKED'});assert.equal((await post('/chat')).status,401);error=Object.assign(Error('Agent reset authority was superseded'),{name:'AbortError'});const superseded=await post('/reset');assert.equal(superseded.status,409);assert.deepEqual(await superseded.json(),{success:false,message:'Reset was superseded or cancelled.'});error=Object.assign(Error('revoked'),{code:'SESSION_REVOKED'});assert.equal((await post('/reset')).status,401);error=Error('other');assert.equal((await post('/chat')).status,500);assert.equal((await post('/reset')).status,500);assert.equal(calls,8);
});
