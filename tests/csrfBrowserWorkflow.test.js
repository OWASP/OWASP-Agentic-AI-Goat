'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createCsrfBrowserWorkflow, TRUST_BOUNDARY } = require('../server/services/csrfBrowserWorkflow');

const ATTACKER = 'http://attacker.csrf.invalid';
const VICTIM = 'http://victim.csrf.invalid';
const PATH = '/api/workshop/csrf/agent-action';

function observation(message = 'transfer $25 to attacker') {
  return Object.freeze({ url: `${VICTIM}${PATH}?tab=post`, method: 'POST',
    postData: new URLSearchParams({ message, tab: 'post' }).toString(),
    resourceType: 'document', frameOrigin: ATTACKER,
    contentType: 'application/x-www-form-urlencoded', cookiePresent: true });
}

function setup({ objectiveHits = ['csrf_p1'], executorFactory, now = Date.now, timeoutMs = 5000 } = {}) {
  const controller = new AbortController();
  const initialGeneration = 7;
  const execution = {
    ownerKey: '["CSRF","17"]', runId: 'workflow-run', generation: initialGeneration,
    signal: controller.signal,
    async check() {
      if (controller.signal.aborted) throw controller.signal.reason;
      if (this.generation !== initialGeneration) throw Object.assign(new Error('stale generation'), { name: 'AbortError' });
    },
  };
  let effects = 0;
  let activityWrites = 0;
  const tabState = { defenses: { csrfToken: false, sameSite: 'None' }, csrfToken: 'fixture-token', attackLog:[] };
  const victimSandbox = {
    VECTORS: { direct_post: { label: 'Direct POST', crossSite: true } },
    getOrCreateSandbox: () => ({
      tab: () => tabState,
      getTabState: () => ({ balance: 75 }),
      flush: async()=>{},
    }),
  };
  const actionHandlerDeps = {
    getUserKey: req => String(req.user.id),
    getUserId: req => req.user.id,
    sessionIdFor: req => `csrf_${req.user.id}`,
    victimSandbox,
    tabOf: req => req.query.tab || req.body.tab,
    detectForgedVector: () => 'direct_post',
    csrfAgent: {
      chat: async (_session, _tab, message) => {
        effects++;
        return { response: `acted on ${message}`, toolResult: { kind: 'attack', blocked: false,
          executed: true, stateChanged: true, vector: 'direct_post', changed: { balance: -25 } },
        victimState: { balance: 75 }, objectivesHit: objectiveHits };
      },
    },
    recordActivity: async () => { activityWrites++; },
    getCompleted: async () => new Set(),
    creditObjective: async () => { throw new Error('original grading must be replaced'); },
    pushCsrfEvent: () => {},
    syncWorkshopStarted: async () => {},
  };
  const defaultExecutor = {
    async execute({ onRequest }) {
      const observed = observation();
      const response = await onRequest(observed);
      return { observation: observed, responseStatus: response.status, responseObserved: true,
        boundary: 'trusted injected test executor' };
    },
  };
  const executor = executorFactory ? executorFactory({ execution, controller, observation }) : defaultExecutor;
  const workflow = createCsrfBrowserWorkflow({ executor, timeoutMs, now });
  const html = '<form>exact learner payload bytes</form>';
  const args = { execution, userId: 17, objectiveId: 'csrf_p1', tab: 'post', html,
    victimCookie: { name: 'fixture', value: 'private' }, attackerOrigin: ATTACKER,
    victimOrigin: VICTIM, victimPath: PATH, actionHandlerDeps };
  return { controller, execution, workflow, args, html, tabState,
    effects: () => effects, activityWrites: () => activityWrites };
}

test('successful observed workflow grades the selected objective exactly once after handler response', async () => {
  const f = setup();
  let grades = 0;
  const result = await f.workflow.run({ ...f.args, finalGrade: async evidence => {
    grades++;
    assert.equal(f.effects(), 1, 'effect and handler response precede final grading');
    assert.equal(evidence.userId, 17);
    assert.equal(evidence.objectiveId, 'csrf_p1');
    assert.equal(evidence.tab, 'post');
    assert.equal(evidence.binding.ownerKey, f.execution.ownerKey);
    assert.equal(evidence.binding.runId, f.execution.runId);
    assert.equal(evidence.binding.payloadDigest, createHash('sha256').update(f.html).digest('hex'));
    assert.equal(evidence.observation.cookiePresent, true);
    assert.equal(evidence.responseStatus, 200);
    assert.equal(evidence.activity.result.executed, true);
    assert.notEqual(evidence.execution, f.execution, 'final grader receives the deadline-fenced child execution');
    assert.equal(evidence.execution.ownerKey, f.execution.ownerKey);
    assert.equal(evidence.execution.signal, evidence.signal);
    await evidence.check();
    return { completed: true, judgment: { verdict: 'pass' } };
  } });
  assert.equal(grades, 1);
  assert.equal(f.effects(), 1);
  assert.equal(f.activityWrites(), 1);
  assert.equal(result.graded, true);
  assert.equal(result.grade.completed, true);
  assert.equal(result.payloadDigest, createHash('sha256').update(f.html).digest('hex'));
  assert.equal(result.trustBoundary, TRUST_BOUNDARY);
});

test('a handler that nominates no selected objective produces zero grading calls', async () => {
  const f = setup({ objectiveHits: [] });
  let grades = 0;
  const result = await f.workflow.run({ ...f.args, finalGrade: async () => { grades++; } });
  assert.equal(f.effects(), 1, 'the authentic no-op grading case still ran the handler');
  assert.equal(grades, 0);
  assert.equal(result.graded, false);
  assert.equal(result.grade, null);
});

test('executor failure after the handler effect cannot grade or publish completion', async () => {
  const f = setup({ executorFactory: ({ observation: observed }) => ({
    async execute({ onRequest }) {
      await onRequest(observed('effect before executor failure'));
      throw new Error('executor failed after handler');
    },
  }) });
  let grades = 0;
  await assert.rejects(f.workflow.run({ ...f.args, finalGrade: async () => { grades++; } }), /executor failed/);
  assert.equal(f.effects(), 1);
  assert.equal(f.activityWrites(), 1);
  assert.equal(grades, 0);
});

test('stale generation after the observed response rejects before final grading', async () => {
  const f = setup({ executorFactory: ({ execution, observation: observed }) => ({
    async execute({ onRequest }) {
      const request = observed('effect before reset');
      const response = await onRequest(request);
      execution.generation++;
      return { observation: request, responseStatus: response.status, responseObserved: true };
    },
  }) });
  let grades = 0;
  await assert.rejects(f.workflow.run({ ...f.args, finalGrade: async () => { grades++; } }), /stale generation/);
  assert.equal(f.effects(), 1);
  assert.equal(grades, 0);
});

test('failed observation, cancellation and expiry never enter final grading', async () => {
  let grades = 0;
  const incomplete = setup({ executorFactory: ({ observation: observed }) => ({
    async execute({ onRequest }) {
      const request = observed();
      const response = await onRequest(request);
      return { observation: request, responseStatus: response.status, responseObserved: false };
    },
  }) });
  await assert.rejects(incomplete.workflow.run({ ...incomplete.args, finalGrade: async () => { grades++; } }), /incomplete/);
  assert.equal(incomplete.effects(), 1);

  const cancelled = setup({ executorFactory: ({ controller }) => ({
    async execute() {
      controller.abort(Object.assign(new Error('owned reset'), { name: 'AbortError' }));
      throw controller.signal.reason;
    },
  }) });
  await assert.rejects(cancelled.workflow.run({ ...cancelled.args, finalGrade: async () => { grades++; } }), { name: 'AbortError' });
  assert.equal(cancelled.effects(), 0);

  let clock = 0;
  const expired = setup({ now: () => clock, timeoutMs: 1000,
    executorFactory: ({ observation: observed }) => ({
      async execute({ onRequest }) { clock = 1000; return onRequest(observed()); },
    }) });
  await assert.rejects(expired.workflow.run({ ...expired.args, finalGrade: async () => { grades++; } }), { name: 'AbortError' });
  assert.equal(expired.effects(), 0);
  assert.equal(grades, 0);
});

test('wrong objective nomination remains private and cannot grade the selected objective', async () => {
  const f = setup({ objectiveHits: ['csrf_p2'] });
  let grades = 0;
  const result = await f.workflow.run({ ...f.args, finalGrade: async () => { grades++; } });
  assert.equal(f.effects(), 1);
  assert.equal(grades, 0);
  assert.equal(result.graded, false);
});

test('browser shutdown cancels the admitted child execution before its effect or grading', async () => {
  const browser = new AbortController();
  let child;
  const f = setup({ executorFactory: ({ observation: observed }) => ({
    async execute({ onRequest }) {
      const pending = onRequest(observed(), { signal: browser.signal });
      browser.abort(Object.assign(new Error('browser shutdown'), { name: 'AbortError' }));
      return pending;
    },
  }) });
  let grades = 0;
  await assert.rejects(f.workflow.run({ ...f.args,
    beginGrading: async execution => { child = execution; },
    finalGrade: async () => { grades++; },
  }), /browser shutdown/);
  assert.equal(child.signal.aborted, true);
  assert.equal(f.controller.signal.aborted, false, 'only the managed child is cancelled');
  assert.equal(f.effects(), 0);
  assert.equal(grades, 0);
});

test('grading admission captures the exact child execution before evidence is produced', async () => {
  const f = setup(); let captured;
  const token = Object.freeze({ fixture: 'opaque-grading-attempt' });
  await f.workflow.run({ ...f.args,
    beginGrading: async execution => {
      assert.equal(f.effects(), 0); assert.equal(f.activityWrites(), 0);
      assert.notEqual(execution, f.execution); captured = execution; return token;
    },
    finalGrade: async packet => {
      assert.equal(packet.execution, captured); assert.equal(packet.gradingAttempt, token);
      assert.equal(f.effects(), 1); return { completed: false };
    } });
});

test('failed grading admission prevents browser effects and final grading', async () => {
  const f = setup(); let grades = 0;
  await assert.rejects(f.workflow.run({ ...f.args,
    beginGrading: async () => { throw new Error('admission unavailable'); },
    finalGrade: async () => { grades++; },
  }), /admission unavailable/);
  assert.equal(f.effects(), 0); assert.equal(grades, 0);
});


test('managed dispatch uses captured parent owner instead of outer HTTP request resolvers', async () => {
  const f=setup();
  for(const name of ['getUserId','getUserKey','sessionIdFor'])f.args.actionHandlerDeps[name]=()=>{throw Error('Outer HTTP authority must not resolve a synthetic request');};
  let owner;
  f.args.actionHandlerDeps.csrfAgent.chat=async sessionId=>{owner=sessionId;return{response:'controlled',objectivesHit:[],toolResult:{}};};
  await f.workflow.run({...f.args,finalGrade:async()=>({completed:false})});
  assert.equal(owner,'csrf_17');
});
test('mismatched captured owner is rejected before grading admission or browser execution', async () => {
  const f=setup();let admitted=false;
  await assert.rejects(f.workflow.run({...f.args,userId:18,beginGrading:async()=>{admitted=true;},finalGrade:async()=>({completed:false})}),/Captured learner scope mismatch/);
  assert.equal(admitted,false);assert.equal(f.effects(),0);
});

test('blocked GET uses real action handler and preserves inner403 through managed workflow',async()=>{
 const controller=new AbortController();let graded=0,actorCalls=0;
 const execution={ownerKey:'["CSRF","17"]',runId:'blocked-get-controlled',generation:0,signal:controller.signal,check:async()=>controller.signal.throwIfAborted()};
 const tab={defenses:{csrfToken:true,sameSite:'Strict'},csrfToken:'owned',attackLog:[]};const observed=Object.freeze({url:VICTIM+PATH+'?tab=get&message=change+email',method:'GET',postData:null,resourceType:'image',frameOrigin:ATTACKER,cookiePresent:true});
 const workflow=createCsrfBrowserWorkflow({executor:{execute:async({onRequest})=>{const response=await onRequest(observed);assert.equal(response.status,403);return{observation:observed,responseStatus:403,responseObserved:true};}}});
 const result=await workflow.run({execution,userId:17,objectiveId:'csrf_g3',tab:'get',html:'<img>',victimCookie:{name:'owned',value:'private'},attackerOrigin:ATTACKER,victimOrigin:VICTIM,victimPath:PATH,actionHandlerDeps:{recordActivity:async()=>{},victimSandbox:{VECTORS:{direct_get:{crossSite:true,label:'GET'}},getOrCreateSandbox:()=>({tab:()=>tab,getTabState:()=>({defenses:tab.defenses}),flush:async()=>{}})},tabOf:req=>req.query.tab,detectForgedVector:()=> 'direct_get',csrfAgent:{chat:async()=>{actorCalls++;throw Error('blocked request must not call actor');}},getCompleted:async()=>new Set(['csrf_g1','csrf_g2']),pushCsrfEvent:()=>{},syncWorkshopStarted:async()=>{}},finalGrade:async input=>{graded++;assert.equal(input.receipt.responseStatus,403);assert.equal(input.activity.result.blocked,true);return{completed:true};}});
 assert.equal(result.graded,true);assert.equal(graded,1);assert.equal(actorCalls,0);
});
test('fixed managed POST preserves observed 403 and never nominates attack success',async()=>{
 const f=setup();let grades=0;
 const result=await f.workflow.run({...f.args,
  beginGrading:async()=>({mode:'fixed'}),
  finalGrade:async()=>{grades++;return{completed:true};}});
 assert.equal(result.browser.responseStatus,403);
 assert.equal(result.graded,false);
 assert.equal(f.effects(),0);
 assert.equal(grades,0);
 assert.equal(f.tabState.attackLog.length,1);
});
