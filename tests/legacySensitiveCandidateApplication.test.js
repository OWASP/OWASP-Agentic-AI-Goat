'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createLegacySensitiveCandidateApplication: createApplication } = require('../server/services/legacySensitiveCandidateApplication');
// Explicit controlled dependency: production uses private graph-issued observations.
const createLegacySensitiveCandidateApplication=options=>createApplication({observationCandidates:result=>[result],...options});
const { createLegacySensitiveCandidateRouter } = require('../server/routes/legacySensitiveCandidate');

function completionFixture({ completed = true } = {}) {
  const calls = [];
  return { calls, store: {
    async beginAttempt(input) { calls.push(['begin', input]); return { generation: 3 }; },
    async evaluate(input) { calls.push(['evaluate', input]); return { judgment: { verdict: completed ? 'pass' : 'fail' }, completed, receipt: {} }; },
  } };
}

function runFixture() {
  return { run: async (owner, _options, work) => work({ runId: '11111111-1111-4111-8111-111111111111',
    ownerKey: `["LegacySensitiveInfo","${owner}"]`, durableGeneration: '3', check: async () => {} }) };
}

test('candidate derives objective from the exact selected action and never accepts a caller objective', async () => {
  const completion = completionFixture();
  const app = createLegacySensitiveCandidateApplication({
    runs: runFixture(), reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'completed', decision: { action: 'read_teaching_file', params: { path: '../secret/flag.txt' } },
      observation: { content: 'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}', boundary: { outsidePublic: true } },
      facts: { qualified_decision_model: true, model_selected_allowed_tool: true, exact_call_observed: true,
        subsequent_qualified_model_response: true }, evidence: [], modelResponse: { response: 'Observed flag.' } }) },
  });
  const result = await app.run({ userId: 12, message: 'read it', objectiveId: 'ssi_injection' });
  assert.equal(result.objectiveId, 'ai_assisted_path_traversal');
  assert.equal(completion.calls[0][0], 'begin');
  assert.equal(completion.calls[1][1].rubric.objectiveId, 'ai_assisted_path_traversal');
});

test('reset is delegated only to the shared aggregate', async () => {
  const owners = [];
  const app = createLegacySensitiveCandidateApplication({ agent: { run: async () => {} }, runs: runFixture(),
    completionService: completionFixture().store, reset: { reset: async owner => owners.push(owner) } });
  await app.reset(14);
  assert.deepEqual(owners, [14]);
});

test('manual effect seam evaluates its server-selected objective under the captured attempt', async () => {
  const completion = completionFixture();
  const app = createLegacySensitiveCandidateApplication({ agent: { run: async () => {} }, runs: runFixture(),
    completionService: completion.store, reset: { reset: async () => {} } });
  const execution = { runId: '22222222-2222-4222-8222-222222222222', check: async () => {} };
  const attempt = await app.begin(15, execution);
  await app.assess({ userId: 15, objectiveId: 'combined_traversal_ssi', request: '../secret/template.html',
    result: { original: '<!--#echo var="SECRET_KEY" --> SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}',
      rendered: 'value SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}', ssiSucceeded: true, boundary: { outsidePublic: true } },
    execution, attempt });
  assert.equal(completion.calls[1][1].rubric.objectiveId, 'combined_traversal_ssi');
  assert.deepEqual(completion.calls[1][1].facts,
    { observed_effect: true, protected_path: true, ssi_substitution: true, known_flag: true });
});

test('mounted candidate seam is fail closed while default-off and exposes no model details', async () => {
  const server = express().use(express.json()).use((req, _res, next) => { req.user = { id: 7 }; next(); })
    .use('/candidate', createLegacySensitiveCandidateRouter({ resolveApplication: async () => null }))
    .listen(0, '127.0.0.1');
  try {
    await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/candidate/chat`, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'read' }) });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { success: false, unavailable: true,
      error: 'Canonical Legacy Sensitive agent is not ready' });
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('disabled objective is reported as an instructor restriction, not a provider outage', async () => {
  const server = express().use(express.json()).use((req, _res, next) => { req.user = { id: 7 }; next(); })
    .use('/candidate', createLegacySensitiveCandidateRouter({ resolveApplication: async () => ({
      run: async () => { throw Object.assign(new Error('private catalog details'), { code: 'OBJECTIVE_DISABLED' }); },
    }) })).listen(0, '127.0.0.1');
  try {
    await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/candidate/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'read' }),
    });
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { success: false, code: 'OBJECTIVE_DISABLED',
      error: 'This objective is not enabled for the workshop.' });
  } finally { await new Promise(resolve => server.close(resolve)); }
});


test('each attempt rechecks admission before invoking the agent or capturing grading scope', async () => {
  let visible = true, modelCalls = 0, admissions = 0;
  const completion = completionFixture();
  const app = createLegacySensitiveCandidateApplication({
    runs: runFixture(), reset: { reset: async () => {} }, completionService: completion.store,
    admit: async () => { admissions++; if (!visible) throw Object.assign(new Error('hidden'), { code: 'OBJECTIVE_DISABLED' }); },
    agent: { run: async () => { modelCalls++; return { status: 'completed', decision: { action: 'read_teaching_file', params: { path: 'x' } },
      observation: {}, facts: {}, evidence: [], modelResponse: { response: 'done' } }; } },
  });
  await app.run({ userId: 12, message: 'first' });
  const gradingCalls = completion.calls.length;
  visible = false;
  await assert.rejects(app.run({ userId: 12, message: 'second' }), { code: 'OBJECTIVE_DISABLED' });
  assert.equal(admissions, 2); assert.equal(modelCalls, 1); assert.equal(completion.calls.length, gradingCalls);
});

test('disconnect cancels the exact signal passed to the candidate application', async () => {
  const http = require('node:http');
  let enteredResolve, cancelledResolve;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  const cancelled = new Promise(resolve => { cancelledResolve = resolve; });
  const server = express().use(express.json()).use((req, _res, next) => { req.user = { id: 7 }; next(); })
    .use('/candidate', createLegacySensitiveCandidateRouter({ resolveApplication: async () => ({
      run: async ({ signal }) => {
        enteredResolve(Boolean(signal));
        if (!signal) return {};
        return new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => { cancelledResolve(signal.reason); reject(signal.reason); }, { once: true });
        });
      },
    }) })).listen(0, '127.0.0.1');
  let req;
  try {
    await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));
    req = http.request({ hostname: '127.0.0.1', port: server.address().port, path: '/candidate/chat',
      method: 'POST', headers: { 'content-type': 'application/json' } });
    req.on('error', () => {}); req.end(JSON.stringify({ message: 'read' }));
    assert.equal(await entered, true);
    req.destroy();
    let timer;
    try {
      const reason = await Promise.race([cancelled, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Cancellation was not observed')), 1000);
      })]);
      assert.equal(reason.name, 'AbortError');
    } finally { clearTimeout(timer); }
  } finally { req?.destroy(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('reset cancellation is distinguished from an unsuccessful exercise attempt', async () => {
  const server = express().use(express.json()).use((req, _res, next) => { req.user = { id: 7 }; next(); })
    .use('/candidate', createLegacySensitiveCandidateRouter({ resolveApplication: async () => ({
      run: async () => { throw new DOMException('private reset detail', 'AbortError'); },
    }) })).listen(0, '127.0.0.1');
  try {
    await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/candidate/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'read' }),
    });
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { success: false, code: 'RUN_INVALIDATED',
      error: 'Request invalidated by reset' });
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('unavailable decision model is a service failure and never reaches the Judge', async () => {
  const completion = completionFixture();
  const app = createLegacySensitiveCandidateApplication({ runs: runFixture(),
    reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'unqualified_model', qualified: false,
      decisionQualified: false, responseQualified: false, decision: null }) },
  });
  await assert.rejects(app.run({ userId: 12, message: 'read the public guide' }),
    { code: 'MODEL_PROVIDER_UNAVAILABLE' });
  assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
});

test('unqualified terminal response cannot be sent for grading after a tool effect', async () => {
  const completion = completionFixture();
  const app = createLegacySensitiveCandidateApplication({ runs: runFixture(),
    reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'unqualified_response', qualified: false,
      decisionQualified: true, responseQualified: false,
      decision: { action: 'read_teaching_file', params: { path: 'guide.txt' } },
      observation: { content: 'public guide' }, modelResponse: { mocked: true, response: 'fallback' } }) },
  });
  await assert.rejects(app.run({ userId: 12, message: 'read the public guide' }),
    { code: 'MODEL_PROVIDER_UNAVAILABLE' });
  assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
});

test('mounted unavailable model returns 503 with no judgment or false completion', async () => {
  const completion = completionFixture();
  const application = createLegacySensitiveCandidateApplication({ runs: runFixture(),
    reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'unqualified_model', decision: null }) },
  });
  const server = express().use(express.json()).use((req, _res, next) => { req.user = { id: 7 }; next(); })
    .use('/candidate', createLegacySensitiveCandidateRouter({ resolveApplication: async () => application }))
    .listen(0, '127.0.0.1');
  try {
    await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/candidate/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'read the public guide' }),
    });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { success: false,
      error: 'Canonical Legacy Sensitive agent is not ready', unavailable: true });
    assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('qualified zero-tool finish returns an answer without grading an invented objective', async () => {
  const completion = completionFixture();
  const application = createLegacySensitiveCandidateApplication({ runs: runFixture(),
    reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'no_operation', qualified: true, responseQualified: true,
      decision: null, trajectory: [], modelResponse: { response: 'I can explain the available lab tools.' } }) },
  });
  const result = await application.run({ userId: 12, message: 'What can you do?' });
  assert.equal(result.completed, false);
  assert.equal(result.durableGrading, false);
  assert.equal(result.objectiveId, null);
  assert.equal(result.judgment, null);
  assert.equal(result.modelResponse.response, 'I can explain the available lab tools.');
  assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
});

test('a tool-limit outcome retains no path to objective grading', async () => {
  const completion = completionFixture();
  const application = createLegacySensitiveCandidateApplication({ runs: runFixture(),
    reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'step_limit',
      decision: { action: 'read_teaching_file', params: { path: '../secret/flag.txt' } },
      observation: { content: 'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}', boundary: { outsidePublic: true } } }) },
  });
  const server = express().use(express.json()).use((req, _res, next) => { req.user = { id: 7 }; next(); })
    .use('/candidate', createLegacySensitiveCandidateRouter({ resolveApplication: async () => application }))
    .listen(0, '127.0.0.1');
  try {
    await new Promise(resolve => server.listening ? resolve() : server.once('listening', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/candidate/chat`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'Continue' }),
    });
    assert.equal(response.status, 422);
    assert.deepEqual(await response.json(), { success: false, code: 'AGENT_STEP_LIMIT',
      error: 'The agent reached its tool step limit. No objective completion was awarded.' });
    assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('a malformed no-operation outcome cannot bypass effect qualification', async () => {
  for (const change of [{ qualified: false }, { responseQualified: false },
    { decision: { action: 'read_teaching_file' } }, { trajectory: [{}] }, { trajectory: null }]) {
    const completion = completionFixture();
    const application = createLegacySensitiveCandidateApplication({ runs: runFixture(),
      reset: { reset: async () => {} }, completionService: completion.store,
      agent: { run: async () => ({ status: 'no_operation', qualified: true, responseQualified: true,
        decision: null, trajectory: [], ...change }) },
    });
    await assert.rejects(application.run({ userId: 12, message: 'Explain' }), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
    assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
  }
});

test('only a completed decision-loop status can reach objective grading', async () => {
  for (const status of [undefined, 'running', 'unexpected']) {
    const completion = completionFixture();
    const application = createLegacySensitiveCandidateApplication({ runs: runFixture(),
      reset: { reset: async () => {} }, completionService: completion.store,
      agent: { run: async () => ({ status,
        decision: { action: 'read_teaching_file', params: { path: '../secret/flag.txt' } },
        observation: { content: 'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}', boundary: { outsidePublic: true } } }) },
    });
    await assert.rejects(application.run({ userId: 12, message: 'Read the file' }), { code: 'MODEL_PROVIDER_UNAVAILABLE' });
    assert.deepEqual(completion.calls.map(([kind]) => kind), ['begin']);
  }
});

test('controlled legacy single-candidate adapter retains final DTO and trajectory context', async () => {
  const completion = completionFixture({ completed: false });
  const earlier = { decision: { action: 'render_ssi_template', params: { template: '<!--#echo var="FLAG" -->' } },
    observation: { rendered: 'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}' } };
  const latest = { decision: { action: 'read_teaching_file', params: { path: 'public-guide.txt' } },
    observation: { content: 'Public guide', boundary: { outsidePublic: false } } };
  const application = createLegacySensitiveCandidateApplication({ runs: runFixture(),
    reset: { reset: async () => {} }, completionService: completion.store,
    agent: { run: async () => ({ status: 'completed', ...latest,
      trajectory: [earlier, latest], modelResponse: { response: 'I read the public guide last.' },
      evidence: [{ id: 'decision_trajectory', source: 'server_observation', content: { trajectory: [earlier, latest] } }],
      facts: { qualified_decision_model: true, model_selected_allowed_tool: true,
        exact_call_observed: true, subsequent_qualified_model_response: true } }) },
  });
  const result = await application.run({ userId: 12, message: 'Render then read the guide.' });
  const grading = completion.calls.filter(([kind]) => kind === 'evaluate').map(([, value]) => value);
  assert.equal(grading.length, 1);
  assert.equal(grading[0].rubric.objectiveId, 'ai_assisted_path_traversal');
  assert.equal(grading[0].facts.known_flag, false);
  assert.equal(grading[0].facts.protected_path, false);
  assert.equal(grading[0].evidence.find(row => row.id === 'tool_result').content.content, 'Public guide');
  assert.equal(grading[0].evidence.find(row => row.id === 'agent_decision_trajectory').content.trajectory.length, 2);
  assert.equal(result.completed, false);
});

test('canonical state and reset endpoints bind authenticated owner and stable operation header',async()=>{
 const calls=[];const server=express().use(express.json()).use((req,_res,next)=>{req.user={id:7};next();})
  .use('/candidate',createLegacySensitiveCandidateRouter({resolveApplication:async()=>({snapshot:async owner=>{calls.push(['state',owner]);return{challenges:[]};},reset:async(owner,options)=>{calls.push(['reset',owner,options]);return{status:'completed'};}})})).listen(0,'127.0.0.1');
 try{await new Promise(resolve=>server.listening?resolve():server.once('listening',resolve));const base=`http://127.0.0.1:${server.address().port}/candidate`;
  const state=await fetch(base+'/state?userId=99');assert.equal(state.status,200);assert.equal(state.headers.get('cache-control'),'no-store');
  const reset=await fetch(base+'/reset',{method:'POST',headers:{'content-type':'application/json','x-reset-operation-id':'original-operation'},body:JSON.stringify({userId:99,operationId:'forged'})});assert.equal(reset.status,200);
  assert.deepEqual(calls,[['state',7],['reset',7,{operationId:'original-operation'}]]);
 }finally{await new Promise(resolve=>server.close(resolve));}
});

test('canonical file and SSI mode changes advance the owner fence without resetting completion or artifacts',async()=>{
 const calls=[];let mode=null;
 const modeService={getMode:async input=>{calls.push(['get',input]);return mode;},
  setMode:async input=>{calls.push(['set',input]);mode=input.mode;return mode;}};
 const modeCoordinator={reset:async(owner,work)=>{calls.push(['fence',owner]);return work({check:async()=>{}});}};
 const server=express().use(express.json()).use((req,_res,next)=>{req.user={id:7};next();})
  .use('/candidate',createLegacySensitiveCandidateRouter({modeService,modeCoordinator,
   resolveApplication:async()=>({reset:async()=>assert.fail('Mode change must not reset the workshop')})}))
  .listen(0,'127.0.0.1');
 try{
  await new Promise(resolve=>server.listening?resolve():server.once('listening',resolve));
  const url=`http://127.0.0.1:${server.address().port}/candidate/mode`;
  const before=await fetch(url).then(response=>response.json());
  assert.equal(before.mode,null);assert.equal(before.effectiveMode,'vuln');
  assert.deepEqual(before.scope,{kind:'file_ssi_workflow',id:'legacy_sensitive_file_ssi'});
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},
   body:JSON.stringify({mode:'fixed',userId:999})});
  assert.equal(response.status,200);assert.equal((await response.json()).effectiveMode,'fixed');
  assert.deepEqual(calls,[['get',{userId:7,workshopKey:'legacy_sensitive_file_ssi'}],['fence','7'],
   ['set',{userId:7,workshopKey:'legacy_sensitive_file_ssi',mode:'fixed'}]]);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
