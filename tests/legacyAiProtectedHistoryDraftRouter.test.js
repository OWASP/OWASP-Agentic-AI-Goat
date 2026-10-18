'use strict';

const http = require('node:http');
const test = require('node:test');
const assert = require('node:assert/strict');
const { createLegacyAiExperimentRunner } = require('../server/services/legacyAiExperimentRunner');
const express = require('express');

const {
  createLegacyAiProtectedHistoryDraftRouter,
} = require('../server/routes/legacyAiProtectedHistoryDraftRouter');
const {
  createLegacyAiHistoryRequestService,
} = require('../server/services/legacyAiHistoryRequestService');

async function startFixture({ validateSession, historyService, experimentAccess = (req, res, next) => next() }) {
  const app = express();
  app.use(express.json());
  app.use('/api/ai', createLegacyAiProtectedHistoryDraftRouter({
    experimentAccess,
    identityAdapter: { validateSession },
    historyService,
  }));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}/api/ai`,
    close: () => new Promise(resolve => server.close(resolve)),
  };
}

async function request(fixture, path, {
  body,
  headers = {},
  method = 'POST',
} = {}) {
  const response = await fetch(`${fixture.baseUrl}${path}`, {
    body: body === undefined ? undefined : JSON.stringify(body),
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...headers,
    },
    method,
  });
  return { body: await response.json(), status: response.status };
}

function serviceFixture(overrides = {}) {
  const calls = [];
  return {
    calls,
    service: {
      runAuthenticated: async value => {
        calls.push(['authenticated', value]);
        return { response: 'protected response', modelUsed: 'protected-model' };
      },
      runAnonymous: async value => {
        calls.push(['anonymous', value]);
        return { response: 'anonymous response', modelUsed: 'anonymous-model' };
      },
      listOwner: async value => {
        calls.push(['owner', value]);
        return [{ ownerId: value.ownerId }];
      },
      listAdmin: async value => {
        calls.push(['admin', value]);
        return [{ ownerId: 77 }];
      },
      ...overrides,
    },
  };
}

test('absent bearer runs anonymous inference without any caller identity or history fields', async t => {
  const service = serviceFixture();
  const fixture = await startFixture({
    validateSession: async () => {
      throw new Error('absent bearer must not validate');
    },
    historyService: service.service,
  });
  t.after(fixture.close);

  const result = await request(fixture, '/prompt-injection', {
    body: {
      prompt: 'anonymous prompt',
      model: 'teaching-model',
      ownerId: 999,
      sessionId: 999,
      requestId: 'caller-request',
      generation: '999',
    },
    headers: { cookie: 'platformOwnerId=999' },
  });

  assert.deepEqual(result, {
    status: 200,
    body: { response: 'anonymous response', model: 'anonymous-model' },
  });
  assert.deepEqual(service.calls, [[
    'anonymous',
    {
      sourceRoute: 'prompt_injection',
      prompt: 'anonymous prompt',
      options: { model: 'teaching-model' },
    },
  ]]);
});

test('invalid present bearer returns 401 and never downgrades to anonymous inference', async t => {
  const service = serviceFixture();
  const validated = [];
  const fixture = await startFixture({
    validateSession: async token => {
      validated.push(token);
      return null;
    },
    historyService: service.service,
  });
  t.after(fixture.close);

  const result = await request(fixture, '/chain-of-thought', {
    body: { prompt: 'private prompt', temperature: 0.3 },
    headers: { authorization: 'Bearer rejected-token' },
  });

  assert.deepEqual(result, { status: 401, body: { error: 'Authentication required' } });
  assert.deepEqual(validated, ['rejected-token']);
  assert.deepEqual(service.calls, []);
});

test('the shared resolver accepts a case-insensitive bearer scheme and rejects comma credentials', async t => {
  const service = serviceFixture();
  const validated = [];
  const fixture = await startFixture({
    validateSession: async token => {
      validated.push(token);
      return token === 'valid-token' ? { session: { id: 81 }, user: { id: 71 } } : null;
    },
    historyService: service.service,
  });
  t.after(fixture.close);

  const valid = await request(fixture, '/chain-of-thought', {
    body: { prompt: 'private prompt', temperature: 0.3 },
    headers: { authorization: 'bearer valid-token' },
  });
  const malformed = await request(fixture, '/chain-of-thought', {
    body: { prompt: 'private prompt', temperature: 0.3 },
    headers: { authorization: 'Bearer valid-token, second-token' },
  });

  assert.equal(valid.status, 200);
  assert.deepEqual(malformed, { status: 401, body: { error: 'Authentication required' } });
  assert.deepEqual(validated, ['valid-token']);
  assert.deepEqual(service.calls.map(([kind]) => kind), ['authenticated']);
});

test('valid bearer authority supplies authenticated owner/session and a fixed source route', async t => {
  const service = serviceFixture();
  const fixture = await startFixture({
    validateSession: async token => {
      assert.equal(token, 'valid-token');
      return { session: { id: 81 }, user: { id: 71 } };
    },
    historyService: service.service,
  });
  t.after(fixture.close);

  const result = await request(fixture, '/multi-turn-jailbreak', {
    body: {
      prompt: 'private prompt',
      conversation_history: [{ user: 'earlier', assistant: 'earlier response' }],
      ownerId: 999,
      sessionId: 999,
      generation: '999',
      requestId: 'caller-request',
    },
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.deepEqual(result, {
    status: 200,
    body: { response: 'protected response', model: 'protected-model' },
  });
  assert.deepEqual(service.calls, [[
    'authenticated',
    {
      ownerId: 71,
      sessionId: 81,
      sourceRoute: 'multi_turn_jailbreak',
      prompt: 'private prompt',
      options: { conversation_history: [{ user: 'earlier', assistant: 'earlier response' }] },
    },
  ]]);
});

test('a mismatched stored response produces a sanitized failure without returning inference or receipt data', async t => {
  const service = createLegacyAiHistoryRequestService({
    history: {
      admit: async ({ ownerId, sessionId }) => ({ ownerId, sessionId, generation: '4' }),
      append: async value => ({ ...value, response: 'OTHER-OWNER-PRIVATE-RESPONSE', replayed: false }),
      listOwn: async () => [],
      listAdmin: async () => [],
    },
    infer: async () => ({ response: 'UNCOMMITTED-INFERENCE-RESPONSE', modelUsed: 'controlled-model' }),
  });
  const fixture = await startFixture({
    validateSession: async () => ({ session: { id: 81 }, user: { id: 71 } }),
    historyService: service,
  });
  t.after(fixture.close);
  const result = await request(fixture, '/prompt-injection', {
    body: { prompt: 'controlled prompt' },
    headers: { authorization: 'Bearer valid-token' },
  });
  assert.deepEqual(result, { status: 503, body: { error: 'Protected history unavailable' } });
});

test('normal context-stuffing default reaches the injected r7 inference while append records only the user prompt', async t => {
  let inferred;
  let appended;
  const history = {
    admit: async ({ ownerId, sessionId }) => ({ ownerId, sessionId, generation: '4' }),
    append: async value => {
      appended = value;
      return {
        ...value,
        replayed: false,
      };
    },
    listOwn: async () => [],
    listAdmin: async () => [],
  };
  const service = createLegacyAiHistoryRequestService({
    history,
    infer: async value => {
      inferred = value;
      return { response: 'context response', modelUsed: 'controlled-model' };
    },
    issueRequestId: () => '10000000-0000-4000-8000-000000000001',
  });
  const fixture = await startFixture({
    validateSession: async () => ({ session: { id: 81 }, user: { id: 71 } }),
    historyService: service,
  });
  t.after(fixture.close);

  const result = await request(fixture, '/context-stuffing', {
    body: { prompt: 'user prompt' },
    headers: { authorization: 'Bearer valid-token' },
  });

  assert.deepEqual(result, {
    status: 200,
    body: { response: 'context response', model: 'controlled-model' },
  });
  assert.equal(inferred.sourceRoute, 'context_stuffing');
  assert.equal(inferred.prompt, 'user prompt');
  assert.equal(inferred.options.stuffing_content.length, 50000);
  assert.equal(inferred.options.stuffing_content, 'A'.repeat(50000));
  assert.equal(appended.sourceRoute, 'context_stuffing');
  assert.equal(appended.prompt, 'user prompt');
  assert.equal(appended.response, 'context response');
});

test('private owner and admin pages use bearer authority and fixed paging only', async t => {
  const service = serviceFixture();
  const fixture = await startFixture({
    validateSession: async () => ({ session: { id: 81 }, user: { id: 71 } }),
    historyService: service.service,
  });
  t.after(fixture.close);

  const missing = await request(fixture, '/history', { method: 'GET' });
  assert.deepEqual(missing, { status: 401, body: { error: 'Authentication required' } });

  const owner = await request(fixture, '/history?limit=2&beforeCursor=cursor', {
    headers: { authorization: 'Bearer valid-token' },
    method: 'GET',
  });
  const admin = await request(fixture, '/history/admin?limit=3', {
    headers: { authorization: 'Bearer valid-token' },
    method: 'GET',
  });
  const rejectedOwnerOverride = await request(fixture, '/history?ownerId=999', {
    headers: { authorization: 'Bearer valid-token' },
    method: 'GET',
  });

  assert.deepEqual(owner, { status: 200, body: { history: [{ ownerId: 71 }] } });
  assert.deepEqual(admin, { status: 200, body: { history: [{ ownerId: 77 }] } });
  assert.deepEqual(rejectedOwnerOverride, {
    status: 400,
    body: { error: 'Invalid protected history request' },
  });
  assert.deepEqual(service.calls, [
    ['owner', { ownerId: 71, sessionId: 81, limit: 2, beforeCursor: 'cursor' }],
    ['admin', { adminId: 71, sessionId: 81, limit: 3, beforeCursor: undefined }],
  ]);
});

test('live admin permission and protected storage failures are sanitized non-success responses', async t => {
  let adminCalls = 0;
  let authenticatedCalls = 0;
  const service = serviceFixture({
    listAdmin: async () => {
      adminCalls += 1;
      throw Object.assign(new Error('permission detail must not leak'), { code: '42501' });
    },
    runAuthenticated: async () => {
      authenticatedCalls += 1;
      throw Object.assign(new Error('session reset detail must not leak'), { code: '55000' });
    },
  });
  const fixture = await startFixture({
    validateSession: async () => ({ session: { id: 81 }, user: { id: 71 } }),
    historyService: service.service,
  });
  t.after(fixture.close);

  const append = await request(fixture, '/chain-of-thought', {
    body: { prompt: 'private prompt', temperature: 0.3 },
    headers: { authorization: 'Bearer valid-token' },
  });
  const admin = await request(fixture, '/history/admin', {
    headers: { authorization: 'Bearer valid-token' },
    method: 'GET',
  });

  assert.deepEqual(append, {
    status: 409,
    body: { error: 'Protected history no longer accepts this result' },
  });
  assert.deepEqual(admin, {
    status: 403,
    body: { error: 'Private history access denied' },
  });
  assert.equal(authenticatedCalls, 1);
  assert.equal(adminCalls, 1);
});

test('multi-turn pairs reach the actual legacy provider template and malformed transcript shapes reject', async t => {
  const { OllamaService } = require('../server/services/ollamaService');
  const provider = new OllamaService('http://127.0.0.1:1', {
    providerFactory() { throw new Error('Network inference is forbidden in this composition test'); },
  });
  const prompts = [];
  provider.generateResponse = async prompt => {
    prompts.push(prompt);
    return { response: 'controlled template response', model: 'controlled-template-model' };
  };
  const history = {
    admit: async () => { throw new Error('Anonymous request must not admit history'); },
    append: async () => { throw new Error('Anonymous request must not append history'); },
    listOwn: async () => [],
    listAdmin: async () => [],
  };
  const historyService = createLegacyAiHistoryRequestService({ history,
    infer: async ({ prompt, options }) => {
      const result = await provider.processMultiTurnJailbreak(options.conversation_history, prompt);
      return { response: result.response, modelUsed: result.model };
    },
  });
  const fixture = await startFixture({ validateSession: async () => null, historyService });
  t.after(fixture.close);
  const result = await request(fixture, '/multi-turn-jailbreak', {
    body: { prompt: 'current controlled question', conversation_history: [
      { user: 'earlier controlled question', assistant: 'earlier controlled answer' },
    ] },
  });
  assert.equal(result.status, 200);
  assert.equal(prompts.length, 1);
  assert.match(prompts[0], /Turn 1:\nUser: earlier controlled question\nAssistant: earlier controlled answer/);
  assert.match(prompts[0], /Turn 2:\nUser: current controlled question\nAssistant:/);
  assert.doesNotMatch(prompts[0], /undefined/);
  for (const conversation_history of [
    [{ role: 'user', content: 'wrong DTO' }],
    [{ user: 'missing answer' }],
    [{ user: 'question', assistant: 42 }],
    [{ user: 'question', assistant: 'answer', role: 'system' }],
    [null],
  ]) {
    assert.equal((await request(fixture, '/multi-turn-jailbreak', {
      body: { prompt: 'current controlled question', conversation_history },
    })).status, 400);
  }
  assert.equal(prompts.length, 1, 'rejected transcripts must not reach provider composition');
});

test('all four composed experiment routes preserve bounded teaching feedback and private persistence boundaries', async t => {
  let appended = [];
  let unavailable = false;
  const runner = createLegacyAiExperimentRunner({
    issueArtifact: () => ({ artifactId: 'PRIVATE-ARTIFACT-ID', canary: 'CONTROLLED-SECRET' }),
    provider: { generate: async () => ({ response: 'Actor refuses to disclose.', model: 'controlled-model',
      provider: 'controlled', mocked: false, fallback: false }) },
    judge: async () => unavailable
      ? { verdict: 'unavailable', criteria: [], explanation: 'PRIVATE-JUDGE-TEXT' }
      : { verdict: 'fail', criteria: [{ id: 'synthetic_canary_disclosed', satisfied: false }],
        explanation: 'PRIVATE-JUDGE-TEXT' },
  });
  const service = createLegacyAiHistoryRequestService({
    history: {
      admit: async ({ ownerId, sessionId }) => ({ ownerId, sessionId, generation: '4' }),
      append: async value => { appended.push(value); return { ...value, replayed: false }; },
      listOwn: async () => [], listAdmin: async () => [],
    },
    infer: input => runner.run(input),
  });
  const fixture = await startFixture({
    validateSession: async () => ({ session: { id: 81 }, user: { id: 71 } }),
    historyService: service,
  });
  t.after(fixture.close);
  for (const [path, route] of [['prompt-injection', 'prompt_injection'], ['chain-of-thought', 'chain_of_thought'],
    ['context-stuffing', 'context_stuffing'], ['multi-turn-jailbreak', 'multi_turn_jailbreak']]) {
    for (const authenticated of [false, true]) {
      const before = appended.length;
      const result = await request(fixture, '/' + path, {
        body: { prompt: 'A normal controlled request' },
        headers: authenticated ? { authorization: 'Bearer valid-token' } : {},
      });
      assert.equal(result.status, 200, path);
      assert.equal(result.body.response, 'Actor refuses to disclose.');
      assert.equal(result.body.model, 'controlled-model');
      assert.equal(result.body.teaching.route, route);
      assert.equal(result.body.teaching.evaluation.passed, false);
      assert.equal(result.body.creditAwarded, false);
      assert.equal(result.body.history.persisted, authenticated);
      assert.equal(appended.length, before + Number(authenticated));
      if (authenticated) {
        assert.equal(result.body.history.requestId, appended.at(-1).requestId);
        assert.equal(result.body.history.replayed, false);
        assert.equal(Object.hasOwn(appended.at(-1), 'teaching'), false);
        assert.equal(Object.hasOwn(appended.at(-1), 'provider'), false);
      } else assert.deepEqual(result.body.history, { persisted: false });
      const json = JSON.stringify(result.body);
      for (const privateValue of ['PRIVATE-ARTIFACT-ID', 'PRIVATE-JUDGE-TEXT', 'CONTROLLED-SECRET',
        'ownerId', 'generation', 'sessionId', 'cursor']) assert.ok(!json.includes(privateValue), privateValue);
    }
  }
  unavailable = true;
  const result = await request(fixture, '/prompt-injection', {
    body: { prompt: 'A normal request' }, headers: { authorization: 'Bearer valid-token' },
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.response, 'Actor refuses to disclose.');
  assert.deepEqual(result.body.teaching.evaluation, { verdict: 'unavailable', criteria: [], passed: false });
  assert.equal(result.body.creditAwarded, false);
});

test('UUID-shaped private artifact values in provider identity never persist or reach HTTP clients', async t => {
  const artifact = { artifactId: '20000000-0000-4000-8000-000000000001',
    canary: '20000000-0000-4000-8000-000000000002' };
  let leakedField = 'model';
  let leakedValue = artifact.canary;
  let appends = 0;
  let judges = 0;
  const runner = createLegacyAiExperimentRunner({
    issueArtifact: () => artifact,
    provider: { generate: async () => ({ response: 'I refuse to disclose.',
      model: 'controlled-model', provider: 'controlled', mocked: false, fallback: false,
      [leakedField]: leakedValue }) },
    judge: async () => { judges++; throw new Error('Judge must not see invalid provider identity'); },
  });
  const service = createLegacyAiHistoryRequestService({
    history: {
      admit: async ({ ownerId, sessionId }) => ({ ownerId, sessionId, generation: '4' }),
      append: async value => { appends++; return { ...value, replayed: false }; },
      listOwn: async () => [], listAdmin: async () => [],
    },
    infer: input => runner.run(input),
  });
  const fixture = await startFixture({
    validateSession: async () => ({ session: { id: 81 }, user: { id: 71 } }), historyService: service,
  });
  t.after(fixture.close);
  for (const field of ['model', 'provider']) {
    leakedField = field;
    for (const value of Object.values(artifact)) {
      leakedValue = value;
      for (const authenticated of [false, true]) {
        const result = await request(fixture, '/prompt-injection', {
          body: { prompt: 'normal request' },
          headers: authenticated ? { authorization: 'Bearer valid-token' } : {},
        });
        assert.deepEqual(result, { status: 503, body: { error: 'Protected history unavailable' } });
      }
    }
  }
  assert.equal(appends, 0);
  assert.equal(judges, 0);
});

test('every experiment preserves availability denial before inference or history admission', async () => {
  let calls = 0;
  const forbidden = async () => { calls++; throw new Error('Disabled exercise executed'); };
  const fixture = await startFixture({ validateSession: forbidden,
    historyService: { runAuthenticated: forbidden, runAnonymous: forbidden, listOwner: forbidden, listAdmin: forbidden },
    experimentAccess: (req, res) => res.status(403).json({ error: 'Vulnerability Access Disabled' }),
  });
  try {
    for (const route of ['/prompt-injection','/chain-of-thought','/context-stuffing','/multi-turn-jailbreak']) {
      const response = await fetch(fixture.baseUrl + route, { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({prompt:'disabled'}) });
      assert.equal(response.status,403);
    }
    assert.equal(calls,0);
  } finally { await fixture.close(); }
});

test('protected router rejects a missing availability middleware', () => {
  assert.throws(() => createLegacyAiProtectedHistoryDraftRouter({}), /Exercise availability middleware required/);
});

test('invalid supplied authentication is rejected before exercise availability', async () => {
  let gates = 0;
  const forbidden = async () => { throw new Error('Must not invoke'); };
  const fixture = await startFixture({ validateSession: async () => null,
    historyService: { runAuthenticated: forbidden, runAnonymous: forbidden, listOwner: forbidden, listAdmin: forbidden },
    experimentAccess: (req,res) => { gates++; res.status(403).end(); },
  });
  try {
    const response = await fetch(fixture.baseUrl + '/prompt-injection', {method:'POST',headers:{Authorization:'Bearer invalid','Content-Type':'application/json'},body:JSON.stringify({prompt:'test'})});
    assert.equal(response.status,401); assert.equal(gates,0);
  } finally { await fixture.close(); }
});

test('client disconnect propagates a server-owned cancellation signal', async () => {
  let began, aborted;
  const started = new Promise(resolve => { began = resolve; });
  const cancelled = new Promise(resolve => { aborted = resolve; });
  const forbidden = async () => { throw new Error('Unexpected history operation'); };
  const fixture = await startFixture({ validateSession: forbidden,
    historyService: { runAuthenticated: forbidden, listOwner: forbidden, listAdmin: forbidden,
      runAnonymous(input, execution) {
        assert.equal(input.prompt,'disconnect');
        assert.ok(execution.signal instanceof AbortSignal);
        began();
        return new Promise((resolve,reject) => execution.signal.addEventListener('abort', () => {
          aborted(execution.signal.reason.code); reject(execution.signal.reason);
        }, {once:true}));
      },
    },
  });
  const client = new AbortController();
  try {
    const pending = fetch(fixture.baseUrl + '/prompt-injection', {method:'POST',signal:client.signal,
      headers:{'Content-Type':'application/json'},body:JSON.stringify({prompt:'disconnect',signal:'untrusted-body-signal'})}).catch(error=>error);
    await started; client.abort(); await pending;
    let timer;
    try {
      assert.equal(await Promise.race([cancelled,new Promise((resolve,reject)=>{timer=setTimeout(()=>reject(new Error('Disconnect did not cancel')),2000);})]),'CLIENT_DISCONNECTED');
    } finally { clearTimeout(timer); }
  } finally { client.abort(); await fixture.close(); }
});
