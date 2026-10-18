const test = require('node:test');
const assert = require('node:assert/strict');
const { createPostgresAdminRouter } = require('../server/routes/postgresAdmin');

const ROUTE_CASES = [
  ['POST /challenges/toggle', {
    body: { challengeKey: 'direct_prompt_injection', enabled: false }, params: {},
  }],
  ['PATCH /challenges/:challengeKey/toggle', {
    body: {}, params: { challengeKey: 'direct_prompt_injection' },
  }],
  ['POST /challenges/solutions/toggle', {
    body: { challengeKey: 'indirect_prompt_injection', showSolutions: false }, params: {},
  }],
  ['POST /challenges/hints/toggle', {
    body: { challengeKey: 'direct_prompt_injection', showHints: false }, params: {},
  }],
  ['POST /workshops/:workshopKey/objectives/:objectiveId/toggle', {
    body: { enabled: false },
    params: { workshopKey: 'direct_prompt_injection', objectiveId: 'jailbreak' },
  }],
  ['POST /workshops/:workshopKey/hints/:objectiveId/toggle', {
    body: { enabled: false },
    params: { workshopKey: 'direct_prompt_injection', objectiveId: 'jailbreak' },
  }],
  ['POST /workshops/:workshopKey/objectives/bulk-toggle', {
    body: { enabled: false }, params: { workshopKey: 'direct_prompt_injection' },
  }],
  ['POST /workshops/:workshopKey/hints/bulk-toggle', {
    body: { enabled: false }, params: { workshopKey: 'indirect_prompt_injection' },
  }],
  ['POST /ipi-workshop/solutions/toggle', {
    body: { objectiveId: 'rag_upload', enabled: false }, params: {},
  }],
  ['POST /ipi-workshop/solutions/bulk', {
    body: { enabled: false }, params: {},
  }],
  ['POST /pi-workshop/solutions/toggle', {
    body: { challengeId: 'jailbreak', enabled: false }, params: {},
  }],
  ['POST /pi-workshop/solutions/bulk', {
    body: { enabled: false }, params: {},
  }],
  ['POST /pi-workshop/solutions/:objectiveId', {
    body: { title: 'Updated' }, params: { objectiveId: 'jailbreak' },
  }],
  ['PATCH /solutions/:solutionId/visibility', {
    body: { isPublic: false }, params: { solutionId: 'direct_prompt_injection:jailbreak' },
  }],
];

const VISIBILITY_ROUTE_CASES = ROUTE_CASES.filter(([route]) => ![
  'POST /challenges/toggle',
  'PATCH /challenges/:challengeKey/toggle',
  'POST /pi-workshop/solutions/:objectiveId',
].includes(route));

function createMutationService(resultFactory, calls) {
  const service = {
    async getHintVisibilityMap() {
      return { rag_upload: false, email_create_inbox: false };
    },
    async getSnapshot() {
      return { exercises: { indirect_prompt_injection: {
        workshopKey: 'indirect_prompt_injection',
        objectives: {
          rag_upload: { workshopKey: 'indirect_prompt_injection', label: 'RAG upload', hasHintContent: true,
            raw: { objectiveEnabled: true, hintEnabled: false, solutionEnabled: false } },
          email_create_inbox: { workshopKey: 'indirect_prompt_injection', label: 'Email inbox', hasHintContent: false,
            raw: { objectiveEnabled: true, hintEnabled: false, solutionEnabled: false } },
        },
      } } };
    },
  };
  for (const method of [
    'setExerciseVisibility',
    'toggleExerciseVisibility',
    'setMasterSolutionVisibility',
    'setMasterHintVisibility',
    'setObjectiveVisibility',
    'setAllObjectiveVisibility',
    'setObjectiveHintVisibility',
    'setObjectiveSolutionVisibility',
    'updateSolutionContent',
    'updateExercise',
    'resetAllChallengeVisibility',
  ]) {
    service[method] = async (...args) => {
      calls.push({ method, args });
      return resultFactory();
    };
  }
  return service;
}

function loadHandlers(mutationService) {
  const handlers = {};
  const pass = (_req, _res, next) => next?.();
  const noop = async () => null;
  const router = createPostgresAdminRouter({
    adapter: { repository: {}, jwtSecret: 'controlled-postgres-secret' },
    stores: { config: mutationService, progress: {}, pool: {} },
    auth: {
      authenticateToken: pass,
      requireAdminLevel: () => pass,
      requirePermission: () => pass,
      logActivity: () => pass,
    },
    repository: {},
    resetService: {},
    operational: new Proxy({}, { get: () => pass }),
    xssLegacyRepository: {},
    deletionService: {},
    analytics: { listRunSummaries: noop },
  });
  for (const layer of router.stack) {
    if (!layer.route) continue;
    const handler = layer.route.stack.at(-1).handle;
    for (const method of Object.keys(layer.route.methods)) {
      handlers[`${method.toUpperCase()} ${layer.route.path}`] = handler;
    }
  }
  return handlers;
}

function invoke(handler, request) {
  return new Promise((resolve, reject) => {
    let status = 200;
    const response = {
      status(code) { status = code; return response; },
      json(body) { resolve({ status, body }); },
    };
    Promise.resolve(handler({
      ...request,
      user: { id: 1, username: 'admin' },
    }, response)).catch(reject);
  });
}

async function invokeAll(resultFactory) {
  const calls = [];
  const handlers = loadHandlers(createMutationService(resultFactory, calls));
  assert.equal(ROUTE_CASES.length, 14);

  const responses = [];
  for (const [key, request] of ROUTE_CASES) {
    assert.equal(typeof handlers[key], 'function', `missing registered handler for ${key}`);
    responses.push(await invoke(handlers[key], request));
  }
  return { calls, responses };
}

test('all 14 legacy prompt-injection routes return changed and no-op success contracts', async () => {
  const changed = await invokeAll(() => ({
    changed: true,
    revision: 51,
    exercise: { objectives: {} },
  }));
  assert.equal(changed.calls.length, 14);
  assert.equal(changed.responses.every(({ status, body }) => status === 200 && body.changed === true), true);

  const noOp = await invokeAll(() => ({
    changed: false,
    revision: 90,
    exercise: { objectives: {} },
  }));
  assert.equal(noOp.calls.length, 14);
  assert.equal(noOp.responses.every(({ status, body }) => status === 200 && body.changed === false), true);
});

test('all 14 legacy prompt-injection routes map service BAD_REQUEST failures to 400', async () => {
  const failed = await invokeAll(() => {
    throw Object.assign(new Error('mutation rejected'), { code: 'BAD_REQUEST' });
  });
  assert.equal(failed.calls.length, 14);
  assert.equal(failed.responses.every(({ status, body }) =>
    status === 400 && body.error === 'mutation rejected'), true);
});

test('all 14 PostgreSQL compatibility routes call the canonical mutation once and return its revision', async () => {
  const calls = [];
  const handlers = loadHandlers(createMutationService(() => ({
    changed: true,
    revision: 51,
    exercise: { isVisible: false, objectives: {} },
  }), calls));

  for (const [key, request] of ROUTE_CASES) {
    const response = await invoke(handlers[key], request);
    assert.equal(response.status, 200, key);
    assert.equal(response.body.changed, true, key);
    assert.equal(response.body.revision, 51, key);
  }

  assert.deepEqual(calls.map(({ method }) => method), [
    'setExerciseVisibility',
    'toggleExerciseVisibility',
    'setMasterSolutionVisibility',
    'setMasterHintVisibility',
    'setObjectiveVisibility',
    'setObjectiveHintVisibility',
    'setAllObjectiveVisibility',
    'setMasterHintVisibility',
    'setObjectiveSolutionVisibility',
    'setMasterSolutionVisibility',
    'setObjectiveSolutionVisibility',
    'setMasterSolutionVisibility',
    'updateSolutionContent',
    'setObjectiveSolutionVisibility',
  ]);
  assert.deepEqual(calls.at(-1).args,
    ['direct_prompt_injection', 'jailbreak', false, 1]);
});

test('no-op and rejected compatibility mutations preserve canonical results without extra calls', async () => {
  const noOpCalls = [];
  const noOpHandlers = loadHandlers(createMutationService(() => ({
    changed: false,
    revision: 90,
    exercise: { objectives: {} },
  }), noOpCalls));
  for (const [key, request] of VISIBILITY_ROUTE_CASES) {
    const response = await invoke(noOpHandlers[key], request);
    assert.equal(response.status, 200, key);
    assert.equal(response.body.changed, false, key);
    assert.equal(response.body.revision, 90, key);
  }
  assert.equal(noOpCalls.length, VISIBILITY_ROUTE_CASES.length);

  const rejectedCalls = [];
  const rejectedHandlers = loadHandlers(createMutationService(() => {
    throw Object.assign(new Error('mutation rejected'), { code: 'BAD_REQUEST' });
  }, rejectedCalls));
  for (const [key, request] of VISIBILITY_ROUTE_CASES) {
    const response = await invoke(rejectedHandlers[key], request);
    assert.equal(response.status, 400, key);
    assert.equal(response.body.error, 'mutation rejected', key);
  }
  assert.equal(rejectedCalls.length, VISIBILITY_ROUTE_CASES.length);
});

test('solution visibility requires a canonical compound identity before mutation', async () => {
  const calls = [];
  const handlers = loadHandlers(createMutationService(() => ({ changed: true, revision: 1 }), calls));
  const response = await invoke(handlers['PATCH /solutions/:solutionId/visibility'], {
    body: { isPublic: false }, params: { solutionId: '1' },
  });
  assert.deepEqual(response, { status: 404, body: { error: 'Unknown solution ID' } });
  assert.deepEqual(calls, []);
});

test('legacy system reset fails closed before any canonical mutation', async () => {
  const calls = [];
  const handlers = loadHandlers(createMutationService(() => ({ changed: true, revision: 51 }), calls));
  const request = {
    body: { resetType: 'challenges', confirmText: 'RESET_PLATFORM' },
    params: {},
  };
  const response = await invoke(handlers['POST /system/reset'], request);
  assert.deepEqual(response, {
    status: 409,
    body: {
      success: false,
      code: 'CONFIRMED_RESET_REQUIRED',
      error: 'Use /api/admin/database/reset with resetType challenges and the current administrator password',
    },
  });
  assert.deepEqual(calls, []);
});

test('admin hint and objective listings retain canonical PostgreSQL gates and content metadata', async () => {
  const handlers = loadHandlers(createMutationService(() => ({ changed: false }), []));
  const hints = await invoke(
    handlers['GET /workshops/:workshopKey/hints'],
    { params: { workshopKey: 'indirect_prompt_injection' }, body: {} },
  );
  const objectives = await invoke(
    handlers['GET /workshops/:workshopKey/objectives'],
    { params: { workshopKey: 'indirect_prompt_injection' }, body: {} },
  );

  assert.deepEqual(hints, {
    status: 200,
    body: {
      success: true,
      hints: { rag_upload: false, email_create_inbox: false },
    },
  });
  assert.deepEqual(objectives, {
    status: 200,
    body: {
      success: true,
      workshopKey: 'indirect_prompt_injection',
      objectives: [
        {
          workshopKey: 'indirect_prompt_injection', objective_id: 'rag_upload', label: 'RAG upload',
          is_enabled: true, hint_enabled: false, solutions_enabled: false, has_hint_content: true,
        },
        {
          workshopKey: 'indirect_prompt_injection', objective_id: 'email_create_inbox', label: 'Email inbox',
          is_enabled: true, hint_enabled: false, solutions_enabled: false, has_hint_content: false,
        },
      ],
    },
  });
});

test('legacy challenge visibility routes delegate non-prompt-injection rows to the canonical service', async () => {
  const calls = [];
  const handlers = loadHandlers(createMutationService(() => ({
    changed: true,
    revision: 17,
    enabled: false,
    exercise: { isVisible: false, objectives: {} },
  }), calls));

  const responses = await Promise.all([
    invoke(handlers['POST /challenges/toggle'], {
      body: { challengeKey: 'reflected_xss_llm', enabled: false }, params: {},
    }),
    invoke(handlers['PATCH /challenges/:challengeKey/toggle'], {
      body: {}, params: { challengeKey: 'csrf_prompt_injection' },
    }),
    invoke(handlers['PUT /challenges/:challengeKey'], {
      body: {
        challengeName: 'XSS Workshop', category: 'web', difficulty: 'intermediate',
        isVisible: false, showSolutions: true, description: 'XSS training', route: '/workshop/xss',
      },
      params: { challengeKey: 'reflected_xss_llm' },
    }),
  ]);

  assert.deepEqual(calls.map(({ method }) => method), [
    'setExerciseVisibility',
    'toggleExerciseVisibility',
    'updateExercise',
  ]);
  assert.deepEqual(calls[0].args, ['reflected_xss_llm', false, 1]);
  assert.deepEqual(calls[1].args, ['csrf_prompt_injection', 1]);
  assert.deepEqual(calls[2].args, [{
    key: 'reflected_xss_llm',
    challengeName: 'XSS Workshop',
    category: 'web',
    difficulty: 'intermediate',
    isVisible: false,
    showSolutions: true,
    description: 'XSS training',
    route: '/workshop/xss',
    userId: 1,
  }]);
  assert.equal(responses.every(({ status, body }) =>
    status === 200 && body.changed === true && body.revision === 17), true);
  assert.equal(responses[1].body.enabled, false);
});

async function invokeNonPromptInjectionVisibilityRoutes(handlers) {
  return Promise.all([
    invoke(handlers['POST /challenges/toggle'], {
      body: { challengeKey: 'reflected_xss_llm', enabled: false }, params: {},
    }),
    invoke(handlers['PUT /challenges/:challengeKey'], {
      body: {
        challengeName: 'XSS Workshop', category: 'web', difficulty: 'intermediate',
        isVisible: false, showSolutions: true, description: 'XSS training', route: '/workshop/xss',
      },
      params: { challengeKey: 'reflected_xss_llm' },
    }),
    invoke(handlers['PATCH /challenges/:challengeKey/toggle'], {
      body: {}, params: { challengeKey: 'csrf_prompt_injection' },
    }),
  ]);
}

test('non-prompt-injection visibility routes preserve precise canonical not-found errors', async () => {
  const service = createMutationService(() => {
    throw Object.assign(new Error('Unknown exercise: reflected_xss_llm'), {
      code: 'NOT_FOUND',
    });
  }, []);
  const responses = await invokeNonPromptInjectionVisibilityRoutes(loadHandlers(service));

  assert.deepEqual(responses, [
    { status: 404, body: { error: 'Unknown exercise: reflected_xss_llm' } },
    { status: 404, body: { error: 'Unknown exercise: reflected_xss_llm' } },
    { status: 404, body: { error: 'Unknown exercise: reflected_xss_llm' } },
  ]);
});

test('non-prompt-injection visibility routes never expose database failure details', async () => {
  const service = createMutationService(() => {
    throw new Error('private PostgreSQL failure detail');
  }, []);
  const logged = [];
  const originalConsoleError = console.error;
  console.error = (...args) => logged.push(args);
  let responses;
  try {
    responses = await invokeNonPromptInjectionVisibilityRoutes(loadHandlers(service));
  } finally {
    console.error = originalConsoleError;
  }

  assert.deepEqual(responses, [
    { status: 500, body: { error: 'Failed to update challenge visibility' } },
    { status: 500, body: { error: 'Failed to update challenge' } },
    { status: 500, body: { error: 'Failed to update challenge visibility' } },
  ]);
  assert.equal(logged.length, 3);
});
