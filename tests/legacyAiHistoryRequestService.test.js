'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createLegacyAiHistoryRequestService,
} = require('../server/services/legacyAiHistoryRequestService');

const REQUEST_ID = '10000000-0000-4000-8000-000000000001';
const INPUT = Object.freeze({
  ownerId: 7,
  sessionId: '8',
  sourceRoute: 'prompt_injection',
  prompt: 'private prompt',
  options: Object.freeze({ temperature: 0.2 }),
});

function createFixture({
  admit = async ({ ownerId, sessionId }) => ({ ownerId, sessionId, generation: '4' }),
  append = async value => ({ ...value, replayed: false,
    createdAt: new Date('2026-09-16T00:00:00.000Z'),
    cursor: `2026-09-16T00:00:00.000001Z|${value.requestId}` }),
  infer = async () => ({ response: 'model response', modelUsed: 'controlled-model' }),
  issueRequestId = () => REQUEST_ID,
  requestTimeoutMs,
} = {}) {
  const calls = [];
  const history = {
    admit: async value => {
      calls.push(['admit', value]);
      return admit(value);
    },
    append: async value => {
      calls.push(['append', value]);
      return append(value);
    },
    listOwn: async value => {
      calls.push(['listOwn', value]);
      return value;
    },
    listAdmin: async value => {
      calls.push(['listAdmin', value]);
      return value;
    },
  };
  const service = createLegacyAiHistoryRequestService({
    history,
    infer: async (value, execution) => {
      calls.push(['infer', value]);
      return infer(value, execution);
    },
    issueRequestId,
    ...(requestTimeoutMs === undefined ? {} : { requestTimeoutMs }),
  });
  return { calls, service };
}

test('authenticated inference is bound to admitted owner, request UUID, prompt, and route', async () => {
  const fixture = createFixture();
  const result = await fixture.service.runAuthenticated({
    ...INPUT,
    owner: 999,
    requestId: 'attacker-request-id',
    generation: '999',
  });

  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit', 'infer', 'admit', 'append']);
  assert.deepEqual(fixture.calls[0][1], { ownerId: INPUT.ownerId, sessionId: INPUT.sessionId });
  assert.deepEqual(fixture.calls[1][1], {
    prompt: INPUT.prompt,
    sourceRoute: INPUT.sourceRoute,
    options: INPUT.options,
  });
  assert.deepEqual(fixture.calls[3][1], {
    ownerId: INPUT.ownerId,
    sessionId: INPUT.sessionId,
    generation: '4',
    requestId: REQUEST_ID,
    sourceRoute: INPUT.sourceRoute,
    prompt: INPUT.prompt,
    response: 'model response',
    modelUsed: 'controlled-model',
  });
  assert.equal(result.requestId, REQUEST_ID);
});

test('rejected admission makes no inference or append call', async () => {
  const rejected = new Error('session revoked');
  const fixture = createFixture({
    admit: async () => {
      throw rejected;
    },
  });

  await assert.rejects(fixture.service.runAuthenticated(INPUT), error => error === rejected);
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit']);
});

test('mismatched persistence receipts never return another owner or substituted inference', async () => {
  const substitutions = {
    requestId: '10000000-0000-4000-8000-000000000002',
    ownerId: 8,
    generation: '5',
    sourceRoute: 'multi_turn_jailbreak',
    prompt: 'other prompt',
    response: 'other private response',
    modelUsed: 'other model',
  };
  for (const [field, replacement] of Object.entries(substitutions)) {
    const fixture = createFixture({ append: async value => ({ ...value, replayed: false, [field]: replacement }) });
    await assert.rejects(fixture.service.runAuthenticated(INPUT),
      error => error.code === 'HISTORY_RECEIPT_MISMATCH', field);
    assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit', 'infer', 'admit', 'append']);
  }
  const absent = createFixture({ append: async () => null });
  await assert.rejects(absent.service.runAuthenticated(INPUT),
    error => error.code === 'HISTORY_RECEIPT_MISMATCH');
});

test('fresh online requests reject replay receipts and detach public results from mutable stored rows', async () => {
  for (const replayed of [true, undefined, 'false']) {
    const fixture = createFixture({ append: async value => ({ ...value, replayed }) });
    await assert.rejects(fixture.service.runAuthenticated(INPUT),
      error => error.code === 'HISTORY_RECEIPT_MISMATCH');
  }
  let stored;
  const fixture = createFixture({ append: async value => {
    stored = { ...value, replayed: false, createdAt: new Date(), cursor: 'private cursor',
      privateExtra: 'must not escape' };
    return stored;
  } });
  const result = await fixture.service.runAuthenticated(INPUT);
  stored.response = 'mutated response';
  stored.createdAt.setTime(0);
  assert.deepEqual(result, { requestId: REQUEST_ID, response: 'model response',
    modelUsed: 'controlled-model', replayed: false });
  assert.ok(Object.isFrozen(result));
  const accessor = createFixture({ append: async value => ({ ...value, replayed: false,
    get response() { throw new Error('Receipt accessor must not execute'); } }) });
  await assert.rejects(accessor.service.runAuthenticated(INPUT),
    error => error.code === 'HISTORY_RECEIPT_MISMATCH');
});

test('failed inference makes no append call', async () => {
  const failedInference = new Error('provider failed');
  const fixture = createFixture({
    infer: async () => {
      throw failedInference;
    },
  });

  await assert.rejects(fixture.service.runAuthenticated(INPUT), error => error === failedInference);
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit', 'infer']);
});

test('authenticated inference receives an immutable options snapshot made before admission', async () => {
  let releaseAdmission;
  let seenOptions;
  const callerOptions = { nested: { temperature: 0.2 } };
  const fixture = createFixture({
    admit: () => releaseAdmission
      ? Promise.resolve({ ownerId: INPUT.ownerId, sessionId: INPUT.sessionId, generation: '4' })
      : new Promise(resolve => {
        releaseAdmission = () => resolve({ ownerId: INPUT.ownerId, sessionId: INPUT.sessionId, generation: '4' });
      }),
    infer: async value => {
      seenOptions = value.options;
      return { response: 'model response', modelUsed: 'controlled-model' };
    },
  });

  const pending = fixture.service.runAuthenticated({ ...INPUT, options: callerOptions });
  callerOptions.nested.temperature = 99;
  callerOptions.injected = 'late';
  releaseAdmission();
  await pending;

  assert.deepEqual(seenOptions, { nested: { temperature: 0.2 } });
  assert.ok(Object.isFrozen(seenOptions));
  assert.ok(Object.isFrozen(seenOptions.nested));
});

test('anonymous asynchronous inference receives an immutable options snapshot', async () => {
  let releaseInference;
  let seenOptions;
  const callerOptions = { nested: { topP: 0.9 } };
  const fixture = createFixture({
    infer: value => new Promise(resolve => {
      seenOptions = value.options;
      releaseInference = () => resolve({ response: 'anonymous response', modelUsed: 'controlled-model' });
    }),
  });

  const pending = fixture.service.runAnonymous({
    sourceRoute: INPUT.sourceRoute,
    prompt: INPUT.prompt,
    options: callerOptions,
  });
  callerOptions.nested.topP = 0.1;
  callerOptions.injected = 'late';
  releaseInference();
  await pending;

  assert.deepEqual(seenOptions, { nested: { topP: 0.9 } });
  assert.ok(Object.isFrozen(seenOptions));
  assert.ok(Object.isFrozen(seenOptions.nested));
});

test('append remains generation-checked after inference settles', async () => {
  let releaseInference;
  const resetRejected = Object.assign(new Error('history generation changed'), { code: '55000' });
  const fixture = createFixture({
    infer: () => new Promise(resolve => {
      releaseInference = () => resolve({ response: 'late response', modelUsed: 'controlled-model' });
    }),
    append: async () => {
      throw resetRejected;
    },
  });

  const pending = fixture.service.runAuthenticated(INPUT);
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit', 'infer']);
  releaseInference();

  await assert.rejects(pending, error => error === resetRejected);
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit', 'infer', 'admit', 'append']);
});

test('admission authority mismatch prevents inference and append', async () => {
  const fixture = createFixture({
    admit: async () => ({ ownerId: 8, sessionId: '8', generation: '4' }),
  });

  await assert.rejects(
    fixture.service.runAuthenticated(INPUT),
    error => error.code === '55000' && error.message === 'History admission authority mismatch',
  );
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit']);
});

test('invalid input is rejected before admission, and an invalid issued UUID is rejected before inference', async () => {
  const fixture = createFixture({ issueRequestId: () => 'not-a-uuid' });

  await assert.rejects(
    fixture.service.runAuthenticated({ ...INPUT, sourceRoute: 'untrusted-route' }),
    error => error.code === 'BAD_REQUEST',
  );
  await assert.rejects(
    fixture.service.runAuthenticated({ ...INPUT, prompt: '' }),
    error => error.code === 'BAD_REQUEST',
  );
  await assert.rejects(
    fixture.service.runAuthenticated({ ...INPUT, prompt: 'a'.repeat(65537) }),
    error => error.code === 'BAD_REQUEST',
  );
  await assert.rejects(
    fixture.service.runAuthenticated(INPUT),
    error => error.code === 'BAD_REQUEST',
  );
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit']);
});

test('options reject non-JSON values, accessors, custom prototypes, and excess depth before admission', async () => {
  const fixture = createFixture();
  const accessed = {};
  Object.defineProperty(accessed, 'late', {
    enumerable: true,
    get() {
      throw new Error('must not read accessor');
    },
  });
  const custom = Object.create({ inherited: true });
  custom.value = 'x';
  const tooDeep = { a: { b: { c: { d: { e: { f: { g: { h: 'x' } } } } } } } };

  for (const options of [{ callback() {} }, accessed, custom, tooDeep]) {
    await assert.rejects(
      fixture.service.runAuthenticated({ ...INPUT, options }),
      error => error.code === 'BAD_REQUEST',
    );
  }
  assert.deepEqual(fixture.calls, []);
});

test('options accept the 256KiB JSON boundary and reject one byte beyond it', async () => {
  let observedOptions;
  const fixture = createFixture({
    infer: async value => {
      observedOptions = value.options;
      return { response: 'anonymous response', modelUsed: 'controlled-model' };
    },
  });
  const envelopeBytes = Buffer.byteLength(JSON.stringify({ stuffing_content: '' }));
  const atLimit = 'x'.repeat((256 * 1024) - envelopeBytes);

  await fixture.service.runAnonymous({
    sourceRoute: INPUT.sourceRoute,
    prompt: INPUT.prompt,
    options: { stuffing_content: atLimit },
  });
  assert.equal(observedOptions.stuffing_content.length, atLimit.length);
  await assert.rejects(
    fixture.service.runAnonymous({
      sourceRoute: INPUT.sourceRoute,
      prompt: INPUT.prompt,
      options: { stuffing_content: `${atLimit}x` },
    }),
    error => error.code === 'BAD_REQUEST',
  );
});

test('invalid or oversized model result is rejected without append', async () => {
  const fixture = createFixture({
    infer: async () => ({ response: '', modelUsed: 'controlled-model' }),
  });

  await assert.rejects(
    fixture.service.runAuthenticated(INPUT),
    error => error.code === 'BAD_REQUEST',
  );
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['admit', 'infer']);

  const oversized = createFixture({
    infer: async () => ({ response: 'a'.repeat(262145), modelUsed: 'controlled-model' }),
  });
  await assert.rejects(
    oversized.service.runAuthenticated(INPUT),
    error => error.code === 'BAD_REQUEST',
  );
  assert.deepEqual(oversized.calls.map(([kind]) => kind), ['admit', 'infer']);
});

test('anonymous inference is bound to prompt and route, never touches history, and paging is fixed', async () => {
  const fixture = createFixture({
    infer: async value => ({ response: 'anonymous response', modelUsed: 'controlled-model', echoed: value }),
  });

  const anonymous = await fixture.service.runAnonymous({
    sourceRoute: INPUT.sourceRoute,
    prompt: INPUT.prompt,
    options: INPUT.options,
    ownerId: 999,
    sessionId: '999',
  });
  assert.deepEqual(anonymous, { response: 'anonymous response', modelUsed: 'controlled-model' });
  assert.deepEqual(fixture.calls[0][1], {
      prompt: INPUT.prompt,
      sourceRoute: INPUT.sourceRoute,
      options: INPUT.options,
  });
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['infer']);
  await assert.rejects(
    fixture.service.runAnonymous({ sourceRoute: 'untrusted-route', prompt: INPUT.prompt }),
    error => error.code === 'BAD_REQUEST',
  );
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['infer']);

  assert.deepEqual(
    await fixture.service.listOwner({ ownerId: 1, sessionId: '2', limit: 3, beforeCursor: null }),
    { ownerId: 1, sessionId: '2', limit: 3, beforeCursor: null },
  );
  assert.deepEqual(
    await fixture.service.listAdmin({ adminId: 9, sessionId: '10', limit: 3, beforeCursor: null }),
    { adminId: 9, sessionId: '10', limit: 3, beforeCursor: null },
  );
});

test('trusted execution rejects reset and revoked session during inference before append', async () => {
  for (const mode of ['generation', 'session']) {
    let changed = false;
    const fixture = createFixture({
      admit: async ({ ownerId, sessionId }) => {
        if (changed && mode === 'session') throw Object.assign(new Error('Revoked session'), { code: '55000' });
        return { ownerId, sessionId, generation: changed ? '5' : '4' };
      },
      infer: async (input, execution) => {
        assert.ok(Object.isFrozen(execution));
        assert.equal(execution.ownerId, INPUT.ownerId);
        assert.equal(execution.sessionId, INPUT.sessionId);
        assert.equal(execution.generation, '4');
        changed = true;
        await execution.check();
        throw new Error('Must not reach model publication');
      },
    });
    await assert.rejects(fixture.service.runAuthenticated(INPUT), error => error.code === '55000');
    assert.ok(!fixture.calls.some(([kind]) => kind === 'append'));
  }
});

test('server abort and timeout bound uncooperative inference and prevent late append', async () => {
  for (const mode of ['abort', 'timeout']) {
    const controller = new AbortController();
    let finish;
    let seen;
    const fixture = createFixture({ requestTimeoutMs: 100,
      infer: (input, execution) => { seen = execution; return new Promise(resolve => { finish = resolve; }); } });
    const pending = fixture.service.runAuthenticated(INPUT, { signal: controller.signal });
    await new Promise(resolve => setImmediate(resolve));
    if (mode === 'abort') controller.abort(new Error('Disconnected'));
    await assert.rejects(pending, mode === 'abort' ? /Disconnected/ : /timed out/);
    assert.equal(seen.signal.aborted, true);
    finish({ response: 'late', modelUsed: 'controlled-model' });
    await new Promise(resolve => setImmediate(resolve));
    assert.ok(!fixture.calls.some(([kind]) => kind === 'append'));
  }
});

test('anonymous scope ignores input authority and checks cancellation without admitting history', async () => {
  const fixture = createFixture({ infer: async (input, execution) => {
    assert.ok(Object.isFrozen(execution));
    assert.equal(execution.ownerId, null);
    assert.equal(execution.sessionId, undefined);
    await execution.check();
    return { response: 'anonymous', modelUsed: 'controlled-model' };
  } });
  await fixture.service.runAnonymous(INPUT);
  assert.deepEqual(fixture.calls.map(([kind]) => kind), ['infer']);
});

test('concurrent owners receive distinct immutable execution scopes', async () => {
  const seen = [];
  let release;
  const barrier = new Promise(resolve => { release = resolve; });
  const fixture = createFixture({ infer: async (input, execution) => {
    seen.push(execution);
    if (seen.length === 2) release();
    await barrier;
    await execution.check();
    return { response: 'response', modelUsed: 'controlled-model' };
  } });
  await Promise.all([fixture.service.runAuthenticated(INPUT),
    fixture.service.runAuthenticated({ ...INPUT, ownerId: 17, sessionId: '18' })]);
  assert.deepEqual(seen.map(scope => [scope.ownerId, scope.sessionId]), [[7, '8'], [17, '18']]);
  assert.notEqual(seen[0].signal, seen[1].signal);
});

test('server timeout and execution arguments are validated and pre-abort never admits', async () => {
  for (const requestTimeoutMs of [0, 99, 240001, NaN, '100']) {
    assert.throws(() => createFixture({ requestTimeoutMs }), /timeout/);
  }
  const fixture = createFixture();
  await assert.rejects(fixture.service.runAuthenticated(INPUT, { signal: {} }), /execution signal/);
  const controller = new AbortController(); controller.abort(new Error('Already closed'));
  await assert.rejects(fixture.service.runAuthenticated(INPUT, { signal: controller.signal }), /Already closed/);
  assert.deepEqual(fixture.calls, []);
});

test('server abort listeners are removed after success and failure', async () => {
  const { getEventListeners } = require('node:events');
  const controller = new AbortController();
  for (const fail of [false, true]) {
    const fixture = createFixture({ infer: async () => {
      if (fail) throw new Error('Inference failed');
      return { response: 'ok', modelUsed: 'controlled-model' };
    } });
    const pending = fixture.service.runAnonymous(INPUT, { signal: controller.signal });
    if (fail) await assert.rejects(pending, /Inference failed/);
    else await pending;
    assert.deepEqual(getEventListeners(controller.signal, 'abort'), []);
  }
});
