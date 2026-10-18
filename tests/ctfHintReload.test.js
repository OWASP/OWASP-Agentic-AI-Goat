'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const path = require('node:path');

const { parseCtfHints, purchasedCtfHints } = require('../server/services/ctfHintState');

function loadRouteWithFakes() {
  const routePath = path.resolve(__dirname, '../server/routes/ctf.js');
  const defensePath = path.resolve(__dirname, '../server/services/ctfDefenseLayers.js');
  const ctfDb = {};
  const CTFHelpers = {};
  const aiService = {};
  const originalLoad = Module._load;

  Module._load = function loadRouteDependencies(request, parent, isMain) {
    if (parent?.filename === routePath) {
      if (request === '../database/ctfDb') {
        return { ctfDb, CTFHelpers, engine: 'postgres' };
      }
      if (request === '../services/multiProviderAIService') return aiService;
      if (request === '../utils/contextLogger') return { error() {} };
    }
    if (parent?.filename === defensePath && request === './multiProviderAIService') return aiService;
    if (/(?:^|\/)(authDb|ctfDb)(?:\.js)?$/.test(request)) {
      throw new Error('Database initializer forbidden in controlled CTF hint test');
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  try {
    delete require.cache[routePath];
    delete require.cache[defensePath];
    return { ...require(routePath), CTFHelpers };
  } finally {
    Module._load = originalLoad;
    delete require.cache[routePath];
    delete require.cache[defensePath];
  }
}

const { router, CTFHelpers, leaderboardRefresh } = loadRouteWithFakes();
leaderboardRefresh.requestRefresh = () => {};

function routeHandler(routePath, method) {
  const layer = router.stack.find((entry) => entry.route?.path === routePath && entry.route.methods[method]);
  assert.ok(layer, `${method.toUpperCase()} ${routePath} must exist`);
  return layer.route.stack.at(-1).handle;
}

function responseRecorder() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

test('stored hint parser exposes only a bounded purchased prefix', () => {
  const stored = JSON.stringify(['first', 'second', 'unpurchased']);
  assert.deepEqual(parseCtfHints(stored), ['first', 'second', 'unpurchased']);
  assert.deepEqual(purchasedCtfHints(stored, 2), ['first', 'second']);
  assert.deepEqual(purchasedCtfHints(stored, 99), ['first', 'second', 'unpurchased']);
  assert.deepEqual(purchasedCtfHints(JSON.stringify(['one', 'two', 'three', 'not purchasable']), 99), ['one', 'two', 'three']);
  assert.deepEqual(purchasedCtfHints(stored, -1), []);
  assert.deepEqual(purchasedCtfHints('[]', 2), [], 'cleared instructor content stays unavailable after purchase');
  assert.deepEqual(purchasedCtfHints('{malformed', 2), []);
  assert.deepEqual(purchasedCtfHints('{"not":"an array"}', 2), []);
  assert.deepEqual(
    purchasedCtfHints(JSON.stringify(['first', { text: 'object must not render' }, 'third']), 2),
    [],
    'malformed entries fail closed without shifting purchase indexes',
  );
});

test('stage restart restores only the authenticated owner purchased prefix', async () => {
  const handler = routeHandler('/stage/:stageId/start', 'post');
  const original = {};
  for (const method of ['findActiveParticipant', 'isBanned', 'getActiveStage', 'getConfig', 'getProgress', 'getStageHints']) {
    original[method] = CTFHelpers[method];
  }
  const progressReads = [];
  const allHints = ['first hint', 'second hint', 'never purchased'];

  CTFHelpers.findActiveParticipant = async (userId) => ({
    id: userId === 71 ? 701 : 801,
    user_id: userId,
    started_at: '2026-09-15T00:00:00.000Z',
  });
  CTFHelpers.isBanned = async () => false;
  CTFHelpers.getActiveStage = async (stageId) => ({
    id: stageId,
    stage_order: 1,
    stage_number: 1,
    stage_name: 'Fixture stage',
    level_score: 100,
  });
  CTFHelpers.getConfig = async (key) => {
    if (key === 'ctf_time_limit') return '-1';
    if (key === 'ctf_hint_gating_attempts') return '3';
    throw new Error(`Unexpected config read: ${key}`);
  };
  CTFHelpers.getProgress = async (participantId, stageId) => {
    progressReads.push([participantId, stageId]);
    return {
      status: 'in_progress',
      attempts_count: 4,
      hints_used: participantId === 701 ? 2 : 1,
      hint_penalty_total: participantId === 701 ? 40 : 15,
    };
  };
  CTFHelpers.getStageHints = async (stageId) => {
    assert.equal(stageId, 9);
    return { hints: JSON.stringify(allHints), level_score: 100 };
  };

  try {
    const ownerResponse = responseRecorder();
    await handler({ user: { id: 71 }, params: { stageId: '9' } }, ownerResponse);
    assert.equal(ownerResponse.statusCode, 200);
    assert.deepEqual(ownerResponse.body.purchasedHints, ['first hint', 'second hint']);
    assert.equal(ownerResponse.body.hintsUsed, 2);
    assert.equal(ownerResponse.body.hintPenaltyTotal, 40);
    assert.equal(ownerResponse.body.hintsAvailable, true);
    assert.equal(JSON.stringify(ownerResponse.body).includes('never purchased'), false);

    const siblingResponse = responseRecorder();
    await handler({ user: { id: 81 }, params: { stageId: '9' } }, siblingResponse);
    assert.deepEqual(siblingResponse.body.purchasedHints, ['first hint']);
    assert.equal(siblingResponse.body.hintsUsed, 1);
    assert.equal(siblingResponse.body.hintPenaltyTotal, 15);

    CTFHelpers.getStageHints = async () => ({ hints: '[]', level_score: 100 });
    const clearedResponse = responseRecorder();
    await handler({ user: { id: 81 }, params: { stageId: '9' } }, clearedResponse);
    assert.deepEqual(clearedResponse.body.purchasedHints, []);
    assert.equal(clearedResponse.body.hintsUsed, 1, 'persisted purchase count and fee state are unchanged');
    assert.equal(clearedResponse.body.hintsAvailable, true, 'attempt gating semantics remain unchanged');
    assert.deepEqual(progressReads, [[701, 9], [801, 9], [801, 9]]);
  } finally {
    Object.assign(CTFHelpers, original);
  }
});

test('fresh stage exposes no hint text and existing fees remain authoritative', async () => {
  const start = routeHandler('/stage/:stageId/start', 'post');
  const purchase = routeHandler('/stage/:stageId/hint', 'post');
  const original = {};
  for (const method of [
    'findActiveParticipant', 'isBanned', 'getActiveStage', 'getConfig', 'getProgress',
    'startStage', 'updateParticipantActivity', 'recordStageStart', 'getStageHints', 'purchaseHint',
  ]) original[method] = CTFHelpers[method];
  const events = [];

  CTFHelpers.findActiveParticipant = async () => ({ id: 901, started_at: '2026-09-15T00:00:00.000Z' });
  CTFHelpers.isBanned = async () => false;
  CTFHelpers.getActiveStage = async (stageId) => ({ id: stageId, stage_order: 1, stage_number: 1, stage_name: 'Fixture', level_score: 100 });
  CTFHelpers.getConfig = async (key) => ({
    ctf_time_limit: '-1',
    ctf_hint_gating_attempts: '3',
    ctf_hint_cost_2: '25',
  })[key] ?? null;
  CTFHelpers.getProgress = async () => null;
  CTFHelpers.startStage = async (...args) => events.push(['start', ...args]);
  CTFHelpers.updateParticipantActivity = async (...args) => events.push(['activity', ...args]);
  CTFHelpers.recordStageStart = async (...args) => events.push(['event', ...args]);

  try {
    const freshResponse = responseRecorder();
    await start({ user: { id: 91 }, params: { stageId: '9' } }, freshResponse);
    assert.deepEqual(freshResponse.body.purchasedHints, []);
    assert.equal(freshResponse.body.hintsUsed, 0);
    assert.equal(freshResponse.body.hintPenaltyTotal, 0);

    CTFHelpers.getProgress = async () => ({
      id: 44,
      status: 'in_progress',
      attempts_count: 3,
      hints_used: 1,
      hint_penalty_total: 15,
    });
    CTFHelpers.getStageHints = async () => ({
      hints: JSON.stringify(['first hint', { text: 'object must not render' }, 'third hint']),
      level_score: 100,
    });
    CTFHelpers.purchaseHint = async (...args) => events.push(['usage', ...args]);

    const malformedResponse = responseRecorder();
    await purchase({ user: { id: 91 }, params: { stageId: '9' }, body: { hintIndex: 1 } }, malformedResponse);
    assert.equal(malformedResponse.statusCode, 400);
    assert.equal(malformedResponse.body.error, 'No more hints available for this stage');
    assert.equal(events.some(([name]) => name === 'usage'), false);

    CTFHelpers.getStageHints = async () => ({
      hints: JSON.stringify(['first hint', 'second hint', 'third hint']),
      level_score: 100,
    });
    const purchaseResponse = responseRecorder();
    await purchase({ user: { id: 91 }, params: { stageId: '9' }, body: { hintIndex: 1 } }, purchaseResponse);
    assert.equal(purchaseResponse.statusCode, 200);
    assert.equal(purchaseResponse.body.hint, 'second hint');
    assert.equal(purchaseResponse.body.cost, 25);
    assert.equal(purchaseResponse.body.totalPenalty, 40);
    assert.deepEqual(events.at(-1), ['usage', 44, 1, 25]);
  } finally {
    Object.assign(CTFHelpers, original);
  }
});
