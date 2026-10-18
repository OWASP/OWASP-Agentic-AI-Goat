'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { syntheticChatBody } = require('./fixtures/dpiContainmentRendered');
test('synthetic initial response preserves rawpass while explicitly pending and noncredit', () => {
  for (const objectiveId of ['virtualization', 'obfuscation']) {
    const raw = { objectiveId, verdict: 'pass', explanation: 'Synthetic preserved raw output' };
    const receipt = { disposition: 'grading_unqualified', evaluationId: 'fixture-id', result: raw };
    const before = JSON.stringify(receipt), body = syntheticChatBody(receipt);
    assert.equal(body.completed, false);
    assert.equal(body.judgment.verdict, 'pass');
    assert.equal(body.judgment.gradingStatus, 'pending');
    assert.equal(body.judgment.canRetry, false);
    assert.equal(body.judgment.evaluationId, 'fixture-id');
    assert.equal(Object.hasOwn(body, 'completedObjective'), false);
    assert.equal(JSON.stringify(receipt), before);
  }
});
test('fixture refuses an awarded or missing-containment receipt', () => {
  for (const disposition of ['awarded', 'pending', undefined]) {
    assert.throws(() => syntheticChatBody({ disposition, result: { verdict: 'pass' } }));
  }
});
test('final receipt projection distinguishes baseline zero from exact synthetic identities', () => {
  const { assertReceiptProjection } = require('./fixtures/dpiContainmentRendered');
  assert.deepEqual(assertReceiptProjection([], []), { noJudgeReceipts: true, syntheticJudgeReceipts: 0, actualJudgeCalls: 0 });
  const rows = ['a', 'b'].map(evaluation_id => ({ evaluation_id, family: 'DPI', disposition: 'grading_unqualified', verdict: 'pass', result_json: { provider: 'fixture', model: 'fixture' } }));
  assert.deepEqual(assertReceiptProjection(rows, ['b', 'a']), { noJudgeReceipts: false, syntheticJudgeReceipts: 2, actualJudgeCalls: 0 });
  assert.throws(() => assertReceiptProjection(rows, []));
  assert.throws(() => assertReceiptProjection(rows, ['a', 'foreign']));
  assert.throws(() => assertReceiptProjection([{ ...rows[0], disposition: 'awarded' }], ['a']));
});
test('response wait rejection is observed immediately but still reaches awaiting caller', async () => {
  const { observedResponse } = require('./fixtures/dpiContainmentRendered');
  const pending = observedResponse({ waitForResponse: () => Promise.reject(Error('fixture timeout')) }, () => true);
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(pending, /fixture timeout/);
});
test('capture readiness rejects hidden, transparent, offscreen and moving content, then accepts settled frames', () => {
  const { captureReady } = require('./fixtures/dpiCaptureReadiness');
  const oldWindow = global.window, oldStyle = global.getComputedStyle;
  let x = 10;
  const ancestor = { parentElement: null, style: { opacity: '1', visibility: 'visible', display: 'block' } };
  const element = { isConnected: true, parentElement: ancestor, style: { opacity: '1', visibility: 'visible', display: 'block' }, getBoundingClientRect: () => ({ x, y: 10, top: 10, left: x, right: x + 100, bottom: 60, width: 100, height: 50 }) };
  try {
    global.window = { innerWidth: 1440, innerHeight: 1100 };
    global.getComputedStyle = e => e.style;
    for (const [field, value] of [['opacity', '0.05'], ['visibility', 'hidden'], ['display', 'none']]) {
      const before = ancestor.style[field]; ancestor.style[field] = value;
      for (let i = 0; i < 6; i++) assert.equal(captureReady(element), false);
      ancestor.style[field] = before;
    }
    x = -20; for (let i = 0; i < 6; i++) assert.equal(captureReady(element), false);
    for (let i = 0; i < 10; i++) { x = i * 2; assert.equal(captureReady(element), false); }
    assert.equal(captureReady(element), false); assert.equal(captureReady(element), false); assert.equal(captureReady(element), true);
    element.isConnected = false; assert.equal(captureReady(element), false);
  } finally { global.window = oldWindow; global.getComputedStyle = oldStyle; }
});
test('pointer readiness rejects occluded and disabled targets despite stable geometry', () => {
  const { captureReady } = require('./fixtures/dpiCaptureReadiness');
  const previous = { window: global.window, document: global.document, getComputedStyle: global.getComputedStyle };
  let hit;
  const element = { isConnected: true, disabled: false, parentElement: null, contains: e => e === hit && hit?.child === true,
    getBoundingClientRect: () => ({ x: 10, y: 10, top: 10, left: 10, right: 110, bottom: 60, width: 100, height: 50 }) };
  try {
    global.window = { innerWidth: 1440, innerHeight: 1100 };
    global.getComputedStyle = () => ({ opacity: '1', visibility: 'visible', display: 'block' });
    global.document = { elementFromPoint: () => hit };
    hit = {}; for (let i = 0; i < 6; i++) assert.equal(captureReady(element, true), false);
    hit = element; element.disabled = true; for (let i = 0; i < 6; i++) assert.equal(captureReady(element, true), false);
    element.disabled = false; hit = { child: true };
    assert.equal(captureReady(element, true), false); assert.equal(captureReady(element, true), false); assert.equal(captureReady(element, true), true);
  } finally { Object.assign(global, previous); }
});
test('authenticated route readiness requires token and exact role destination, never either login alias', () => {
  const { authenticatedRouteReady } = require('./fixtures/dpiCaptureReadiness');
  const oldLocation = global.location, oldStorage = global.localStorage;
  let token = 'synthetic-test-token';
  try {
    global.localStorage = { getItem: () => token };
    for (const expected of ['/workshop-dashboard', '/admin/dashboard']) {
      for (const pathname of ['/workshop-login', '/workshop/login', '/', '/workshop/agent-runs']) {
        global.location = { pathname }; assert.equal(authenticatedRouteReady(expected), false);
      }
      global.location = { pathname: expected }; assert.equal(authenticatedRouteReady(expected), true);
      token = ''; assert.equal(authenticatedRouteReady(expected), false); token = 'synthetic-test-token';
    }
    global.location = { pathname: '/admin/dashboard' }; assert.equal(authenticatedRouteReady('/workshop-dashboard'), false);
    global.location = { pathname: '/workshop/login' }; assert.equal(authenticatedRouteReady('/workshop/login'), false);
  } finally { global.location = oldLocation; global.localStorage = oldStorage; }
});
