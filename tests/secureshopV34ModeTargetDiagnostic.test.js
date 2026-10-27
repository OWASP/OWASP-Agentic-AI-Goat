'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { v34ModeTargetSnapshot, withV34ModeTargetDiagnostic } = require('./fixtures/secureshopV34ModeTargetDiagnostic');

test('snapshot retains only bounded target geometry and state, including disappearance', () => {
  const oldDocument = global.document, oldWindow = global.window;
  let present = true, hit;
  const target = { textContent: 'Fixed', isConnected: true, disabled: false,
    getAttribute: () => 'false', contains: value => value === target,
    getBoundingClientRect: () => ({ left: 12.1, top: 30.7, width: 80, height: 20 }) };
  hit = target; target.tagName = 'BUTTON';
  global.window = { innerWidth: 1280, innerHeight: 900, scrollX: NaN, scrollY: 1e12 };
  global.document = { querySelectorAll: () => present ? [{ querySelectorAll: () => [target] }] : [],
    elementFromPoint: () => hit,
    querySelector: selector => selector.startsWith('aside') ? (present ? {} : null) : { getAttribute: () => String(present) } };
  try {
    const good = v34ModeTargetSnapshot('Fixed');
    assert.equal(good.targetOwnsHit, true); assert.equal(good.hitTag, 'BUTTON');
    assert.deepEqual(good.rect, { left: 12, top: 31, width: 80, height: 20 });
    assert.equal(good.viewport.scrollX, null); assert.equal(good.viewport.scrollY, 1000000);
    hit = { tagName: 'IFRAME', secret: 'never retain' };
    const occluded = v34ModeTargetSnapshot('Fixed');
    assert.equal(occluded.targetOwnsHit, false); assert.equal(occluded.hitTag, 'IFRAME');
    target.isConnected = false;
    assert.equal(v34ModeTargetSnapshot('Fixed').connected, false);
    present = false;
    const absent = v34ModeTargetSnapshot('Fixed');
    assert.equal(absent.groupCount, 0); assert.equal(absent.rect, null);
    assert.equal(JSON.stringify([good, occluded, absent]).includes('never retain'), false);
  } finally { global.document = oldDocument; global.window = oldWindow; }
});

test('failure captures exactly two snapshots, preserving identical original error', async () => {
  const original = new Error('original timeout'), records = [], events = [];
  const frame = { evaluate: async (fn, label) => { assert.equal(fn, v34ModeTargetSnapshot); assert.equal(label, 'Fixed'); events.push('snapshot'); return { ordinal: events.length }; } };
  await assert.rejects(withV34ModeTargetDiagnostic(frame, 'Fixed', async () => {
    events.push('original wait'); throw original;
  }, async value => { records.push(value); }), error => error === original);
  assert.deepEqual(events, ['snapshot', 'original wait', 'snapshot']);
  assert.equal(records.length, 1); assert.equal(records[0].requestedMode, 'fixed');
});

test('diagnostic errors do not replace original failure; successful operation is unchanged', async () => {
  const original = new Error('original'), frame = { evaluate: async () => { throw Error('diagnostic'); } };
  await assert.rejects(withV34ModeTargetDiagnostic(frame, 'Fixed', async () => { throw original; }, async () => { throw Error('capture'); }), error => error === original);
  assert.equal(await withV34ModeTargetDiagnostic(frame, 'Fixed', async () => 7, () => { throw Error('unexpected capture'); }), 7);
});

test('actual fixture keeps exact hit predicate, timeout and physical click order', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres/secureshopStandalonePricingRendered.integration.test.js'), 'utf8');
  const physical = source.slice(source.indexOf(' async function physical('), source.indexOf(' async function frame()'));
  assert.match(physical, /return hit===node\|\|node\.contains\(hit\)\}, \{timeout:20000\},text,scope\)/);
  assert.ok(physical.indexOf('withV34ModeTargetDiagnostic') < physical.indexOf('await element.click()'));
  assert.match(physical, /else await waitForHit\(\)/);
});

test('stalled diagnostics cannot hold the original error indefinitely', async () => {
  const original = new Error('original'), never = () => new Promise(() => {});
  const start = Date.now();
  await assert.rejects(withV34ModeTargetDiagnostic({ evaluate: never }, 'Fixed',
    async () => { throw original; }, never), error => error === original);
  assert.ok(Date.now() - start < 2000);
});
