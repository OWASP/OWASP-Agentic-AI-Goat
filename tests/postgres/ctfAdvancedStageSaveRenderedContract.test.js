'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { assertAdvancedStageSaveReceipt, exactPhysicalAdvancedPut, validatedAdvancedBrowserBearer,
  findAdvancedInput, replacePhysicalAdvancedScore, FIELDS, FACTS, PUT_PATH } =
  require('./support/ctfAdvancedStageSaveRenderedCases');
const { JSDOM } = require('../../client/node_modules/jsdom');

const id = n => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000001`;
const operation = (n, sequence) => ({ originalStatus: 200, resolvedStatus: 200, sameIdGets: 0,
  operationId: id(n), sequence: String(sequence), browserAckOperationId: null, ackMessage: 'Stage updated' });
const valid = () => ({ version: 1, profile: 'ctf-advanced-stage-save-q05', targetStageId: 2,
  siblingStageId: 3, mountedActorId: '1001', mountedSessionId: '1002', observedPath: PUT_PATH,
  browserPuts: 1, fixtureRestorePuts: 1,
  dialogTimeAba: { eventsObserved: 2, noPut: true },
  confirmed: operation(1, 11), restore: { ...operation(2, 12), scope: 'content-equivalence-only' },
  facts: Object.fromEntries(FACTS.map(name => [name, true])),
  excluded: ['byte-identical-undo', 'provenance-rollback', 'model-qualification'],
  unexpectedApiPaths: [], stage: 'complete', modelCalls: 0, judgeCalls: 0 });
const clone = value => JSON.parse(JSON.stringify(value));

test('separate Q05 Advanced Save receipt admits only exact bounded action and restoration', () => {
  assert.equal(FIELDS.length, 9);
  assert.equal(assertAdvancedStageSaveReceipt(valid()), true);
  for (const mutation of [
    r => { r.targetStageId = 3; },
    r => { r.browserPuts = 2; },
    r => { r.fixtureRestorePuts = 0; },
    r => { r.dialogTimeAba.eventsObserved = 1; },
    r => { r.dialogTimeAba.noPut = false; },
    r => { r.confirmed.sequence = '12'; r.restore.sequence = '11'; },
    r => { r.confirmed.operationId = r.restore.operationId; },
    r => { r.facts.cancelNoPut = false; },
    r => { r.facts.policyAndScoreChanged = false; },
    r => { r.facts.siblingPreserved = false; },
    r => { r.facts.restoreContentEquivalent = false; },
    r => { r.modelCalls = 1; },
    r => { r.judgeCalls = 1; },
    r => { r.unexpectedApiPaths = ['/api/ctf/admin/reset']; },
    r => { r.excluded = []; },
    r => { r.stage = 'partial'; },
    r => { r.unknown = true; },
  ]) {
    const changed = clone(valid()); mutation(changed);
    assert.throws(() => assertAdvancedStageSaveReceipt(changed));
  }
});

test('genuine 202 Advanced Save requires same-ID GET, distinct restore and no replayed PUT', () => {
  const receipt = valid();
  receipt.confirmed = { originalStatus: 202, resolvedStatus: 200, sameIdGets: 1,
    operationId: id(1), sequence: '11', browserAckOperationId: id(1), ackMessage: null };
  assert.equal(assertAdvancedStageSaveReceipt(receipt), true);
  receipt.confirmed.sameIdGets = 0;
  assert.throws(() => assertAdvancedStageSaveReceipt(receipt));
  receipt.confirmed.sameIdGets = 1;
  receipt.confirmed.browserAckOperationId = id(9);
  assert.throws(() => assertAdvancedStageSaveReceipt(receipt));
});

test('physical one-PUT witness requires exact path, bearer and all nine primitive fields', () => {
  const body = Object.fromEntries(FIELDS.map((key, index) => [key, key === 'level_score' ? 107 : `value-${index}`]));
  const seen = { puts: 1, paths: [PUT_PATH], physical: [{ body: clone(body), bearer: 'Bearer original' }] };
  assert.equal(exactPhysicalAdvancedPut(seen, 'Bearer original', body), true);
  for (const changed of [
    { puts: 2, paths: [PUT_PATH], physical: seen.physical },
    { puts: 1, paths: ['/api/ctf/admin/stages/3'], physical: seen.physical },
    { puts: 1, paths: [PUT_PATH, '/api/ctf/admin/stages/3'], physical: seen.physical },
    { puts: 1, paths: [PUT_PATH], physical: [{ body, bearer: 'Bearer refreshed' }] },
    { puts: 1, paths: [PUT_PATH], physical: [{ body: { ...body, extra: true }, bearer: 'Bearer original' }] },
    { puts: 1, paths: [PUT_PATH], physical: [{ body: { ...body, success_criteria: 'different' }, bearer: 'Bearer original' }] },
  ]) assert.equal(exactPhysicalAdvancedPut(changed, 'Bearer original', body), false);
});

test('refreshed browser bearer is accepted only for the same mounted actor and session', async () => {
  const adapter = { validateSession: async token => token === 'refreshed'
    ? { user: { id: 1001 }, session: { id: 2001 } }
    : token === 'other-session'
      ? { user: { id: 1001 }, session: { id: 2002 } }
      : { user: { id: 1002 }, session: { id: 2001 } } };
  const bearer = await validatedAdvancedBrowserBearer('refreshed', adapter, '1001', '2001');
  assert.equal(bearer, 'Bearer refreshed');
  const body = Object.fromEntries(FIELDS.map((key, index) => [key, key === 'level_score' ? 107 : `value-${index}`]));
  assert.equal(exactPhysicalAdvancedPut({ puts: 1, paths: [PUT_PATH],
    physical: [{ body, bearer }] }, bearer, body), true);
  await assert.rejects(validatedAdvancedBrowserBearer('other-session', adapter, '1001', '2001'));
  await assert.rejects(validatedAdvancedBrowserBearer('other-actor', adapter, '1001', '2001'));
  await assert.rejects(validatedAdvancedBrowserBearer(null, adapter, '1001', '2001'));
});

test('advanced field lookup excludes the preceding Teaching editor and rejects duplicates', () => {
  const dom = new JSDOM('<table><tbody><tr><td>' +
    '<section aria-label="Teaching content editor"><label>Stage Name</label><input id="teaching"></section>' +
    '<h3>Advanced stage controls</h3>' +
    '<div><label>Stage Name</label><input id="advanced"></div>' +
    '<div><label>System Prompt</label><textarea id="system"></textarea></div>' +
    '</td></tr></tbody></table>');
  const doc = dom.window.document;
  assert.equal(findAdvancedInput('Stage Name', doc)?.id, 'advanced');
  assert.equal(findAdvancedInput('System Prompt', doc)?.id, 'system');
  assert.equal(findAdvancedInput('Teaching Objective', doc), null);
  const duplicate = doc.createElement('div');
  duplicate.innerHTML = '<label>Stage Name</label><input id="duplicate">';
  doc.querySelector('td').append(duplicate);
  assert.equal(findAdvancedInput('Stage Name', doc), null);
  dom.window.close();
});

test('physical number replacement preserves SelectAll through typing without controlled zero reset', async () => {
  const events = [];
  const element = { value: '100' };
  let selected = false;
  const handle = {
    evaluate: async callback => callback(element),
    press: async (key, options) => {
      events.push(['press', key, options]);
      if (key === 'A' && options?.commands?.join() === 'SelectAll') selected = true;
      else if (key === 'Backspace') { element.value = '0'; selected = false; }
    },
    type: async text => {
      events.push(['type', text]);
      element.value = selected ? text : element.value + text;
      selected = false;
    },
  };
  const action = callback => callback();
  await replacePhysicalAdvancedScore(handle, action, 157);
  assert.equal(element.value, '157');
  assert.deepEqual(events.map(event => event[0]), ['press', 'type']);
  assert.deepEqual(events[0], ['press', 'A', { commands: ['SelectAll'], text: '' }]);
  await assert.rejects(replacePhysicalAdvancedScore({
    ...handle, press: async () => { selected = false; },
  }, action, 157));
});
