'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { assertTeachingSaveReceipt, exactPhysicalTeachingPut, exactFinalTeachingPut,
  replacePhysicalTeachingField, CONTENT_FIELDS, PUT_PATH } = require('./support/ctfTeachingSaveRenderedCases');

const makeReceipt = () => ({
  version: 1, profile: 'ctf-teaching-save-q05', modelCalls: 0, judgeCalls: 0,
  targetStageId: 2, siblingStageId: 3, mountedActorId: '500', mountedSessionId: '900',
  observedPath: '/api/ctf/admin/stages/2/content', browserPuts: 1, fixtureDeniedPuts: 1, fixtureRestorePuts: 1,
  dialogTimeAba: { eventsObserved: 2, noPut: true },
  confirmed: { originalStatus: 200, resolvedStatus: 200, sameIdGets: 0,
    operationId: '10000000-0000-0000-0000-000000000001', sequence: '10',
    browserAckOperationId: null, ackMessage: 'Stage updated' },
  restore: { scope: 'content-equivalence-only', originalStatus: 200, resolvedStatus: 200, sameIdGets: 0,
    operationId: '10000000-0000-0000-0000-000000000002', sequence: '11',
    browserAckOperationId: null, ackMessage: 'Stage updated' },
  facts: { cancelNoPut: true, cancelNoEffect: true, dialogAbaNoPut: true, dialogAbaNoEffect: true,
    confirmedOnePhysicalPut: true, physicalRequestFiveFieldsAndBearer: true, fiveFieldsExact: true,
    canonicalProjectionApplied: true, actorSessionBound: true, learnerMutationDenied: true,
    guardianAndScoringUnchanged: true, siblingPreserved: true,
    adminHintsAndSolutionVisible: true, learnerObjectiveVisible: true,
    learnerRawHintsAndSolutionAbsent: true, restoreContentEquivalent: true,
    restorationGuardianAndScoringUnchanged: true },
  excluded: ['byte-identical-undo', 'provenance-rollback'], unexpectedApiPaths: [], stage: 'complete',
});
const altered = update => { const copy = structuredClone(makeReceipt()); update(copy); return copy; };

test('Teaching Save receipt is separate from original 55-fact content receipt and names only five fields', () => {
  assert.equal(assertTeachingSaveReceipt(makeReceipt()), true);
  assert.deepEqual(CONTENT_FIELDS, ['stage_name', 'stage_description', 'hints', 'teaching_objective', 'solution_content']);
  assert.equal(PUT_PATH, '/api/ctf/admin/stages/2/content');
  assert.equal(assertTeachingSaveReceipt(altered(r => {
    r.confirmed.originalStatus = 202; r.confirmed.sameIdGets = 1;
    r.confirmed.browserAckOperationId = r.confirmed.operationId; r.confirmed.ackMessage = null;
    r.restore.originalStatus = 202; r.restore.sameIdGets = 1;
    r.restore.browserAckOperationId = r.restore.operationId; r.restore.ackMessage = null;
  })), true);
});

test('Cancel, ABA, physical PUT, original authority, and readback facts fail closed', () => {
  for (const change of [
    r => { r.facts.cancelNoPut = false; }, r => { r.facts.cancelNoEffect = false; },
    r => { r.dialogTimeAba.eventsObserved = 1; }, r => { r.facts.dialogAbaNoPut = false; },
    r => { r.browserPuts = 2; }, r => { r.observedPath = '/api/ctf/admin/stages/3/content'; },
    r => { r.fixtureDeniedPuts = 0; }, r => { r.facts.learnerMutationDenied = false; },
    r => { r.mountedSessionId = '0'; }, r => { r.facts.actorSessionBound = false; },
    r => { r.facts.physicalRequestFiveFieldsAndBearer = false; },
    r => { r.facts.guardianAndScoringUnchanged = false; }, r => { r.facts.siblingPreserved = false; },
    r => { r.facts.adminHintsAndSolutionVisible = false; },
    r => { r.facts.learnerRawHintsAndSolutionAbsent = false; },
    r => { r.facts.restorationGuardianAndScoringUnchanged = false; },
    r => { r.modelCalls = 1; }, r => { r.unexpectedApiPaths.push('/api/other'); },
  ]) assert.throws(() => assertTeachingSaveReceipt(altered(change)));
});

test('a pending operation requires same-ID readback; restoration is a distinct supported mutation, not rollback', () => {
  for (const change of [
    r => { r.confirmed.originalStatus = 202; r.confirmed.sameIdGets = 0; },
    r => { r.restore.originalStatus = 202; r.restore.sameIdGets = 0; },
    r => { r.confirmed.originalStatus = 202; r.confirmed.sameIdGets = 1; r.confirmed.browserAckOperationId = r.restore.operationId; r.confirmed.ackMessage = null; },
    r => { r.restore.originalStatus = 202; r.restore.sameIdGets = 1; r.restore.browserAckOperationId = r.confirmed.operationId; r.restore.ackMessage = null; },
    r => { r.restore.operationId = r.confirmed.operationId; },
    r => { r.restore.sequence = '9'; },
    r => { r.fixtureRestorePuts = 0; },
    r => { r.restore.scope = 'byte-identical-undo'; },
    r => { r.excluded = []; },
    r => { r.facts.restoreContentEquivalent = false; },
    r => { r.confirmed.unverified = true; },
    r => { r.unexpectedReceiptField = true; },
  ]) assert.throws(() => assertTeachingSaveReceipt(altered(change)));
});

test('physical request check compares exactly five submitted values and the captured bearer without persisting them', () => {
  const fields = { stage_name: 'Title', stage_description: 'Description', hints: '["Hint"]',
    teaching_objective: 'Objective', solution_content: 'Admin solution' };
  const request = { body: { ...fields }, bearer: 'Bearer mounted-admin' };
  assert.equal(exactPhysicalTeachingPut([request], 'Bearer mounted-admin', fields), true);
  assert.equal(exactPhysicalTeachingPut([request, request], 'Bearer mounted-admin', fields), false);
  assert.equal(exactPhysicalTeachingPut([{ ...request, bearer: 'Bearer other-admin' }], 'Bearer mounted-admin', fields), false);
  assert.equal(exactPhysicalTeachingPut([{ ...request, body: { ...fields, system_prompt: 'unsafe' } }], 'Bearer mounted-admin', fields), false);
  assert.equal(exactPhysicalTeachingPut([{ ...request, body: { ...fields, hints: '["Changed"]' } }], 'Bearer mounted-admin', fields), false);
  assert.equal(exactPhysicalTeachingPut([{ ...request, body: null }], 'Bearer mounted-admin', fields), false);
});

test('final physical witness rejects a wrong-route PUT arriving after the valid confirmation', () => {
  const fields = { stage_name: 'Title', stage_description: 'Description', hints: '["Hint"]',
    teaching_objective: 'Objective', solution_content: 'Admin solution' };
  const seen = { puts: 1, paths: [PUT_PATH], physicalRequests: [{ body: { ...fields }, bearer: 'Bearer mounted-admin' }] };
  assert.equal(exactFinalTeachingPut(seen, 'Bearer mounted-admin', fields), true);
  seen.paths.push('/api/ctf/admin/stages/3/content');
  assert.equal(exactFinalTeachingPut(seen, 'Bearer mounted-admin', fields), false);
  seen.paths.pop();
  seen.paths.push('/api/ctf/admin/stages/2');
  assert.equal(exactFinalTeachingPut(seen, 'Bearer mounted-admin', fields), false);
  seen.paths.pop();
  seen.physicalRequests[0].bearer = 'Bearer other-admin';
  assert.equal(exactFinalTeachingPut(seen, 'Bearer mounted-admin', fields), false);
});

test('native editor SelectAll clears nonempty input and multiline textarea before physical typing', async () => {
  for (const [before, replacement] of [['Simple Guard', 'Q05 rendered teaching title'],
    ['Existing first line\nExisting second line', 'New first line\nNew second line']]) {
    const element = { value: before, selectionStart: before.length, selectionEnd: before.length };
    const events = [];
    const handle = {
      evaluate: async callback => callback(element),
      press: async (key, options) => {
        events.push({ kind: 'press', key, options });
        if (key === 'A' && options?.commands?.[0] === 'SelectAll' && options.text === '') {
          element.selectionStart = 0; element.selectionEnd = element.value.length;
        } else if (key === 'Backspace') {
          element.value = element.value.slice(0, element.selectionStart) + element.value.slice(element.selectionEnd);
          element.selectionEnd = element.selectionStart; events.push({ kind: 'input', value: element.value });
        } else throw Error('Unexpected keyboard command');
      },
      type: async value => {
        events.push({ kind: 'type', value });
        element.value = value; element.selectionStart = value.length; element.selectionEnd = value.length;
        events.push({ kind: 'input', value: element.value });
      },
    };
    await replacePhysicalTeachingField(handle, fn => fn(), 'controlled field', replacement);
    assert.equal(element.value, replacement);
    assert.deepEqual(events, [
      { kind: 'press', key: 'A', options: { commands: ['SelectAll'], text: '' } },
      { kind: 'press', key: 'Backspace', options: undefined },
      { kind: 'input', value: '' },
      { kind: 'type', value: replacement },
      { kind: 'input', value: replacement },
    ]);
  }
});

test('failed native selection aborts before Backspace or typing', async () => {
  const element = { value: 'Simple Guard', selectionStart: 12, selectionEnd: 12 };
  let destructiveCommands = 0;
  const handle = {
    evaluate: async callback => callback(element),
    press: async key => { if (key !== 'A') destructiveCommands++; },
    type: async () => { destructiveCommands++; },
  };
  await assert.rejects(replacePhysicalTeachingField(handle, fn => fn(), 'Stage Name', 'New title'), /fully selected/);
  assert.equal(destructiveCommands, 0);
  assert.equal(element.value, 'Simple Guard');
});

test('installed Puppeteer sends SelectAll as a no-text native editor command', async () => {
  const packageRoot = path.dirname(require.resolve('puppeteer-core/package.json'));
  const { CdpKeyboard } = await import(pathToFileURL(path.join(packageRoot, 'lib/puppeteer/cdp/Input.js')).href);
  const sent = [];
  const keyboard = new CdpKeyboard({ send: async (method, payload) => sent.push({ method, payload }) });
  await keyboard.press('A', { commands: ['SelectAll'], text: '' });
  assert.equal(sent.length, 2);
  assert.equal(sent[0].method, 'Input.dispatchKeyEvent');
  assert.equal(sent[0].payload.type, 'rawKeyDown');
  assert.deepEqual(sent[0].payload.commands, ['SelectAll']);
  assert.equal(sent[0].payload.text, '');
  assert.equal(sent[1].payload.type, 'keyUp');
});
