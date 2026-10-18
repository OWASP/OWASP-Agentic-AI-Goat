'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const hints = require('../server/data/workshopHints');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const { resolveObjectiveContent } = require('../server/database/postgres/workshopPlatformSeedCore');

// Exact prior checked-in defaults; used only to test managed-default succession.
const prior = {
  xss_e1: { title: 'List Your SharkLaser Inbox', hints: [
    'Configure your permitted SharkLaser address, then ask the assistant to show your emails.',
    'The listEmails tool must query the owner-configured inbox; an empty successful inbox response still proves listing.',
    'This is the baseline before you deliver an event-handler payload.'
  ] },
  xss_e2: { title: 'Send the XSS Attack Email', hints: [
    'Use the setup panel to select or enter an HTML event-handler payload and send it to your canonical SharkLaser inbox.',
    'An image onerror payload is automatic; hover payloads need interaction later.',
    'Completion requires the server mail service to confirm delivery to the owner-configured recipient.'
  ] },
  xss_e3: { title: 'Retrieve, Render, and Trigger Email XSS', hints: [
    'Ask the assistant to summarize the attack email from indirectpromptinjection@gmail.com.',
    'The route must retrieve that email body and append the exact raw body to the response.',
    'Completion requires the retrieved handler to execute in the isolated innerHTML browser; merely mentioning a payload is insufficient.'
  ] },
};

function client(current, applied, state = 'managed') {
  const writes = [];
  return { writes, async query(sql, params = []) {
    if (/SELECT revision/.test(sql)) return { rows: [{ revision: 1 }] };
    if (/SELECT hint_content AS value/.test(sql)) return { rows: [{ value: current }], rowCount: 1 };
    if (/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql)) return { rows: state === null ? [] : [{
      provenance_state: state, applied_default_hash: provenance.hashDocument(provenance.document(applied)),
    }] };
    if (/(?:UPDATE|INSERT INTO) workshop_platform\.(?:objectives|catalog_field_defaults)/.test(sql)) {
      writes.push({ sql, params }); return { rows: [], rowCount: 1 };
    }
    throw Error('Unexpected controlled SQL');
  } };
}

test('email hint defaults describe configured ownership and distinct SMTP/retrieval/browser stages', () => {
  assert.deepEqual(Object.keys(prior), ['xss_e1', 'xss_e2', 'xss_e3']);
  for (const objectiveId of Object.keys(prior)) {
    const content = resolveObjectiveContent({ workshopKey: 'xss_workshop', objectiveId, hints, solutions: {} });
    assert.equal(content.hintPresent, true);
    assert.deepEqual(content.hint, hints.xss_workshop[objectiveId]);
    assert.equal(content.hint.hints.length, 3);
    assert.doesNotMatch(JSON.stringify(content.hint), /SharkLaser|indirectpromptinjection@gmail\.com|confirm delivery/i);
  }
  assert.match(hints.xss_workshop.xss_e1.hints[0], /assigned workshop inbox/);
  assert.match(hints.xss_workshop.xss_e2.hints[2], /SMTP acceptance/);
  assert.match(hints.xss_workshop.xss_e2.hints[2], /retrieval.*separate/);
  assert.match(hints.xss_workshop.xss_e3.hints[0], /current.*dispatch/);
  assert.match(hints.xss_workshop.xss_e3.hints[1], /exact raw body/);
  assert.match(hints.xss_workshop.xss_e3.hints[2], /execute.*isolated innerHTML browser/);
});

for (const [objectiveId, old] of Object.entries(prior)) {
  const value = hints.xss_workshop[objectiveId];
  const spec = { entityKind: 'objective', workshopKey: 'xss_workshop', objectiveId,
    fieldName: 'hint_content', sourceValue: value, sourceVersion: 'email-owned-inbox-copy' };
  test(objectiveId + ' managed prior default upgrades; second seed does not rewrite content', async () => {
    const db = client(old, old);
    assert.equal((await provenance.reconcileField(db, spec)).changed, true);
    const updates = db.writes.filter(x => /UPDATE workshop_platform.objectives/.test(x.sql));
    assert.equal(updates.length, 1);
    assert.deepEqual(JSON.parse(updates[0].params[2]), value);
    const again = client(value, value);
    assert.equal((await provenance.reconcileField(again, spec)).changed, false);
    assert(!again.writes.some(x => /UPDATE workshop_platform.objectives/.test(x.sql)));
  });
  test(objectiveId + ' instructor content, explicit null and unknown provenance survive', async () => {
    for (const state of ['managed', 'custom', null]) for (const current of [null, { title: 'Instructor title', hints: ['Keep this exercise'] }]) {
      const db = client(current, old, state);
      assert.equal((await provenance.reconcileField(db, spec)).changed, false);
      assert(!db.writes.some(x => /UPDATE workshop_platform.objectives/.test(x.sql)));
    }
  });
}
