'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { SCOPE, FLAGS, assertDirectAuditContext, assertDirectAuditReceipt,
  qualifyDirectAudit } = require('./fixtures/secureshopDirectAuditRenderedQualification');
const { ASSERTION, DIRECT_ASSERTION, DIRECT_SCOPE, DIRECT_FLAGS, assertDirectFinalReceipt } =
  require('./postgres/secureshopAdminAuditJobsRendered.integration.test');

test('direct Audit qualification exports an inert callable fixture with a closed receipt', () => {
  assert.equal(typeof qualifyDirectAudit, 'function');
  const receipt = { scope: SCOPE, searchOperationId: randomUUID(), summaryRunId: randomUUID(),
    actorCalls: 2, judgeCalls: 1, ...Object.fromEntries(FLAGS.map(key => [key, true])) };
  assert.equal(assertDirectAuditReceipt(receipt), receipt);
  assert.throws(() => assertDirectAuditReceipt({ ...receipt, directSearchRendered: false }), /directSearchRendered/);
  assert.throws(() => assertDirectAuditReceipt({ ...receipt, modelCalls: 2 }), /deep-equal/);
  assert.throws(() => assertDirectAuditReceipt({ ...receipt, judgeCalls: 0 }), /judgeCalls/);
  assert.throws(() => assertDirectAuditReceipt({ ...receipt, actorCalls: 13 }), /actorCalls/);
});

test('direct Audit qualification requires a genuine current-scoped caller-owned composition', () => {
  assert.throws(() => assertDirectAuditContext({}), /requires page/);
  const stub = { page: { waitForResponse() {} }, frame: { waitForSelector() {} },
    origin: 'http://127.0.0.1:12345', scope: { platformOwnerId: 1 },
    principal: { user: { role: 'admin' } },
    headers: { 'x-owasp-ai-goat-secureshop-launch': 'owned-launch', authorization: 'Bearer owned-persona' },
    peer: { scope: { platformOwnerId: 2 }, headers: {
      'x-owasp-ai-goat-secureshop-launch': 'peer-launch', authorization: 'Bearer peer-persona' } },
    identity: { query() {} }, agents: { query() {} }, control: { query() {} },
    audit: { agents: { append() {} } }, backend: { target() {} },
    launches: { beginReset() {} }, modeAuthority: { capture() {}, assertToken() {} },
    assessmentCatalog: { list() {} }, configurationAdminContext: { role: 'admin' },
    errorEvidence() { return []; }, actorCalls() { return 0; }, judgeCalls() { return 0; },
    evidence: { save() {} } };
  assert.doesNotThrow(() => assertDirectAuditContext(stub));
  assert.throws(() => assertDirectAuditContext({ ...stub, peer: {
    ...stub.peer, scope: { platformOwnerId: 1 } } }), /distinct real platform owner/);
});

test('direct Audit has a distinct opt-in test and closed cleanup receipt', () => {
  assert.notEqual(DIRECT_ASSERTION, ASSERTION);
  assert.equal(DIRECT_SCOPE, SCOPE);
  const receipt = { ...Object.fromEntries(DIRECT_FLAGS.map(key => [key, true])),
    scope: SCOPE, searchOperationId: randomUUID(), summaryRunId: randomUUID(),
    actorCalls: 2, judgeCalls: 1, errors: [] };
  assert.doesNotThrow(() => assertDirectFinalReceipt(receipt));
  assert.throws(() => assertDirectFinalReceipt({ ...receipt, fixtureCleaned: false }), /fixtureCleaned/);
  assert.throws(() => assertDirectFinalReceipt({ ...receipt, errors: [{ stage: 'search' }] }), /deep-equal/);
  assert.throws(() => assertDirectFinalReceipt({ ...receipt, actorCalls: 0 }), /actorCalls/);
});
