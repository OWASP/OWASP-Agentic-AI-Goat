'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createMailInlineApplication } = require('../server/services/secureshopMailInlineApplication');
async function fixture(mode = 'vuln') {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 1, platformSessionId: 2 };
  const context = { scope, persona: { id: 12, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  const requestId = randomUUID(), readOperationId = randomUUID(), targetId = randomUUID(), sessionId = randomUUID();
  const selected = { version: 1, kind: 'detail', readOperationId, receiptSha256: 'a'.repeat(64),
    mailModeCapability: { version: 1, featureId: 'mail', policyVersion: 'owned-mail-recipient-header-and-html-v1',
      effectiveMode: mode, scope: { kind: 'launch_feature', id: 'mail' } },
    recipient: { id: 12, username: 'merchant', email: 'merchant@owned.invalid', role: 'merchant' },
    messageId: 23, messageSha256: 'b'.repeat(64), status: 'complete', message: { id: 23, threadId: 23,
      from: 'merchant@owned.invalid', to: 'merchant@owned.invalid', subject: 'Owned message',
      createdAt: '2026-10-13T00:00:00.000Z', sha256: 'b'.repeat(64), bodyMarkdown: '', bodyHtml: '',
      headersRaw: '', sourceBytes: 0, oversized: false } };
  const state = { send: null, summary: null, run: 0, reserve: 0, save: 0, activate: 0, reads: 0,
    canceled: 0, async check() {}, async afterSave() {}, async onActivate() {} };
  const deps = {
    async admit(ctx, id, options) { assert.deepEqual(ctx, context); return {
      binding: { ...context, mode, targetId, operationId: id }, check: () => state.check(), fresh: options.fresh }; },
    async listPersonas() { return [selected.recipient]; },
    mailRepository: { async recover() { return state.send || { found: false }; } },
    bindingRepository: {
      async readBound() { return { sendOperationId: requestId, targetId, messageId: 23, threadId: 23 }; },
      async saveTeachingMessage(raw, { reservation, payload }) {
        assert.equal(raw.operationId, requestId); assert.equal(payload.to, selected.recipient.email);
        assert(payload.body_html.includes('http://127.0.0.1:32345/image')); assert(reservation.issuanceId);
        state.save++; state.send = { found: true, action: 'send', operationId: requestId,
          receipt: { email_id: 23, thread_id: 23, recipientId: 12, contentSha256: 'b'.repeat(64) } };
        await state.afterSave(); return { send: { operationId: requestId, replayed: false, receipt: state.send.receipt } };
      },
    },
    targetPool: { async reserve() { state.reserve++; return { url: 'http://127.0.0.1:32345/image', reservation: { issuanceId: randomUUID() } }; },
      async activate() { state.activate++; await state.onActivate(); },
      async cancelPending() { state.canceled++; } },
    async resolveSelected(_raw, value) { assert.equal(value.readOperationId, readOperationId); return { selected }; },
    graph: {
      async read() { state.reads++; return state.summary; },
      async run(_raw, options) { state.run++; await options.beforeEffect(); state.summary = { sessionId,
        stopReason: 'end_turn', text: 'Original summary', taskMetadata: { mailSummary: { requestId,
          selected: { readOperationId, messageId: 23, messageSha256: selected.messageSha256 } } } }; return state.summary; },
    },
  };
  return { context, requestId, readOperationId, selected, state, deps,
    app: createMailInlineApplication(deps), summaryInput: { requestId, readOperationId, messageId: 23 } };
}
test('physical save derives its message server-side, replay and GET reserve no listener or mail', async () => {
  const f = await fixture();
  assert.equal((await f.app.readTeaching(f.context, { requestId: f.requestId })).status, 'unconfirmed');
  assert.equal((await f.app.saveTeaching(f.context, { requestId: f.requestId })).replayed, false);
  assert.equal((await f.app.readTeaching(f.context, { requestId: f.requestId })).status, 'saved');
  assert.equal((await f.app.saveTeaching(f.context, { requestId: f.requestId })).replayed, true);
  assert.deepEqual([f.state.reserve, f.state.save, f.state.activate], [1, 1, 2]);
});
test('summary reload and exact same-ID replay read saved original without graph dispatch', async () => {
  const f = await fixture();
  assert.equal((await f.app.readSummary(f.context, { requestId: f.requestId })).status, 'unconfirmed');
  const first = await f.app.summarize(f.context, f.summaryInput);
  assert.equal(first.status, 'completed'); assert.equal(first.replayed, false);
  assert.equal((await f.app.readSummary(f.context, { requestId: f.requestId })).text, first.text);
  assert.equal((await f.app.summarize(f.context, f.summaryInput)).replayed, true);
  assert.equal(f.state.run, 1);
  await assert.rejects(f.app.summarize(f.context, { ...f.summaryInput, messageId: 24 }));
  assert.equal(f.state.run, 1);
});
test('fixed source denies graph/HTTP; public source extensions and foreign recipient fail', async () => {
  const f = await fixture('fixed');
  await assert.rejects(f.app.summarize(f.context, f.summaryInput), { code: 'MAIL_INLINE_FIXED_DENIED' });
  assert.equal(f.state.run, 0);
  await assert.rejects(f.app.summarize(f.context, { ...f.summaryInput, url: 'private' }), { code: 'INVALID_ARGUMENT' });
  await assert.rejects(f.app.saveTeaching({ ...f.context, persona: { id: 12, role: 'customer' } }, { requestId: f.requestId }), { code: 'SHOP_AUTH_INVALID' });
});
test('lost save acknowledgement is GET-only recoverable and stale authority blocks new work', async () => {
  const f = await fixture(); f.state.afterSave = async () => { throw Error('lost acknowledgement'); };
  assert.equal((await f.app.saveTeaching(f.context, { requestId: f.requestId })).status, 'saved');
  assert.equal((await f.app.readTeaching(f.context, { requestId: f.requestId })).status, 'saved');
  assert.equal(f.state.reserve, 1); assert.equal(f.state.activate, 1); assert.equal(f.state.canceled, 0);
  f.state.check = async () => { throw Error('revoked'); };
  await assert.rejects(f.app.summarize(f.context, f.summaryInput), /revoked/); assert.equal(f.state.run, 0);
});
test('activation failure leaves saved mail recoverable; same POST activates existing reservation without resend', async () => {
  const f = await fixture(); f.state.onActivate = async () => { throw Error('activation interrupted'); };
  await assert.rejects(f.app.saveTeaching(f.context, { requestId: f.requestId }), /activation interrupted/);
  assert.equal((await f.app.readTeaching(f.context, { requestId: f.requestId })).status, 'saved');
  assert.equal(f.state.activate, 1);
  f.state.onActivate = async () => {};
  assert.equal((await f.app.saveTeaching(f.context, { requestId: f.requestId })).replayed, true);
  assert.deepEqual([f.state.reserve, f.state.save, f.state.activate, f.state.canceled], [1, 1, 2, 0]);
});
test('proven no-send failure cancels only pending reservation; uncertain readback never claims rollback', async () => {
  const f = await fixture(); f.deps.bindingRepository.saveTeachingMessage = async () => { throw Error('save failed'); };
  await assert.rejects(f.app.saveTeaching(f.context, { requestId: f.requestId }), /save failed/);
  assert.equal(f.state.canceled, 1);
  const g = await fixture(); let reads = 0;
  g.deps.mailRepository.recover = async () => { if (++reads > 1) throw Error('read unavailable'); return { found: false }; };
  g.deps.bindingRepository.saveTeachingMessage = async () => { throw Error('commit unknown'); };
  await assert.rejects(g.app.saveTeaching(g.context, { requestId: g.requestId }), /read unavailable/);
  assert.equal(g.state.canceled, 0); assert.equal(g.state.activate, 0);
});
