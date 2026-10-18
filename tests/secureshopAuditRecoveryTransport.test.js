'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createInboxController } = require('./postgres/secureshopMailBrowserJudgeTransport');
const model = 'llama3.3:70b';
const digest = 'a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa';
const messages = [{ role: 'system', content: 'Judge' }, { role: 'user', content: 'Support' }];
const format = { type: 'object', properties: { pass: { type: 'boolean' } }, required: ['pass'] };
const options = { temperature: 0, num_predict: 4096, num_ctx: 32768, format };
const body = JSON.stringify({ model, messages, stream: true, options: { temperature: 0, num_predict: 4096, num_ctx: 32768 }, format });
const admission = { evaluationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sourceCheckpointSha256: 'a'.repeat(64), effectCheckpointSha256: 'b'.repeat(64), parentErrorCode: 'JUDGE_TIMEOUT', canRetry: true };
async function interrupted(t, reason = 'TimeoutError') {
  let calls = 0;
  const judge = new AbortController();
  const partial = '{"model":"llama3.3:70b","message":{"content":"partial"}}\n';
  const c = createInboxController({ profile: 'audit-instruction-actual', audit70b: true, auditContinuation: true, fetch: async (url, { signal }) => {
    if (url.endsWith('/api/tags')) return new Response(JSON.stringify({ models: [{ name: model, digest }] }));
    calls++;
    if (calls === 3) return new Response(new ReadableStream({ start(stream) {
      stream.enqueue(Buffer.from(partial));
      signal.addEventListener('abort', () => stream.error(signal.reason), { once: true });
      setImmediate(() => judge.abort(new DOMException('controlled interruption', reason)));
    } }));
    return new Response(JSON.stringify({ model, message: { content: '{}' }, done: true, done_reason: 'stop' }) + '\n');
  } });
  t.after(() => c.close());
  await c.initialize(); c.beginCase('benign'); c.endCase(); c.beginCase('injected');
  for (let i = 0; i < 2; i++) {
    c.expect('judge', { messages, tools: [], options });
    await c.request({ method: 'POST', path: '/api/chat', body });
  }
  c.expect('judge', { messages, tools: [], options: { ...options, signal: judge.signal } });
  // An independent HTTP signal must not discard the production Judge signal.
  await assert.rejects(c.request({ method: 'POST', path: '/api/chat', body, signal: new AbortController().signal }));
  c.endCase();
  return { c, calls: () => calls, partial };
}
test('ordinary cancellation cannot qualify recovery even with a claimed timeout receipt', async t => {
  const { c, calls } = await interrupted(t, 'AbortError');
  assert.throws(() => c.beginRecovery(admission), /AUDIT_RECOVERY_SCOPE/);
  assert.equal(calls(), 3);
});
test('Judge timeout retains partial bytes and original failure through successful recovery', async t => {
  const { c, partial } = await interrupted(t);
  const before = c.snapshot();
  assert.equal(before.calls[3].partialResponse, partial);
  assert.equal(before.calls[3].judgeAbortReason, 'TimeoutError');
  c.beginRecovery(admission);
  await c.request({ method: 'POST', path: '/api/chat', body });
  c.endCase();
  assert.deepEqual(c.snapshot().calls[3], before.calls[3]);
  assert.deepEqual(c.snapshot().originalFailure, before.originalFailure);
});
test('changed interrupted support request is denied before inference', async t => {
  const { c, calls } = await interrupted(t);
  c.beginRecovery(admission);
  const changed = JSON.parse(body); changed.messages[1].content = 'Different stage';
  await assert.rejects(c.request({ method: 'POST', path: '/api/chat', body: JSON.stringify(changed) }), /INBOX_REQUEST_MISMATCH/);
  assert.equal(calls(), 3);
});
test('recovery cannot dispatch a second support call', async t => {
  const { c, calls } = await interrupted(t);
  c.beginRecovery(admission);
  await c.request({ method: 'POST', path: '/api/chat', body });
  await assert.rejects(c.request({ method: 'POST', path: '/api/chat', body }), /AUDIT_RECOVERY_SCOPE/);
  assert.equal(calls(), 4);
});
