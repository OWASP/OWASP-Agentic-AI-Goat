'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
test('CSRF late response guard rejects reset/tab changes and identity replacement', async () => {
  const { createCsrfResponseGuard } = await import('../client/src/utils/csrfResponseGuard.mjs');
  let identity = 'owner-a';
  const guard = createCsrfResponseGuard(() => identity);
  const beforeReset = guard.capture();
  assert.equal(beforeReset(), true);
  guard.invalidate();
  assert.equal(beforeReset(), false);
  const beforeIdentity = guard.capture();
  identity = 'owner-b';
  assert.equal(beforeIdentity(), false);
  assert.equal(guard.capture()(), true);
});
test('judge feedback uses fixed text and does not echo model explanation or claim pass is credit', async () => {
  const { csrfJudgeFeedback } = await import('../client/src/utils/csrfResponseGuard.mjs');
  const result = csrfJudgeFeedback(['fail','inconclusive','unavailable','pass','fail'].map(verdict => ({ verdict, explanation: '<script>secret</script>' })));
  assert.equal(result.length, 3);
  assert.equal(result.some(text => text.includes('script')), false);
});
