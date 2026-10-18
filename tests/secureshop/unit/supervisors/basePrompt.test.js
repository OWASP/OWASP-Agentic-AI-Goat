const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../../..');
const { buildBasePrompt, ROLE_PROMPTS } = require(path.join(REPO, 'server/services/secureshop/supervisors/basePrompt.js'));

test('basePrompt: ROLE_PROMPTS defines customer/merchant/admin', () => {
  assert.ok(ROLE_PROMPTS.customer, 'customer prompt exists');
  assert.ok(ROLE_PROMPTS.merchant, 'merchant prompt exists');
  assert.ok(ROLE_PROMPTS.admin, 'admin prompt exists');
});

test('basePrompt: customer prompt names customer-scoped agents in system prompt', () => {
  const prompt = buildBasePrompt('customer');
  assert.match(prompt, /product-search/, 'lists product-search');
  assert.match(prompt, /summarizer/, 'lists summarizer');
  assert.match(prompt, /price-advisor/, 'lists price-advisor');
  assert.match(prompt, /cart/, 'lists cart');
  assert.match(prompt, /support/, 'lists support');
  // customer prompt should NOT list user-management (runtime does not enforce — intentional)
  assert.doesNotMatch(prompt, /user-management/, 'does not list user-management');
});

test('basePrompt: buildBasePrompt accepts extra system additions', () => {
  const prompt = buildBasePrompt('customer', { extra: 'EXTRA_MARKER_XYZ' });
  assert.match(prompt, /EXTRA_MARKER_XYZ/);
});
