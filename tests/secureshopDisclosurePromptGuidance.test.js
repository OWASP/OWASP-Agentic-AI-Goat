'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { idorLessonBasePrompt, withCompletedSyntheticLookupGuidance } =
  require('../server/services/secureshopDisclosurePromptGuidance');

test('order lesson requests the three exact observed values and keeps fixed denial honest', () => {
  const order = idorLessonBasePrompt('order_status', 17, 'lesson.order_status');
  assert.match(order, /lesson\.order_status tool with \{"numericId":17\}/);
  for (const field of ['shippingAddress', 'paymentMethod', 'paymentStatus'])
    assert.match(order, new RegExp(field));
  assert.match(order, /If the tool denies the read, report the denial/);
  const cart = idorLessonBasePrompt('cart_remove', 19, 'lesson.cart_remove');
  assert.doesNotMatch(cart, /shippingAddress|paymentMethod|paymentStatus/);
});

test('synthetic lookup guidance is bound to a complete vulnerable tool observation', () => {
  const user = { username: 'student_customer', password: '$2b$10$' + 'a'.repeat(53),
    api_key: 'TRAINING_API_' + 'b'.repeat(48),
    session_token: 'TRAINING_SESSION_' + 'c'.repeat(48),
    full_name: 'Synthetic Customer', email: 'student@example.invalid', phone: '+1-555-0101' };
  const lookup = { status: 'complete', user };
  const observation = { content: [{ type: 'text', text: JSON.stringify({ version: 1,
    status: 'complete', user }) }] };
  const input = { system: 'Original authority', messages: [{ role: 'tool', content: observation.content[0].text }] };
  const guided = withCompletedSyntheticLookupGuidance(input, { lookup, observation, mode: 'vuln' });
  assert.notEqual(guided, input);
  assert.match(guided.system, /^Original authority\n/);
  for (const field of ['password', 'api_key', 'session_token', 'full_name', 'email', 'phone'])
    assert.match(guided.system, new RegExp(field));
  assert.deepEqual(guided.messages, input.messages);
  for (const value of Object.values(user)) assert.equal(guided.system.includes(value), false);
  assert.equal(withCompletedSyntheticLookupGuidance(input, { lookup, observation, mode: 'fixed' }), input);
  assert.equal(withCompletedSyntheticLookupGuidance(input, {
    lookup: { ...lookup, status: 'redacted' }, observation, mode: 'vuln' }), input);
  assert.equal(withCompletedSyntheticLookupGuidance(input, { lookup, observation: {
    content: [{ type: 'text', text: JSON.stringify({ version: 1, status: 'complete',
      user: { ...user, api_key: 'substitution' } }) }],
  }, mode: 'vuln' }), input);
});
