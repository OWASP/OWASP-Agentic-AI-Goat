import { openStandalonePasswordReset, openStandaloneTeachingPasswordReset,
  openStandaloneChatPasswordReset, PASSWORD_RESET_PANEL_CHANNEL } from './passwordResetIntent.mjs';

function frame(url) {
  const messages = [];
  const value = { location: new URL(url), document: { baseURI: 'http://localhost:3000/secureshop-frame.html' },
    parent: { postMessage: (...args) => messages.push(args) } };
  return { value, messages };
}

test('standalone frame sends only validated target ID and nonce', () => {
  const { value, messages } = frame(`http://localhost:3000/secureshop-frame.html?standalone=1#${'a'.repeat(64)}`);
  expect(openStandalonePasswordReset(17, value)).toBe(true);
  expect(messages).toEqual([[{ channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open',
    nonce: 'a'.repeat(64), targetId: 17 }, 'http://localhost:3000']]);
  expect(Object.keys(messages[0][0]).sort()).toEqual(['channel', 'nonce', 'targetId', 'type']);
});

test('unbound frames and invalid IDs cannot suggest a reset', () => {
  const unbound = frame(`http://localhost:3000/secureshop-frame.html#${'a'.repeat(64)}`);
  expect(openStandalonePasswordReset(17, unbound.value)).toBe(false);
  expect(unbound.messages).toHaveLength(0);
  const bound = frame(`http://localhost:3000/secureshop-frame.html?standalone=1#${'a'.repeat(64)}`);
  for (const id of [0, -1, 2147483648, '17', 1.2]) expect(openStandalonePasswordReset(id, bound.value)).toBe(false);
  expect(bound.messages).toHaveLength(0);
});

test('teaching manual and saved chat handoffs carry only identifiers to the parent', () => {
  const bound = frame(`http://localhost:3000/secureshop-frame.html?standalone=1#${'a'.repeat(64)}`);
  const tuple = { sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    choiceId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  expect(openStandaloneTeachingPasswordReset(17, bound.value)).toBe(true);
  expect(openStandaloneChatPasswordReset(tuple, bound.value)).toBe(true);
  expect(bound.messages.map(([message]) => message)).toEqual([
    { channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open-teaching', nonce: 'a'.repeat(64), targetId: 17 },
    { channel: PASSWORD_RESET_PANEL_CHANNEL, type: 'open-chat', nonce: 'a'.repeat(64), ...tuple },
  ]);
  expect(openStandaloneChatPasswordReset({ ...tuple, choiceId: tuple.choiceId.toUpperCase() }, bound.value)).toBe(false);
  expect(bound.messages).toHaveLength(2);
});
