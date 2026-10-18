import { createGuestCartFrameChannel } from './guestCartFrame.mjs';
import { GUEST_CART_CHANNEL } from './guestCartProtocol.mjs';

const origin = 'https://shop.invalid';
const nonce = 'a'.repeat(64);

function frameHarness() {
  const messages = [];
  let listener;
  const parent = { postMessage: jest.fn((message, target) => messages.push([message, target])) };
  const frameWindow = { parent, setTimeout, clearTimeout,
    addEventListener: jest.fn((_type, next) => { listener = next; }),
    removeEventListener: jest.fn(),
  };
  const dispatch = (data, { source = parent, senderOrigin = origin } = {}) =>
    listener({ data, source, origin: senderOrigin });
  return { frameWindow, messages, dispatch, parent };
}

test('frame accepts only parent nonce, hydrates, then serializes snapshots on acknowledgements', async () => {
  const h = frameHarness();
  const channel = createGuestCartFrameChannel({ frameWindow: h.frameWindow, origin, nonce });
  h.dispatch({ channel: GUEST_CART_CHANNEL, type: 'hydrate', nonce, revision: 4,
    items: [{ productId: 125, quantity: 1 }] }, { senderOrigin: 'https://evil.invalid' });
  h.dispatch({ channel: GUEST_CART_CHANNEL, type: 'hydrate', nonce: 'b'.repeat(64), revision: 4,
    items: [] });
  expect(h.messages).toHaveLength(0);
  h.dispatch({ channel: GUEST_CART_CHANNEL, type: 'hydrate', nonce, revision: 4,
    items: [{ productId: 125, quantity: 1 }] });
  await expect(channel.ready).resolves.toEqual([{ productId: 125, quantity: 1 }]);
  expect(channel.snapshot()).toEqual([{ productId: 125, quantity: 1 }]);
  expect(channel.save([{ productId: 125, quantity: 2 }])).toBe(true);
  expect(channel.save([{ productId: 125, quantity: 3 }])).toBe(true);
  expect(channel.snapshot()).toEqual([{ productId: 125, quantity: 3 }]);
  expect(h.messages).toHaveLength(1);
  expect(h.messages[0][0]).toEqual({ channel: GUEST_CART_CHANNEL, type: 'snapshot', nonce,
    baseRevision: 4, items: [{ productId: 125, quantity: 2 }] });
  expect(h.messages[0][1]).toBe(origin);
  h.dispatch({ channel: GUEST_CART_CHANNEL, type: 'ack', nonce, revision: 5 });
  expect(h.messages[1][0]).toEqual({ channel: GUEST_CART_CHANNEL, type: 'snapshot', nonce,
    baseRevision: 5, items: [{ productId: 125, quantity: 3 }] });
  channel.close();
});

test('storage failure stops persistence but leaves page-local cart usable', async () => {
  const h = frameHarness();
  const channel = createGuestCartFrameChannel({ frameWindow: h.frameWindow, origin, nonce });
  h.dispatch({ channel: GUEST_CART_CHANNEL, type: 'hydrate', nonce, revision: 0, items: [] });
  await channel.ready;
  const failed = jest.fn();
  channel.onError(failed);
  h.dispatch({ channel: GUEST_CART_CHANNEL, type: 'storage-error', nonce });
  expect(failed).toHaveBeenCalledTimes(1);
  expect(channel.save([{ productId: 1, quantity: 1 }])).toBe(false);
  expect(h.messages).toHaveLength(0);
  channel.close();
});
