import { requestBoundCartReadback, BOUND_CART_REFRESH_CHANNEL } from './cartRefresh.mjs';

const nonce = 'a'.repeat(64);
const requestId = '7f078c35-0bda-4bb4-9c9f-819807aa2668';
const items = [{ productId: 125, quantity: 2 }];
let frame, send;

beforeEach(() => {
  jest.useFakeTimers();
  frame = document.createElement('iframe'); document.body.appendChild(frame);
  send = jest.fn(); frame.contentWindow.postMessage = send;
});
afterEach(() => { frame.remove(); jest.useRealTimers(); });

function reply({ source = frame.contentWindow, origin = 'null', responseNonce = nonce,
  responseRequestId = requestId, confirmed = true, extra = {} } = {}) {
  window.dispatchEvent(new MessageEvent('message', { source, origin, data: {
    channel: BOUND_CART_REFRESH_CHANNEL, type: 'readback', nonce: responseNonce,
    requestId: responseRequestId, confirmed, ...extra,
  } }));
}

test('late frame listener receives bounded identical read-only refresh and settles once', async () => {
  const result = requestBoundCartReadback({ frame, nonce, requestId, items, timeoutMs: 600 });
  expect(send).toHaveBeenCalledTimes(1);
  await jest.advanceTimersByTimeAsync(150);
  expect(send.mock.calls.length).toBeGreaterThan(1);
  for (const [payload] of send.mock.calls) expect(payload).toEqual({
    channel: BOUND_CART_REFRESH_CHANNEL, type: 'refresh', nonce, requestId, items,
  });
  reply(); expect(await result).toBe(true);
  const count = send.mock.calls.length;
  await jest.advanceTimersByTimeAsync(1000);
  expect(send).toHaveBeenCalledTimes(count);
});

test('forged or stale readback cannot settle; exact negative readback remains negative', async () => {
  const result = requestBoundCartReadback({ frame, nonce, requestId, items, timeoutMs: 600 });
  let settled = false; void result.then(() => { settled = true; });
  reply({ origin: 'http://attacker.test' });
  reply({ responseNonce: 'b'.repeat(64) });
  reply({ responseRequestId: '11111111-1111-4111-8111-111111111111' });
  reply({ extra: { claimed: true } });
  await Promise.resolve(); expect(settled).toBe(false);
  reply({ confirmed: false }); expect(await result).toBe(false);
});

test('missing listener times out and stops resending without a mutation', async () => {
  const result = requestBoundCartReadback({ frame, nonce, requestId, items, timeoutMs: 350 });
  const rejection = expect(result).rejects.toThrow('Cart refresh was not confirmed');
  await jest.advanceTimersByTimeAsync(350); await rejection;
  const count = send.mock.calls.length;
  await jest.advanceTimersByTimeAsync(1000); expect(send).toHaveBeenCalledTimes(count);
});
