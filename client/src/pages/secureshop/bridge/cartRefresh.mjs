export const BOUND_CART_REFRESH_CHANNEL = 'owasp-ai-goat-secureshop-bound-cart-refresh-v1';
export const BOUND_CART_REFRESH_EVENT = 'owasp-ai-goat-secureshop-bound-cart-refresh';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE = /^[a-f0-9]{64}$/i;

export function requestBoundCartReadback({ frame, nonce, requestId, items,
  hostWindow = globalThis.window, timeoutMs = 10000 }) {
  if (frame?.tagName !== 'IFRAME' || !frame.contentWindow || !NONCE.test(nonce || '')
    || !UUID.test(requestId || '') || !Array.isArray(items) || items.length < 1 || items.length > 50
    || items.some(item => !Number.isSafeInteger(item.productId) || item.productId < 1
      || !Number.isSafeInteger(item.quantity) || item.quantity < 1 || item.quantity > 99)) {
    return Promise.reject(new TypeError('Bound cart readback required'));
  }
  const source = frame.contentWindow;
  const payload = Object.freeze({ channel: BOUND_CART_REFRESH_CHANNEL, type: 'refresh', nonce, requestId,
    items: items.map(item => Object.freeze({ productId: item.productId, quantity: item.quantity })) });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error, confirmed = false) => {
      if (settled) return;
      settled = true;
      hostWindow.clearTimeout(timer);
      hostWindow.clearInterval(retry);
      hostWindow.removeEventListener('message', receive);
      if (error) reject(error); else resolve(confirmed);
    };
    const receive = event => {
      const data = event.data;
      if (event.source !== source || event.origin !== 'null' || event.ports.length !== 0
        || !data || Object.keys(data).length !== 5 || data.channel !== BOUND_CART_REFRESH_CHANNEL
        || data.type !== 'readback' || data.nonce !== nonce || data.requestId !== requestId
        || typeof data.confirmed !== 'boolean') return;
      finish(null, data.confirmed);
    };
    const timer = hostWindow.setTimeout(() => finish(new Error('Cart refresh was not confirmed')), timeoutMs);
    hostWindow.addEventListener('message', receive);
    const send = () => {
      try {
        if (!frame.isConnected || frame.contentWindow !== source) throw new Error('Bound cart frame is unavailable');
        source.postMessage(payload, '*');
      } catch (error) { finish(error); }
    };
    // Bridge readiness precedes CartProvider's authenticated listener. Retry
    // the same read-only request until that listener can answer; never import again.
    const retry = hostWindow.setInterval(send, Math.min(750, Math.max(100, Math.floor(timeoutMs / 4))));
    send();
  });
}
