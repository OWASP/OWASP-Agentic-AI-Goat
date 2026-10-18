import { exactCartMessage, GUEST_CART_CHANNEL, validGuestCartItems } from './guestCartProtocol.mjs';

export function createGuestCartFrameChannel({ frameWindow = globalThis.window, origin, nonce, timeoutMs = 10000 }) {
  if (typeof origin !== 'string' || !/^https?:\/\//.test(origin)
    || typeof nonce !== 'string' || !/^[a-f0-9]{64}$/i.test(nonce)) {
    throw new TypeError('Trusted guest cart frame required');
  }
  let closed = false; let hydrated = false; let revision = 0;
  let pending = null; let queued = null; let failed = false; let currentItems = null;
  const errors = new Set();
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  // A frame may close before React mounts the cart consumer. Keep its public
  // promise rejectable for consumers without an unhandled teardown rejection.
  ready.catch(() => {});
  const notifyFailure = () => {
    if (failed) return;
    failed = true; pending = null; queued = null;
    for (const listener of errors) listener();
  };
  const send = items => {
    if (closed || !hydrated || !validGuestCartItems(items)) return false;
    currentItems = items.map(item => ({ ...item }));
    if (failed) return false;
    if (pending) { queued = currentItems; return true; }
    pending = { baseRevision: revision, items: currentItems };
    try {
      frameWindow.parent.postMessage({ channel: GUEST_CART_CHANNEL, type: 'snapshot',
        nonce, baseRevision: revision, items: pending.items }, origin);
      return true;
    } catch { notifyFailure(); return false; }
  };
  const timer = frameWindow.setTimeout(() => {
    if (!hydrated && !closed) { notifyFailure(); rejectReady(new Error('Guest cart restore unavailable')); }
  }, timeoutMs);
  const onMessage = event => {
    if (closed || event.source !== frameWindow.parent || event.origin !== origin) return;
    const data = event.data;
    if (data?.nonce !== nonce) return;
    if (exactCartMessage(data, 'hydrate') && Number.isSafeInteger(data.revision)
      && data.revision >= 0 && validGuestCartItems(data.items)) {
      revision = data.revision;
      if (!hydrated) {
        hydrated = true; currentItems = data.items.map(item => ({ ...item }));
        frameWindow.clearTimeout(timer); resolveReady(data.items);
      } else if (pending) {
        pending = null;
        const latest = queued; queued = null;
        if (latest) send(latest);
      }
      return;
    }
    if (exactCartMessage(data, 'ack') && pending
      && data.revision === pending.baseRevision + 1) {
      revision = data.revision; pending = null;
      const latest = queued; queued = null;
      if (latest) send(latest);
      return;
    }
    if (exactCartMessage(data, 'storage-error')) notifyFailure();
  };
  frameWindow.addEventListener('message', onMessage);
  return Object.freeze({ ready, save: send,
    snapshot() { return currentItems?.map(item => ({ ...item })) ?? null; },
    onError(listener) { if (typeof listener !== 'function') throw new TypeError('Cart error listener required');
      errors.add(listener); if (failed) listener(); return () => errors.delete(listener); },
    close() { if (closed) return; closed = true; frameWindow.clearTimeout(timer);
      frameWindow.removeEventListener('message', onMessage);
      if (!hydrated) rejectReady(new Error('Guest cart frame closed'));
      errors.clear(); },
  });
}
