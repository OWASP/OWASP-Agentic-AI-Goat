export const STANDALONE_SESSION_CHANNEL = 'dvaia-secureshop-standalone-session-v1';

export function requestStandaloneSessionIntent(type, { role, frameWindow = globalThis.window,
  origin = new URL(frameWindow.document.baseURI).origin, timeoutMs = 10000 } = {}) {
  if (!['logout', 'switch-role'].includes(type) || (type === 'switch-role'
    && !['customer', 'merchant', 'admin'].includes(role))) {
    return Promise.reject(new TypeError('Supported shop session action required'));
  }
  const nonce = frameWindow.location.hash.slice(1);
  if (!/^[a-f0-9]{64}$/i.test(nonce) || frameWindow.parent === frameWindow
    || typeof origin !== 'string' || !/^https?:\/\//.test(origin)) {
    return Promise.reject(new Error('Shop session bridge unavailable'));
  }
  const requestId = [...frameWindow.crypto.getRandomValues(new Uint8Array(16))]
    .map(value => value.toString(16).padStart(2, '0')).join('');
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = error => {
      if (done) return;
      done = true; frameWindow.clearTimeout(timer);
      frameWindow.removeEventListener('message', onMessage);
      frameWindow.removeEventListener('pagehide', onClose);
      if (error) reject(error); else resolve();
    };
    const onClose = () => finish(new DOMException('Shop frame closed', 'AbortError'));
    const onMessage = event => {
      const data = event.data;
      if (event.source !== frameWindow.parent || event.origin !== origin || event.ports.length !== 0
        || !data || data.channel !== STANDALONE_SESSION_CHANNEL || data.type !== 'result'
        || data.nonce !== nonce || data.requestId !== requestId
        || Object.keys(data).length !== (data.ok === true ? 5 : 6)) return;
      finish(data.ok === true ? null : new Error(data.error || 'Shop session action failed'));
    };
    const timer = frameWindow.setTimeout(() => finish(new Error('Shop session action timed out')), timeoutMs);
    frameWindow.addEventListener('message', onMessage);
    frameWindow.addEventListener('pagehide', onClose, { once: true });
    frameWindow.parent.postMessage({ channel: STANDALONE_SESSION_CHANNEL, type, nonce,
      requestId, ...(type === 'switch-role' ? { role } : {}) }, origin);
  });
}
