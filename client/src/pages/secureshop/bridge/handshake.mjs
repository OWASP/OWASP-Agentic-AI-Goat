import { createHostTransport, createFrameTransport } from './transport.mjs';
import { createHostShopStateChannel, connectFrameShopState } from './stateChannel.mjs';

const CHANNEL = 'dvaia-secureshop-bridge-v1';
const mountedFrames = new WeakSet();
const cancelled = () => new DOMException('Shop frame disconnected', 'AbortError');
const validNonce = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const validOrigin = value => {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value) throw new TypeError('Exact application origin required');
  return value;
};
const envelope = (data, type, nonce) => data && typeof data === 'object'
  && Object.keys(data).length === 3 && data.channel === CHANNEL && data.type === type && data.nonce === nonce;

// One instance owns one iframe document and one launch generation. A reset or
// navigation must dispose it and create a new instance, never recycle its port.
export function mountShopFrame({ frame, url, origin, compileOperation, getLaunchBearer,
  hostWindow = globalThis.window, timeoutMs = 15000, transportOptions = {}, stateStore, onActivity = () => {} }) {
  validOrigin(origin);
  const target = new URL(url, origin);
  if (target.origin !== origin || target.username || target.password) throw new TypeError('Same-origin shop entry required');
  if (!frame || frame.isConnected || mountedFrames.has(frame)) throw new TypeError('A detached, fresh iframe is required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('Positive handshake timeout required');
  const nonce = [...hostWindow.crypto.getRandomValues(new Uint8Array(32))].map(byte => byte.toString(16).padStart(2, '0')).join('');
  mountedFrames.add(frame);
  target.hash = nonce;
  // The real shop uses React form submit handlers for login, reviews and
  // checkout. allow-forms permits those events; the frame document's
  // form-action CSP blocks native transport, and the remaining sandbox flags
  // preserve the opaque boundary.
  frame.setAttribute('sandbox', 'allow-scripts allow-forms');
  frame.src = target.href;
  let closed = false; let connected = false; let loaded = false; let transport; let stateTransport;
  let lastActivity = 0;
  let resolveReady; let rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const close = () => {
    if (closed) return;
    closed = true; clearTimeout(timer);
    hostWindow.removeEventListener('message', receive);
    hostWindow.removeEventListener('pagehide', close);
    frame.removeEventListener('load', onLoad);
    transport?.close(); stateTransport?.close(); rejectReady(cancelled());
  };
  const onLoad = () => {
    if (loaded) { close(); return; }
    loaded = true;
    try { frame.contentWindow.postMessage({ channel: CHANNEL, type: 'offer', nonce }, '*'); } catch { close(); }
  };
  const receive = event => {
    if (closed || !loaded || event.source !== frame.contentWindow || event.origin !== 'null' || event.ports.length !== 0) return;
    if (connected && envelope(event.data, 'activity', nonce)) {
      const now = Date.now(); if (now - lastActivity >= 1000) { lastActivity = now; onActivity(); } return;
    }
    if (connected && envelope(event.data, 'connected', nonce)) {
      clearTimeout(timer); resolveReady(transport); return;
    }
    if (connected || !envelope(event.data, 'ready', nonce)) return;
    connected = true;
    let channel; let stateChannel;
    try {
      channel = new hostWindow.MessageChannel();
      transport = createHostTransport({ ...transportOptions, port: channel.port1, compileOperation, origin,
        ...(getLaunchBearer === undefined ? {} : { getLaunchBearer }) });
      const ports = [channel.port2];
      if (stateStore) {
        stateChannel = new hostWindow.MessageChannel();
        stateTransport = createHostShopStateChannel({port:stateChannel.port1,store:stateStore});
        ports.push(stateChannel.port2);
      }
      frame.contentWindow.postMessage({ channel: CHANNEL, type: 'connect', nonce }, '*', ports);
    } catch { channel?.port1.close(); channel?.port2.close(); stateChannel?.port1.close(); stateChannel?.port2.close(); close(); }
  };
  const timer = setTimeout(() => { close(); }, timeoutMs);
  hostWindow.addEventListener('message', receive);
  hostWindow.addEventListener('pagehide', close);
  frame.addEventListener('load', onLoad);
  return Object.freeze({ ready, close });
}

export function connectShopFrame({ origin, frameWindow = globalThis.window, timeoutMs = 15000,
  transportOptions = {} }) {
  validOrigin(origin);
  if (frameWindow.parent === frameWindow) throw new TypeError('Shop bridge requires a child frame');
  const nonce = frameWindow.location.hash.slice(1);
  if (!validNonce(nonce)) throw new TypeError('Fresh frame nonce required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('Positive handshake timeout required');
  let closed = false; let transport; let state; let stateAbort; let resolveReady; let rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const close = () => {
    if (closed) return;
    closed = true; clearTimeout(timer);
    frameWindow.removeEventListener('message', receive);
    frameWindow.removeEventListener('pagehide', close);
    transport?.close(); stateAbort?.abort(); state?.close(); rejectReady(cancelled());
  };
  const receive = async event => {
    if (closed || transport || event.source !== frameWindow.parent || event.origin !== origin) return;
    if (event.ports.length === 0 && envelope(event.data, 'offer', nonce)) {
      try { frameWindow.parent.postMessage({ channel: CHANNEL, type: 'ready', nonce }, origin); } catch { close(); }
      return;
    }
    if (![1,2].includes(event.ports.length) || !envelope(event.data, 'connect', nonce)) return;
    try {
      transport = createFrameTransport({ ...transportOptions, port: event.ports[0] });
      if (event.ports[1]) {
        stateAbort = new AbortController();
        state = await connectFrameShopState({port:event.ports[1],timeoutMs,signal:stateAbort.signal});
      }
      if (closed) { state?.close(); return; }
      frameWindow.parent.postMessage({ channel: CHANNEL, type: 'connected', nonce }, origin);
      clearTimeout(timer); frameWindow.removeEventListener('message', receive); resolveReady(Object.freeze({...transport,...(state?{state}:{}),close,markActivity(){if(!closed)frameWindow.parent.postMessage({channel:CHANNEL,type:'activity',nonce},origin);}}));
    } catch { for (const port of event.ports) port.close(); close(); }
  };
  const timer = setTimeout(close, timeoutMs);
  frameWindow.addEventListener('message', receive);
  frameWindow.addEventListener('pagehide', close);
  try { frameWindow.parent.postMessage({ channel: CHANNEL, type: 'ready', nonce }, origin); } catch { close(); }
  return Object.freeze({ ready, close });
}
