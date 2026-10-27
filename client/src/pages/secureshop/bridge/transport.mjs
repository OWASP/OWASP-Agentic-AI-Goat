import { buildAccountAvatarFormData, buildAvatarTraversalFormData, buildAvatarUploadFormData, buildFileSummaryFormData, buildUploadFormData } from './uploads.mjs';
import { compileGuestRead, isGuestReadOperation } from './guestRead.mjs';

// Ports must be transferred only after the host verifies the expected frame,
// origin and launch generation. This transport does not perform that handshake.
const encoder = new TextEncoder();
const keysAre = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).every(key => allowed.includes(key));
const validId = id => Number.isSafeInteger(id) && id > 0;
const abortError = () => new DOMException('Shop request cancelled', 'AbortError');
const timeoutError = () => new DOMException('Shop request timed out', 'TimeoutError');
const protocolError = () => new Error('Invalid shop bridge response');

export function createHostTransport({ port, compileOperation, fetchImpl = globalThis.fetch,
  origin, getLaunchBearer, publicOnly = false, publicReadFallback = false, maxPending = 32, maxResponseBytes = 8 * 1024 * 1024,
  maxBodyBytes = 2 * 1024 * 1024, timeoutMs = 300000, onLaunchUnavailable }) {
  const base = new URL(origin);
  if (!['http:', 'https:'].includes(base.protocol) || base.origin !== origin) throw new TypeError('Trusted application origin required');
  if (typeof compileOperation !== 'function' || typeof fetchImpl !== 'function'
    || (publicOnly ? getLaunchBearer !== undefined : typeof getLaunchBearer !== 'function')
    || typeof publicReadFallback !== 'boolean'
    || (onLaunchUnavailable !== undefined && typeof onLaunchUnavailable !== 'function')) {
    throw new TypeError('Trusted bridge dependencies required');
  }
  for (const value of [maxPending, maxResponseBytes, maxBodyBytes, timeoutMs]) if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError('Positive bridge limits required');
  const pending = new Map();
  let closed = false; let lastId = 0;
  const send = (value, transfer = []) => {
    if (closed) return false;
    try { port.postMessage(value, transfer); return true; } catch { return false; }
  };
  async function execute(message) {
    const { id } = message;
    if (pending.size >= maxPending) { send({ type: 'error', id, code: 'BUSY' }); return; }
    const controller = new AbortController();
    const state = { controller, reader: null, credit: false, wake: null, timedOut: false };
    let completed = false;
    controller.signal.addEventListener('abort', () => state.wake?.(), { once: true });
    pending.set(id, state);
    const timer = setTimeout(() => { state.timedOut = true;controller.abort(); }, timeoutMs);
    try {
      const anonymousCatalogRead = publicReadFallback && message.shopBearer === undefined
        && isGuestReadOperation(message.operation);
      const request = anonymousCatalogRead
        ? compileGuestRead(message.operation, message.input)
        : compileOperation(message.operation, message.input);
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)
        || !['json', 'sse'].includes(request.responseKind)
        || typeof request.path !== 'string' || !request.path.startsWith('/api/secureshop/')) throw protocolError();
      const url = new URL(request.path, origin);
      if (url.origin !== origin || !url.pathname.startsWith('/api/secureshop/') || url.hash || url.username || url.password) throw protocolError();
      // The anonymous frame has no launch, persona or credential channel. Its
      // host transport accepts only the public, read-only catalog namespace.
      if ((publicOnly || anonymousCatalogRead) && (request.method !== 'GET'
        || !/^\/api\/secureshop\/public\/(?:products(?:\/[^/]+(?:\/(?:reviews|related))?)?|categories)$/.test(url.pathname)
        || message.shopBearer !== undefined || request.body !== undefined)) throw protocolError();
      const multipart = request.bodyKind === 'multipart';
      if (request.bodyKind !== undefined && !multipart) throw protocolError();
      if (multipart && (!['/api/secureshop/uploads','/api/secureshop/uploads/avatar','/api/secureshop/agents/customer/avatar-upload/path-traversal/run','/api/secureshop/agents/customer/avatar-upload/run','/api/secureshop/agents/customer/file-summary/run'].includes(request.path) || request.method !== 'POST')) throw protocolError();
      const body = multipart ? (request.path === '/api/secureshop/uploads/avatar'?buildAccountAvatarFormData(request.body):request.path.endsWith('/customer/avatar-upload/path-traversal/run')?buildAvatarTraversalFormData(request.body):request.path.endsWith('/customer/avatar-upload/run')?buildAvatarUploadFormData(request.body):request.path.endsWith('/customer/file-summary/run')?buildFileSummaryFormData(request.body):buildUploadFormData(request.body)) : request.body === undefined ? undefined : JSON.stringify(request.body);
      if (!multipart && body !== undefined && (request.method === 'GET' || encoder.encode(body).byteLength > maxBodyBytes)) throw protocolError();
      const headers = new Headers({ Accept: request.responseKind === 'sse' ? 'text/event-stream' : 'application/json' });
      if (!multipart && body !== undefined) headers.set('Content-Type', 'application/json');
      if (message.shopBearer !== undefined) {
        if (typeof message.shopBearer !== 'string' || message.shopBearer.length > 8192 || /[\r\n]/.test(message.shopBearer)) throw protocolError();
        headers.set('Authorization', `Bearer ${message.shopBearer}`);
      }
      const launch = publicOnly || anonymousCatalogRead ? null : getLaunchBearer();
      if (launch !== null) {
        if (typeof launch !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(launch)) throw protocolError();
        headers.set('X-DVAIA-SecureShop-Launch', launch);
      }
      const response = await fetchImpl(url.href, { method: request.method, headers, body,
        credentials: 'omit', redirect: 'error', signal: controller.signal });
      if (controller.signal.aborted || closed) throw abortError();
      if (launch !== null && response.status === 401
        && response.headers.get('x-dvaia-secureshop-launch-state') === 'unavailable') {
        onLaunchUnavailable?.(launch);
        if (controller.signal.aborted || closed) throw abortError();
      }
      const contentType = response.headers.get('content-type') || '';
      const mime = contentType.split(';')[0].trim().toLowerCase();
      if (![204, 205, 304].includes(response.status)
        && mime !== (response.ok && request.responseKind === 'sse' ? 'text/event-stream' : 'application/json')) throw protocolError();
      if (!send({ type: 'start', id, status: response.status, contentType })) throw protocolError();
      let seq = 0; let bytes = 0;
      if (response.body) {
        state.reader = response.body.getReader();
        while (true) {
          if (!state.credit) await new Promise(resolve => { state.wake = resolve; });
          state.wake = null;
          if (controller.signal.aborted || closed) throw abortError();
          state.credit = false;
          const { done, value } = await state.reader.read();
          if (controller.signal.aborted || closed) throw abortError();
          if (done) break;
          bytes += value.byteLength;
          if (bytes > maxResponseBytes) throw protocolError();
          const chunk = value.slice().buffer;
          if (!send({ type: 'chunk', id, seq: seq++, chunk }, [chunk])) throw protocolError();
        }
      }
      if (!send({ type: 'end', id, seq })) throw protocolError();
      completed = true;
    } catch {
      send({ type: 'error', id, code: state.timedOut ? 'TIMEOUT' : controller.signal.aborted ? 'CANCELLED' : 'REQUEST_FAILED' });
    } finally {
      clearTimeout(timer);
      if (!completed) {
        controller.abort();
        if (state.reader) { try { await state.reader.cancel(); } catch {} }
      } else if (state.reader) {
        try { state.reader.releaseLock(); } catch {}
      }
      pending.delete(id);
    }
  }
  const listener = event => {
    if (closed) return;
    const message = event.data;
    if (message?.type === 'pull' && keysAre(message, ['type', 'id']) && validId(message.id)) {
      const request = pending.get(message.id);
      if (request && !request.credit) { request.credit = true; request.wake?.(); }
      return;
    }
    if (message?.type === 'cancel' && keysAre(message, ['type', 'id']) && validId(message.id)) {
      const request = pending.get(message.id);
      request?.controller.abort();
      if (request?.reader) request.reader.cancel().catch(() => {});
      return;
    }
    if (!keysAre(message, ['type', 'id', 'operation', 'input', 'shopBearer']) || message.type !== 'request'
      || !validId(message.id) || typeof message.operation !== 'string') return;
    if (message.id <= lastId) return; // replay cannot overwrite or cancel the original request
    lastId = message.id;
    void execute(message);
  };
  port.addEventListener('message', listener); port.start();
  return Object.freeze({ close() {
    if (closed) return;
    send({ type: 'shutdown' });
    closed = true;
    port.removeEventListener('message', listener);
    for (const request of pending.values()) {
      request.controller.abort();
      if (request.reader) request.reader.cancel().catch(() => {});
    }
    port.close();
  } });
}

export function createFrameTransport({ port, timeoutMs = 300000 }) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new TypeError('Positive bridge timeout required');
  let nextId = 0; let closed = false;
  const pending = new Map();
  const send = value => {
    if (closed) return false;
    try { port.postMessage(value); return true; } catch { return false; }
  };
  const finish = (id, error) => {
    const state = pending.get(id); if (!state) return;
    pending.delete(id); clearTimeout(state.timer);
    state.signal?.removeEventListener('abort', state.abort);
    if (error) {
      try { state.controller?.error(error); } catch {}
      state.reject(error);
    } else {
      try { state.controller?.close(); } catch {}
    }
  };
  const listener = event => {
    const message = event.data;
    if (message?.type === 'shutdown' && keysAre(message, ['type'])) {
      closed = true;
      for (const id of [...pending.keys()]) finish(id, abortError());
      port.removeEventListener('message', listener); port.close(); return;
    }
    if (!message || !validId(message.id)) return;
    const state = pending.get(message.id); if (!state) return;
    try {
      if (message.type === 'start' && keysAre(message, ['type', 'id', 'status', 'contentType']) && !state.started) {
        if (!Number.isInteger(message.status) || message.status < 200 || message.status > 599 || typeof message.contentType !== 'string') throw protocolError();
        state.started = true;
        const stream = new ReadableStream({ start(controller) { state.controller = controller; },
          pull() {
            if (!state.creditPending) {
              state.creditPending = true;
              if (!send({ type: 'pull', id: message.id })) finish(message.id, protocolError());
            }
          },
          cancel() { send({ type: 'cancel', id: message.id }); finish(message.id, abortError()); } });
        const noBody = [204, 205, 304].includes(message.status);
        const response = new Response(noBody ? null : stream, { status: message.status, headers: { 'content-type': message.contentType } });
        state.resolve(response);
      } else if (message.type === 'chunk' && keysAre(message, ['type', 'id', 'seq', 'chunk']) && state.started && message.seq === state.seq && message.chunk instanceof ArrayBuffer) {
        state.seq++; state.creditPending = false; state.controller.enqueue(new Uint8Array(message.chunk));
      } else if (message.type === 'end' && keysAre(message, ['type', 'id', 'seq']) && state.started && message.seq === state.seq) {
        finish(message.id);
      } else if (message.type === 'error' && keysAre(message, ['type', 'id', 'code'])) {
        finish(message.id, message.code === 'TIMEOUT' ? timeoutError() : message.code === 'CANCELLED' ? abortError() : new Error('Shop request failed'));
      } else throw protocolError();
    } catch (error) {
      send({ type: 'cancel', id: message.id }); finish(message.id, error);
    }
  };
  port.addEventListener('message', listener); port.start();
  return Object.freeze({
    request(operation, input = {}, { shopBearer, signal } = {}) {
      if (closed || signal?.aborted) return Promise.reject(abortError());
      const id = ++nextId;
      return new Promise((resolve, reject) => {
        const abort = () => { send({ type: 'cancel', id }); finish(id, abortError()); };
        const state = { resolve, reject, signal, abort, started: false, seq: 0, timer: setTimeout(() => { send({ type: 'cancel', id });finish(id, timeoutError()); }, timeoutMs) };
        pending.set(id, state); signal?.addEventListener('abort', abort, { once: true });
        if (!send({ type: 'request', id, operation, input, ...(shopBearer === undefined ? {} : { shopBearer }) })) {
          finish(id, protocolError());
        }
      });
    },
    close() {
      if (closed) return;
      for (const id of [...pending.keys()]) { send({ type: 'cancel', id }); finish(id, abortError()); }
      closed = true;
      port.removeEventListener('message', listener); port.close();
    },
  });
}
