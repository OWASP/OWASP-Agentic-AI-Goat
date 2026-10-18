const DEFAULT_RETRY_MS = 1000;
const MAX_FRAME_BUFFER_BYTES = 256 * 1024;

function eventFrame(raw) {
  let type = 'message';
  let lastEventId = '';
  const data = [];
  for (const line of raw.split(/\r?\n/)) {
    if (!line || line.startsWith(':')) continue;
    const colon = line.indexOf(':');
    const field = colon < 0 ? line : line.slice(0, colon);
    let value = colon < 0 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) value = value.slice(1);
    if (field === 'event') type = value || 'message';
    else if (field === 'data') data.push(value);
    else if (field === 'id' && !value.includes('\0')) lastEventId = value;
  }
  return data.length ? { type, data: data.join('\n'), lastEventId } : null;
}

function authenticatedToken(getToken) {
  const token = getToken();
  if (typeof token !== 'string' || !token.trim() || /[\r\n]/.test(token)) {
    throw new Error('Authenticated event token unavailable');
  }
  return token;
}

function authenticatedStreamUrl(value) {
  let base;
  let resolved;
  try {
    base = new URL(globalThis.location.href);
    resolved = new URL(value, base);
  } catch {
    throw new TypeError('Invalid authenticated SSE configuration');
  }
  if (typeof value !== 'string' || !/^\/(?![\\/])/.test(value)
    || /[\\\u0000-\u001f\u007f]/.test(value)
    || !['http:', 'https:'].includes(base.protocol)
    || resolved.origin !== base.origin || resolved.username || resolved.password
    || resolved.search || resolved.hash) {
    throw new TypeError('Invalid authenticated SSE configuration');
  }
  return `${resolved.pathname}`;
}

export function connectAuthenticatedSse({
  url,
  getToken,
  onOpen = () => {},
  onError = () => {},
  onEvent = () => {},
  fetchImpl = globalThis.fetch,
  scheduler = {
    setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
    clearTimeout: timer => globalThis.clearTimeout(timer),
  },
  retryMs = DEFAULT_RETRY_MS,
} = {}) {
  if (typeof getToken !== 'function' || typeof fetchImpl !== 'function'
    || typeof onOpen !== 'function' || typeof onError !== 'function' || typeof onEvent !== 'function'
    || typeof scheduler?.setTimeout !== 'function' || typeof scheduler?.clearTimeout !== 'function'
    || !Number.isInteger(retryMs) || retryMs < 10 || retryMs > 60000) {
    throw new TypeError('Invalid authenticated SSE configuration');
  }
  const requestUrl = authenticatedStreamUrl(url);

  let closed = false;
  let timer = null;
  let controller = null;
  let reader = null;
  let retryDelay = retryMs;

  const schedule = () => {
    if (closed || timer !== null) return;
    const delay = retryDelay;
    retryDelay = Math.min(30000, retryDelay * 2);
    timer = scheduler.setTimeout(() => {
      timer = null;
      void connect();
    }, delay);
  };

  const connect = async () => {
    if (closed) return;
    controller = new AbortController();
    const decoder = new TextDecoder();
    try {
      const token = authenticatedToken(getToken);
      const response = await fetchImpl(requestUrl, {
        method: 'GET',
        headers: { Accept: 'text/event-stream', Authorization: `Bearer ${token}` },
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        signal: controller.signal,
      });
      if (closed) return;
      const contentType = response?.headers?.get?.('content-type')?.split(';', 1)[0].trim().toLowerCase();
      if (!response?.ok || contentType !== 'text/event-stream' || !response.body?.getReader) {
        try { await response?.body?.cancel?.(); } catch {}
        throw new Error('Authenticated event stream unavailable');
      }
      reader = response.body.getReader();
      retryDelay = retryMs;
      onOpen();
      let buffer = '';
      while (!closed) {
        const packet = await reader.read();
        if (closed) return;
        if (packet.done) throw new Error('Authenticated event stream ended');
        buffer += decoder.decode(packet.value, { stream: true });
        if (new TextEncoder().encode(buffer).byteLength > MAX_FRAME_BUFFER_BYTES) {
          throw new Error('Authenticated event frame is too large');
        }
        let boundary;
        while ((boundary = buffer.search(/\r?\n\r?\n/)) >= 0) {
          const match = buffer.slice(boundary).match(/^\r?\n\r?\n/)[0];
          const raw = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + match.length);
          const event = eventFrame(raw);
          if (event && !closed) onEvent(event);
        }
      }
    } catch (error) {
      if (!closed && error?.name !== 'AbortError') onError(error);
    } finally {
      const currentReader = reader;
      reader = null;
      controller = null;
      if (currentReader) {
        try { await currentReader.cancel(); } catch {}
      }
      schedule();
    }
  };

  void connect();
  return Object.freeze({
    close() {
      if (closed) return;
      closed = true;
      if (timer !== null) scheduler.clearTimeout(timer);
      timer = null;
      controller?.abort();
      try { void reader?.cancel().catch(() => {}); } catch {}
      reader = null;
    },
  });
}

export { DEFAULT_RETRY_MS, MAX_FRAME_BUFFER_BYTES };
