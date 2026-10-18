'use strict';
const http = require('node:http');
const { createSystemConfigExecutor } = require('./executor');
const { createSystemConfigHttpHandler } = require('./http-handler');
const failure = code => Object.assign(new Error(code), { code });
const HOSTS = new Set(['127.0.0.1', '::1', '0.0.0.0', '::']);
const CLOSE_TIMEOUT_MS = 20000;

// Separate opt-in service, never imported by the main sandbox entrypoint.
function createSystemConfigHttpListener({ enabled, token, host, port, executor,
  maxConcurrent = 2, bodyTimeoutMs = 3000 } = {}) {
  if (enabled !== true) throw failure('SYSTEM_LISTENER_DISABLED');
  if (!HOSTS.has(host) || !Number.isInteger(port) || port < 0 || port > 65535)
    throw failure('SYSTEM_LISTENER_BIND_INVALID');
  // Validate all trusted configuration before constructing the native executor.
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)
      || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16
      || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 10000)
    throw failure('SYSTEM_LISTENER_CONFIG_INVALID');
  const worker = executor || createSystemConfigExecutor();
  if (typeof worker.assertReady !== 'function' || typeof worker.read !== 'function')
    throw failure('SYSTEM_LISTENER_CONFIG_INVALID');
  const handler = createSystemConfigHttpHandler({ enabled: true, token, executor: worker, maxConcurrent, bodyTimeoutMs });
  let state = 'new', startPromise, closePromise;
  const sockets = new Set();
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 15000,
    headersTimeout: 5000, keepAliveTimeout: 1000, connectionsCheckingInterval: 1000 }, (req, res) => {
    const reject = (status, code) => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' });
      res.end(JSON.stringify({ error: code }));
    };
    if (req.rawHeaders.length > 64) { reject(431, 'SYSTEM_HEADERS_TOO_LARGE'); return; }
    if (state !== 'listening') { reject(503, 'SYSTEM_LISTENER_CLOSING'); return; }
    handler.handle(req, res).then(handled => {
      if (!handled) reject(404, 'SYSTEM_NOT_FOUND');
    }, () => reject(503, 'SYSTEM_CONFIG_UNAVAILABLE'));
  });
  // Keep raw headers intact for the explicit closed count check above; the
  // parser still enforces the8KiB byte ceiling. Truncation could hide duplicates.
  server.maxHeadersCount = 0;
  server.maxConnections = 64;
  server.maxRequestsPerSocket = 100;
  server.setTimeout(15000, socket => socket.destroy());
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('clientError', (_error, socket) => {
    if (!socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  // Bind errors are consumed by start(). No raw OS errors reach service logs.
  server.on('error', () => {});
  function start() {
    if (state === 'starting' || state === 'listening') return startPromise;
    if (state !== 'new') return Promise.reject(failure('SYSTEM_LISTENER_CLOSED'));
    state = 'starting';
    startPromise = (async () => {
      try {
        const readiness = worker.assertReady();
        if (readiness && typeof readiness.then === 'function') {
          Promise.resolve(readiness).catch(() => {});
          throw failure('SYSTEM_LISTENER_NOT_READY');
        }
        await new Promise((resolve, reject) => {
          const error = () => { server.off('listening', listening); reject(failure('SYSTEM_LISTENER_BIND_FAILED')); };
          const listening = () => { server.off('error', error); resolve(); };
          server.once('error', error); server.once('listening', listening); server.listen(port, host);
        });
        if (state !== 'starting') throw failure('SYSTEM_LISTENER_CLOSED');
        state = 'listening';
        return Object.freeze({ ...server.address() });
      } catch (error) {
        if (state === 'starting') state = 'failed';
        if (['SYSTEM_LISTENER_BIND_FAILED', 'SYSTEM_LISTENER_CLOSED'].includes(error.code)) throw error;
        throw failure('SYSTEM_LISTENER_NOT_READY');
      }
    })();
    return startPromise;
  }
  function close() {
    if (closePromise) return closePromise;
    state = 'closing';
    closePromise = (async () => {
      let timer, drainError;
      try {
        await Promise.race([handler.close(), new Promise((_, reject) => {
          timer = setTimeout(() => reject(failure('SYSTEM_LISTENER_DRAIN_TIMEOUT')), CLOSE_TIMEOUT_MS);
        })]);
      } catch { drainError = failure('SYSTEM_LISTENER_DRAIN_FAILED'); }
      finally { clearTimeout(timer); }
      // Settle a racing listen before final socket/listener cleanup.
      if (startPromise) await startPromise.catch(() => {});
      const closed = new Promise(resolve => server.close(() => resolve()));
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections();
      await closed;
      state = 'closed';
      if (drainError) throw drainError;
    })();
    return closePromise;
  }
  return Object.freeze({ start, close, address: () => state === 'listening' ? Object.freeze({ ...server.address() }) : null });
}

async function runSystemConfigListener({ env = process.env, signals = process,
  createListener = createSystemConfigHttpListener, write = text => process.stdout.write(text) } = {}) {
  let listener, closePromise, signalObserved;
  const signaled = new Promise(resolve => { signalObserved = resolve; });
  const stop = () => { if (!closePromise) closePromise = listener.close(); return closePromise; };
  const onSignal = () => { stop().catch(() => {}); signalObserved(); };
  try {
    if (env.SECURESHOP_SYSTEM_CONFIG_HTTP_ENABLED !== 'true') throw failure('SYSTEM_LISTENER_DISABLED');
    const text = env.SECURESHOP_SYSTEM_CONFIG_PORT;
    if (typeof text !== 'string' || !/^[1-9][0-9]{0,4}$/.test(text)) throw failure('SYSTEM_LISTENER_BIND_INVALID');
    listener = createListener({ enabled: true, token: env.SECURESHOP_SYSTEM_CONFIG_TOKEN,
      host: env.SECURESHOP_SYSTEM_CONFIG_HOST, port: Number(text) });
    signals.on('SIGTERM', onSignal); signals.on('SIGINT', onSignal);
    await listener.start();
    write('SYSTEM_LISTENER_READY\n');
    await signaled;
    await closePromise;
    write('SYSTEM_LISTENER_CLOSED\n');
    return 0;
  } catch {
    if (listener) { try { await stop(); } catch {} }
    write('SYSTEM_LISTENER_FAILED\n');
    return 1;
  } finally {
    signals.off('SIGTERM', onSignal); signals.off('SIGINT', onSignal);
  }
}
if (require.main === module) runSystemConfigListener().then(code => { process.exitCode = code; }, () => { process.exitCode = 1; });
module.exports = { createSystemConfigHttpListener, runSystemConfigListener };
