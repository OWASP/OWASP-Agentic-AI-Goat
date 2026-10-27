'use strict';
const http = require('node:http');
const { createOwnedPricingHttpExecutor } = require('./executor');
const { createPricingHttpHandler } = require('./http-handler');
const failure = code => Object.assign(new Error(code), { code });
const HOSTS = new Set(['127.0.0.1', '::1', '0.0.0.0', '::']);
const CLOSE_TIMEOUT_MS = 20000;
// Private startup diagnostics are versioned, opt-in, and never contain error
// messages, paths, command output, tokens, or stacks. They do not alter status.
const STARTUP_CODES = new Set(['HTTP_ASSET_UNTRUSTED','HTTP_ASSET_CHANGED','HTTP_ASSET_REGISTRY_INVALID',
  'HTTP_PLATFORM_UNAVAILABLE','HTTP_PROFILE_UNAVAILABLE','HTTP_SUPERVISOR_CAPABILITIES','HTTP_REQUEST_INVALID',
  'HTTP_OPERATION_ABORTED','HTTP_EXECUTION_TIMEOUT','HTTP_OUTPUT_LIMIT','HTTP_INPUT_FAILURE','HTTP_CHILD_FAILED',
  'HTTP_NAMESPACE_UNAVAILABLE','EACCES','ENOENT','EPERM','PRICING_LISTENER_DISABLED','PRICING_LISTENER_BIND_INVALID',
  'PRICING_LISTENER_CONFIG_INVALID','PRICING_LISTENER_CLOSED','PRICING_LISTENER_BIND_FAILED','PRICING_LISTENER_NOT_READY',
  'PRICING_LISTENER_DRAIN_TIMEOUT','PRICING_LISTENER_DRAIN_FAILED']);
const startupCauses = new WeakMap();
function startupDiagnostic(error) {
  if(error&&startupCauses.has(error))return startupCauses.get(error);
  const code=STARTUP_CODES.has(error?.code)?error.code:'UNKNOWN';
  return Object.freeze({version:1,code,childExit:code==='HTTP_CHILD_FAILED'&&Number.isInteger(error.exitCode)&&error.exitCode>=0&&error.exitCode<=255?error.exitCode:null});
}

// Separate opt-in service, never imported by the main sandbox entrypoint.
function createPricingHttpListener({ enabled, token, host, port, executor, expectedProfile,
  maxConcurrent = 2, bodyTimeoutMs = 3000, readinessTimeoutMs = 15000, closeTimeoutMs = CLOSE_TIMEOUT_MS } = {}) {
  if (enabled !== true) throw failure('PRICING_LISTENER_DISABLED');
  if (!HOSTS.has(host) || !Number.isInteger(port) || port < 0 || port > 65535)
    throw failure('PRICING_LISTENER_BIND_INVALID');
  // Validate all trusted configuration before constructing the native executor.
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43,128}$/.test(token)
      || !Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 16
      || !Number.isInteger(bodyTimeoutMs) || bodyTimeoutMs < 100 || bodyTimeoutMs > 10000
      || !Number.isInteger(readinessTimeoutMs) || readinessTimeoutMs < 10 || readinessTimeoutMs > 15000
      || !Number.isInteger(closeTimeoutMs) || closeTimeoutMs < 10 || closeTimeoutMs > CLOSE_TIMEOUT_MS)
    throw failure('PRICING_LISTENER_CONFIG_INVALID');
  const worker = executor || createOwnedPricingHttpExecutor({expectedProfile});
  if (typeof worker.assertReady !== 'function' || typeof worker.execute !== 'function' || typeof worker.checkReadiness !== 'function')
    throw failure('PRICING_LISTENER_CONFIG_INVALID');
  const handler = createPricingHttpHandler({ enabled: true, token, executor: worker, maxConcurrent, bodyTimeoutMs });
  let state = 'new', startPromise, closePromise, readyWork;
  const startupAbort=new AbortController();
  const sockets = new Set();
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 20000,
    headersTimeout: 5000, keepAliveTimeout: 1000, connectionsCheckingInterval: 1000 }, (req, res) => {
    const reject = (status, code) => {
      if (res.destroyed || res.writableEnded) return;
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', connection: 'close' });
      res.end(JSON.stringify({ error: code }));
    };
    if (req.rawHeaders.length > 64) { reject(431, 'PRICING_HEADERS_TOO_LARGE'); return; }
    if (state !== 'listening') { reject(503, 'PRICING_LISTENER_CLOSING'); return; }
    handler.handle(req, res).then(handled => {
      if (!handled) reject(404, 'PRICING_NOT_FOUND');
    }, () => reject(503, 'PRICING_UNAVAILABLE'));
  });
  // Keep raw headers intact for the explicit closed count check above; the
  // parser still enforces the8KiB byte ceiling. Truncation could hide duplicates.
  server.maxHeadersCount = 0;
  server.maxConnections = 64;
  server.maxRequestsPerSocket = 100;
  server.setTimeout(20000, socket => socket.destroy());
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.on('clientError', (_error, socket) => {
    if (!socket.destroyed) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  // Bind errors are consumed by start(). No raw OS errors reach service logs.
  server.on('error', () => {});
  function start() {
    if (state === 'starting' || state === 'listening') return startPromise;
    if (state !== 'new') return Promise.reject(failure('PRICING_LISTENER_CLOSED'));
    state = 'starting';
    startPromise = (async () => {
      try {
        let readyTimer;
        try {
          readyWork=Promise.resolve().then(()=>worker.assertReady({signal:startupAbort.signal}).then(value=>{if(value?.ready!==true)throw failure('PRICING_LISTENER_NOT_READY');return value;}));
          await Promise.race([readyWork,new Promise((_,reject)=>{
            readyTimer=setTimeout(()=>{startupAbort.abort();reject(failure('PRICING_LISTENER_NOT_READY'));},readinessTimeoutMs);
          })]);
        } finally { clearTimeout(readyTimer); }
        if(state!=='starting')throw failure('PRICING_LISTENER_CLOSED');
        await new Promise((resolve, reject) => {
          const error = () => { server.off('listening', listening); reject(failure('PRICING_LISTENER_BIND_FAILED')); };
          const listening = () => { server.off('error', error); resolve(); };
          server.once('error', error); server.once('listening', listening); server.listen(port, host);
        });
        if (state !== 'starting') throw failure('PRICING_LISTENER_CLOSED');
        state = 'listening';
        return Object.freeze({ ...server.address() });
      } catch (error) {
        if (state === 'starting') state = 'failed';
        if (['PRICING_LISTENER_BIND_FAILED', 'PRICING_LISTENER_CLOSED'].includes(error.code)) throw error;
        const unavailable=failure('PRICING_LISTENER_NOT_READY');
        startupCauses.set(unavailable,startupDiagnostic(error));
        throw unavailable;
      }
    })();
    return startPromise;
  }
  function close() {
    if (closePromise) return closePromise;
    state = 'closing';
    startupAbort.abort();
    closePromise = (async () => {
      let timer, drainError;
      try {
        await Promise.race([Promise.all([handler.close(),startPromise?.catch(()=>{}),readyWork?.catch(()=>{})]), new Promise((_, reject) => {
          timer = setTimeout(() => reject(failure('PRICING_LISTENER_DRAIN_TIMEOUT')), closeTimeoutMs);
        })]);
      } catch { drainError = failure('PRICING_LISTENER_DRAIN_FAILED'); }
      finally { clearTimeout(timer); }
      // A closing state prevents a delayed readiness result from starting a listener.
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

async function runPricingHttpListener({ env = process.env, signals = process,
  createListener = createPricingHttpListener, write = text => process.stdout.write(text) } = {}) {
  let listener, closePromise, signalObserved;
  const signaled = new Promise(resolve => { signalObserved = resolve; });
  const stop = () => { if (!closePromise) closePromise = listener.close(); return closePromise; };
  const onSignal = () => { stop().catch(() => {}); signalObserved(); };
  try {
    if (env.SECURESHOP_PRICING_ENABLED !== 'true') throw failure('PRICING_LISTENER_DISABLED');
    const text = env.SECURESHOP_PRICING_PORT;
    if (typeof text !== 'string' || !/^[1-9][0-9]{0,4}$/.test(text)) throw failure('PRICING_LISTENER_BIND_INVALID');
    listener = createListener({ enabled: true, token: env.SECURESHOP_PRICING_TOKEN,
      host: env.SECURESHOP_PRICING_HOST, port: Number(text), expectedProfile: env.SECURESHOP_PRICING_PROFILE });
    signals.on('SIGTERM', onSignal); signals.on('SIGINT', onSignal);
    await listener.start();
    write('PRICING_LISTENER_READY\n');
    await signaled;
    await closePromise;
    write('PRICING_LISTENER_CLOSED\n');
    return 0;
  } catch (error) {
    if (listener) { try { await stop(); } catch {} }
    if(env.SECURESHOP_PRICING_DIAGNOSTICS==='startup-v1')write('PRICING_STARTUP_DIAGNOSTIC_V1:'+JSON.stringify(startupDiagnostic(error))+'\n');
    write('PRICING_LISTENER_FAILED\n');
    return 1;
  } finally {
    signals.off('SIGTERM', onSignal); signals.off('SIGINT', onSignal);
  }
}
if (require.main === module) runPricingHttpListener().then(code => { process.exitCode = code; }, () => { process.exitCode = 1; });
module.exports = { createPricingHttpListener, runPricingHttpListener };
