'use strict';

const fs = require('node:fs');
const http = require('node:http');
const policyExecutor = require('./executor');
const { createPolicyRenderHttpHandler } = require('./http-handler');

const PORT = 8090;
const BWRAP = '/usr/bin/bwrap';

function packagedExecutable(filename, lstatSync) {
  try {
    const stat = lstatSync(filename);
    return stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 && stat.gid === 0
      && (stat.mode & 0o022) === 0 && (stat.mode & 0o111) !== 0;
  } catch { return false; }
}

function createPolicyOnlyListener({ env = process.env, lstatSync = fs.lstatSync,
  checkAssets = policyExecutor.checkAssets, strictProbe = policyExecutor.strictProbe,
  createExecutor = policyExecutor.createPolicyRenderExecutor,
  createHandler = createPolicyRenderHttpHandler, transportDrainMs = 1000,
  policyDrainMs = 5000 } = {}) {
  if (env.SECURESHOP_POLICY_RENDER_ENABLED !== 'true'
      || (env.SECURESHOP_POLICY_RENDER_MAX_CONCURRENT !== undefined
        && env.SECURESHOP_POLICY_RENDER_MAX_CONCURRENT !== '1')
      || !Number.isInteger(transportDrainMs) || transportDrainMs < 100 || transportDrainMs > 5000
      || !Number.isInteger(policyDrainMs) || policyDrainMs < 100 || policyDrainMs > 10000) {
    throw Object.assign(new Error('Dedicated policy renderer configuration unavailable'), { code: 'POLICY_RENDER_UNAVAILABLE' });
  }
  if (!packagedExecutable(BWRAP, lstatSync)
      || !packagedExecutable(policyExecutor.DEFAULT_SUPERVISOR, lstatSync)
      || !packagedExecutable(policyExecutor.DEFAULT_INIT, lstatSync)) {
    throw Object.assign(new Error('Packaged policy renderer helpers unavailable'), { code: 'POLICY_RENDER_UNAVAILABLE' });
  }
  try { checkAssets(); if (!strictProbe()) throw new Error('Strict namespace unavailable'); }
  catch { throw Object.assign(new Error('Strict policy renderer unavailable'), { code: 'POLICY_RENDER_UNAVAILABLE' }); }

  const handler = createHandler({ executor: createExecutor(), maxConcurrent: 1 });
  const respond = (res, status, body) => {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };
  const server = http.createServer(async (req, res) => {
    if (req.url === '/health') {
      if (req.method !== 'GET') return respond(res, 405, { error: 'METHOD_NOT_ALLOWED' });
      return respond(res, 200, { status: 'ok', policyRenderer: {
        enabled: true, available: true, isolation: policyExecutor.ISOLATION,
      } });
    }
    if (req.url !== '/secureshop/policy-render') return respond(res, 404, { error: 'NOT_FOUND' });
    try { await handler.handle(req, res); }
    catch { respond(res, 503, { error: 'POLICY_RENDER_UNAVAILABLE' }); }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.maxRequestsPerSocket = 32;
  let pendingClose;
  function close() {
    if (pendingClose) return pendingClose;
    pendingClose = (async () => {
      let drainError = null;
      let drainTimer;
      try {
        await Promise.race([handler.close(), new Promise((_, reject) => {
          drainTimer = setTimeout(() => reject(Object.assign(new Error('Policy renderer drain timed out'),
            { code: 'POLICY_RENDER_DRAIN_TIMEOUT' })), policyDrainMs);
        })]);
      } catch (error) { drainError = error; }
      finally { clearTimeout(drainTimer); }
      if (server.listening) {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => server.closeAllConnections(), transportDrainMs);
          timer.unref?.();
          server.close(error => { clearTimeout(timer); if (error) reject(error); else resolve(); });
          if (drainError) server.closeAllConnections();
        });
      }
      if (drainError) throw drainError;
    })();
    return pendingClose;
  }
  function listen(port = PORT, host = '0.0.0.0') {
    return new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, () => { server.off('error', reject); resolve(server.address()); });
    });
  }
  return Object.freeze({ server, listen, close });
}

if (require.main === module) {
  const listener = createPolicyOnlyListener();
  listener.listen().catch(() => { process.exitCode = 1; });
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
    listener.close().catch(() => { process.exitCode = 1; });
  });
}

module.exports = { createPolicyOnlyListener, packagedExecutable };
