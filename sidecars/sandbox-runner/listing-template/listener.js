'use strict';

const fs = require('node:fs');
const http = require('node:http');
const strict = require('./strict-helpers');
const templateExecutor = require('./executor');
const { createListingTemplateHttpHandler } = require('./http-handler');
const { ISOLATION } = require('../../../server/services/secureshopListingTemplateExecutorContract');

const PORT = 8090;
function packagedExecutable(filename, lstatSync) {
  try {
    const stat = lstatSync(filename);
    return stat.isFile() && !stat.isSymbolicLink() && stat.uid === 0 && stat.gid === 0
      && (stat.mode & 0o022) === 0 && (stat.mode & 0o111) !== 0;
  } catch { return false; }
}
function createListingTemplateOnlyListener({ env = process.env, lstatSync = fs.lstatSync,
  checkAssets = templateExecutor.checkedAssets, strictProbe = strict.strictProbe,
  createExecutor = templateExecutor.createListingTemplateExecutor,
  createHandler = createListingTemplateHttpHandler, transportDrainMs = 1000, executionDrainMs = 5000 } = {}) {
  if (env.SECURESHOP_LISTING_TEMPLATE_ENABLED !== 'true'
      || (env.SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT !== undefined
        && env.SECURESHOP_LISTING_TEMPLATE_MAX_CONCURRENT !== '1')
      || !Number.isInteger(transportDrainMs) || transportDrainMs < 100 || transportDrainMs > 5000
      || !Number.isInteger(executionDrainMs) || executionDrainMs < 100 || executionDrainMs > 10000) {
    throw Object.assign(new Error('Dedicated template executor unavailable'), { code: 'LISTING_TEMPLATE_UNAVAILABLE' });
  }
  if (!packagedExecutable('/usr/bin/bwrap', lstatSync)
      || !packagedExecutable(strict.DEFAULT_SUPERVISOR, lstatSync)
      || !packagedExecutable(strict.DEFAULT_INIT, lstatSync)) {
    throw Object.assign(new Error('Packaged template helpers unavailable'), { code: 'LISTING_TEMPLATE_UNAVAILABLE' });
  }
  try { checkAssets(); if (!strictProbe()) throw new Error('Strict namespace unavailable'); }
  catch { throw Object.assign(new Error('Strict template executor unavailable'), { code: 'LISTING_TEMPLATE_UNAVAILABLE' }); }
  const handler = createHandler({ executor: createExecutor() });
  const respond = (res, status, body) => {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
  };
  const server = http.createServer(async (req, res) => {
    if (req.url === '/health') {
      if (req.method !== 'GET') return respond(res, 405, { error: 'METHOD_NOT_ALLOWED' });
      return respond(res, 200, { status: 'ok', listingTemplate: { enabled: true, available: true, isolation: ISOLATION } });
    }
    if (req.url !== '/secureshop/listing-template-render') return respond(res, 404, { error: 'NOT_FOUND' });
    try { await handler.handle(req, res); }
    catch { respond(res, 503, { error: 'LISTING_TEMPLATE_UNAVAILABLE' }); }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  server.maxRequestsPerSocket = 32;
  let pendingClose;
  function close() {
    if (pendingClose) return pendingClose;
    pendingClose = (async () => {
      let drainError = null, drainTimer;
      try {
        await Promise.race([handler.close(), new Promise((_, reject) => {
          drainTimer = setTimeout(() => reject(Object.assign(new Error('Template executor drain timed out'),
            { code: 'LISTING_TEMPLATE_DRAIN_TIMEOUT' })), executionDrainMs);
        })]);
      } catch (error) { drainError = error; }
      finally { clearTimeout(drainTimer); }
      if (server.listening) await new Promise((resolve, reject) => {
        const timer = setTimeout(() => server.closeAllConnections(), transportDrainMs);
        timer.unref?.();
        server.close(error => { clearTimeout(timer); if (error) reject(error); else resolve(); });
        if (drainError) server.closeAllConnections();
      });
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
  const listener = createListingTemplateOnlyListener();
  listener.listen().catch(() => { process.exitCode = 1; });
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => {
    listener.close().catch(() => { process.exitCode = 1; });
  });
}
module.exports = { createListingTemplateOnlyListener, packagedExecutable };
