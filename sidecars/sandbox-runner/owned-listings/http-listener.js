'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const { createListingOperationExecutor } = require('./operation-executor');
const { createOwnedListingsExecutor } = require('./namespace-executor');
async function createListingListener({ token, directory, mode, identity, namespace, host = '127.0.0.1', port = 0 }) {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(token || '') || !namespace?.checkReadiness || !namespace?.execute) throw TypeError('Private listener configuration required');
  const ready = await namespace.checkReadiness();
  if (!ready.ready) throw Error('Listings unavailable');
  const runtimeIdentity = crypto.createHash('sha256').update(JSON.stringify({ identity, runtimeDigest: ready.runtimeDigest })).digest('hex');
  const executor = await createListingOperationExecutor({ directory, mode, identity: runtimeIdentity,
    executeImport: ({ request, mode, signal }) => namespace.execute({ request, mode }, { signal }) });
  let accepting = true; const pending = new Set();
  const send = (res, status, value) => { if (!res.destroyed) { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(value)); } };
  async function handle(req, res) {
    const supplied = Buffer.from(req.headers.authorization || ''), expected = Buffer.from('Bearer ' + token);
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return send(res, 401, { error: 'UNAUTHORIZED' });
    if (!accepting) return send(res, 503, { error: 'CLOSING' });
    if (req.method === 'GET' && req.url === '/health') {
      const current = await namespace.checkReadiness();
      if (current.ready !== true || current.runtimeDigest !== ready.runtimeDigest) return send(res, 503, { error: 'NOT_READY' });
      return send(res, 200, { version: 1, ready: true, identity: runtimeIdentity, runtimeDigest: current.runtimeDigest, mode, isolation: 'owned-listings.v1' });
    }
    const retireMatch = /^\/operations\/([0-9a-f-]{36})\/retire$/.exec(req.url);
    if (req.method === 'POST' && retireMatch) {
      let bytes = '';
      for await (const chunk of req) { bytes += chunk; if (Buffer.byteLength(bytes) > 64) return send(res, 413, { error: 'LIMIT' }); }
      const body = JSON.parse(bytes);
      if (!body || Array.isArray(body) || Object.keys(body).length) return send(res, 400, { error: 'INVALID_BODY' });
      const result = await executor.retire(retireMatch[1]);
      return send(res, result ? 200 : 404, result || { error: 'NOT_FOUND' });
    }
    const match = /^\/operations\/([0-9a-f-]{36})$/.exec(req.url);
    if (req.method === 'GET' && match) { const receipt = await executor.get(match[1]); return send(res, receipt ? 200 : 404, receipt || { error: 'NOT_FOUND' }); }
    if (req.method !== 'POST' || req.url !== '/operations') return send(res, 404, { error: 'NOT_FOUND' });
    let size = 0; const chunks = [];
    for await (const chunk of req) { size += chunk.length; if (size > 16384) { send(res, 413, { error: 'LIMIT' }); req.destroy(); return; } chunks.push(chunk); }
    const request = JSON.parse(Buffer.concat(chunks));
    // Response disconnect never cancels a durable operation; GET reconciles it.
    const result = await executor.execute(request);
    send(res, 200, result);
  }
  function dispatch(req,res) {
    const promise = handle(req, res).catch(error => send(res, error.code === 'LISTING_OPERATION_CONFLICT' ? 409 : error.code === 'LISTING_EXECUTOR_BUSY' ? 429 : 400, { error: 'LISTINGS_REQUEST_FAILED' }));
    pending.add(promise); promise.finally(() => pending.delete(promise));return promise;
  }
  const server = http.createServer({ headersTimeout: 5000, requestTimeout: 20000, maxHeaderSize: 8192 },dispatch);
  server.maxConnections = 16;
  return { handle:dispatch,async retireAll(){
      accepting=false;await Promise.allSettled([...pending]);
      const files=await require('node:fs/promises').readdir(directory),ids=new Set(files.map(file=>/^([0-9a-f-]{36})\.(?:admission|receipt|retired)\.json$/.exec(file)?.[1]).filter(Boolean)),tombstones=[];
      for(const id of [...ids].sort()){const receipt=await executor.retire(id);if(receipt)tombstones.push(receipt);}
      return tombstones;
    }, async start() { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); }); return server.address(); },
    async close() { accepting = false; await Promise.allSettled([...pending]); await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); } };
}
async function main() {
  const env = process.env;
  if (env.LISTINGS_ENABLED !== 'true' || !/^[a-f0-9]{64}$/.test(env.LISTINGS_IDENTITY || '')) throw Error('Disabled or invalid identity');
  const namespace = createOwnedListingsExecutor({ expectedProfile: env.LISTINGS_PROFILE });
  await namespace.assertReady();
  const listener = await createListingListener({ token: env.LISTINGS_TOKEN, directory: '/journal', mode: env.LISTINGS_MODE,
    identity: env.LISTINGS_IDENTITY, namespace, host: '0.0.0.0', port: 8095 });
  await listener.start();
  let closing;
  const close = () => closing ||= listener.close().catch(() => { process.exitCode = 1; });
  process.once('SIGTERM', close); process.once('SIGINT', close);
  process.stdout.write('LISTINGS_READY\n');
}
if (require.main === module) main().catch(() => { process.stderr.write('LISTINGS_UNAVAILABLE\n'); process.exitCode = 1; });
module.exports = { createListingListener };
