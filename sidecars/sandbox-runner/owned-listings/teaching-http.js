'use strict';
// Runs inside a launch-owned network namespace. Loopback is not isolation on
// its own: the launcher must deny host/sibling routes before starting this.
const http = require('node:http');
const crypto = require('node:crypto');
const MAX = 1024 * 1024;
function startServer(routes) {
  return new Promise((resolve, reject) => {
    const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 }, (req, res) => {
      if (req.method !== 'GET' || !routes.has(req.url)) {
        res.writeHead(req.method === 'GET' ? 404 : 405, { 'content-type': 'text/plain' }); res.end('Unavailable'); return;
      }
      const value = routes.get(req.url);
      res.writeHead(200, { 'content-type': value.type, 'content-length': value.bytes.length, 'cache-control': 'no-store' });
      res.end(value.bytes);
    });
    server.maxConnections = 8;
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}
function copyRoutes(raw) {
  if (!Array.isArray(raw) || raw.length < 1 || raw.length > 16) throw TypeError('Trusted synthetic routes required');
  const routes = new Map(); let total = 0;
  for (const row of raw) {
    if (!row || typeof row.path !== 'string' || !/^\/[a-zA-Z0-9_./-]{1,128}$/.test(row.path)
        || row.path.includes('..') || routes.has(row.path) || !Buffer.isBuffer(row.bytes)
        || !['application/json', 'application/xml', 'text/plain'].includes(row.type)) throw TypeError('Invalid synthetic route');
    total += row.bytes.length; if (total > MAX) throw TypeError('Synthetic route budget exceeded');
    routes.set(row.path, { type: row.type, bytes: Buffer.from(row.bytes) });
  }
  return routes;
}
async function createListingTeachingHttp({ supplierRoutes, internalRoutes } = {}) {
  // Copy every input before any await, so bootstrap cannot mutate serving data.
  const supplier = copyRoutes(supplierRoutes), internal = copyRoutes(internalRoutes);
  const servers = [];
  async function close() { await Promise.all(servers.map(server => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }))); }
  try {
    servers.push(await startServer(supplier)); servers.push(await startServer(internal));
  } catch (error) { await close(); throw error; }
  const origins = servers.map(server => `http://127.0.0.1:${server.address().port}`);
  const manifest = [supplier, internal].map((routes, index) => ({ origin: origins[index], kind: index ? 'internal' : 'supplier',
    resources: [...routes].map(([route, value]) => ({ path: route, byteCount: value.bytes.length,
      sha256: crypto.createHash('sha256').update(value.bytes).digest('hex') })) }));
  return Object.freeze({ supplierOrigin: origins[0], internalOrigin: origins[1],
    // Fixed mode can fetch only supplier routes. XML's fixed parser separately
    // rejects all SYSTEM entities, including supplier resources.
    originsForMode(mode) { if (!['fixed', 'vuln'].includes(mode)) throw TypeError('Mode required'); return mode === 'fixed' ? [origins[0]] : [...origins]; },
    manifest: JSON.parse(JSON.stringify(manifest)), close });
}
module.exports = { createListingTeachingHttp };
