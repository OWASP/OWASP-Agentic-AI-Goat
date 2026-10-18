'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

function backendEndpoint(value) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/'
      || url.search || url.hash || url.username || url.password) throw Error('Exact owned backend origin required');
  return url;
}
function assetPath(root, requestUrl) {
  const url = new URL(requestUrl, 'http://owned.invalid');
  const decoded = decodeURIComponent(url.pathname);
  if (decoded.includes('\0') || decoded.includes('\\')) throw Error('Invalid asset path');
  const candidate = path.resolve(root, '.' + decoded);
  if (candidate !== root && !candidate.startsWith(root + path.sep)) throw Error('Asset escaped build');
  return candidate;
}
// Test infrastructure budget; this does not change production API/UI timeouts.
function apiTimeout(method, pathname, mcpChatTimeoutMs = 10000, secureShopTimeoutMs = 10000) {
  if (!Number.isSafeInteger(mcpChatTimeoutMs) || mcpChatTimeoutMs < 10000 || mcpChatTimeoutMs > 2400000) {
    throw Error('Invalid bounded MCP chat timeout');
  }
  if (!Number.isSafeInteger(secureShopTimeoutMs) || secureShopTimeoutMs < 10000 || secureShopTimeoutMs > 420000) {
    throw Error('Invalid bounded SecureShop timeout');
  }
  if (method !== 'POST') return 10000;
  if (['/api/workshop/mcp/chat', '/api/workshop/mcp/conversation/chat'].includes(pathname)) return mcpChatTimeoutMs;
  if (['/api/secureshop/v2/persona-inbox/read', '/api/secureshop/v2/mcp-trust/run',
    '/api/secureshop/v2/controlled-ssrf/run', '/api/secureshop/merchant/reviews/moderate-all'].includes(pathname)
    || /^\/api\/secureshop\/products\/[1-9]\d*\/reviews\/[1-9]\d*\/browser-attempt$/.test(pathname)) return secureShopTimeoutMs;
  return 10000;
}
async function createFullBackendBrowserProxy({ buildRoot, backendOrigin, port = 0, mcpChatTimeoutMs = 10000, secureShopTimeoutMs = 10000 }) {
  apiTimeout('GET', '/', mcpChatTimeoutMs, secureShopTimeoutMs);
  if (!path.isAbsolute(buildRoot) || fs.realpathSync(buildRoot) !== buildRoot
      || fs.lstatSync(buildRoot).isSymbolicLink()) throw Error('Canonical build root required');
  const backend = backendEndpoint(backendOrigin);
  const pending = new Set();
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://owned.invalid').pathname;
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      const headers = { ...req.headers, host: backend.host };
      for (const key of ['connection', 'proxy-authorization', 'proxy-connection', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']) delete headers[key];
      const upstream = http.request({ hostname: backend.hostname, port: backend.port, path: req.url,
        method: req.method, headers, timeout: apiTimeout(req.method, pathname, mcpChatTimeoutMs, secureShopTimeoutMs) }, response => {
        res.writeHead(response.statusCode, response.headers);response.pipe(res);
      });
      const cancel = () => upstream.destroy();
      const disconnect = () => { if (!res.writableFinished) cancel(); };
      pending.add(upstream);upstream.once('close', () => {
        pending.delete(upstream);req.removeListener('aborted', cancel);res.removeListener('close', disconnect);
      });
      req.once('aborted', cancel);res.once('close', disconnect);
      upstream.on('timeout', () => upstream.destroy(Error('Owned backend timeout')));
      upstream.on('error', () => { if (!res.headersSent) res.writeHead(502);res.end(); });
      req.pipe(upstream);return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405);res.end();return; }
    try {
      let file = assetPath(buildRoot, req.url);
      if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(buildRoot, 'index.html');
      if (fs.realpathSync(file) !== file || !file.startsWith(buildRoot + path.sep)) throw Error('Substituted asset');
      const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };
      res.setHeader('content-type', mime[path.extname(file)] || 'application/octet-stream');
      res.setHeader('cache-control', 'no-store');
      const relative = path.relative(buildRoot, file);
      if (relative.startsWith(`assets${path.sep}`)) res.setHeader('access-control-allow-origin', '*');
      if (req.method === 'HEAD') res.end();else fs.createReadStream(file).pipe(res);
    } catch { res.writeHead(404);res.end(); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject);server.listen(port, '127.0.0.1', resolve); });
  return { origin: `http://127.0.0.1:${server.address().port}`, async close() {
    for (const request of pending) request.destroy();
    server.closeAllConnections();await new Promise(resolve => server.close(resolve));
  } };
}
module.exports = { apiTimeout, backendEndpoint, assetPath, createFullBackendBrowserProxy };
