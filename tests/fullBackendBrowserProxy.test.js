'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), os = require('node:os'), http = require('node:http');
const { once } = require('node:events');
const { backendEndpoint, createFullBackendBrowserProxy } = require('./fixtures/fullBackendBrowserProxy');
test('proxy admission rejects foreign origins and credentials', () => {
  for (const value of ['http://localhost:1234', 'https://127.0.0.1:1234', 'http://u@127.0.0.1:1234', 'http://127.0.0.1:1234/path', 'http://127.0.0.1:1234/?x']) assert.throws(() => backendEndpoint(value));
});
test('owned proxy serves bundle and forwards exact API method/query/body without forwarding spoofed identity', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'owned-browser-proxy-')));
  fs.writeFileSync(path.join(root, 'index.html'), '<html>owned bundle</html>');
  const received = [];
  const backend = http.createServer((req, res) => { let body = '';req.on('data', data => body += data);req.on('end', () => { received.push({ method:req.method,url:req.url,body,forwarded:req.headers['x-forwarded-for'] });res.setHeader('content-type','application/json');res.end('{"success":true}'); }); });
  backend.listen(0,'127.0.0.1');await once(backend,'listening');
  const proxy = await createFullBackendBrowserProxy({ buildRoot:root,backendOrigin:`http://127.0.0.1:${backend.address().port}` });
  try {
    assert.match(await (await fetch(proxy.origin+'/workshop-login')).text(), /owned bundle/);
    assert.equal((await fetch(proxy.origin+'/api/auth/login?test=1',{method:'POST',headers:{'x-forwarded-for':'foreign'},body:'owned'})).status,200);
    assert.deepEqual(received,[{method:'POST',url:'/api/auth/login?test=1',body:'owned',forwarded:undefined}]);
  } finally {await proxy.close();backend.closeAllConnections();await new Promise(resolve=>backend.close(resolve));fs.rmSync(root,{recursive:true});}
});

test('owned proxy serves only built public assets to opaque frames without changing API CORS', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'owned-browser-assets-')));
  fs.mkdirSync(path.join(root, 'assets'));
  fs.writeFileSync(path.join(root, 'index.html'), '<html>owned bundle</html>');
  fs.writeFileSync(path.join(root, 'assets', 'frame.js'), 'export const ready = true;');
  fs.writeFileSync(path.join(root, 'assets', 'frame.css'), ':root{color-scheme:light}');
  const backend = http.createServer((_req, res) => res.end('{"success":true}'));
  backend.listen(0, '127.0.0.1');await once(backend, 'listening');
  const proxy = await createFullBackendBrowserProxy({ buildRoot: root,
    backendOrigin: `http://127.0.0.1:${backend.address().port}` });
  try {
    for (const method of ['GET', 'HEAD']) for (const asset of ['/assets/frame.js', '/assets/frame.css']) {
      const response = await fetch(proxy.origin + asset, { method, headers: { Origin: 'null' } });
      assert.equal(response.status, 200);assert.equal(response.headers.get('access-control-allow-origin'), '*');
      assert.equal(response.headers.get('access-control-allow-credentials'), null);
    }
    const document = await fetch(proxy.origin + '/index.html', { headers: { Origin: 'null' } });
    assert.equal(document.headers.get('access-control-allow-origin'), null);
    const api = await fetch(proxy.origin + '/api/secureshop/v2/auth/login', { headers: { Origin: 'null' } });
    assert.equal(api.headers.get('access-control-allow-origin'), null);
  } finally {
    await proxy.close();backend.closeAllConnections();await new Promise(resolve => backend.close(resolve));
    fs.rmSync(root, { recursive: true });
  }
});

test('MCP timeout override is exact POST route only and finite', () => {
  const { apiTimeout } = require('./fixtures/fullBackendBrowserProxy');
  for (const route of ['/api/workshop/mcp/chat', '/api/workshop/mcp/conversation/chat']) {
    assert.equal(apiTimeout('POST', route, 2400000), 2400000);
    assert.equal(apiTimeout('GET', route, 2400000), 10000);
    assert.equal(apiTimeout('POST', route + '/', 2400000), 10000);
  }
  assert.equal(apiTimeout('POST', '/api/auth/login', 2400000), 10000);
  for (const value of [0, 9999, 2400001, Infinity, NaN, '30000', 10000.5]) assert.throws(() => apiTimeout('POST', '/api/workshop/mcp/chat', value));
});

test('owned HTTP proxy applies route budgets and cancels upstream after client disconnect', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'owned-chat-proxy-')));
  fs.writeFileSync(path.join(root, 'index.html'), 'owned');
  const sockets = new Set(), pendingResponses = [];
  const backend = http.createServer((req, res) => {
    req.resume();
    if (req.url === '/api/held') { pendingResponses.push(res);return; }
    res.end('owned');
  });
  backend.on('connection', socket => { sockets.add(socket);socket.on('close', () => sockets.delete(socket)); });
  backend.listen(0, '127.0.0.1');await once(backend, 'listening');
  const original = http.request, budgets = [];
  http.request = function (options, ...args) {
    if (options.hostname === '127.0.0.1' && Number(options.port) === backend.address().port) budgets.push([options.method, options.path, options.timeout]);
    return original.call(this, options, ...args);
  };
  let proxy;
  try {
    proxy = await createFullBackendBrowserProxy({ buildRoot: root, backendOrigin: `http://127.0.0.1:${backend.address().port}`, mcpChatTimeoutMs: 30000 });
    for (const route of ['/api/workshop/mcp/chat', '/api/workshop/mcp/conversation/chat', '/api/auth/login']) {
      assert.equal(await (await fetch(proxy.origin + route, { method: 'POST' })).text(), 'owned');
    }
    assert.deepEqual(budgets, [['POST', '/api/workshop/mcp/chat', 30000], ['POST', '/api/workshop/mcp/conversation/chat', 30000], ['POST', '/api/auth/login', 10000]]);
    const request = http.get(proxy.origin + '/api/held');request.on('error', () => {});
    const deadline = Date.now() + 2000;
    while (!pendingResponses.length && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(pendingResponses.length, 1);
    const closed = once(pendingResponses[0], 'close', { signal: AbortSignal.timeout(2000) });request.destroy();await closed;
    await proxy.close();proxy = null;
    for (const socket of sockets) assert.equal(socket.destroyed, true);
  } finally {
    http.request = original;
    if (proxy) await proxy.close();
    backend.closeAllConnections();await new Promise(resolve => backend.close(resolve));
    fs.rmSync(root, { recursive: true });
  }
});


test('SecureShop budget is explicit and limited to exact model-driven POST routes',()=>{
  const {apiTimeout}=require('./fixtures/fullBackendBrowserProxy');
  const route='/api/secureshop/products/1/reviews/2/browser-attempt';
  assert.equal(apiTimeout('POST',route),10000);
  assert.equal(apiTimeout('POST',route,30000,420000),420000);
  for(const path of [route+'/',route+'/extra','/api/secureshop/products/0/reviews/2/browser-attempt','/api/secureshop/v2/mcp-trust/discover','/api/auth/login'])assert.equal(apiTimeout('POST',path,30000,420000),10000);
  assert.equal(apiTimeout('GET',route,30000,420000),10000);
  assert.equal(apiTimeout('POST','/api/workshop/mcp/chat',30000,420000),30000);
  for(const value of [9999,420001,NaN,Infinity,10000.5,'420000'])assert.throws(()=>apiTimeout('POST',route,30000,value));
});
