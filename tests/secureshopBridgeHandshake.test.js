'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const origin = 'http://localhost:3000';
const nonce = 'a'.repeat(64);
const message = (target, data, source, messageOrigin, ports = []) => {
  const event = new Event('message');
  Object.assign(event, { data, source, origin: messageOrigin, ports });target.dispatchEvent(event);
};
function fixture() {
  const hostWindow = new EventTarget();Object.assign(hostWindow, { crypto: webcrypto, MessageChannel });
  const frame = new EventTarget();Object.assign(frame, { isConnected: false, setAttribute(key, value) { this[key] = value; }, contentWindow: { postMessage(data, target, ports) { this.connection = { data, target, ports }; } } });
  return { hostWindow, frame };
}
const options = { origin, url: '/frame', compileOperation: () => { throw Error('unused'); }, getLaunchBearer: () => 'a'.repeat(43) };

test('attached startup navigates from the initial empty document before offering authority', async () => {
  const { mountShopFrame } = await import('../client/src/pages/secureshop/bridge/handshake.mjs');
  const f = fixture(); let disconnected = 0;
  const session = mountShopFrame({ ...options, ...f, waitForInitialLoad: true,
    onDisconnect: () => disconnected++ });
  assert.equal(f.frame.src, 'about:blank');
  f.frame.dispatchEvent(new Event('load'));
  assert.equal(new URL(f.frame.src).pathname, '/frame');
  const data = { channel: 'owasp-ai-goat-secureshop-bridge-v1', type: 'ready',
    nonce: new URL(f.frame.src).hash.slice(1) };
  message(f.hostWindow, data, f.frame.contentWindow, 'null');
  assert.equal(f.frame.contentWindow.connection, undefined);
  f.frame.dispatchEvent(new Event('load'));
  message(f.hostWindow, data, f.frame.contentWindow, 'null');
  message(f.hostWindow, { ...data, type: 'connected' }, f.frame.contentWindow, 'null');
  await session.ready;
  f.frame.dispatchEvent(new Event('load'));
  assert.equal(disconnected, 1);
  f.frame.contentWindow.connection.ports.forEach(port => port.close());
  session.close();
});

test('initial frame loads can repeat before authority is transferred', async () => {
  const { mountShopFrame } = await import('../client/src/pages/secureshop/bridge/handshake.mjs');
  const f = fixture();
  const session = mountShopFrame({ ...options, ...f });
  const ready = session.ready;
  // A fresh frame can load its initial blank document before its entry page.
  f.frame.dispatchEvent(new Event('load'));
  f.frame.dispatchEvent(new Event('load'));
  const data = { channel: 'owasp-ai-goat-secureshop-bridge-v1', type: 'ready',
    nonce: new URL(f.frame.src).hash.slice(1) };
  message(f.hostWindow, data, f.frame.contentWindow, 'null');
  message(f.hostWindow, { ...data, type: 'connected' }, f.frame.contentWindow, 'null');
  try { await ready; }
  finally { f.frame.contentWindow.connection?.ports?.forEach(port => port.close()); session.close(); }
});

test('host rejects sibling, nonopaque, stale nonce and extra fields; connects once and fences navigation', async () => {
  const { mountShopFrame } = await import('../client/src/pages/secureshop/bridge/handshake.mjs');
  let disconnected = 0;
  const f = fixture();const session = mountShopFrame({ ...options, ...f, onDisconnect: () => disconnected++ });
  const data = { channel: 'owasp-ai-goat-secureshop-bridge-v1', type: 'ready', nonce: new URL(f.frame.src).hash.slice(1) };
  assert.equal(f.frame.sandbox, 'allow-scripts allow-forms');assert.match(data.nonce, /^[a-f0-9]{64}$/);
  for (const [body, source, o] of [[data, {}, 'null'], [data, f.frame.contentWindow, origin], [{ ...data, nonce }, f.frame.contentWindow, 'null'], [{ ...data, extra: true }, f.frame.contentWindow, 'null']]) message(f.hostWindow, body, source, o);
  assert.equal(f.frame.contentWindow.connection, undefined);
  f.frame.dispatchEvent(new Event('load'));
  message(f.hostWindow, data, f.frame.contentWindow, 'null');
  message(f.hostWindow, { ...data, type: 'connected' }, f.frame.contentWindow, 'null');await session.ready;
  const connection = f.frame.contentWindow.connection;
  message(f.hostWindow, data, f.frame.contentWindow, 'null');assert.equal(f.frame.contentWindow.connection, connection);
  const shutdown = new Promise(resolve => { connection.ports[0].onmessage = e => resolve(e.data); });
  f.frame.dispatchEvent(new Event('load'));assert.deepEqual(await shutdown, { type: 'shutdown' });
  assert.equal(disconnected, 1);
  connection.ports[0].close();session.close();
  assert.equal(disconnected, 1);
  assert.throws(() => mountShopFrame({ ...options, ...f }), /fresh iframe/);
});

test('host timeout, explicit disposal and parent pagehide settle handshake without a connection', async () => {
  const { mountShopFrame } = await import('../client/src/pages/secureshop/bridge/handshake.mjs');
  for (const action of ['timeout', 'close', 'pagehide']) {
    const f = fixture();const session = mountShopFrame({ ...options, ...f, timeoutMs: 10 });
    const rejected = assert.rejects(session.ready, error => {
      assert.equal(error.name, 'AbortError');
      if (action === 'timeout') assert.equal(error.code, 'SHOP_FRAME_LOAD_TIMEOUT');
      else assert.notEqual(error.code, 'SHOP_FRAME_LOAD_TIMEOUT');
      return true;
    });
    if (action === 'close') session.close();if (action === 'pagehide') f.hostWindow.dispatchEvent(new Event('pagehide'));
    await rejected;assert.equal(f.frame.contentWindow.connection, undefined);
  }
});

test('child authenticates parent origin and nonce and closes on pagehide', async () => {
  const { connectShopFrame } = await import('../client/src/pages/secureshop/bridge/handshake.mjs');
  const frameWindow = new EventTarget();let sent;
  Object.assign(frameWindow, { location: { hash: '#' + nonce }, parent: { postMessage(...args) { sent = args; } } });
  const session = connectShopFrame({ origin, frameWindow });
  assert.equal(sent[1], origin);
  const data = { channel: 'owasp-ai-goat-secureshop-bridge-v1', type: 'connect', nonce };
  const channel = new MessageChannel();
  message(frameWindow, data, {}, origin, [channel.port1]);
  message(frameWindow, data, frameWindow.parent, 'http://evil.example', [channel.port1]);
  message(frameWindow, { ...data, nonce: 'b'.repeat(64) }, frameWindow.parent, origin, [channel.port1]);
  message(frameWindow, data, frameWindow.parent, origin, [channel.port1]);
  const transport = await session.ready;
  frameWindow.dispatchEvent(new Event('pagehide'));
  await assert.rejects(transport.request('catalog.list'), { name: 'AbortError' });channel.port2.close();
});

test('host does not report ready until child acknowledges transport construction', async () => {
  const { mountShopFrame } = await import('../client/src/pages/secureshop/bridge/handshake.mjs');
  const f = fixture();const session = mountShopFrame({ ...options, ...f, timeoutMs: 10 });
  const rejected = assert.rejects(session.ready, error => {
    assert.equal(error.name, 'AbortError');
    assert.notEqual(error.code, 'SHOP_FRAME_LOAD_TIMEOUT');
    return true;
  });
  f.frame.dispatchEvent(new Event('load'));
  message(f.hostWindow, { channel:'owasp-ai-goat-secureshop-bridge-v1', type:'ready', nonce:new URL(f.frame.src).hash.slice(1) }, f.frame.contentWindow, 'null');
  await rejected;f.frame.contentWindow.connection.ports[0].close();
});

test('pagehide aborts pending state hydration immediately instead of waiting for deadline',{timeout:1000},async()=>{
 const {connectShopFrame}=await import('../client/src/pages/secureshop/bridge/handshake.mjs');
 const frameWindow=new EventTarget();Object.assign(frameWindow,{location:{hash:'#'+nonce},parent:{postMessage(){}}});
 const session=connectShopFrame({origin,frameWindow,timeoutMs:30000});
 const rejection=assert.rejects(session.ready,{name:'AbortError'});
 const http=new MessageChannel();const state=new MessageChannel();
 const stateClosed=new Promise(resolve=>state.port2.addEventListener('close',resolve,{once:true}));state.port2.start();
 message(frameWindow,{channel:'owasp-ai-goat-secureshop-bridge-v1',type:'connect',nonce},frameWindow.parent,origin,[http.port1,state.port1]);
 frameWindow.dispatchEvent(new Event('pagehide'));await rejection;await stateClosed;
 http.port2.close();state.port2.close();
});

test('activity only reaches current connected opaque frame and closed nonce envelope',async()=>{
 const {mountShopFrame}=await import('../client/src/pages/secureshop/bridge/handshake.mjs');const f=fixture();let activity=0;
 const session=mountShopFrame({...options,...f,onActivity:()=>activity++});const data={channel:'owasp-ai-goat-secureshop-bridge-v1',type:'ready',nonce:new URL(f.frame.src).hash.slice(1)};
 f.frame.dispatchEvent(new Event('load'));message(f.hostWindow,{...data,type:'activity'},f.frame.contentWindow,'null');assert.equal(activity,0);
 message(f.hostWindow,data,f.frame.contentWindow,'null');message(f.hostWindow,{...data,type:'connected'},f.frame.contentWindow,'null');await session.ready;
 for(const [body,source,o] of [[{...data,type:'activity'}, {},'null'],[{...data,type:'activity',owner:1},f.frame.contentWindow,'null'],[{...data,type:'activity',nonce:'b'.repeat(64)},f.frame.contentWindow,'null']])message(f.hostWindow,body,source,o);
 assert.equal(activity,0);message(f.hostWindow,{...data,type:'activity'},f.frame.contentWindow,'null');message(f.hostWindow,{...data,type:'activity'},f.frame.contentWindow,'null');assert.equal(activity,1);
 session.close();message(f.hostWindow,{...data,type:'activity'},f.frame.contentWindow,'null');assert.equal(activity,1);f.frame.contentWindow.connection.ports.forEach(p=>p.close());
});
