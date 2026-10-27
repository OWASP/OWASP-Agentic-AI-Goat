import { compileBridgeOperation } from './compiler.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';
import { buildUploadFormData } from './uploads.mjs';
import { matchOperationRequest } from './operations.mjs';
import { createHostTransport } from './transport.mjs';
Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Request = web.Request; global.Response = web.Response; global.Headers = web.Headers;

const descriptor = { productId: '12', sha256: 'a'.repeat(64), sizeBytes: '6',
  filename: 'manual.txt', mime: 'text/plain', public: 'false' };
const recoveryScopeKey = 'b'.repeat(64);

test('receipt GET is exact and cannot carry extra owner or replay fields', () => {
  const compiled = compileBridgeOperation('uploads.productManual.receipt', { query: descriptor });
  expect(compiled).toEqual({ path: '/api/secureshop/uploads/product-manual/receipt?productId=12'
    + `&sha256=${descriptor.sha256}&sizeBytes=6&filename=manual.txt&mime=text%2Fplain&public=false`,
  method: 'GET', responseKind: 'json' });
  expect(matchOperationRequest({ pathname: '/api/secureshop/uploads/product-manual/receipt',
    method: 'GET', query: { ...descriptor, recoveryScopeKey } }).name).toBe('uploads.productManual.receipt');
  for (const query of [{ ...descriptor, ownerId: '7' }, { ...descriptor, sizeBytes: '06' },
    { ...descriptor, recoveryScopeKey: 'bad' }, { ...descriptor, public: 'yes' },
    { ...descriptor, filename: 'manual\n.txt' }, { ...descriptor, sha256: 'A'.repeat(64) }])
    expect(() => compileBridgeOperation('uploads.productManual.receipt', { query })).toThrow();
  expect(() => compileBridgeOperation('uploads.productManual.receipt', { query: descriptor, body: {} })).toThrow();
});

test('only product-manual multipart carries an optional opaque scope key end to end', async () => {
  const file = new Blob(['manual'], { type: 'text/plain' });
  const fields = { kind: 'product_manual', scope_id: '12', mime: 'text/plain', public: 'false' };
  const base = compileBridgeOperation('uploads.create', { file, filename: 'manual.txt', fields });
  expect(Object.keys(base.body.fields)).toEqual(['kind', 'scope_id', 'mime', 'public']);
  const scoped = compileBridgeOperation('uploads.create', { file, filename: 'manual.txt',
    fields: { ...fields, recoveryScopeKey } });
  expect(scoped.body.fields.recoveryScopeKey).toBe(recoveryScopeKey);
  expect(() => compileBridgeOperation('uploads.create', { file, filename: 'manual.txt',
    fields: { ...fields, kind: 'avatar', recoveryScopeKey } })).toThrow();
  expect(() => compileBridgeOperation('uploads.create', { file, filename: 'manual.txt',
    fields: { ...fields, recoveryScopeKey: 'bad' } })).toThrow();
  const bridge = { request: jest.fn(async () => ({ ok: true })) };
  const bridgeFetch = createBridgeFetch({ bridge, origin: 'https://shop.test' });
  await bridgeFetch('https://shop.test/api/secureshop/uploads', { method: 'POST',
    body: buildUploadFormData({ file, filename: 'manual.txt', fields: { ...fields, recoveryScopeKey } }) });
  expect(bridge.request).toHaveBeenCalledWith('uploads.create', expect.objectContaining({
    fields: expect.objectContaining({ recoveryScopeKey }) }), expect.anything());
  const listeners = new Set(); const messages = [];
  const port = { addEventListener: (_type, listener) => listeners.add(listener),
    removeEventListener: (_type, listener) => listeners.delete(listener), start() {}, close() {},
    postMessage(message) { messages.push(message);
      if (message.type === 'start' || message.type === 'chunk')
        queueMicrotask(() => listeners.forEach(listener => listener({ data: { type: 'pull', id: message.id } })));
    } };
  const fetchImpl = jest.fn(async () => new Response('{}', { status: 200,
    headers: { 'content-type': 'application/json' } }));
  const transport = createHostTransport({ port, origin: 'https://shop.test',
    compileOperation: compileBridgeOperation, fetchImpl, getLaunchBearer: () => 'a'.repeat(43) });
  try {
    listeners.forEach(listener => listener({ data: { type: 'request', id: 1,
      operation: 'uploads.create', input: bridge.request.mock.calls[0][1], shopBearer: 'persona' } }));
    for (let index = 0; index < 30 && !messages.some(message => ['end', 'error'].includes(message.type)); index += 1)
      await new Promise(resolve => setTimeout(resolve, 0));
    expect(messages.filter(message => message.type === 'error')).toEqual([]);
    const [url, options] = fetchImpl.mock.calls[0];
    expect(url).toBe('https://shop.test/api/secureshop/uploads');
    expect(options.body.get('recoveryScopeKey')).toBe(recoveryScopeKey);
    expect([...options.body.keys()]).toEqual(['file', 'kind', 'scope_id', 'mime', 'public', 'recoveryScopeKey']);
  } finally { transport.close(); }
});
