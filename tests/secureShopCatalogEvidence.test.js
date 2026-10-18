'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { createSecureShopCatalogEvidence } = require('./fixtures/secureShopCatalogEvidence');
const origin = 'http://127.0.0.1:23451';
function fixture() {
  const page = new EventEmitter(), context = {};
  page.browserContext = () => context;
  const observer = createSecureShopCatalogEvidence({ page, origin });
  function response({ status = 200, etag = 'W/"first"', validator, body = { challenges: [] }, url = origin + '/api/workshop/challenges', method = 'GET', actualPage = page } = {}) {
    return { url: () => url, status: () => status, headers: () => ({ etag }),
      request: () => ({ method: () => method, headers: () => ({ 'if-none-match': validator }) }),
      frame: () => ({ page: () => actualPage }), json: async () => { assert.equal(status, 200); return body; } };
  }
  return { page, observer, response };
}
test('pre-login observer serializes background 200 then reentry 304 and detaches', async () => {
  const { page, observer, response } = fixture();
  let release;
  const first = response({ body: { owner: 1 } });
  first.json = () => new Promise(resolve => { release = () => resolve({ owner: 1 }); });
  page.emit('response', first);
  const next = response({ status: 304, validator: 'W/"first"' });
  page.emit('response', next);
  const pending = observer.read(next);
  await Promise.resolve(); release();
  const body = await pending; assert.deepEqual(body, { owner: 1 }); body.owner = 2;
  assert.deepEqual(await observer.read(response({ status: 304, validator: 'W/"first"' })), { owner: 1 });
  await observer.close(); assert.equal(page.listenerCount('response'), 0);
  await observer.close(); await assert.rejects(observer.read(next), /closed/);
});
test('wrong validator, uncaptured representation and foreign page cannot supply catalog proof', async () => {
  for (const options of [{ status: 304, validator: 'wrong' }, { status: 304, etag: 'W/"other"', validator: 'W/"other"' }, { actualPage: {} }]) {
    const { page, observer, response } = fixture();
    page.emit('response', response()); await observer.settle();
    await assert.rejects(observer.read(response(options)));
    await assert.rejects(observer.close()); assert.equal(page.listenerCount('response'), 0);
  }
});
test('only exact GET URL is observed; malformed background JSON failure is retained through cleanup', async () => {
  const { page, observer, response } = fixture();
  for (const options of [{ method: 'POST' }, { url: origin + '/api/workshop/challenges?owner=2' }, { url: 'http://127.0.0.1:23452/api/workshop/challenges' }]) {
    const item = response(options); item.json = async () => { throw Error('Must not read unrelated response'); }; page.emit('response', item);
  }
  await observer.settle();
  const broken = response(); broken.json = async () => { throw Error('controlled parse failure'); };
  page.emit('response', broken);
  await assert.rejects(observer.settle(), /controlled parse failure/);
  await assert.rejects(observer.read(response()), /controlled parse failure/);
  await assert.rejects(observer.close(), /controlled parse failure/);
  assert.equal(page.listenerCount('response'), 0);
});
