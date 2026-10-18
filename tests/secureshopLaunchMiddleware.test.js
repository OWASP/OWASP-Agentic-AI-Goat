'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const { requireSecureShopLaunch, LAUNCH_STATE_HEADER, LAUNCH_UNAVAILABLE }
  = require('../server/middleware/secureshopLaunch');
const bearer = 'a'.repeat(43);
function fixture(resolver, headers = { 'x-dvaia-secureshop-launch': bearer }, rawHeaders = []) {
  const req = { headers, rawHeaders, ssLaunch: { platformOwnerId: 999 }, body: { platformOwnerId: 999 } };
  const res = { headers: {}, setHeader(k,v) { this.headers[k] = v; }, status(n) { this.code = n; return this; }, json(value) { this.body = value; return this; } };
  let next = 0;
  return { req, res, run: async () => { await requireSecureShopLaunch({ launches: { resolveCapability: resolver } })(req,res,()=>{next++;}); return next; } };
}
test('launch middleware derives only frozen ownership coordinates from its resolver', async () => {
  const binding = { launchId: '11111111-1111-4111-8111-111111111111', scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1, platformOwnerId: 7, platformSessionId: 8, bearer: 'private' };
  const f = fixture(async value => { assert.equal(value, bearer); return binding; });
  assert.equal(await f.run(), 1); assert.equal(f.req.ssLaunch.platformOwnerId, 7);
  assert.ok(Object.isFrozen(f.req.ssLaunch)); assert.ok(!JSON.stringify(f.req.ssLaunch).includes('private'));
  assert.equal(f.res.headers['Cache-Control'], 'no-store');
});
test('missing, malformed and duplicate launch headers never resolve or retain caller scope', async () => {
  for (const [headers, raw] of [[{}, []], [{ 'x-dvaia-secureshop-launch': 'bad' }, []], [{ 'x-dvaia-secureshop-launch': bearer }, ['X-DVAIA-SecureShop-Launch',bearer,'x-dvaia-secureshop-launch',bearer]]]) {
    const f = fixture(() => assert.fail('must not resolve'), headers, raw);
    assert.equal(await f.run(), 0); assert.equal(f.res.code, 401); assert.equal(f.req.ssLaunch, undefined);
    assert.equal(f.res.headers[LAUNCH_STATE_HEADER], LAUNCH_UNAVAILABLE);
  }
});
test('invalid authority and resolver failures expose no credential or native cause', async () => {
  for (const [resolver, code] of [[async()=>({ platformOwnerId: 7 }),503],[async()=>null,401],[async()=>{throw Error(bearer);},503]]) {
    const f = fixture(resolver); assert.equal(await f.run(), 0); assert.equal(f.res.code, code);
    assert.ok(!JSON.stringify(f.res.body).includes(bearer)); assert.equal(f.req.ssLaunch, undefined);
    assert.equal(f.res.headers[LAUNCH_STATE_HEADER], code === 401 ? LAUNCH_UNAVAILABLE : undefined);
  }
});

test('actual HTTP rejects repeated headers and never accepts body-provided launch scope', async t => {
  const express = require('express'), http = require('node:http');
  const app = express(); app.use(express.json());
  let resolutions = 0;
  app.post('/bound', requireSecureShopLaunch({ launches: { async resolveCapability(value) {
    resolutions++; assert.equal(value, bearer);
    return { launchId: '11111111-1111-4111-8111-111111111111', scenarioId: '22222222-2222-4222-8222-222222222222', generation: 1, platformOwnerId: 7, platformSessionId: 8 };
  } } }), (req,res)=>res.json({ owner: req.ssLaunch.platformOwnerId }));
  const server = await new Promise(resolve => { const s = app.listen(0,'127.0.0.1',()=>resolve(s)); });
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  async function request(headers) {
    return new Promise((resolve,reject)=>{
      const req = http.request({ hostname:'127.0.0.1', port:server.address().port, path:'/bound',method:'POST',headers },res=>{
        let body='';res.on('data',chunk=>{body+=chunk;});res.on('end',()=>resolve({code:res.statusCode,headers:res.headers,body:JSON.parse(body)}));
      }); req.on('error',reject);req.end('{"platformOwnerId":999}');
    });
  }
  const missing=await request({'content-type':'application/json'});assert.equal(missing.code,401);
  const duplicate=await request({'content-type':'application/json','x-dvaia-secureshop-launch':[bearer,bearer]});assert.equal(duplicate.code,401);
  assert.equal(missing.headers['x-dvaia-secureshop-launch-state'], LAUNCH_UNAVAILABLE);
  assert.equal(duplicate.headers['x-dvaia-secureshop-launch-state'], LAUNCH_UNAVAILABLE);
  assert.equal(resolutions,0);
  const valid=await request({'content-type':'application/json','x-dvaia-secureshop-launch':bearer});
  assert.equal(valid.code,200);assert.deepEqual(valid.body,{owner:7});assert.equal(valid.headers['cache-control'],'no-store');
  assert.equal(valid.headers['x-dvaia-secureshop-launch-state'], undefined);
});
