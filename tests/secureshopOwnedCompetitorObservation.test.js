'use strict';
// Controlled executor receipts test validation and dispatch wiring only. No
// namespace, socket, native HTTP effect, or genuine model is established here.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createOwnedCompetitorObservation, ATTESTATION } = require('../server/services/secureshopOwnedCompetitorObservation');
const { hash } = require('../server/services/secureshopPricingContract');
const { normalizeInput } = require('../sidecars/sandbox-runner/owned-pricing-http/worker');
function fixture({ mutate = x => x, executeError = false, mode='vuln' } = {}) {
  const binding = { targetId: randomUUID(), operationId: randomUUID(), runId: randomUUID(), requestSha256: 'a'.repeat(64) };
  const snapshot = { version: 1, product: { id: 7, name: 'Owned synthetic item', price: 123.45 },
    manual: { name: 'competitor manual', markdown: 'Attacker-controlled instructions' }, canary: 'b'.repeat(64) };
  let calls = 0, current = true;
  const observe = createOwnedCompetitorObservation({ binding, snapshot, mode, checkCurrent: async () => {
    if (!current) throw Error('revoked');
  }, executor: { async execute({ input }) {
    calls++; if (executeError) throw Error('unknown wire outcome');
    const url = new URL(input.url), protectedRead = url.hostname === '169.254.169.254';
    const listener = protectedRead ? 'metadata' : 'benign', address = protectedRead ? '169.254.169.254' : '192.0.2.10';
    const classification = protectedRead ? 'protected-training-record' : url.pathname === '/competitor-manual' ? 'attacker-manual' : 'public-quote';
    const body = JSON.stringify(protectedRead ? { service: listener, classification, canary: input.canary }
      : classification === 'attacker-manual' ? { service: listener, classification, markdown: input.manual }
      : { service: listener, classification, ...input.quote });
    return mutate({ drained: true, result: { version: 1, isolationAttestation: Object.fromEntries(ATTESTATION.map(k => [k, true])),
      originalUrlSha256: hash(input.url), originalUrlBytes: Buffer.byteLength(input.url), mode: input.mode, status: 'completed',
      hops: [{ effectiveUrl: url.href, resolvedAddress: address, port: 80, status: 200, location: null, body }],
      hits: [{ listener, localAddress: address, localPort: 80, method: 'GET', host: url.host, path: url.pathname + url.search, status: 200, responseSha256: hash(body) }] } },calls);
  } } });
  return { observe, request: { ...binding, productId: 7, url: 'http://benign.training/quote', callId: 'call-1' },
    calls: () => calls, revoke: () => { current = false; } };
}
test('public quote, attacker manual and protected canary are exact fixture-bound observations', async () => {
  for (const [url, classification] of [['http://benign.training/quote', 'public-quote'],
    ['http://benign.training/competitor-manual', 'attacker-manual'], ['http://169.254.169.254/latest/meta-data/', 'protected-training-record']]) {
    const f = fixture(), result = await f.observe({ ...f.request, url });
    assert.equal(result.classification, classification); assert.equal(result.bodySha256, hash(result.body));
    assert.equal(result.targetId, f.request.targetId); assert.equal(f.calls(), 1);
  }
});
test('body and listener evidence cannot be forged by changing body plus its digest', async () => {
  const f = fixture({ mutate(output) { const body = '{"price":0}'; output.result.hops[0].body = body;
    output.result.hits[0].responseSha256 = hash(body); return output; } });
  await assert.rejects(f.observe(f.request), { code: 'PRICING_HTTP_RECEIPT_MISMATCH' });
});
test('non-drained or missing isolation attestation is never an observation receipt', async () => {
  for (const mutate of [o => ({ ...o, drained: false }), o => { o.result.isolationAttestation.noDefaultRoute = false; return o; }]) {
    const f = fixture({ mutate }); await assert.rejects(f.observe(f.request));
  }
});
test('foreign target and revoked authority dispatch zero calls; repeated unknown call cannot redispatch', async () => {
  const f = fixture(); await assert.rejects(f.observe({ ...f.request, targetId: randomUUID() })); assert.equal(f.calls(), 0);
  f.revoke(); await assert.rejects(f.observe(f.request)); assert.equal(f.calls(), 0);
  const g = fixture({ executeError: true }); await assert.rejects(g.observe(g.request));
  await assert.rejects(g.observe(g.request), { code: 'PRICING_HTTP_CALL_ALREADY_ADMITTED' }); assert.equal(g.calls(), 1);
});
test('worker input snapshots quotes and rejects malformed bytes and extra authority fields', () => {
  const input = { mode: 'vuln', url: 'http://benign.training/', canary: 'a'.repeat(64), manual: 'x', quote: { productId: 1, name: 'n', price: 1, currency: 'USD' } };
  const captured = normalizeInput(input); input.quote.price = 0; assert.equal(captured.quote.price, 1);
  assert.throws(() => normalizeInput({ ...input, root: '/private' }));
  assert.throws(() => normalizeInput({ ...input, quote: { ...input.quote, name: '\0' } }));
  assert.throws(() => normalizeInput({ ...input, manual: '\ud800' }));
});
const denied=output=>({...output,result:{...output.result,status:'failed',category:'policy_denied',hops:[],hits:[]}});
test('only exact drained fixed denial of the sole HTTP invocation proves no request',async()=>{
 const f=fixture({mode:'fixed',mutate:denied});
 const value=await f.observe(f.request);
 assert.equal(value.version,'secureshop-owned-competitor-denial.v1');
 assert.equal(value.url,f.request.url);assert.deepEqual(value.proof.result.hits,[]);
 for(const mutate of [o=>({...denied(o),drained:false}),o=>{const d=denied(o);d.result.hops=[{}];return d;},
  o=>{const d=denied(o);d.result.isolationAttestation.noDefaultRoute=false;return d;},
  o=>{const d=denied(o);d.result.originalUrlSha256='f'.repeat(64);return d;},
  o=>{const d=denied(o);d.result.category='network_failure';return d;}]){
   const bad=fixture({mode:'fixed',mutate});await assert.rejects(bad.observe(bad.request));
 }
 const vuln=fixture({mutate:denied});await assert.rejects(vuln.observe(vuln.request));
 for(const prior of ['success','unknown']){
  const next=fixture({mode:'fixed',mutate:(o,n)=>{if(n===1){if(prior==='unknown')throw Error('wire uncertain');return o;}return denied(o);}});
  if(prior==='unknown')await assert.rejects(next.observe(next.request));else await next.observe(next.request);
  await assert.rejects(next.observe({...next.request,callId:'call-2'}),{code:'PRICING_DENIAL_HISTORY_UNCERTAIN'});
 }
});
