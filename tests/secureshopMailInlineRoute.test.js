'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');
const { createBoundMailInlineRouter, projectAssessment } = require('../server/routes/secureshop/boundMailInline');
function fixture(assessment) {
  const calls = [], requestId = randomUUID(), sessionId = randomUUID(); let result = { ok: true, status: 'unconfirmed', requestId }, error;
  const app = Object.fromEntries(['saveTeaching', 'readTeaching', 'summarize', 'readSummary'].map(name => [name,
    async (...args) => { calls.push({ name, args }); if (error) throw error; return result; }]));
  const router = createBoundMailInlineRouter({ application: app, assessment, authenticatePersona: (_req, _res, next) => next() });
  async function invoke(path, method, body = { requestId }) {
    const route = router.stack.find(layer => layer.route?.path === path && layer.route.methods[method]).route;
    const req = Object.assign(new EventEmitter(), { body, params: Object.assign(Object.create(null), { requestId }), query: {},
      is: () => true, ssLaunch: { owned: true }, ssUser: { id: 12, role: 'merchant' },
      ssPersonaSession: { sessionId: randomUUID(), authorityVersion: '1' } });
    if(path.includes(':sessionId')) req.params.sessionId=sessionId;
    const res = Object.assign(new EventEmitter(), { code: 200, set() {}, status(value) { this.code = value; return this; },
      json(value) { this.body = value; return this; } });
    await route.stack.at(-1).handle(req, res); return { req, res };
  }
  return { calls, requestId, sessionId, invoke, setResult: value => { result = value; }, setError: value => { error = value; } };
}
test('dedicated saved GET copies Express null-prototype params and never invokes work', async () => {
  const f = fixture(), { res, req } = await f.invoke('/email/inline/summary/:requestId', 'get');
  assert.equal(res.code, 200); assert.equal(f.calls[0].name, 'readSummary');
  assert.deepEqual(f.calls[0].args[1], { requestId: f.requestId });
  assert.equal(f.calls[0].args[2].signal.aborted, false);
  assert.equal(req.listenerCount('aborted'), 0); assert.equal(res.listenerCount('close'), 0);
});
test('POST accepts only opaque selectors, rejects authority/url/body extensions before service', async () => {
  const f = fixture();
  for (const body of [{ requestId: f.requestId, url: 'http://127.0.0.1' },
    Object.assign(Object.create(null), { requestId: f.requestId }), { requestId: 'bad' }]) {
    assert.equal((await f.invoke('/email/inline/teaching-message', 'post', body)).res.code, 400);
  }
  assert.equal(f.calls.length, 0);
  await f.invoke('/email/inline/summary', 'post', { requestId: f.requestId, readOperationId: randomUUID(), messageId: 2 });
  assert.equal(f.calls.length, 1); assert.equal(f.calls[0].name, 'summarize');
});
test('closed public projection rejects private extras and source substitution', async () => {
  const f = fixture();
  for (const result of [{ ok: true, status: 'unconfirmed', requestId: f.requestId, binding: {} },
    { ok: true, status: 'unconfirmed', requestId: randomUUID() }]) {
    f.setResult(result); const { res } = await f.invoke('/email/inline/summary/:requestId', 'get');
    assert.equal(res.code, 503); assert(!JSON.stringify(res.body).includes('binding'));
  }
});
test('fixed denial is explicit and no error detail or automatic retry is projected', async () => {
  const f = fixture(); f.setError(Object.assign(Error('private failure'), { code: 'MAIL_INLINE_FIXED_DENIED' }));
  const { res } = await f.invoke('/email/inline/summary', 'post', { requestId: f.requestId, readOperationId: randomUUID(), messageId: 2 });
  assert.equal(res.code, 403); assert.deepEqual(res.body, { ok: false, code: 'MAIL_INLINE_FIXED_DENIED', error: 'Inline image fetch blocked in fixed mode' });
});
test('canonical full judgment projects only public fields and fails closed on malformed required values',()=>{
 const judgment={verdict:'pass',evaluationId:randomUUID(),canRetry:false,evidenceDigest:'private',criteria:[{private:true}]};
 assert.deepEqual(projectAssessment({completed:true,replayed:false,judgment}),{completed:true,replayed:false,
  judgment:{verdict:'pass',evaluationId:judgment.evaluationId,canRetry:false}});
 for(const changed of [{...judgment,evaluationId:'bad'},{...judgment,canRetry:undefined},{...judgment,verdict:'fail'}])
  assert.throws(()=>projectAssessment({completed:true,replayed:false,judgment:changed}));
 assert.deepEqual(projectAssessment({completed:false,status:'ineligible',modelEvaluated:false}),
  {completed:false,status:'ineligible',modelEvaluated:false});
});
test('assessment physical POST and saved GET retain exact IDs/current authority and GET never regrades',async()=>{
 const calls=[],assessment={
  async runAttempt(input){calls.push(['post',input]);return {completed:true,replayed:false,judgment:{verdict:'pass',evaluationId:randomUUID(),canRetry:false,privatePacket:'secret'}};},
  async readOutcome(input){calls.push(['get',input]);return {completed:false,status:'unconfirmed',modelEvaluated:false};},
 };
 const f=fixture(assessment);
 const get=await f.invoke('/email/inline/assessment/:sessionId/:requestId','get');
 assert.equal(get.res.code,200);assert.equal(calls[0][0],'get');
 assert.equal(calls[0][1].sessionId,f.sessionId);assert.equal(calls[0][1].requestId,f.requestId);
 assert.deepEqual(calls[0][1].persona,{id:12,role:'merchant'});assert.equal(calls[0][1].signal.aborted,false);
 const post=await f.invoke('/email/inline/assessment','post',{sessionId:f.sessionId,requestId:f.requestId});
 assert.equal(post.res.code,200);assert.equal(calls[1][0],'post');assert(!JSON.stringify(post.res.body).includes('secret'));
 for(const extra of ['url','binding','mode','evaluationId']){
  const denied=await f.invoke('/email/inline/assessment','post',{sessionId:f.sessionId,requestId:f.requestId,[extra]:'not accepted'});
  assert.equal(denied.res.code,400);
 }
 assert.equal(calls.length,2);
});
