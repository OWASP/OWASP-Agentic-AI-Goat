'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createBoundPromptPolicyService } = require('../server/services/secureshopBoundPromptPolicyService');
const { requestDigest, ISOLATION } = require('../server/services/secureshopPromptPolicyContract');
const input = () => ({ action: 'upsert', expectedVersion: '1', scope: { launchId: 'owned' },
  request: { operationId: '018f5b4e-5c8a-4b9c-8d0e-1f2a3b4c5d6e', name: 'policy', markdown: 'exact', targets: ['admin'] } });
function fixture(state = 'admitted') {
  const calls = [];
  const repository = {
    async beginRender(value) { calls.push(['begin', value]); return { state, operationId: value.request.operationId,
      requestSha256: requestDigest(value.request), receipt: state === 'completed' ? { version: '2' } : undefined }; },
    async publish(value) { calls.push(['publish', value]); return { version: '2' }; },
    async remove() {}, async operation() {}, async list() {},
  };
  const renderer = { async render(request) { calls.push(['render', request]); const rendered = request.markdown;
    return { version: 1, operationId: request.operationId, requestSha256: requestDigest(request), isolation: ISOLATION,
      rendered, renderedSha256: createHash('sha256').update(rendered).digest('hex'), exitCode: 0,
      timedOut: false, truncated: false, drained: true }; } };
  return { repository, renderer, calls, service: createBoundPromptPolicyService({ repository, renderer }) };
}
test('new admission renders once outside admission and publishes captured inputs', async () => {
  const f = fixture(); const raw = input(); const promise = f.service.render(raw);
  raw.scope.launchId = 'different'; raw.request.markdown = 'changed';
  assert.deepEqual(await promise, { state: 'completed', receipt: { version: '2' } });
  assert.deepEqual(f.calls.map(call => call[0]), ['begin', 'render', 'publish']);
  assert.equal(f.calls[2][1].scope.launchId, 'owned');
  assert.equal(f.calls[2][1].renderResult.rendered, 'exact');
});
test('pending and completed replays never render or publish again', async () => {
  for (const state of ['pending', 'completed']) {
    const f = fixture(state); const result = await f.service.render(input());
    assert.equal(result.state, state); assert.deepEqual(f.calls.map(call => call[0]), ['begin']);
  }
});
test('invalid receipt and uncertain renderer failures never publish', async () => {
  for (const render of [async () => ({ forged: true }), async () => { throw new Error('lost response'); }]) {
    const f = fixture(); f.renderer.render = render;
    await assert.rejects(f.service.render(input()));
    assert.deepEqual(f.calls.map(call => call[0]), ['begin']);
  }
});
test('abort after durable admission leaves operation pending without render', async () => {
  const f = fixture(); const controller = new AbortController(); const begin = f.repository.beginRender;
  f.repository.beginRender = async value => { const result = await begin(value); controller.abort(); return result; };
  await assert.rejects(f.service.render(input(), { signal: controller.signal }), { name: 'AbortError' });
  assert.deepEqual(f.calls.map(call => call[0]), ['begin']);
});
test('mismatched admission is rejected before renderer', async () => {
  const f = fixture(); f.repository.beginRender = async () => ({ state: 'admitted', operationId: input().request.operationId, requestSha256: '0'.repeat(64) });
  await assert.rejects(f.service.render(input()), /Invalid policy render admission/);
  assert.equal(f.calls.length, 0);
});

test('administration scope key binds original session and launch without exposing coordinates', async () => {
 const f=fixture(); f.repository.list=async()=>({version:'1',policies:[]});
 const context={scope:{launchId:'launch',scenarioId:'scenario',generation:1,platformOwnerId:2,platformSessionId:3},persona:{id:4,role:'admin'},personaSession:{sessionId:'session',authorityVersion:'1'}};
 const original=await f.service.list(context); assert.match(original.administration.scopeKey,/^[a-f0-9]{64}$/);
 assert.equal(original.administration.versionedPolicy,true);
 for(const changed of [{...context,personaSession:{...context.personaSession,sessionId:'new-session'}},{...context,scope:{...context.scope,generation:2}}])assert.notEqual((await f.service.list(changed)).administration.scopeKey,original.administration.scopeKey);
 assert.equal((await f.service.list(context)).administration.scopeKey,original.administration.scopeKey);
});

test('renderer capacity rejects before reservation and releases on failure without blocking readback', async () => {
 const f=fixture(); const release=Promise.withResolvers(); const entered=Promise.withResolvers();
 f.renderer.render=async()=>{entered.resolve();await release.promise;throw Error('controlled failure');};
 const service=createBoundPromptPolicyService({repository:f.repository,renderer:f.renderer,maxConcurrentRenders:1});
 const first=service.render(input()); const failure=assert.rejects(first,/controlled failure/); await entered.promise;
 await assert.rejects(service.render(input()),{code:'POLICY_RENDER_BUSY'});
 assert.equal(f.calls.filter(call=>call[0]==='begin').length,1);
 let read=false; f.repository.operation=async()=>{read=true;return{state:'pending'};};
 assert.deepEqual(await service.operation({}),{state:'pending'}); assert.equal(read,true);
 release.resolve();await failure;
 f.repository.beginRender=async value=>({state:'pending',operationId:value.request.operationId,requestSha256:requestDigest(value.request)});
 assert.equal((await service.render(input())).state,'pending');
 for(const maxConcurrentRenders of [0,17,1.5])assert.throws(()=>createBoundPromptPolicyService({repository:f.repository,renderer:f.renderer,maxConcurrentRenders}));
});

test('v2 admits exact task targets but renders only the v1 projection and validates alias binding', async () => {
  const task = require('../server/services/secureshopPromptPolicyTaskMutation');
  const raw = input(); raw.request = { ...raw.request, contractVersion: 2, targets: ['summarizer', 'review-moderator'] };
  for (const corrupt of [null, 'admission', 'publication']) {
    const f = fixture(); let renders = 0;
    const projection = task.renderRequest(raw.request), digest = task.taskMutationDigest(raw.request);
    f.repository.beginRender = async value => {
      assert.deepEqual(value.request.targets, ['review-moderator', 'summarizer']);
      return { state: 'admitted', operationId: projection.operationId, requestSha256: requestDigest(projection), policyRequestSha256: corrupt === 'admission' ? '0'.repeat(64) : digest };
    };
    const originalRender = f.renderer.render;
    f.renderer.render = async request => { renders++; assert.deepEqual(request, projection); return originalRender(request); };
    f.repository.publish = async value => ({ version: '2', operationId: projection.operationId, requestSha256: requestDigest(projection),
      policyRequestSha256: corrupt === 'publication' ? '0'.repeat(64) : digest, renderResult: value.renderResult });
    if (corrupt) await assert.rejects(f.service.render(raw));
    else assert.equal((await f.service.render(raw)).receipt.policyRequestSha256, digest);
    assert.equal(renders, corrupt === 'admission' ? 0 : 1);
  }
});

test('policy readiness checks the configured strict renderer without admitting policy operations',async()=>{
 const f=fixture();let probes=0;
 f.renderer.checkReadiness=async()=>{probes++;return true;};
 assert.deepEqual(await f.service.readiness(),{ready:true});assert.equal(probes,1);assert.deepEqual(f.calls,[]);
 f.renderer.checkReadiness=async()=>false;await assert.rejects(f.service.readiness(),{code:'POLICY_RENDER_UNAVAILABLE'});
 delete f.renderer.checkReadiness;await assert.rejects(f.service.readiness(),{code:'POLICY_RENDER_UNAVAILABLE'});
 assert.deepEqual(f.calls,[]);
});
