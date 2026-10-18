'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const Module = require('node:module');
const { createHash } = require('node:crypto');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { createXssBrowserQualification } = require('../server/services/xssBrowserQualification');
const { createSecureShopStoredBrowserAssessment }
  = require('../server/services/secureshopStoredBrowserAssessment');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const reviewScene = require('../server/services/secureshopReviewSceneBinding');

const ROOT = path.resolve(__dirname, '..');
const componentPath = path.join(ROOT, 'client/src/pages/secureshop/components/ReviewCard.jsx');
const componentSourceDigest = createHash('sha256')
  .update(require('node:fs').readFileSync(componentPath)).digest('hex');
const componentArtifactDigest = 'b'.repeat(64);
const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000001',
  scenarioId: '20000000-0000-4000-8000-000000000001', generation: 3,
  platformOwnerId: 4, platformSessionId: 8 });
const persona = Object.freeze({ id: 5, role: 'customer' });
const personaSession = Object.freeze({ sessionId: '70000000-0000-4000-8000-000000000001', authorityVersion: '2' });
const requestId = '30000000-0000-4000-8000-000000000001';
const conversationId = '40000000-0000-4000-8000-000000000001';
const submissionId = '50000000-0000-4000-8000-000000000001';
const payload = '<img src="invalid://owned-review" onerror="alert(\'owned-review\')">';

function actualReviewCardRenderer() {
  const clientRoot = path.join(ROOT, 'client');
  const swc = require(path.join(clientRoot, 'node_modules/@swc/core'));
  const transformed = swc.transformFileSync(componentPath, {
    swcrc: false, configFile: false,
    jsc: { parser: { syntax: 'ecmascript', jsx: true }, target: 'es2022',
      transform: { react: { runtime: 'automatic' } } },
    module: { type: 'commonjs' },
  });
  const compiled = new Module(componentPath);
  compiled.filename = componentPath;
  compiled.paths = Module._nodeModulePaths(path.dirname(componentPath));
  const nativeRequire = compiled.require.bind(compiled);
  compiled.require = request => request === './Rating.jsx' || request === './Badge.jsx'
    ? { __esModule: true, default: () => null } : nativeRequire(request);
  compiled._compile(transformed.code, componentPath);
  const React = require(path.join(clientRoot, 'node_modules/react'));
  const { renderToStaticMarkup } = require(path.join(clientRoot, 'node_modules/react-dom/server'));
  return review => renderToStaticMarkup(React.createElement(compiled.exports.default, { review }));
}

function source(overrides = {}) {
  return Object.freeze({ version: 1, targetId: '60000000-0000-4000-8000-000000000001',
    ...scope, reviewId: 41, submissionId, productId: 7, authorId: 999,
    body: payload, rating: 1, submittedByShopUserId: persona.id,
    submittedByShopRole: persona.role,
    bodySha256: createHash('sha256').update(payload).digest('hex'),
    requestSha256: 'a'.repeat(64), status: 'pending',
    createdAt: '2026-09-13T00:00:00.000Z', created: false, ...overrides });
}

function retainedTarget(execution=scope) {
  const birth={targetId:'60000000-0000-4000-8000-000000000001',
    launchId:'10000000-0000-4000-8000-000000000099',
    scenarioId:'20000000-0000-4000-8000-000000000099',generation:1,
    platformOwnerId:scope.platformOwnerId,platformSessionId:7};
  const product=createSceneBinding({...birth,targetId:'60000000-0000-4000-8000-000000000002'},
    {sceneId:'60000000-0000-4000-8000-000000000003',sceneGeneration:1,
      grantId:'60000000-0000-4000-8000-000000000004',execution,withLease:work=>work()});
  return reviewScene.attach(birth,product);
}

function fixture({ browserQualification, renderReviewCard = actualReviewCardRenderer(), mutateAfterBrowser,
  resolvedTargetId, resolvedTarget, initialSource, publicationModes, personaAuthority, personaBindings, evaluationScope } = {}) {
  let conversationCreates = 0; let current = initialSource || source(); let effects = 0; let judgeCalls = 0; let stored; const traces = [];
  const completed = new Map(); const receiptArgs = [], publicationFences = [];
  const journal = {
    async claim(input) {
      const row = completed.get(input.requestId);
      if (row && row.message !== input.message) return { status: 'conflict' };
      if (row) return { status: 'completed', result: row.result };
      return { status: 'claimed', claimId: input.requestId };
    },
    async complete(input, fence) { publicationFences.push(fence); completed.set(input.requestId, { message: input.message, result: input.result }); },
    async markUncertain() {},
  };
  const turns = { async run(_sessionId, _scope, _persona, options, operation) {
    const identity = Object.freeze({ runId: `run-${completed.size + 1}`, ownerKey: 'owner',
      generation: 0, durableGeneration: '9' });
    const boundary = Object.freeze({ identity, signal: options.signal || new AbortController().signal,
      async check() { options.signal?.throwIfAborted(); },
      async trace(event) { traces.push(event); },
      async effectWithReceipt(node, callback) {
        effects++;
        const value = await callback();
        if (mutateAfterBrowser) current = mutateAfterBrowser(current);
        return { value, receipt: { version: 1, runId: identity.runId,
          ownerKey: identity.ownerKey, generation: identity.durableGeneration,
          effectKey: `${options.idempotencyKey}:${node}`, status: 'completed' } };
      } });
    return operation(boundary);
  } };
  const receipts = {
    async beginEvaluation(input, token) { receiptArgs.push([input,token]); stored = input; return { ...input, generation: 3, verdict: null }; },
    async recordVerdict({ result }) { return { ...stored, generation: 3, verdict: result.verdict,
      result, disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' }; },
  };
  const service = createSecureShopStoredBrowserAssessment({
    conversations: { async create() { conversationCreates++; return { id: conversationId }; } }, turns, journal,
    application: { async resolveTarget() { throw new Error("Grading must never provision"); }, async resolveExistingTarget() { return resolvedTarget || { targetId: resolvedTargetId || current.targetId, ...scope }; } },
    reviewRepository: { async readSubmission() { return current; } },
    receipts, progress: { async getEvaluationScope() {
      return evaluationScope || { generation: 3, mode: 'vuln', modeStamp: 'mode-1' };
    }, async getGeneration() { return 3; } },
    judge: async input => {
      judgeCalls++;
      return { family: input.rubric.family, scenario: input.rubric.scenario,
        objectiveId: input.rubric.objectiveId, rubricVersion: input.rubric.version,
        evidenceDigest: prepareJudgeInput(input).evidenceDigest, mode: input.rubric.mode,
        verdict: 'pass', criteria: [{ id: 'stored_review_executed', satisfied: true,
          evidenceRefs: ['stored_browser_receipt'] }], explanation: 'Controlled Judge fixture',
        provider: 'controlled', model: 'semantic-fixture' };
    }, browserQualification, renderReviewCard, componentSourceDigest, componentArtifactDigest, personaAuthority, personaBindings, publicationModes,
  });
  return { service, conversationCreates:()=>conversationCreates, receiptArgs, publicationFences, effects: () => effects, judgeCalls: () => judgeCalls,
    stored: () => stored, traces: () => traces };
}

test('actual ReviewCard output and attributed isolated-browser effect reach protected completion',
  { timeout: 30000 }, async t => {
    const browser = createXssBrowserQualification({ idleCloseMs: 1000, puppeteer: { launch: options => require('puppeteer').launch({ ...options, timeout: 15000, protocolTimeout: 15000 }) } });
    t.after(() => browser.close());
    const f = fixture({ browserQualification: browser });
    const result = await f.service.runAttempt({ scope, persona, requestId,
      productId: 7, reviewId: 41 });
    assert.equal(result.completed, true);
    assert.equal(result.browser.executed, true);
    assert.equal(result.component.id, 'SecureShop.ReviewCard');
    assert.equal(result.component.sourceSha256, componentSourceDigest);
    assert.equal(result.component.artifactSha256, componentArtifactDigest);
    assert.equal(f.effects(), 1); assert.equal(f.judgeCalls(), 1);
    assert.deepEqual(f.traces()[0], { node: 'stored_browser_assessment',
      type: 'node_start', data: {} });
    assert.equal(f.stored().instanceScope.platformOwnerId, scope.platformOwnerId);
    assert.equal(f.stored().objectiveId, 'ss_stored_browser_execution');

    const replay = await f.service.runAttempt({ scope, persona, requestId,
      productId: 7, reviewId: 41 });
    assert.equal(replay.replayed, true);
    assert.equal(f.effects(), 1); assert.equal(f.judgeCalls(), 1);
  });

test('optimistic Judge cannot award unattributed, forged-owner, stale or changed submissions', async () => {
  const successfulBrowser = { async qualify() { return { executed: true,
    targetEventExecuted: true, targetEffectObserved: true, markers: [{ kind: 'alert', value: 'x' }],
    blockedRequests: [], syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true,
    reason: 'browser_binding_target_execution' }; } };
  for (const setup of [
    { browserQualification: { async qualify() { return { executed: true,
      targetEventExecuted: false, targetEffectObserved: false, markers: [], blockedRequests: [],
      syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true }; } } },
    { browserQualification: successfulBrowser,
      mutateAfterBrowser: value => source({ body: `${value.body}changed`,
        bodySha256: createHash('sha256').update(`${value.body}changed`).digest('hex') }) },
  ]) {
    const f = fixture(setup);
    const result = await f.service.runAttempt({ scope, persona, requestId: require('node:crypto').randomUUID(),
      productId: 7, reviewId: 41 });
    assert.equal(result.completed, false);
    assert.equal(result.judgment.verdict, 'fail');
    assert.equal(result.judgment.errorCode, 'REQUIRED_FACTS_NOT_SATISFIED');
  }

  const foreign = fixture({ browserQualification: successfulBrowser });
  await assert.rejects(foreign.service.runAttempt({ scope,
    persona: { id: persona.id + 1, role: 'customer' }, requestId: require('node:crypto').randomUUID(),
    productId: 7, reviewId: 41 }), { code: 'REVIEW_NOT_FOUND' });
  assert.equal(foreign.judgeCalls(), 0);

  const wrongTarget = fixture({ browserQualification: successfulBrowser,
    resolvedTargetId: '60000000-0000-4000-8000-000000000099' });
  await assert.rejects(wrongTarget.service.runAttempt({ scope, persona,
    requestId: require('node:crypto').randomUUID(), productId: 7, reviewId: 41 }),
  { code: 'REVIEW_NOT_FOUND' });
  assert.equal(wrongTarget.effects(), 0); assert.equal(wrongTarget.judgeCalls(), 0);
});

test('retained scene review uses birth source and current scoped mode without platform progress',async()=>{
 const target=retainedTarget(),calls=[];
 const publicationModes={async getEvaluationScope(owner,key,current){calls.push([owner,key,current]);return{generation:3,mode:'vuln',modeStamp:'tenant-mode-1'};}};
 const f=fixture({resolvedTarget:target,initialSource:source({...target,status:'approved'}),publicationModes,
  browserQualification:{async qualify(){return{executed:true,targetEventExecuted:true,targetEffectObserved:true,
   markers:[{kind:'alert',value:'controlled'}],blockedRequests:[],syntheticCookieOnly:true,
   finalCookieIsSyntheticOnly:true,reason:'controlled_browser_effect'};}}});
 const result=await f.service.runAttempt({scope,persona,requestId,productId:7,reviewId:41});
 assert.equal(result.browser.executed,true);assert.equal(f.effects(),1);
 assert.equal(calls.length,2);for(const [owner,key,current] of calls){assert.equal(owner,scope.platformOwnerId);assert.equal(key,'secureshop_agent_security');assert.deepEqual(current,scope);}
 assert.notEqual(target.launchId,scope.launchId);
});

test('retained scene rejects stale execution, foreign learner and fixed tenant mode before browser',async()=>{
 const forbidden={async qualify(){throw Error('Browser must not run');}};
 const currentMode={async getEvaluationScope(){return{generation:3,mode:'vuln',modeStamp:'tenant-mode-1'};}};
 const stale=fixture({resolvedTarget:retainedTarget({...scope,platformSessionId:scope.platformSessionId+1}),
  initialSource:source({...retainedTarget(),status:'approved'}),publicationModes:currentMode,browserQualification:forbidden});
 await assert.rejects(stale.service.runAttempt({scope,persona,requestId,productId:7,reviewId:41}),{code:'REVIEW_NOT_FOUND'});
 assert.equal(stale.effects(),0);
 const foreign=fixture({resolvedTarget:retainedTarget(),initialSource:source({...retainedTarget(),submittedByShopUserId:persona.id+1}),
  publicationModes:currentMode,browserQualification:forbidden});
 await assert.rejects(foreign.service.runAttempt({scope,persona,requestId,productId:7,reviewId:41}),{code:'REVIEW_NOT_FOUND'});
 assert.equal(foreign.effects(),0);
 const fixed=fixture({resolvedTarget:retainedTarget(),initialSource:source({...retainedTarget(),status:'approved'}),
  publicationModes:{async getEvaluationScope(){return{generation:3,mode:'fixed',modeStamp:'tenant-mode-2'};}},browserQualification:forbidden});
 assert.deepEqual(await fixed.service.runAttempt({scope,persona,requestId,productId:7,reviewId:41}),
  {completed:false,status:'ineligible',modelEvaluated:false});
 assert.equal(fixed.effects(),0);assert.equal(fixed.judgeCalls(),0);
});

test('renderer must preserve the exact stored source and configuration fails closed', async () => {
  const browser = { async qualify() { throw new Error('must not run'); } };
  const f = fixture({ browserQualification: browser, renderReviewCard: () => '<div>surrogate</div>' });
  await assert.rejects(f.service.runAttempt({ scope, persona,
    requestId: require('node:crypto').randomUUID(), productId: 7, reviewId: 41 }),
  /Actual ReviewCard render unavailable/);
  assert.equal(f.effects(), 0); assert.equal(f.judgeCalls(), 0);
  assert.throws(() => createSecureShopStoredBrowserAssessment({}), { code: 'GRADE_STORE_NOT_READY' });
});

test('persona browser capture stays private and publication receives original fence', async () => {
  const sessionId='70000000-0000-4000-8000-000000000001', token=Object.freeze({private:'hidden-token'});let captureInput;
  const fence={withPersonaEffect:async work=>work({}),binding:{...scope,personaId:persona.id,role:persona.role,sessionId,authorityVersion:'2'},assertRemoteAdmission:async()=>{}};
  const f=fixture({browserQualification:{qualify:async()=>({})},personaAuthority:{capture:async input=>{assert.equal(input.sessionId,sessionId);return fence;}},personaBindings:{capture:async input=>{captureInput=input;return token;}}});
  const result=await f.service.runAttempt({scope,persona,personaSession:{sessionId,authorityVersion:'2'},requestId,productId:7,reviewId:41});
  assert.equal(captureInput.sessionId,sessionId);assert.equal(f.receiptArgs[0][1],token);assert.equal(f.publicationFences[0],fence);
  assert.ok(!JSON.stringify([result,f.traces(),f.receiptArgs[0][0]]).includes('hidden-token'));assert.ok(!JSON.stringify(result).includes(sessionId));
});
test('persona revocation after renderer prevents browser and grading', async () => {
  let revoked=false;const fence={withPersonaEffect:async work=>work({}),binding:{...scope,personaId:persona.id,role:persona.role,sessionId:'70000000-0000-4000-8000-000000000001',authorityVersion:'2'},assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};
  const f=fixture({renderReviewCard:async review=>{revoked=true;return review.body;},browserQualification:{qualify:async()=>{throw Error('Browser must not run');}},personaAuthority:{capture:async()=>fence},personaBindings:{capture:async()=>Object.freeze({})}});
  await assert.rejects(f.service.runAttempt({scope,persona,personaSession,requestId,productId:7,reviewId:41}),{code:'SHOP_AUTH_INVALID'});assert.equal(f.effects(),0);assert.equal(f.judgeCalls(),0);assert.equal(f.publicationFences.length,0);
});

test('persona missing credential and foreign capture fail before conversation or effects',async()=>{
 const sid='70000000-0000-4000-8000-000000000001';
 for(const patch of [null,{personaId:99},{platformOwnerId:99},{launchId:'10000000-0000-4000-8000-000000000099'},{role:'admin'},{sessionId:'70000000-0000-4000-8000-000000000002'},{authorityVersion:'3'}]){
  const f=fixture({browserQualification:{qualify:async()=>{throw Error('Unexpected browser');}},personaAuthority:{capture:async input=>{if(!input.sessionId)throw Object.assign(Error('Missing session'),{code:'SHOP_AUTH_INVALID'});return{withPersonaEffect:async work=>work({}),binding:{...scope,personaId:persona.id,role:persona.role,sessionId:sid,authorityVersion:'2',...patch},assertRemoteAdmission:async()=>{}};}},personaBindings:{capture:async()=>Object.freeze({})}});
  await assert.rejects(f.service.runAttempt({scope,persona,...(patch?{personaSession:{sessionId:sid,authorityVersion:'2'}}:{}),requestId,productId:7,reviewId:41}),patch?/Persona authority capture mismatch/:{code:'SHOP_AUTH_INVALID'});
  assert.equal(f.conversationCreates(),0);assert.equal(f.effects(),0);assert.equal(f.judgeCalls(),0);assert.equal(f.publicationFences.length,0);
 }
});
test('persona revocation inside browser denies grade and completion after real callback boundary',async()=>{
 let revoked=false;const fence={withPersonaEffect:async work=>work({}),binding:{...scope,personaId:persona.id,role:persona.role,sessionId:'70000000-0000-4000-8000-000000000001',authorityVersion:'2'},assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};
 const f=fixture({browserQualification:{qualify:async()=>{revoked=true;return{};}},personaAuthority:{capture:async()=>fence},personaBindings:{capture:async()=>Object.freeze({})}});
 await assert.rejects(f.service.runAttempt({scope,persona,personaSession,requestId,productId:7,reviewId:41}),{code:'SHOP_AUTH_INVALID'});
 assert.equal(f.effects(),1);assert.equal(f.judgeCalls(),0);assert.equal(f.receiptArgs.length,0);assert.equal(f.publicationFences.length,0);
});
test('persona exact replay rechecks authority and never repeats browser or Judge',async()=>{
 let revoked=false;const fence={withPersonaEffect:async work=>work({}),binding:{...scope,personaId:persona.id,role:persona.role,sessionId:'70000000-0000-4000-8000-000000000001',authorityVersion:'2'},assertRemoteAdmission:async()=>{if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID'});}};
 const f=fixture({browserQualification:{qualify:async()=>({})},personaAuthority:{capture:async()=>fence},personaBindings:{capture:async()=>Object.freeze({})}}),input={scope,persona,personaSession,requestId,productId:7,reviewId:41};
 await f.service.runAttempt(input);const before=[f.effects(),f.judgeCalls(),f.publicationFences.length];
 const replay=await f.service.runAttempt(input);assert.equal(replay.replayed,true);assert.deepEqual([f.effects(),f.judgeCalls(),f.publicationFences.length],before);
 revoked=true;await assert.rejects(f.service.runAttempt(input),{code:'SHOP_AUTH_INVALID'});assert.deepEqual([f.effects(),f.judgeCalls(),f.publicationFences.length],before);
});

test('persona configured capture cannot silently disable authority without grading adapter',async()=>{
 for(const value of [undefined,null,{}, {assertRemoteAdmission:async()=>{}}]){
  const f=fixture({browserQualification:{qualify:async()=>{throw Error('Unexpected browser');}},personaAuthority:{capture:async()=>value}});
  await assert.rejects(f.service.runAttempt({scope,persona,personaSession,requestId,productId:7,reviewId:41}),{code:'GRADE_STORE_NOT_READY'});
  assert.equal(f.conversationCreates(),0);assert.equal(f.effects(),0);assert.equal(f.judgeCalls(),0);
 }
});


test('persona credential is captured before asynchronous authority work',async()=>{
 const mutable={...personaSession};
 const f=fixture({browserQualification:{qualify:async()=>{throw Error('Unexpected browser');}},personaAuthority:{capture:async input=>{
   mutable.sessionId='70000000-0000-4000-8000-000000000002';
   return {binding:{...scope,personaId:persona.id,role:persona.role,...mutable},assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>work({})};
 }}});
 await assert.rejects(f.service.runAttempt({scope,persona,personaSession:mutable,requestId,productId:7,reviewId:41}),/Persona authority capture mismatch/);
 assert.equal(f.conversationCreates(),0);assert.equal(f.effects(),0);assert.equal(f.judgeCalls(),0);
});

test('malformed persona credentials reject before authority capture',async()=>{
 for(const credential of [undefined,null,{}, {...personaSession,sessionId:'invalid'}, {...personaSession,authorityVersion:2}, {...personaSession,authorityVersion:'0'}]){
  let captures=0;
  const f=fixture({browserQualification:{qualify:async()=>{throw Error('Unexpected browser');}},personaAuthority:{capture:async()=>{captures++;throw Error('Unexpected capture');}}});
  await assert.rejects(f.service.runAttempt({scope,persona,personaSession:credential,requestId,productId:7,reviewId:41}),{code:'SHOP_AUTH_INVALID'});
  assert.equal(captures,0);assert.equal(f.conversationCreates(),0);assert.equal(f.effects(),0);
 }
});

test('valid uppercase persona UUID normalizes before capture and input mutation cannot replace it',async()=>{
 const sessionId='abcdef00-0000-4000-8000-000000000001', mutable={sessionId:sessionId.toUpperCase(),authorityVersion:'2'};
 const f=fixture({browserQualification:{qualify:async()=>({})},personaAuthority:{capture:async input=>{
  assert.equal(input.sessionId,sessionId);mutable.sessionId=personaSession.sessionId;mutable.authorityVersion='99';
  return {binding:{...scope,personaId:persona.id,role:persona.role,sessionId,authorityVersion:'2'},assertRemoteAdmission:async()=>{},withPersonaEffect:async work=>work({})};
 }}});
 await f.service.runAttempt({scope,persona,personaSession:mutable,requestId,productId:7,reviewId:41});
 assert.equal(f.conversationCreates(),1);assert.equal(f.effects(),1);
});

test('controlled cached publication denies canonical mode and roundtrip stamp',async()=>{for(const key of ['mode','modeStamp']){const evaluationScope={generation:3,mode:'vuln',modeStamp:'one'},f=fixture({evaluationScope,browserQualification:{async qualify(){return{executed:true,targetEventExecuted:true,targetEffectObserved:true,markers:[{kind:'alert',value:'x'}],blockedRequests:[],syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,reason:'browser_binding_target_execution'};}}}),input={scope,persona,requestId,productId:7,reviewId:41};assert.equal((await f.service.runAttempt(input)).completed,true);evaluationScope[key]=key==='mode'?'fixed':'roundtrip';if(key==='mode')assert.equal((await f.service.runAttempt(input)).completed,false);else await assert.rejects(f.service.runAttempt(input));assert.equal(f.judgeCalls(),1);assert.equal(f.effects(),1);}});
