'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const facet = require('./support/ctfFixedPracticeRenderedCases');

function receipt() {
  const phases=['pre-provider-stale','pre-provider-restore','post-provider-stale','post-provider-restore'];
  return { version: 1, profile: facet.PROFILE, actorId: '2403', sessionId: '10',
    participantId: '2403', stageId: 1, siblingOwnerId: '1001',
    cases: {
      modeSelection: { browserPosts: 0, serverPosts: 0, providerStarts: 0,
        responsePublished: false, stateInvariant: true },
      submit: { browserPosts: 1, serverPosts: 1, providerStarts: 1,
        responsePublished: true, status: 200, scoringEligible: false,
        protectedContextIncluded: false, serverSecretProvided: false },
      staleBeforeDispatch: { browserPosts: 0, serverPosts: 0, providerStarts: 0,
        responsePublished: false, stateInvariant: true },
      staleBeforeProvider: { browserPosts: 1, serverPosts: 1, providerStarts: 0,
        responsePublished: false, status: 409, stateInvariant: true },
      staleAfterDispatch: { browserPosts: 1, serverPosts: 1, providerStarts: 1,
        responsePublished: false, status: 409, stateInvariant: true },
    },
    providerDiagnostics: { kind: 'controlled-synthetic-provider', physicalStarted: 2,
      completed: 1, staleAfterDispatch: 1, maxPhysicalCalls: 2 },
    authorityOperations: phases.map((phase,index)=>({phase,
      operationId:`00000000-0000-4000-8000-${String(index+1).padStart(12,'0')}`,
      sequence:String(index+1),actorId:'1002',sessionId:'11',stageId:1})),
    storeWitness: Object.fromEntries(facet.WITNESS.map(key => [key, true])),
    cleanup: { providerDrained: true, ownedBrowserHandles: 0, ownedStoreHandles: 0 },
    facts: Object.fromEntries(facet.FACTS.map(key => [key, true])),
    excluded: [...facet.EXCLUDED], unexpectedApiPaths: [], browserActions: 24,
    apiRequests: 32, stage: 'complete', judgeCalls: 0, genuineCredit: 0 };
}
const tamper = fn => { const value = receipt(); fn(value);
  assert.throws(() => facet.assertFixedPracticeReceipt(value)); };

test('Fixed practice receipt is bounded controlled-provider evidence, never scored qualification', () => {
  assert.equal(facet.assertFixedPracticeReceipt(receipt()), true);
  assert.equal(facet.POST_PATH, '/api/ctf/stage/1/practice');
  assert(facet.EXCLUDED.includes('actual-model-qualification'));
  assert(facet.EXCLUDED.includes('operation-id-recovery'));
});

test('receipt rejects fabricated retry, recovery, provider, publication, or scoring claims', () => {
  tamper(r => { r.cases.modeSelection.browserPosts = 1; });
  tamper(r => { r.cases.submit.scoringEligible = true; });
  tamper(r => { r.cases.submit.protectedContextIncluded = true; });
  tamper(r => { r.cases.staleBeforeDispatch.providerStarts = 1; });
  tamper(r => { r.cases.staleAfterDispatch.responsePublished = true; });
  tamper(r => { r.providerDiagnostics.kind = 'actual-model'; });
  tamper(r => { r.providerDiagnostics.physicalStarted = 3; });
  tamper(r => { r.storeWitness.progressUnchanged = false; });
  tamper(r => { r.authorityOperations[1].sequence = '1'; });
  tamper(r => { r.authorityOperations[2].operationId = r.authorityOperations[0].operationId; });
  tamper(r => { r.authorityOperations[0].phase = 'fabricated'; });
  tamper(r => { r.authorityOperations[0].stageId = 2; });
  tamper(r => { r.authorityOperations[0].actorId = '0'; });
  tamper(r => { r.authorityOperations.pop(); });
  tamper(r => { r.cleanup.providerDrained = false; });
  tamper(r => { r.judgeCalls = 1; });
  tamper(r => { r.genuineCredit = 1; });
  tamper(r => { r.unexpectedApiPaths.push('/api/ctf/operations/fake'); });
  tamper(r => { r.excluded.pop(); });
});

test('prospective admission allows only ordinary page reads and the one practice POST', () => {
  assert.equal(facet.fixedPracticeApiAllowed('POST', facet.POST_PATH), true);
  assert.equal(facet.fixedPracticeApiAllowed('GET', '/api/ctf/status'), true);
  assert.equal(facet.fixedPracticeApiAllowed('GET', '/api/changes/revisions'), true);
  for (const [method, pathname] of [
    ['POST', '/api/ctf/stage/1/attempt'], ['POST', '/api/ctf/stage/1/hint'],
    ['POST', '/api/ctf/admin/config'], ['GET', '/api/ctf/operations/00000000-1111-4111-8111-111111111111'],
    ['POST', '/api/ctf/stage/2/practice'], ['PUT', facet.POST_PATH],
  ]) assert.equal(facet.fixedPracticeApiAllowed(method, pathname), false, `${method} ${pathname}`);
});

test('actual UI and server retain public, unscored, no-operation-recovery practice semantics', () => {
  const root = path.join(__dirname, '..', '..');
  const ui = fs.readFileSync(path.join(root, 'client/src/pages/CTFChallenge.js'), 'utf8');
  const route = fs.readFileSync(path.join(root, 'server/routes/ctfAuthorityRouter.js'), 'utf8');
  const service = fs.readFileSync(path.join(root, 'server/services/ctfFixedPracticeRoute.js'), 'utf8');
  assert(ui.includes("`/api/ctf/stage/${stage.id}/practice`"));
  assert(ui.includes("content: 'Fixed practice — unscored. This response cannot award completion credit, points, or progression.'"));
  assert(ui.includes('Fixed response confirmed: protected context withheld, server secret withheld, and scoring disabled.'));
  assert.match(route, /router\.post\('\/stage\/:stageId\/practice',auth\(\),body\(\['payload','sessionToken'\]\),ctfAttemptInput\('stageId'\),wrap\(practiceHandler\)\)/);
  assert(service.includes('const captured=await runtime.practiceCapture'));
  assert(service.includes('await runtime.practiceRevalidate'));
  assert(service.includes('scoringEligible:false,protectedContextIncluded:false,serverSecretProvided:false'));
  assert(!service.includes('operationId'), 'practice must not acquire saved-operation recovery');
});

test('client-stale facet types under current owner, then invalidates immediately before physical pointer', async () => {
  const events=[];
  let stale=false, enabled=false, clicks=0, disposals=0;
  const page={
    async type(selector,value) {
      assert.equal(selector,'textarea[placeholder="Try the same prompt against the fixed practice path..."]');
      assert.equal(value,'fixed practice stale in client');
      enabled=!stale; events.push('type');
    },
    async waitForFunction() {
      events.push('locate');
      if(!enabled) throw Error('Rendered submit is disabled');
      return {asElement(){return this;},async click(){events.push('pointer');clicks++;},
        async dispose(){events.push('dispose');disposals++;}};
    },
  };
  await facet.physicalFixedSubmit(page,'http://127.0.0.1:18080',
    'fixed practice stale in client',false,async()=>{
      events.push('invalidate');stale=true;
    });
  assert.deepEqual(events,['type','locate','invalidate','pointer','dispose']);
  assert.equal(clicks,1);assert.equal(disposals,1);

  // The failed native ordering invalidated before typing. That rerender
  // cannot supply an enabled submit and therefore proves no physical click.
  stale=true;enabled=false;events.length=0;
  await assert.rejects(facet.physicalFixedSubmit(page,'http://127.0.0.1:18080',
    'fixed practice stale in client',false),/Rendered submit is disabled/);
  assert.deepEqual(events,['type','locate']);
  assert.equal(clicks,1);
});

test('client-stale pre-pointer failure retires the enabled handle without dispatch', async () => {
  let clicks=0,disposals=0;
  const page={async type(){},async waitForFunction(){return {
    asElement(){return this;},async click(){clicks++;},async dispose(){disposals++;},
  };}};
  await assert.rejects(facet.physicalFixedSubmit(page,'http://127.0.0.1:18080',
    'fixed practice stale in client',false,async()=>{throw Error('authority fault failed');}),
  /authority fault failed/);
  assert.equal(clicks,0);assert.equal(disposals,1);
});

test('bounded response waiter is handled before typing and its failure is not swallowed', async () => {
  let rejectResponse,observers=0,clicks=0;
  const response=new Promise((_,reject)=>{rejectResponse=reject;});
  const originalCatch=response.catch.bind(response);
  response.catch=(handler)=>{observers++;return originalCatch(handler);};
  const page={
    waitForResponse(){return response;},
    async type(){
      assert.equal(observers,1,'Response rejection must be observed before typing can stall');
      rejectResponse(Error('response timed out while typing'));
      await Promise.resolve();
    },
    async waitForFunction(){return {asElement(){return this;},
      async click(){clicks++;},async dispose(){}};},
  };
  await assert.rejects(facet.physicalFixedSubmit(page,'http://127.0.0.1:18080',
    'fixed practice baseline'),/response timed out while typing/);
  assert.equal(clicks,1,'Physical click remains measured even if response has already failed');

  let rejectNext,secondObservers=0;
  const next=new Promise((_,reject)=>{rejectNext=reject;});
  const nextCatch=next.catch.bind(next);
  next.catch=(handler)=>{secondObservers++;return nextCatch(handler);};
  const failedTyping={waitForResponse(){return next;},async type(){
    assert.equal(secondObservers,1);
    rejectNext(Error('response timed out while typing'));
    await Promise.resolve();
    throw Error('typing failed');
  }};
  await assert.rejects(facet.physicalFixedSubmit(failedTyping,'http://127.0.0.1:18080',
    'fixed practice baseline'),/typing failed/);
});

test('measured helper rejects a receipt façade and requires mounted observation capabilities', async () => {
  await assert.rejects(facet.runCtfFixedPracticeRenderedCases({ receipt: receipt() }));
  const before = { attempts: ['target'], progress: ['target'], judgments: [], leaderboard: [],
    outbox: [], sibling: ['separate-owner'] };
  assert.deepEqual(facet.fixedPracticeStoreWitness(before, structuredClone(before)),
    Object.fromEntries(facet.WITNESS.map(key => [key, true])));
  assert.throws(() => facet.fixedPracticeStoreWitness(before, { ...structuredClone(before),
    progress: ['changed'] }));
  assert.throws(() => facet.fixedPracticeStoreWitness(before, { ...structuredClone(before),
    outbox: [{ operation_id:'unexpected',sequence:'1' }] }, []));
  assert.throws(() => facet.fixedPracticeStoreWitness({ ...before, sibling: [] }, before));
  assert.deepEqual(facet.fixedPracticeResponse({ status: 409,
    body: { error: 'CTF practice is no longer current' } }, false).body,
  { error: 'CTF practice is no longer current' });
  assert.throws(() => facet.fixedPracticeResponse({ status: 409,
    body: { error: 'stale' } }, false));
});

test('measured helper owns browser, response, provider, and store observation rather than accepting outcomes', () => {
  const helper = fs.readFileSync(path.join(__dirname, 'support',
    'ctfFixedPracticeRenderedCases.js'), 'utf8');
  assert(helper.includes("page.on('request', requestListener)"));
  assert(helper.includes("page.on('response', responseListener)"));
  assert(helper.includes('await snapshotStores()'));
  assert(helper.includes('authoritativeProviderDelta'));
  assert(helper.includes("await physicalFixedSubmit(page, origin, 'fixed practice baseline')"));
  assert(helper.includes("{ error: 'CTF practice is no longer current' }"));
  assert(!helper.includes('async function runCtfFixedPracticeRenderedCases({ exercise, receipt })'));
});

test('measured helper retires listeners and invokes cleanup on a failed measurement', async () => {
  const retired = []; let cleanups = 0;
  const page = { on() {}, off(event) { retired.push(event); },
    setRequestInterception: async () => {} };
  await assert.rejects(facet.runCtfFixedPracticeRenderedCases({ page, origin: 'http://127.0.0.1:18080',
    actorId: '2403', sessionId: '10', participantId: '2403', siblingOwnerId: '1001',
    serverCounts: () => ({ practice: 0 }), providerCounts: () => ({ physicalStarted: 0,
      completed: 0, staleAfterDispatch: 0 }), snapshotStores: async () => { throw Error('snapshot failed'); },
    resolveAuthorization: async () => ({ actorId: '2403', sessionId: '10', participantId: '2403' }),
    authority: { beforeDispatch: async () => {}, beforeProvider: async () => {},
      afterDispatch: async () => {}, restoreCurrent: async () => {} },
    drain: async () => {},
    cleanup: async () => { cleanups++; return { providerDrained: true, ownedBrowserHandles: 0,
      ownedStoreHandles: 0 }; },
  }), /snapshot failed/);
  assert.equal(cleanups, 1);
  assert.deepEqual(retired.sort(), ['request', 'response']);
});

function measuredPage(overrides = {}) {
  const page = new EventEmitter();
  page.setRequestInterception = async enabled => { assert.equal(enabled, true); };
  const origin = 'http://127.0.0.1:18080';
  const snapshot = { attempts: ['owned'], progress: ['owned'], judgments: [],
    leaderboard: [], outbox: [], sibling: ['nonempty peer'] };
  let operationNumber=0;
  const appendOperation=phase=>{
    const sequence=String(++operationNumber);
    const operationId=`00000000-0000-4000-8000-${sequence.padStart(12,'0')}`;
    snapshot.outbox.push({operation_id:operationId,sequence});
    return {phase,operationId,sequence,actorId:'1002',sessionId:'11',stageId:1};
  };
  const state = { phase: 'current', selected: false, typed: '', clicks: 0,
    practice: 2, physicalStarted: 1, completed: 1, staleAfterDispatch: 0,
    rendered: '', aborted: 0, continued: 0 };
  const marker = 'Fixed response confirmed: protected context withheld, server secret withheld, and scoring disabled.';
  page.type = async (_selector, value) => { state.typed = value; };
  page.evaluate = async (fn, value) => {
    const prior = global.document;
    global.document = { body: { textContent: state.rendered } };
    try { return fn(value); } finally { global.document = prior; }
  };
  page.waitForFunction = async fn => {
    const source = fn.toString();
    const kind = source.includes('button[role="tab"]') ? 'tab'
      : source.includes('[role="status"]') ? 'notice'
        : source.includes('button[type="submit"]') ? 'submit' : 'publication';
    if (kind === 'publication') {
      assert(state.rendered.includes(marker));
      assert(state.rendered.includes('controlled fixed answer'));
    }
    return { asElement: () => ({}), dispose: async () => {}, click: async () => {
      if (kind === 'tab') {
        state.selected = true;
        if (overrides.unsafeRequest) page.emit('request', {
          url: () => origin + '/api/ctf/stage/1/attempt', method: () => 'POST',
          headers: () => ({}), postData: () => '{}',
          continue: async () => { state.continued++; },
          abort: async () => { state.aborted++; },
        });
        return;
      }
      assert.equal(kind, 'submit'); assert(state.selected);
      state.clicks++;
      if (state.phase === 'client-stale') return;
      const body = JSON.stringify({ payload: state.typed,
        sessionToken: 'mounted-route-owner' });
      const request = { url: () => origin + facet.POST_PATH, method: () => 'POST',
        headers: () => ({ authorization: overrides.bearer || 'Bearer owned' }),
        postData: () => body, continue: async () => { state.continued++; },
        abort: async () => { state.aborted++; } };
      state.practice++;
      const status = state.phase === 'current' ? 200 : 409;
      if (state.phase === 'current') {
        state.physicalStarted++; state.completed++;
        state.rendered = `controlled fixed answer ${marker}`;
      } else if (state.phase === 'post-provider-stale') {
        state.physicalStarted++; state.staleAfterDispatch++;
      }
      const response = { url: () => origin + facet.POST_PATH,
        request: () => request, status: () => status,
        json: async () => status === 200 ? {
          response: 'controlled fixed answer', mode: 'fixed', practice: true,
          unscored: true, scoringEligible: false,
          protectedContextIncluded: false, serverSecretProvided: false,
        } : { error: overrides.staleError || 'CTF practice is no longer current' } };
      page.emit('request', request); page.emit('response', response);
    } };
  };
  page.waitForResponse = predicate => new Promise(resolve => {
    const listener = value => { if (predicate(value)) {
      page.off('response', listener); resolve(value);
    } };
    page.on('response', listener);
  });
  const run = () => facet.runCtfFixedPracticeRenderedCases({ page, origin,
    actorId: '2403', sessionId: '10', participantId: '2403', siblingOwnerId: '1001',
    serverCounts: () => ({ practice: state.practice }),
    providerCounts: () => ({ physicalStarted: state.physicalStarted,
      completed: state.completed, staleAfterDispatch: state.staleAfterDispatch }),
    snapshotStores: async () => structuredClone(snapshot),
    resolveAuthorization: async bearer => {
      if (bearer !== 'Bearer owned') throw Error('wrong mounted bearer');
      return { actorId: '2403', sessionId: '10', participantId: '2403' };
    },
    authority: {
      beforeDispatch: async () => { state.phase = 'client-stale'; },
      beforeProvider: async () => { state.phase = 'pre-provider-stale';
        return {settled:Promise.resolve(appendOperation('pre-provider-stale'))}; },
      afterDispatch: async () => { state.phase = 'post-provider-stale';
        return {settled:Promise.resolve(appendOperation('post-provider-stale'))}; },
      restoreCurrent: async phase => { state.phase = 'current';return appendOperation(phase); },
    },
    drain: async () => { assert.equal(state.physicalStarted,
      state.completed + state.staleAfterDispatch); },
    cleanup: async () => {
      if (overrides.latePost) state.practice++;
      if (overrides.lateProvider) state.physicalStarted++;
      if (overrides.cleanupFailure) throw Error('owned close failed');
      return { providerDrained: true, ownedBrowserHandles: 0, ownedStoreHandles: 0 };
    },
  });
  return { run, state };
}

test('measured controlled path physically separates client stale, server pre-provider and post-provider', async () => {
  const { run, state } = measuredPage();
  const value = await run();
  assert.equal(value.cases.staleBeforeDispatch.browserPosts, 0);
  assert.equal(value.cases.staleBeforeProvider.browserPosts, 1);
  assert.equal(value.cases.staleAfterDispatch.browserPosts, 1);
  assert.equal(value.providerDiagnostics.physicalStarted, 2);
  assert.equal(state.clicks, 4);
});

test('measured path fails closed on wrong mounted bearer, wrong stale response, late call or cleanup debt', async () => {
  for (const option of [{ bearer: 'Bearer peer' }, { staleError: 'generic failure' },
    { latePost: true }, { lateProvider: true }, { cleanupFailure: true }])
    await assert.rejects(measuredPage(option).run());
  const unsafe = measuredPage({ unsafeRequest: true });
  await assert.rejects(unsafe.run());
  assert.equal(unsafe.state.aborted, 1);
  assert.equal(unsafe.state.continued, 3,
    'Only the three exact admitted practice POSTs may continue');
});

test('DOM predicates accept only the visible Fixed tab and the exact unscored disclosure', () => {
  const original = global.document;
  const tab = { textContent: 'Fixed practice', disabled: false, getClientRects: () => [1] };
  const notice = { textContent: ' Fixed practice — unscored. Responses use the fixed practice path and cannot award credit, points, or stage progression. ', getClientRects: () => [1] };
  global.document = { querySelectorAll(selector) {
    if (selector === 'button[role="tab"]') return [tab];
    if (selector === '[role="status"]') return [notice];
    return [];
  } };
  try {
    assert.equal(facet.fixedPracticeTab(), tab);
    assert.equal(facet.fixedPracticeNotice(), notice);
    tab.disabled = true; assert.equal(facet.fixedPracticeTab(), null);
    tab.disabled = false; notice.textContent = 'Fixed practice — unscored.';
    assert.equal(facet.fixedPracticeNotice(), null);
  } finally { global.document = original; }
});
