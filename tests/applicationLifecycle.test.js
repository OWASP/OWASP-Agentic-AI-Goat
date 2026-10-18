'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createApplicationLifecycle, closeApplicationOwnedResources } = require('../server/services/applicationLifecycle');

test('shutdown drains once and a concurrent fatal error upgrades the exit code', async () => {
  const exits = [];
  let release, calls = 0;
  const lifecycle = createApplicationLifecycle({ exit: code => exits.push(code) });
  lifecycle.register(() => { calls++; return new Promise(resolve => { release = resolve; }); });
  const first = lifecycle.shutdown();
  await Promise.resolve();
  assert.deepEqual(exits, []);
  assert.equal(lifecycle.shutdown(1), first);
  release();
  await first;
  assert.equal(calls, 1);
  assert.deepEqual(exits, [1]);
});

test('stuck cleanup has a bounded non-successful shutdown', async () => {
  const exits = [];
  const lifecycle = createApplicationLifecycle({ timeoutMs: 10, exit: code => exits.push(code) });
  lifecycle.register(() => new Promise(() => {}));
  await lifecycle.shutdown();
  assert.deepEqual(exits, [1]);
});

test('ordered application cleanup attempts later owned resources after SecureShop failure', async () => {
  const calls = [];
  const studentError = new Error('student cleanup failed');
  const hostError = Object.assign(new Error('agent host still live'), { code: 'SS_AGENT_HOST_STOP_TIMEOUT' });
  await assert.rejects(closeApplicationOwnedResources({
    async closeStudentDeletion() { calls.push('student'); throw studentError; },
    async closeSensitiveInfoReset() { calls.push('sensitive'); },
    async closeSecureShopBoundReview() { calls.push('bound'); },
    async closeSecureShop() {
      calls.push('shop'); throw new AggregateError([hostError], 'SecureShop owned cleanup failed');
    },
    async closeSessionDisclosure() { calls.push('session'); },
    async closeSecureShopReviewDb() { calls.push('review-db'); },
    async closePostgresPools() { calls.push('postgres'); },
  }), error => error instanceof AggregateError
    && error.errors.length === 2
    && error.errors[0] === studentError
    && error.errors[1] === hostError);
  assert.deepEqual(calls, ['student', 'sensitive', 'bound', 'shop', 'session', 'review-db', 'postgres']);
});

test('ingress failure still drains HTTP before closing every owned resource', async () => {
  const { settleApplicationCleanup } = require('../server/services/applicationLifecycle');
  const calls = [], exits = [];
  let releaseHttp;
  const httpClosed = new Promise(resolve => { releaseHttp = resolve; });
  const browserError = new Error('browser shutdown failed');
  const poolError = new Error('one pool shutdown failed');
  const lifecycle = createApplicationLifecycle({ exit: code => exits.push(code) });
  lifecycle.register(() => settleApplicationCleanup([
    () => { calls.push('browser'); throw browserError; },
    async () => { calls.push('http'); await httpClosed; },
    () => { calls.push('mail'); },
    () => settleApplicationCleanup([
      () => { calls.push('pool'); throw poolError; },
      () => { calls.push('child'); },
    ]),
  ]));
  const pending = lifecycle.shutdown();
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(calls, ['browser', 'http']);
  assert.deepEqual(exits, []);
  releaseHttp();
  await pending;
  assert.deepEqual(calls, ['browser', 'http', 'mail', 'pool', 'child']);
  assert.deepEqual(exits, [1]);
});

test('sequential cleanup preserves original errors while attempting later steps', async () => {
  const { settleApplicationCleanup } = require('../server/services/applicationLifecycle');
  const first = new Error('first'), second = new Error('second');
  let last = false;
  await assert.rejects(settleApplicationCleanup([
    () => { throw first; },
    () => { throw new AggregateError([second]); },
    () => { last = true; },
  ]), error => error instanceof AggregateError && error.errors[0] === first && error.errors[1] === second);
  assert.equal(last, true);
});

test('production shutdown wiring still closes pools after browser and mail errors', async () => {
  const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
  const { settleApplicationCleanup } = require('../server/services/applicationLifecycle');
  const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  const begin = source.indexOf('lifecycle.register(async () => {');
  const end = source.indexOf('\nassertActive();', begin);
  assert.ok(begin > 0 && end > begin);
  const calls = [];
  let shutdown;
  const browserError = new Error('owned browser failed'), mailError = new Error('owned mail failed');
  const services = {
    './routes/csrfWorkshop': { closeBrowser: async () => { calls.push('csrf'); throw browserError; } },
    './routes/xssWorkshop': { closeBrowser: async () => { calls.push('xss'); } },
    './services/xssMailProvider': { close: async () => { calls.push('mail'); throw mailError; } },
    './services/studentDeletionProduction': { closeProductionStudentDeletionComposition: async () => { calls.push('deletion'); } },
    './services/sensitiveInfoResetComposition': { closeSensitiveInfoResetComposition: async () => { calls.push('reset'); } },
    './services/secureshopOwnedAuditProduction': { closeOwnedAuditProduction: async () => { calls.push('audit'); } },
    './services/sessionDisclosureLab': { closeSessionDisclosureLab: async () => { calls.push('disclosure'); } },
    './database/postgres/secureshopReviewDb': { closeSecureShopReviewDb: async () => { calls.push('review'); } },
    './database/postgres': { closePostgresPools: async () => { calls.push('postgres'); } },
  };
  vm.runInNewContext(source.slice(begin, end), {
    authRoutes: { close: async () => { calls.push('auth'); } },
    lifecycle: { register(fn) { shutdown = fn; } },
    server: { listening: true, close(done) { calls.push('http'); done(); }, closeIdleConnections() {} },
    loaded(name) { assert.ok(Object.hasOwn(services, name), name); return services[name]; },
    sessionManager: null, ctfLeaderboardRefresh: null, startupTasks: [], constructionComplete: true,
    app: { locals: {} }, process: { env: {} },
    evidenceMaintenance: { stop: async () => { calls.push('maintenance'); } },
    teachingSessionProduction: { close: async () => { calls.push('teaching'); } },
    secureShopReady: Promise.resolve(), settleApplicationCleanup, closeApplicationOwnedResources,
  });
  await assert.rejects(shutdown(), error => error instanceof AggregateError
    && error.errors[0] === browserError && error.errors[1] === mailError);
  assert.deepEqual(calls, ['auth', 'csrf', 'http', 'teaching', 'xss', 'mail', 'maintenance', 'deletion', 'reset', 'audit', 'disclosure', 'review', 'postgres']);
});

test('CTF shutdown waits for deletion and drains before shared pools even when CTF reports failure',async()=>{
 const calls=[];let release;
 const deletion=new Promise(resolve=>{release=resolve;});
 const failure=Error('CTF runtime did not drain');
 const cleanup=closeApplicationOwnedResources({
  closeStudentDeletion:async()=>{calls.push('deletion');await deletion;},
  closeCtfRuntime:async()=>{calls.push('ctf');throw failure;},
  closeSensitiveInfoReset:async()=>{},closeSecureShopBoundReview:async()=>{},closeSecureShop:async()=>{},
  closeSessionDisclosure:async()=>{},closeSecureShopReviewDb:async()=>{},closePostgresPools:async()=>{calls.push('pools');}
 });
 const rejected=assert.rejects(cleanup,error=>error instanceof AggregateError&&error.errors.includes(failure));
 await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(calls,['deletion']);
 release();await rejected;assert.deepEqual(calls,['deletion','ctf','pools']);
});

test('finalizers wait for all independent cleanup then run serially once',async()=>{
 const calls=[],exits=[];let a,b,releaseFinal;
 const lifecycle=createApplicationLifecycle({exit:code=>exits.push(code)});
 lifecycle.register(()=>new Promise(resolve=>{a=resolve;}));lifecycle.register(()=>new Promise(resolve=>{b=resolve;}));
 lifecycle.registerFinalizer(async()=>{calls.push('first');await new Promise(resolve=>{releaseFinal=resolve;});});
 lifecycle.registerFinalizer(()=>calls.push('second'));
 const done=lifecycle.shutdown();assert.equal(lifecycle.shutdown(),done);await new Promise(setImmediate);
 a();await new Promise(setImmediate);assert.deepEqual(calls,[]);b();await new Promise(setImmediate);assert.deepEqual(calls,['first']);assert.deepEqual(exits,[]);
 assert.throws(()=>lifecycle.registerFinalizer(()=>{}),TypeError);releaseFinal();await done;assert.deepEqual(calls,['first','second']);assert.deepEqual(exits,[0]);
});
test('failed cleanup never releases final authority',async()=>{
 let called=false;const exits=[];const lifecycle=createApplicationLifecycle({exit:x=>exits.push(x)});
 lifecycle.register(()=>{throw Error('failed drain');});lifecycle.registerFinalizer(()=>{called=true;});await lifecycle.shutdown();assert.equal(called,false);assert.deepEqual(exits,[1]);
});
test('late cleanup after hard deadline cannot trigger finalizers',async()=>{
 let release,called=false;const exits=[];const lifecycle=createApplicationLifecycle({timeoutMs:15,exit:x=>exits.push(x)});
 lifecycle.register(()=>new Promise(resolve=>{release=resolve;}));lifecycle.registerFinalizer(()=>{called=true;});await lifecycle.shutdown();release();await new Promise(setImmediate);assert.equal(called,false);assert.deepEqual(exits,[1]);
});
test('finalizer timeout shares shutdown deadline and prevents subsequent releases',async()=>{
 let release,second=false;const exits=[];const lifecycle=createApplicationLifecycle({timeoutMs:15,exit:x=>exits.push(x)});
 lifecycle.registerFinalizer(()=>new Promise(resolve=>{release=resolve;}));lifecycle.registerFinalizer(()=>{second=true;});await lifecycle.shutdown();release();await new Promise(setImmediate);assert.equal(second,false);assert.deepEqual(exits,[1]);
});
test('failed finalizer fails shutdown and stops later authority releases',async()=>{
 let later=false;const exits=[];const lifecycle=createApplicationLifecycle({exit:x=>exits.push(x)});
 lifecycle.registerFinalizer(()=>{throw Error('release failed');});lifecycle.registerFinalizer(()=>{later=true;});await lifecycle.shutdown();assert.equal(later,false);assert.deepEqual(exits,[1]);
});
