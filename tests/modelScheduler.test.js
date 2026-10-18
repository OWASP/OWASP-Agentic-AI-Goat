'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { AsyncLocalStorage } = require('node:async_hooks');
const { createModelScheduler } = require('../server/agent-runtime/providers/modelScheduler');
const { requestContextMiddleware, syncUserToContext, getRequestContext } = require('../server/utils/requestContext');
test('200-attendee mock burst preserves ownership and bounds active transports', async () => {
  const scheduler = createModelScheduler({ concurrency: 2, queueLimit: 256 });
  let active = 0, peak = 0;
  const results = await Promise.all(Array.from({ length: 200 }, (_, owner) => scheduler.run(owner, null, async () => {
    active++; peak = Math.max(peak, active);
    await new Promise(resolve => setImmediate(resolve)); active--;
    return { owner, response: `only-user-${owner}` };
  })));
  assert.equal(peak, 2);
  results.forEach((value, owner) => assert.deepEqual(value, { owner, response: `only-user-${owner}` }));
  assert.equal(scheduler.snapshot().queued, 0);
});
test('bounded queue rejects overload and removes aborted waiting jobs', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 1 });
  let release; const first = scheduler.run('a', null, () => new Promise(resolve => { release = resolve; }));
  const abort = new AbortController();
  const second = scheduler.run('b', abort.signal, () => { throw new Error('must not execute'); });
  const cancelled = assert.rejects(second, { name: 'AbortError' });
  await assert.rejects(scheduler.run('c', null, () => {}), { code: 'AI_QUEUE_FULL' });
  abort.abort(); await cancelled; release(); await first;
  assert.equal(scheduler.snapshot().queued, 0);
});
test('round-robin owners prevent one attendee draining the queue first', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 20 });
  let release; const order = [];
  const running = scheduler.run('hold', null, () => new Promise(resolve => { release = resolve; }));
  const work = ['a','a','a','b','b'].map(owner => scheduler.run(owner, null, async () => order.push(owner)));
  await new Promise(resolve => setImmediate(resolve)); release();
  await Promise.all([running, ...work]);
  assert.deepEqual(order, ['a','b','a','b','a']);
});
test('equivalent provider endpoint URLs share one physical concurrency budget', async () => {
  const {sharedModelScheduler}=require('../server/agent-runtime/providers/modelScheduler');
  const a=sharedModelScheduler('ollama','http://MODEL-BUDGET.TEST:80');
  const b=sharedModelScheduler('ollama','http://model-budget.test/');
  let active=0,peak=0;
  await Promise.all(Array.from({length:12},(_,i)=>(i%2?a:b).run(String(i),null,async()=>{
    active++;peak=Math.max(peak,active);await new Promise(resolve=>setImmediate(resolve));active--;
  })));
  assert.equal(peak,2);
  assert.notEqual(a,sharedModelScheduler('ollama','http://model-budget.test:11434/'));
});

test('queued work preserves the submitter AsyncLocalStorage context', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 4 });
  const context = new AsyncLocalStorage();
  let release;
  const running = context.run('first-owner', () => scheduler.run('first-owner', null,
    async () => { await new Promise(resolve => { release = resolve; }); return context.getStore(); }));
  const queued = context.run('second-owner', () => scheduler.run('second-owner', null,
    async () => context.getStore()));
  await new Promise(resolve => setImmediate(resolve));
  release();
  assert.equal(await running, 'first-owner');
  assert.equal(await queued, 'second-owner');
});

test('queued production request contexts do not inherit the prior user', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 2 });
  let release;
  const submit = (requestId, userId, work = async () => getRequestContext()) => new Promise((resolve, reject) => {
    const request = { requestId, ip: '127.0.0.1', user: { id: userId, username: `user-${userId}` } };
    requestContextMiddleware(request, {}, () => {
      syncUserToContext(request);
      scheduler.run(String(userId), null, work).then(resolve, reject);
    });
  });
  const first = submit('req-first', 101, async () => {
    await new Promise(resolve => { release = resolve; });
    return getRequestContext();
  });
  const second = submit('req-second', 202);
  await new Promise(resolve => setImmediate(resolve));
  release();
  assert.deepEqual(await first, { requestId: 'req-first', ip: '127.0.0.1', userId: 101, username: 'user-101' });
  assert.deepEqual(await second, { requestId: 'req-second', ip: '127.0.0.1', userId: 202, username: 'user-202' });
});


test('cancellation after admission but before dispatch never starts work', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 2 });
  const controller = new AbortController(); let invoked = 0;
  const job = scheduler.run('cancelled', controller.signal, () => { invoked++; });
  const denied = assert.rejects(job, { name: 'AbortError' });
  controller.abort();
  await denied;
  await scheduler.run('next', null, () => 'next');
  assert.equal(invoked, 0);
});

test('active cancelled work retains its physical slot until settlement', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 2 });
  const controller = new AbortController(); let release, nextStarted = false;
  const active = scheduler.run('active', controller.signal, () => new Promise(resolve => { release = resolve; }));
  await new Promise(resolve => setImmediate(resolve));
  controller.abort();
  const next = scheduler.run('next', null, () => { nextStarted = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(nextStarted, false);
  assert.equal(scheduler.snapshot().active, 1);
  release(); await Promise.all([active, next]);
  assert.equal(nextStarted, true);
});


test('per-owner waiting cap preserves admission for another owner and cancellation releases quota', async () => {
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 20, ownerQueueLimit: 2 });
  let release;
  const active = scheduler.run('flood', null, () => new Promise(resolve => { release = resolve; }));
  const controller = new AbortController();
  const cancelled = scheduler.run('flood', controller.signal, () => assert.fail('cancelled work'));
  const cancellation = assert.rejects(cancelled, { name: 'AbortError' });
  const queued = scheduler.run('flood', null, () => 'queued');
  await assert.rejects(scheduler.run('flood', null, () => assert.fail('over cap')), { code: 'AI_QUEUE_FULL' });
  const other = scheduler.run('other', null, () => 'other');
  controller.abort(); await cancellation;
  const replacement = scheduler.run('flood', null, () => 'replacement');
  assert.equal(scheduler.snapshot().queued, 3);
  release(); assert.deepEqual(await Promise.all([active, queued, other, replacement]), [undefined, 'queued', 'other', 'replacement']);
});

test('default waiting cap and configured bounds are explicit', () => {
  assert.equal(createModelScheduler().snapshot().ownerQueueLimit, 16);
  for (const ownerQueueLimit of [0, -1, 1.5, 2001, NaN]) {
    assert.throws(() => createModelScheduler({ ownerQueueLimit }), RangeError);
  }
  assert.equal(createModelScheduler({ ownerQueueLimit: 2000 }).snapshot().ownerQueueLimit, 2000);
});

test('shared local scheduler reads bounded per-owner configuration and defaults safely', () => {
  const { sharedModelScheduler } = require('../server/agent-runtime/providers/modelScheduler');
  const name = 'AI_OLLAMA_OWNER_QUEUE_LIMIT', prior = process.env[name];
  try {
    process.env[name] = '3';
    assert.equal(sharedModelScheduler('ollama', 'http://owner-cap-config.test').snapshot().ownerQueueLimit, 3);
    process.env[name] = '0';
    const defaults = sharedModelScheduler('ollama', 'http://owner-cap-default.test').snapshot();
    assert.equal(defaults.ownerQueueLimit, 16);
    assert.equal(defaults.concurrency, 2);
    assert.equal(defaults.queueLimit, 256);
  } finally { if (prior === undefined) delete process.env[name]; else process.env[name] = prior; }
});

test('aggregate diagnostics distinguish rejection, queued cancellation and settled work', async () => {
  let time = 10, release;
  const scheduler = createModelScheduler({ concurrency: 1, queueLimit: 1, now: () => time });
  const active = scheduler.run('private-owner', null, () => new Promise(resolve => { release = resolve; }));
  const controller = new AbortController();
  const waiting = scheduler.run('other-private-owner', controller.signal, () => assert.fail('cancelled'));
  const cancelled = assert.rejects(waiting, { name: 'AbortError' });
  time = 35;
  assert.equal(scheduler.snapshot().oldestQueuedAgeMs, 25);
  time = 5;
  assert.equal(scheduler.snapshot().oldestQueuedAgeMs, 0);
  await assert.rejects(scheduler.run('third', null, () => {}), { code: 'AI_QUEUE_FULL' });
  controller.abort(); await cancelled;
  assert.equal(scheduler.snapshot().oldestQueuedAgeMs, 0);
  release(); await active; await new Promise(resolve => setImmediate(resolve));
  const metrics = scheduler.snapshot();
  assert.deepEqual([metrics.accepted, metrics.rejected, metrics.queuedCancelled, metrics.preDispatchCancelled, metrics.settled], [2, 1, 1, 0, 1]);
  assert.doesNotMatch(JSON.stringify(metrics), /private-owner/);
});

test('pre-dispatch cancellation is not settled transport; thrown work is settled', async () => {
  const scheduler = createModelScheduler();
  const controller = new AbortController();
  const pending = scheduler.run('owner', controller.signal, () => assert.fail('not invoked'));
  const rejected = assert.rejects(pending, { name: 'AbortError' });
  controller.abort(); await rejected;
  await assert.rejects(scheduler.run('owner', null, () => { throw Error('controlled'); }), /controlled/);
  await assert.rejects(scheduler.run('owner', controller.signal, () => {}), { name: 'AbortError' });
  await new Promise(resolve => setImmediate(resolve));
  const metrics = scheduler.snapshot();
  assert.deepEqual([metrics.accepted, metrics.rejected, metrics.queuedCancelled, metrics.preDispatchCancelled, metrics.settled], [2, 1, 0, 1, 1]);
});
