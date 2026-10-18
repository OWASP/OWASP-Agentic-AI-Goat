import { createSecureShopWorkshopController } from './SecureShopWorkshopController.mjs';

const launch = (generation = 2, credentialVersion = 5) => ({
  launchId: '10000000-0000-4000-8000-000000000071', generation, credentialVersion,
  expiresAt: '2026-09-13T23:00:00.000Z',
});
const credential = (generation = 2, credentialVersion = 5, bearer = 'a'.repeat(43)) => ({
  launch: launch(generation, credentialVersion), bearer,
});
const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
  json: async () => body });

function harness(replies, { getPlatformToken = () => 'platform-token', clock = () => Date.parse('2026-09-13T22:30:00.000Z') } = {}) {
  const requests = []; const mounts = []; const stores = []; const states = []; const timers = [];
  const clearTimer = jest.fn(timer => { if (timer?.delay <= 60000 && timer?.delay > 30000) { const i = timers.indexOf(timer); if (i >= 0) timers.splice(i, 1); } });
  const randomUUID = jest.fn(() => '30000000-0000-4000-8000-000000000071');
  const fetchImpl = jest.fn(async (url, init) => {
    requests.push({ url, init, body: init.body && JSON.parse(init.body) });
    const reply = replies.shift();
    return typeof reply === 'function' ? reply(url, init) : reply;
  });
  const mountFrame = jest.fn(options => {
    const session = { ready: Promise.resolve(), close: jest.fn() };
    mounts.push({ ...options, session }); return session;
  });
  const createStateStore = jest.fn(options => {
    const store = { close: jest.fn(), retire: jest.fn() };
    stores.push({ options, store }); return store;
  });
  const host = document.createElement('div'); document.body.appendChild(host);
  const controller = createSecureShopWorkshopController({ fetchImpl, getPlatformToken,
    storage: {}, documentRef: document, origin: window.location.origin, mountFrame,
    compileOperation: jest.fn(), createStateStore, randomUUID,
    onState: state => states.push(state), now: clock,
    setTimer: (callback, delay) => { const timer = { callback, delay }; timers.push(timer); return timer; }, clearTimer });
  return { controller, host, requests, mounts, stores, states, fetchImpl, timers, clearTimer, randomUUID };
}

afterEach(() => { document.body.replaceChildren(); });

test('issues a launch, scopes parent state by launch and generation, and keeps bearer memory-only', async () => {
  const f = harness([response({ preparationOnly: true, launch: null }), response(credential(), 201)]);
  await f.controller.start(f.host);
  expect(f.requests.map(item => [item.init.method, item.url])).toEqual([
    ['GET', '/api/auth/secureshop-launch'], ['POST', '/api/auth/secureshop-launch'],
  ]);
  expect(f.requests[1].body).toEqual({});
  expect(f.stores[0].options.scenarioId).toBe(launch().launchId);
  expect(f.stores[0].options.generation).toBe(2);
  expect(f.mounts[0].getLaunchBearer()).toBe('a'.repeat(43));
  expect(f.host.querySelectorAll('iframe')).toHaveLength(1);
  expect(f.host.querySelector('iframe').title).toBe('SecureShop');
  expect(f.host.querySelector('iframe').getAttribute('aria-label')).toBe('SecureShop storefront');
  expect(f.host.querySelector('iframe').style.height).toBe('100%');
  expect(f.host.querySelector('iframe').getAttribute('sandbox')).toBeNull();
  expect(f.states.at(-1)).toEqual({ status: 'ready', launch: launch() });
});

test('recovers an existing launch using exact public metadata before mounting', async () => {
  const f = harness([response({ preparationOnly: true, launch: launch() }), response(credential())]);
  await f.controller.start(f.host);
  expect(f.requests[1].url).toBe('/api/auth/secureshop-launch/recover');
  expect(f.requests[1].body).toEqual({ launchId: launch().launchId, expectedCredentialVersion: 5 });
});

test('one create race rereads only this session metadata and recovers it', async () => {
  const f = harness([response({ launch: null }), response({ error: 'Launch request could not be completed' }, 409),
    response({ launch: launch() }), response(credential())]);
  await f.controller.start(f.host);
  expect(f.requests.map(item => [item.init.method, item.url])).toEqual([
    ['GET', '/api/auth/secureshop-launch'], ['POST', '/api/auth/secureshop-launch'],
    ['GET', '/api/auth/secureshop-launch'], ['POST', '/api/auth/secureshop-launch/recover'],
  ]);
  expect(f.requests[3].body).toEqual({ launchId: launch().launchId, expectedCredentialVersion: 5 });
  expect(f.states.at(-1)).toEqual({ status: 'ready', launch: launch() });
});

test('terminal same-session launch requires a new login without retrying or mounting', async () => {
  const f = harness([response({ launch: null }), response({ error: 'Launch request could not be completed',
    code: 'LAUNCH_SESSION_TERMINAL' }, 409)]);
  await expect(f.controller.start(f.host)).rejects.toMatchObject({ code: 'LAUNCH_SESSION_TERMINAL' });
  expect(f.requests).toHaveLength(2);
  expect(f.mounts).toHaveLength(0);
  expect(f.states.at(-1)).toEqual({ status: 'error', terminalLaunch: true,
    message: 'This platform session’s SecureShop launch has ended. Sign out and sign in again to start a new session.' });
});

test('capacity denial keeps the backend recovery message and does not race a second launch', async () => {
  const f = harness([response({ launch: null }), response({
    code: 'LAUNCH_CAPACITY', error: 'SecureShop product target capacity reached. Try again after an instructor retires old targets.',
  }, 409)]);
  await expect(f.controller.start(f.host)).rejects.toMatchObject({ code: 'LAUNCH_CAPACITY', status: 409 });
  expect(f.requests.map(item => item.url)).toEqual([
    '/api/auth/secureshop-launch', '/api/auth/secureshop-launch',
  ]);
  expect(f.mounts).toHaveLength(0);
  expect(f.states.at(-1)).toEqual({ status: 'error', capacity: true,
    message: 'SecureShop product target capacity reached. Try again after an instructor retires old targets.' });
});

test('changing the platform token immediately fences the mounted bridge and storage authority', async () => {
  let token = 'platform-token';
  const f = harness([response({ launch: null }), response(credential(), 201)],
    { getPlatformToken: () => token });
  await f.controller.start(f.host);
  expect(f.host.querySelector('iframe').style.width).toBe('100%');
  expect(f.stores[0].options.isCurrent()).toBe(true);
  token = 'different-session-token';
  expect(f.stores[0].options.isCurrent()).toBe(false);
  expect(() => f.mounts[0].getLaunchBearer()).toThrow('SecureShop workshop closed');
  expect(f.requests).toHaveLength(2);
});

test('trusted current launch rejection detaches the frame and presents the existing reconnect state', async () => {
  const f = harness([response({ launch: null }), response(credential(), 201)]);
  await f.controller.start(f.host);
  f.mounts[0].transportOptions.onLaunchUnavailable('a'.repeat(43));
  expect(f.mounts[0].session.close).toHaveBeenCalledTimes(1);
  expect(f.host.querySelector('iframe')).toBeNull();
  expect(f.states.at(-1)).toEqual({ status: 'error',
    message: 'SecureShop connection needs to be renewed. Reconnect to continue.' });
  expect(f.requests).toHaveLength(2);
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
});

test('late stale-launch callbacks cannot detach a renewed frame or a changed platform session', async () => {
  let token = 'platform-token';
  const extended = credential(2, 6, 'b'.repeat(43));
  extended.launch.expiresAt = '2026-09-13T23:30:00.000Z';
  const f = harness([response({ launch: null }), response(credential(), 201), response(extended)],
    { getPlatformToken: () => token });
  await f.controller.start(f.host);
  f.timers[0].callback();
  await new Promise(resolve => setTimeout(resolve, 0));
  f.mounts[0].transportOptions.onLaunchUnavailable('a'.repeat(43));
  expect(f.host.querySelector('iframe')).not.toBeNull();
  expect(f.mounts[0].session.close).not.toHaveBeenCalled();
  expect(f.mounts[0].getLaunchBearer()).toBe('b'.repeat(43));

  token = 'different-session-token';
  f.mounts[0].transportOptions.onLaunchUnavailable('b'.repeat(43));
  expect(f.host.querySelector('iframe')).not.toBeNull();
  expect(f.mounts[0].session.close).not.toHaveBeenCalled();
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
});

test('reset closes old channel first, retires state only after exact cleanup, recovers credential and mounts fresh frame', async () => {
  let resolveReset;
  const pending = new Promise(resolve => { resolveReset = resolve; });
  const f = harness([response({ preparationOnly: true, launch: null }), response(credential(), 201),
    () => pending, response(credential(3, 6, 'b'.repeat(43))) ]);
  await f.controller.start(f.host);
  const reset = f.controller.reset();
  expect(f.mounts[0].session.close).toHaveBeenCalledTimes(1);
  expect(f.host.querySelectorAll('iframe')).toHaveLength(0);
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
  expect(f.requests[2].body).toEqual({ launchId: launch().launchId, expectedGeneration: 2,
    idempotencyKey: '30000000-0000-4000-8000-000000000071' });
  resolveReset(response({ resetId: '40000000-0000-4000-8000-000000000071', cleanupComplete: true,
    launch: launch(3, 6) }));
  await reset;
  expect(f.stores[0].store.retire).toHaveBeenCalledTimes(1);
  expect(f.requests[3].body).toEqual({ launchId: launch().launchId, expectedCredentialVersion: 6 });
  expect(f.mounts).toHaveLength(2);
  expect(f.mounts[1].frame).not.toBe(f.mounts[0].frame);
  expect(f.mounts[1].getLaunchBearer()).toBe('b'.repeat(43));
  expect(f.stores[1].options.generation).toBe(3);
});

test('uncertain reset keeps the old generation detached and reuses its idempotency key on retry', async () => {
  const f = harness([response({ preparationOnly: true, launch: null }), response(credential(), 201),
    response({ error: 'busy' }, 503), response({ resetId: '40000000-0000-4000-8000-000000000071',
      cleanupComplete: true, launch: launch(3, 6) }), response(credential(3, 6, 'b'.repeat(43))) ]);
  await f.controller.start(f.host);
  await expect(f.controller.reset()).rejects.toThrow('busy');
  expect(f.mounts).toHaveLength(1);
  expect(f.host.querySelectorAll('iframe')).toHaveLength(0);
  expect(f.states.at(-1).retryReset).toBe(true);
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
  await f.controller.reset();
  expect(f.requests[2].body.idempotencyKey).toBe(f.requests[3].body.idempotencyKey);
  expect(f.stores[0].store.retire).toHaveBeenCalledTimes(1);
  expect(f.mounts).toHaveLength(2);
});

test('closing during launch acquisition aborts stale completion without mounting or revoking', async () => {
  let resolveMetadata;
  const pending = new Promise(resolve => { resolveMetadata = resolve; });
  const f = harness([() => pending]);
  const started = f.controller.start(f.host);
  f.controller.close();
  resolveMetadata(response({ preparationOnly: true, launch: null }));
  await expect(started).rejects.toMatchObject({ name: 'AbortError' });
  expect(f.mounts).toHaveLength(0);
  expect(f.requests).toHaveLength(1);
  expect(f.requests.some(item => item.init.method === 'DELETE')).toBe(false);
});


test('renewal rotates only the parent handle and preserves the existing frame and scoped storage', async () => {
  const extended = credential(2, 6, 'b'.repeat(43));
  extended.launch.expiresAt = '2026-09-13T23:30:00.000Z';
  const f = harness([response({ launch: null }), response(credential(), 201), response(extended)]);
  await f.controller.start(f.host);
  expect(f.timers[0].delay).toBe(25 * 60 * 1000);
  f.timers[0].callback();
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.requests[2].init.method).toBe('PATCH');
  expect(f.requests[2].body).toEqual({ bearer: 'a'.repeat(43) });
  expect(f.mounts).toHaveLength(1);
  expect(f.mounts[0].getLaunchBearer()).toBe('b'.repeat(43));
  expect(f.stores[0].options.isCurrent()).toBe(true);
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
  f.controller.close();
  expect(f.clearTimer).toHaveBeenCalledWith(f.timers.filter(t=>t.delay>30000).at(-1));
});

test('uncertain renewal stops the old bridge and never retires learner state', async () => {
  const f = harness([response({ launch: null }), response(credential(), 201),
    () => Promise.reject(new Error('response lost'))]);
  await f.controller.start(f.host);
  f.timers[0].callback();
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.host.querySelector('iframe')).toBeNull();
  expect(f.states.at(-1).status).toBe('error');
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
  expect(() => f.mounts[0].getLaunchBearer()).toThrow();
});

test('a platform-session-capped renewal schedules expiry instead of a renewal loop', async () => {
  const f = harness([response({ launch: null }), response(credential(), 201), response(credential(2, 6))]);
  await f.controller.start(f.host);
  f.timers[0].callback();
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.timers.filter(t=>t.delay>30000).at(-1).delay).toBe(30 * 60 * 1000);
  f.timers.filter(t=>t.delay>30000).at(-1).callback();
  expect(f.requests).toHaveLength(3);
  expect(f.host.querySelector('iframe')).toBeNull();
  expect(f.states.at(-1).message).toContain('expired');
});

test('reset fences a late renewal response and keeps the new generation credential', async () => {
  let finishRenewal;
  const pending = new Promise(resolve => { finishRenewal = resolve; });
  const f = harness([response({ launch: null }), response(credential(), 201), () => pending,
    response({ resetId: '40000000-0000-4000-8000-000000000071', cleanupComplete: true,
      launch: launch(3, 6) }), response(credential(3, 6, 'c'.repeat(43)))]);
  await f.controller.start(f.host);
  f.timers[0].callback();
  await f.controller.reset();
  expect(f.requests[2].init.signal.aborted).toBe(true);
  finishRenewal(response(credential(2, 6, 'b'.repeat(43))));
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.mounts).toHaveLength(2);
  expect(f.mounts[1].getLaunchBearer()).toBe('c'.repeat(43));
  expect(f.states.at(-1).launch.generation).toBe(3);
  expect(f.stores[0].store.retire).toHaveBeenCalledTimes(1);
  f.controller.close();
});

test('new generation renewal is not swallowed by an unsettled old generation PATCH', async () => {
  let finishOld;
  const pending = new Promise(resolve => { finishOld = resolve; });
  const extended = credential(3, 7, 'd'.repeat(43));
  extended.launch.expiresAt = '2026-09-14T00:00:00.000Z';
  const f = harness([response({ launch: null }), response(credential(), 201), () => pending,
    response({ resetId: '40000000-0000-4000-8000-000000000071', cleanupComplete: true,
      launch: launch(3, 6) }), response(credential(3, 6, 'c'.repeat(43))), response(extended)]);
  await f.controller.start(f.host);
  f.timers[0].callback();
  await f.controller.reset();
  f.timers.filter(t=>t.delay>30000).at(-1).callback();
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.requests[5].body).toEqual({ bearer: 'c'.repeat(43) });
  expect(f.mounts[1].getLaunchBearer()).toBe('d'.repeat(43));
  finishOld(response(credential(2, 6, 'b'.repeat(43))));
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(f.mounts[1].getLaunchBearer()).toBe('d'.repeat(43));
  expect(f.states.at(-1).launch.generation).toBe(3);
  f.controller.close();
});

test('reset after platform token loss detaches the fenced frame and reports session loss', async () => {
  let token = 'platform-token';
  const f = harness([response({ launch: null }), response(credential(), 201)],
    { getPlatformToken: () => token });
  await f.controller.start(f.host);
  token = null;
  await expect(f.controller.reset()).rejects.toThrow();
  expect(f.host.querySelector('iframe')).toBeNull();
  expect(f.states.at(-1).message).toContain('Platform session changed');
  expect(f.requests).toHaveLength(2);
  expect(f.stores[0].store.retire).not.toHaveBeenCalled();
});

test('heartbeat uses current ready launch, respects hidden document and stops old frame after close',async()=>{
 const f=harness([response({launch:null}),response(credential(),201),response({success:true})]);
 await f.controller.start(f.host);const first=f.timers.find(t=>t.delay===0);expect(first).toBeDefined();
 Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});
 await first.callback();expect(f.requests.at(-1).url).toBe('/api/auth/secureshop-launch/heartbeat');expect(f.requests.at(-1).body).toEqual({bearer:'a'.repeat(43),expectedGeneration:2});
 const tick=f.timers.filter(t=>t.delay===30000).at(-1);const count=f.requests.length;
 Object.defineProperty(document,'visibilityState',{configurable:true,value:'hidden'});await tick.callback();expect(f.requests).toHaveLength(count);
 f.controller.close();f.mounts[0].onActivity();await tick.callback();expect(f.requests).toHaveLength(count);
 Object.defineProperty(document,'visibilityState',{configurable:true,value:'visible'});
});

test.each(['reset','renew'])('late old heartbeat409 cannot detach after %s',async operation=>{
 let finish;const pending=new Promise(r=>{finish=r;});let clock=Date.parse('2026-09-13T22:30:00.000Z');
 const next=credential(operation==='reset'?3:2,6,'b'.repeat(43));next.launch.expiresAt='2026-09-14T00:00:00.000Z';
 const replies=[response({launch:null}),response(credential(),201),()=>pending];
 if(operation==='reset')replies.push(response({resetId:'40000000-0000-4000-8000-000000000071',cleanupComplete:true,launch:next.launch}));replies.push(response(next));
 const f=harness(replies,{clock:()=>clock});await f.controller.start(f.host);const heartbeat=f.timers.find(t=>t.delay===0).callback();
 if(operation==='reset')await f.controller.reset();else{clock+=121000;f.timers.find(t=>t.delay>30000).callback();await new Promise(r=>setTimeout(r,0));}
 finish(response({error:'old credential'},409));await heartbeat;await new Promise(r=>setTimeout(r,0));
 expect(f.host.querySelector('iframe')).not.toBeNull();expect(f.states.at(-1).status).toBe('ready');expect(f.mounts.at(-1).getLaunchBearer()).toBe('b'.repeat(43));
 if(operation==='renew'){const count=f.requests.length;await f.timers.filter(t=>t.delay===0).at(-1).callback();expect(f.requests).toHaveLength(count);f.mounts[0].onActivity();await f.timers.filter(t=>t.delay===30000).at(-1).callback();expect(f.requests).toHaveLength(count+1);}
 f.controller.close();
});

for (const stage of ['headers', 'body']) test(`stalled ${stage} reaches error; late completion cannot mount and timer is cleared`, async () => {
  let finish;
  const waiting = new Promise(resolve => { finish = resolve; });
  const f = harness([stage === 'headers' ? () => waiting : { ok: true, json: () => waiting }]);
  const pending = f.controller.start(f.host);
  const rejected = expect(pending).rejects.toMatchObject({ name: 'TimeoutError' });
  await Promise.resolve(); await Promise.resolve();
  const timer = f.timers.find(t => t.delay === 60000);
  timer.callback(); await rejected;
  expect(f.states.at(-1).status).toBe('error');
  expect(f.requests[0].init.signal.aborted).toBe(true);
  expect(f.clearTimer).toHaveBeenCalledWith(timer);
  finish(stage === 'headers' ? response({ launch: null }) : { launch: null });
  await Promise.resolve(); await Promise.resolve();
  expect(f.requests).toHaveLength(1); expect(f.mounts).toHaveLength(0);
  f.controller.close();
});

test('metadata and recovery share the original operation deadline', async () => {
  let now=Date.parse('2026-09-13T22:30:00.000Z');
  const f=harness([()=>{now+=45000;return response({launch:launch()});},()=>new Promise(()=>{})],{clock:()=>now});
  const pending=f.controller.start(f.host);const rejected=expect(pending).rejects.toMatchObject({name:'TimeoutError'});
  for(let i=0;i<8;i++)await Promise.resolve();
  const timer=f.timers.find(t=>t.delay===15000);expect(timer).toBeDefined();timer.callback();await rejected;
  expect(f.mounts).toHaveLength(0);f.controller.close();
});

test('timed-out uncertain reset retries the same key and never restores the old frame', async () => {
  let late;const waiting=new Promise(resolve=>{late=resolve;});
  const receipt={resetId:'40000000-0000-4000-8000-000000000071',cleanupComplete:true,launch:launch(3,6)};
  const f=harness([response({launch:null}),response(credential()),()=>waiting,response(receipt),response(credential(3,6))]);
  await f.controller.start(f.host);const pending=f.controller.reset();const rejected=expect(pending).rejects.toMatchObject({name:'TimeoutError'});
  f.timers.find(t=>t.delay===60000).callback();await rejected;
  expect(f.states.at(-1).retryReset).toBe(true);expect(f.host.querySelector('iframe')).toBeNull();
  await f.controller.reset();const requests=f.requests.filter(x=>x.url.endsWith('/reset'));
  expect(requests).toHaveLength(2);expect(requests[1].body).toEqual(requests[0].body);expect(f.randomUUID).toHaveBeenCalledTimes(1);
  late(response(receipt));await Promise.resolve();await Promise.resolve();
  expect(f.mounts).toHaveLength(2);expect(f.states.at(-1).launch.generation).toBe(3);f.controller.close();
});

test('close settles a noncooperative fetch and removes its timeout', async()=>{
  const f=harness([()=>new Promise(()=>{})]);const pending=f.controller.start(f.host);const rejected=expect(pending).rejects.toMatchObject({name:'AbortError'});
  const timer=f.timers.find(t=>t.delay===60000);f.controller.close();await rejected;expect(f.clearTimer).toHaveBeenCalledWith(timer);
});
