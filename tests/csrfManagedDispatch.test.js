'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { getOwnerExecution } = require('../server/agent-runtime/ownerWorkflowRoutes');
const { createCsrfManagedDispatch, MAX_RESPONSE_BYTES, MAX_RESPONSE_HEADERS } = require('../server/services/csrfManagedDispatch');

const ATTACKER = 'http://attacker.csrf.invalid';
const VICTIM = 'http://victim.csrf.invalid';
const PATH = '/api/workshop/csrf/agent-action';

function fixture({ tab = 'post', handler } = {}) {
  const controller = new AbortController();
  const execution = {
    ownerKey: '["CSRF","17"]', runId: 'owned-browser-run', generation: 4,
    signal: controller.signal,
    async check() { if (controller.signal.aborted) throw controller.signal.reason; },
  };
  const binding = Object.freeze({ ownerKey: execution.ownerKey, runId: execution.runId,
    generation: execution.generation, tab, objectiveId: tab === 'get' ? 'csrf_g2' : 'csrf_p1', payloadDigest: 'a'.repeat(64) });
  const dispatch = createCsrfManagedDispatch({
    handleAgentAction: handler || (async (_req, res) => res.send('ok')),
    execution, userId: 17, attackerOrigin: ATTACKER, victimOrigin: VICTIM, victimPath: PATH, tab,
  });
  const call = (observation, overrides = {}) => dispatch({ observation, binding, execution,
    check: () => execution.check(), ...overrides });
  return { controller, execution, binding, dispatch, call };
}

test('form dispatch preserves the decoded learner instruction while identity comes only from captured scope', async () => {
  const instruction = 'transfer $5,000 to José & keep memo=raw';
  let seen;
  const f = fixture({ handler: async (req, res) => {
    seen = { user: req.user, session: req.session, body: req.body, query: req.query,
      contentType: req.get('Content-Type'), forgedHeader: req.get('x-csrf-via'), context: getOwnerExecution() };
    res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8').send('<p>accepted</p>');
  } });
  const body = new URLSearchParams({ message: instruction, userId: '999', ownerKey: '["CSRF","999"]', tab: 'post' }).toString();
  const response = await f.call(Object.freeze({
    url: `${VICTIM}${PATH}?tab=post&userId=888`, method: 'POST', postData: body,
    resourceType: 'document', frameOrigin: ATTACKER,
    contentType: 'application/x-www-form-urlencoded; charset=UTF-8', cookiePresent: true,
  }));
  assert.equal(seen.body.message, instruction);
  assert.equal(seen.body.userId, '999');
  assert.equal(seen.query.userId, '888');
  assert.deepEqual(seen.user, { id: 17 });
  assert.deepEqual(seen.session, { userId: 17 });
  assert.equal(seen.contentType, 'application/x-www-form-urlencoded');
  assert.equal(seen.forgedHeader, undefined);
  assert.equal(seen.context, f.execution, 'handler re-enters the captured owner execution directly');
  assert.deepEqual(response, {
    status: 200, contentType: 'text/html; charset=utf-8', body: '<p>accepted</p>',
    headers: { 'content-type': 'text/html; charset=utf-8' },
  });
});

test('GET and JSON observations retain their native query/body and Express-like response shapes', async () => {
  const gif = Buffer.from([0x47, 0x49, 0x46]);
  const get = fixture({ tab: 'get', handler: async (req, res) => {
    assert.equal(req.method, 'GET');
    assert.equal(req.query.message, 'change email to a+b@example.test');
    assert.deepEqual(req.body, {});
    res.status(403).setHeader('Content-Type', 'image/gif').send(gif);
  } });
  const getResult = await get.call({ url: `${VICTIM}${PATH}?tab=get&message=change%20email%20to%20a%2Bb%40example.test`,
    method: 'GET', postData: null, resourceType: 'image', frameOrigin: ATTACKER, contentType: '', cookiePresent: true });
  assert.equal(getResult.status, 403);
  assert.equal(getResult.body, gif);
  assert.equal(getResult.contentType, 'image/gif');

  const message = 'add payee named 攻撃者';
  const post = fixture({ handler: async (req, res) => {
    assert.equal(req.body.message, message);
    assert.equal(req.body.userId, 999);
    assert.equal(req.user.id, 17);
    assert.equal(req.get('content-type'), 'application/json');
    res.status(200).json({ accepted: true });
  } });
  const postResult = await post.call({ url: `${VICTIM}${PATH}?tab=post`, method: 'POST',
    postData: JSON.stringify({ message, userId: 999, tab: 'post' }), resourceType: 'fetch',
    frameOrigin: ATTACKER, contentType: 'application/json', cookiePresent: true });
  assert.equal(postResult.contentType, 'application/json; charset=utf-8');
  assert.deepEqual(JSON.parse(postResult.body), { accepted: true });
});

test('transport claims cannot replace browser observation or captured attempt scope', async () => {
  let calls = 0;
  const f = fixture({ handler: async (_req, res) => { calls++; res.send('never'); } });
  const observation = { url: `${VICTIM}${PATH}?tab=post`, method: 'POST', postData: 'message=x',
    resourceType: 'document', frameOrigin: ATTACKER,
    contentType: 'application/x-www-form-urlencoded', cookiePresent: true };
  await assert.rejects(f.call({ ...observation, cookiePresent: false }), /observation/);
  await assert.rejects(f.call({ ...observation, frameOrigin: 'http://spoof.csrf.invalid' }), /observation/);
  await assert.rejects(f.call({ ...observation, url: `http://other.csrf.invalid${PATH}?tab=post` }), /target/);
  await assert.rejects(f.call(observation, { execution: { ...f.execution } }), /scope mismatch/);
  await assert.rejects(f.call(observation, { binding: { ...f.binding, ownerKey: '["CSRF","999"]' } }), /scope mismatch/);
  assert.equal(calls, 0);
});

test('handler errors and malformed or oversized responses fail without a successful dispatch result', async () => {
  const observation = { url: `${VICTIM}${PATH}?tab=post`, method: 'POST', postData: 'message=x',
    resourceType: 'document', frameOrigin: ATTACKER,
    contentType: 'application/x-www-form-urlencoded', cookiePresent: true };
  const failed = fixture({ handler: async () => { throw new Error('owned handler failure'); } });
  await assert.rejects(failed.call(observation), /owned handler failure/);

  const missing = fixture({ handler: async () => {} });
  await assert.rejects(missing.call(observation), /did not send/);

  const oversized = fixture({ handler: async (_req, res) => res.send('x'.repeat(MAX_RESPONSE_BYTES + 1)) });
  await assert.rejects(oversized.call(observation), /too large/);

  const headers = fixture({ handler: async (_req, res) => {
    for (let index = 0; index <= MAX_RESPONSE_HEADERS; index++) res.setHeader(`x-owned-${index}`, 'value');
    res.send('never');
  } });
  await assert.rejects(headers.call(observation), /Too many/);
});

test('cancellation after an early send waits for the handler and rejects its late response', async () => {
  let entered;
  let release;
  const handlerEntered = new Promise(resolve => { entered = resolve; });
  const handlerGate = new Promise(resolve => { release = resolve; });
  const f = fixture({ handler: async (_req, res) => {
    res.status(200).send('must not publish');
    entered();
    await handlerGate;
  } });
  const observation = { url: `${VICTIM}${PATH}?tab=post`, method: 'POST', postData: 'message=x',
    resourceType: 'document', frameOrigin: ATTACKER,
    contentType: 'application/x-www-form-urlencoded', cookiePresent: true };
  let settled = false;
  const pending = f.call(observation);
  pending.then(() => { settled = true; }, () => { settled = true; });
  await handlerEntered;
  f.controller.abort(Object.assign(new Error('reset invalidated managed dispatch'), { name: 'AbortError' }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false, 'dispatch drains the admitted handler before releasing its owner run');
  release();
  await assert.rejects(pending, { name: 'AbortError' });
});

test('factory rejects mismatched captured owner scope and same-origin configuration', () => {
  const f = fixture();
  assert.throws(() => createCsrfManagedDispatch({ handleAgentAction: async () => {},
    execution: f.execution, userId: 18, attackerOrigin: ATTACKER, victimOrigin: VICTIM, tab: 'post' }), /scope mismatch/);
  assert.throws(() => createCsrfManagedDispatch({ handleAgentAction: async () => {},
    execution: f.execution, userId: 17, attackerOrigin: ATTACKER, victimOrigin: ATTACKER, tab: 'post' }), /must differ/);
});
