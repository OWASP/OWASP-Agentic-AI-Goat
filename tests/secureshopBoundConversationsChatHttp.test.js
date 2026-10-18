'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const express = require('express');
const { buildBoundConversationRouter } = require('../server/routes/secureshopBoundConversations');

const sessionId = '11111111-1111-4111-8111-111111111111';
const requestId = '22222222-2222-4222-8222-222222222222';
const scope = Object.freeze({
  launchId: '33333333-3333-4333-8333-333333333333',
  scenarioId: '44444444-4444-4444-8444-444444444444',
  generation: 3, platformOwnerId: 7, platformSessionId: 8,
});
const persona = Object.freeze({ id: 9, role: 'customer' });
const launchToken = 'a'.repeat(43);

async function fixture(t, runner) {
  const app = express();
  app.use(express.json());
  app.use(buildBoundConversationRouter({
    role: 'customer', runner, service: {},
    launches: { async resolveCapability(token) { return token === launchToken ? scope : null; } },
    authenticatePersona(req, _res, next) { req.ssUser = persona; next(); },
  }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(resolve);
  }));
  return `http://127.0.0.1:${server.address().port}`;
}

function headers(contentType = 'application/json') {
  return { 'x-dvaia-secureshop-launch': launchToken, 'content-type': contentType };
}

function eventNames(text) {
  return [...text.matchAll(/^event: (.+)$/gm)].map(match => match[1]);
}

test('optional bound chat route preserves request identity, raw message and existing SSE event contract', async t => {
  const calls = [];
  const runner = { async run(input) {
    calls.push(input);
    assert.equal(input.signal.aborted, false);
    input.stream.send('tool_call', { id: 'c1', tool: 'system.read_config', params: { path: '../file' }, step: 1 });
    input.stream.send('tool_result', { id: 'c1', result: { content: [{ type: 'text', text: 'raw' }] }, latencyMs: 2 });
    input.stream.send('assistant_message', { text: 'done', stopReason: 'end_turn', hops: 1 });
    input.stream.send('done', { sessionId: input.sessionId, stopReason: 'end_turn', steps: 2 });
    return { text: 'done' };
  } };
  const base = await fixture(t, runner);
  const rawMessage = "  preserve 'quoted' <script> input  ";
  const response = await fetch(`${base}/sessions/${sessionId}/chat`, {
    method: 'POST', headers: headers(), body: JSON.stringify({ requestId, message: rawMessage }),
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/event-stream');
  assert.equal(response.headers.get('cache-control'), 'no-store, no-transform');
  assert.deepEqual(eventNames(await response.text()), ['tool_call', 'tool_result', 'assistant_message', 'done']);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].sessionId, sessionId);
  assert.equal(calls[0].requestId, requestId);
  assert.equal(calls[0].message, rawMessage);
  assert.deepEqual(calls[0].scope, scope);
  assert.deepEqual(calls[0].persona, persona);

  const byteLimit = '😀'.repeat(16384);
  const boundary = await fetch(`${base}/sessions/${sessionId}/chat`, {
    method: 'POST', headers: headers(), body: JSON.stringify({ requestId, message: byteLimit }),
  });
  assert.equal(boundary.status, 200);
  await boundary.text();
  assert.equal(calls[1].message, byteLimit);
  assert.equal(Buffer.byteLength(calls[1].message, 'utf8'), 64 * 1024);
});

test('bound chat rejects non-JSON, malformed or authority-bearing bodies before the runner', async t => {
  let runs = 0;
  const base = await fixture(t, { async run() { runs++; } });
  const cases = [
    { body: { requestId, message: 'hello', scope } },
    { body: { requestId, message: 'hello', provider: 'ollama' } },
    { body: { requestId: 'not-a-uuid', message: 'hello' } },
    { body: { requestId, message: '  ' } },
    { body: { requestId, message: '😀'.repeat(16385) } },
    { body: [] },
  ];
  for (const item of cases) {
    const response = await fetch(`${base}/sessions/${sessionId}/chat`, {
      method: 'POST', headers: headers(), body: JSON.stringify(item.body),
    });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'requestId and message required' });
  }
  const query = await fetch(`${base}/sessions/${sessionId}/chat?owner=7`, {
    method: 'POST', headers: headers(), body: JSON.stringify({ requestId, message: 'hello' }),
  });
  assert.equal(query.status, 400);
  const wrongType = await fetch(`${base}/sessions/${sessionId}/chat`, {
    method: 'POST', headers: headers('text/plain'), body: JSON.stringify({ requestId, message: 'hello' }),
  });
  assert.equal(wrongType.status, 415);
  assert.equal(runs, 0);
});

test('pre-stream turn failures receive stable status classes without internal exception disclosure', async t => {
  const runner = { async run({ message }) {
    const code = ({ conflict: 'TURN_REQUEST_CONFLICT', recovery: 'TURN_RECOVERY_REQUIRED',
      capacity: 'TURN_CAPACITY', missing: 'CONVERSATION_UNAVAILABLE', stale: 'STALE_LAUNCH' })[message];
    throw Object.assign(new Error(`private database detail for ${message}`), { code });
  } };
  const base = await fixture(t, runner);
  const expected = {
    conflict: [409, 'Turn request conflicts with its original message'],
    recovery: [409, 'Turn outcome requires recovery'],
    capacity: [409, 'Conversation turn limit reached'],
    missing: [404, 'Conversation unavailable'],
    stale: [401, 'SecureShop launch unavailable'],
    internal: [503, 'Conversation service unavailable'],
  };
  for (const [message, [status, error]] of Object.entries(expected)) {
    const response = await fetch(`${base}/sessions/${sessionId}/chat`, {
      method: 'POST', headers: headers(), body: JSON.stringify({ requestId, message }),
    });
    assert.equal(response.status, status, message);
    const body = await response.json();
    assert.deepEqual(body, { error });
    assert.equal(JSON.stringify(body).includes('private database detail'), false);
  }
});

test('post-stream failure emits one redacted SSE error and closes the stream', async t => {
  const base = await fixture(t, { async run({ stream }) {
    stream.send('tool_call', { id: 'c1', tool: 'system.read_config', params: {}, step: 1 });
    throw new Error('private filesystem path /tmp/owned-secret');
  } });
  const response = await fetch(`${base}/sessions/${sessionId}/chat`, {
    method: 'POST', headers: headers(), body: JSON.stringify({ requestId, message: 'stream failure' }),
  });
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.deepEqual(eventNames(text), ['tool_call', 'error']);
  assert.match(text, /Conversation service unavailable/);
  assert.doesNotMatch(text, /private filesystem|owned-secret/);
});

test('closing a pending HTTP request aborts the runner and suppresses later writes', async t => {
  let enteredResolve, settledResolve;
  const entered = new Promise(resolve => { enteredResolve = resolve; });
  const settled = new Promise(resolve => { settledResolve = resolve; });
  let lateWrite;
  const base = await fixture(t, { async run({ signal, stream }) {
    enteredResolve();
    await new Promise(resolve => signal.addEventListener('abort', resolve, { once: true }));
    lateWrite = stream.send('assistant_message', { text: 'must not be written', stopReason: 'end_turn' });
    settledResolve();
    throw signal.reason || new DOMException('aborted', 'AbortError');
  } });
  const url = new URL(`${base}/sessions/${sessionId}/chat`);
  const req = http.request({ hostname: url.hostname, port: url.port, path: url.pathname,
    method: 'POST', headers: { ...headers(), connection: 'close' } });
  req.on('error', () => {});
  req.end(JSON.stringify({ requestId, message: 'wait for disconnect' }));
  await entered;
  req.destroy();
  await settled;
  assert.equal(lateWrite, false);
});

test('omitting the optional runner leaves the chat endpoint absent', async t => {
  const base = await fixture(t, undefined);
  const response = await fetch(`${base}/sessions/${sessionId}/chat`, {
    method: 'POST', headers: headers(), body: JSON.stringify({ requestId, message: 'hello' }),
  });
  assert.equal(response.status, 404);
});
test('bound conversation already projects coordinator busy as safe503 before opening SSE',async t=>{
 let calls=0;const base=await fixture(t,{run:async()=>{calls++;throw Object.assign(Error('private owner/capacity details'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503});}});
 const response=await fetch(`${base}/sessions/${sessionId}/chat`,{method:'POST',headers:headers(),body:JSON.stringify({requestId,message:'Controlled'})});assert.equal(response.status,503);assert.deepEqual(await response.json(),{error:'Conversation service unavailable'});assert.equal(calls,1);
});
