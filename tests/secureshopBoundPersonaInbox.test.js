'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createBoundPersonaInboxRouter } = require('../server/routes/secureshop/boundPersonaInbox');

const bearer = 'p'.repeat(43);
const scope = Object.freeze({ launchId: '10000000-0000-4000-8000-000000000002',
  scenarioId: '20000000-0000-4000-8000-000000000002', generation: 1,
  platformOwnerId: 9, platformSessionId: 10 });
async function fixture(t, personaSession) {
  const calls = [];
  const launches = { async resolveCapability(value) { return value === bearer ? scope : null; } };
  const authenticatePersona = (req, res, next) => {
    const match = /^Bearer (customer|merchant|admin)-(\d+)$/.exec(req.get('authorization') || '');
    if (!match) return res.status(401).json({ error: 'Shop authentication required' });
    req.ssUser = { id: Number(match[2]), role: match[1] }; if(personaSession)req.ssPersonaSession=personaSession;next();
  };
  const application = {
    async status(input) { calls.push(['status', input]); return { ready: true, acl: { version: 1, mode: 'advisory' }, messages: [] }; },
    async run(input) { calls.push(['run', input]); return { ok: true, stopReason: 'end_turn', replayed: false, accesses: [] }; },
    async enforce(input) { calls.push(['enforce', input]); if (input.persona.role !== 'merchant') {
      throw Object.assign(new Error('role'), { code: 'OWNER_MISMATCH' });
    } return { version: 2, mode: 'enforced' }; },
  };
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', createBoundPersonaInboxRouter({ launches, authenticatePersona, application }));
  app.use((_req, res) => res.status(599).json({ legacy: true }));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { base: `http://127.0.0.1:${server.address().port}/api/secureshop`, calls };
}
function headers(role = 'merchant', token = bearer) {
  return { authorization: `Bearer ${role}-12`, 'x-owasp-ai-goat-secureshop-launch': token,
    'content-type': 'application/json' };
}

test('mounted routes bind launch and persona without body authority', async t => {
  const f = await fixture(t);
  const ready = await fetch(`${f.base}/v2/persona-inbox/readiness`, { headers: headers() });
  assert.equal(ready.status, 200); assert.equal((await ready.json()).ready, true);
  const id = '30000000-0000-4000-8000-000000000002';
  const read = await fetch(`${f.base}/v2/persona-inbox/read`, { method: 'POST', headers: headers(),
    body: JSON.stringify({ request_id: id, message_id: 3 }) });
  assert.equal(read.status, 200);
  assert.deepEqual(f.calls[1][1].scope, scope);
  assert.deepEqual(f.calls[1][1].persona, { id: 12, role: 'merchant' });
  assert.equal(f.calls[1][1].requestId, id); assert.equal(f.calls[1][1].messageId, 3);
});

test('invalid authority and malformed requests fail without fallback', async t => {
  const f = await fixture(t);
  assert.equal((await fetch(`${f.base}/v2/persona-inbox/readiness`, { headers: headers('merchant', 'x'.repeat(43)) })).status, 401);
  assert.equal((await fetch(`${f.base}/v2/persona-inbox/read`, { method: 'POST', headers: headers(),
    body: JSON.stringify({ request_id: 'bad', message_id: 3, platformOwnerId: 99 }) })).status, 400);
  assert.equal(f.calls.length, 0);
});

test('ACL transition requires merchant and exposes no caller-selected version or mode', async t => {
  const f = await fixture(t);
  const denied = await fetch(`${f.base}/v2/persona-inbox/enforce`, { method: 'POST', headers: headers('customer'), body: '{}' });
  assert.equal(denied.status, 403);
  const invalid = await fetch(`${f.base}/v2/persona-inbox/enforce`, { method: 'POST', headers: headers(),
    body: JSON.stringify({ expectedVersion: 99, mode: 'advisory' }) });
  assert.equal(invalid.status, 400);
  const accepted = await fetch(`${f.base}/v2/persona-inbox/enforce`, { method: 'POST', headers: headers(), body: '{}' });
  assert.equal(accepted.status, 200); assert.equal((await accepted.json()).acl.mode, 'enforced');
});

test('manual status and enforce forward only verified middleware session metadata',async t=>{
 const session=Object.freeze({sessionId:'owned-session',authorityVersion:'3'}),f=await fixture(t,session);
 assert.equal((await fetch(`${f.base}/v2/persona-inbox/readiness`,{headers:headers()})).status,200);
 assert.equal((await fetch(`${f.base}/v2/persona-inbox/enforce`,{method:'POST',headers:headers(),body:'{}'})).status,200);
 assert.equal(f.calls[0][1].personaSession,session);assert.equal(f.calls[1][1].personaSession,session);
 assert.equal((await fetch(`${f.base}/v2/persona-inbox/enforce`,{method:'POST',headers:headers(),body:JSON.stringify({personaSession:{sessionId:'forged'}})})).status,400);assert.equal(f.calls.length,2);
});
