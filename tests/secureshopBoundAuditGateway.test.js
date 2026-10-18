'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createSecureShopBoundGateway } = require('../server/routes/secureshop/boundGateway');

const launch = Object.freeze({
  launchId: '10000000-0000-4000-8000-000000000091',
  scenarioId: '20000000-0000-4000-8000-000000000091',
  generation: 4, platformOwnerId: 91, platformSessionId: 901,
});
const sessionId = '30000000-0000-4000-8000-000000000091';
const requestId = '40000000-0000-4000-8000-000000000091';
const runId = '50000000-0000-4000-8000-000000000091';
const personaSession = Object.freeze({ sessionId: '60000000-0000-4000-8000-000000000091', authorityVersion: '9', expiresAt: 9999999999 });

function methods(names) {
  return Object.fromEntries(names.map(name => [name, async () => ({})]));
}

function gateway(auditSummary, role='admin', {auditSearch, auditAgentReady = false, auditTimingReady = false, auditUnbounded} = {}) {
  const personaAuth = methods(['login', 'renew', 'logout', 'listSessions', 'revokeOwnedSession',
    'changePassword', 'listApiKey', 'rotateApiKey', 'authenticateApiKey']);
  return createSecureShopBoundGateway({
    launches: { async resolveCapability() { return launch; } },
    authenticatePersona(req, res, next) {
      req.ssUser = { id: 7, role };
      req.ssPersonaSession = personaSession;
      next();
    },
    personaAuth,
    reviewsRouter: express.Router(), browserRouter: express.Router(),
    catalog: methods(['listProducts', 'getProduct', 'listMerchantProducts', 'createMerchantProduct',
      'updateMerchantProduct', 'archiveMerchantProduct', 'categories']),
    commerce: methods(['cart', 'add', 'update', 'remove', 'summary', 'checkout', 'orders', 'order']),
    account: methods(['profile', 'updateProfile', 'addresses', 'createAddress', 'updateAddress',
      'deleteAddress']),
    auditSummary, auditUnbounded, auditSearch, auditAgentReady, auditTimingReady,
  });
}

async function appServer(t, auditSummary, role='admin', options) {
  const app = express(); app.use(express.json());
  app.use('/api/secureshop', gateway(auditSummary,role,options));
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}/api/secureshop`;
}

function headers() {
  return { authorization: 'Bearer admin-7', 'x-dvaia-secureshop-launch': 'g'.repeat(43) };
}

test('bound audit capabilities report each composed admission without claiming model-agent readiness from method presence', async t => {
  const path = '/admin/audit/capabilities';
  const read = async base => {
    const response = await fetch(`${base}${path}`, { headers: headers() });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    return response.json();
  };
  const absent = await read(await appServer(t));
  assert.deepEqual(absent, { ok: true, capabilities: {
    manualSearch: { ready: false, reason: 'Owned audit search is unavailable' },
    agentSearch: { ready: false, reason: 'Owned audit agent is unavailable' },
    timingAgent: { ready: false, reason: 'Owned audit timing agent is unavailable' },
    summary: { ready: false, reason: 'Audit summary is unavailable' },
    unbounded: { ready: false, reason: 'Audit unbounded summary is unavailable' },
  } });

  const auditSearch = methods(['search', 'createAgentSession', 'runAgent']);
  const manualOnly = await read(await appServer(t, undefined, 'admin', { auditSearch }));
  assert.deepEqual(manualOnly.capabilities, {
    manualSearch: { ready: true },
    agentSearch: { ready: false, reason: 'Owned audit agent is unavailable' },
    timingAgent: { ready: false, reason: 'Owned audit timing agent is unavailable' },
    summary: { ready: false, reason: 'Audit summary is unavailable' },
    unbounded: { ready: false, reason: 'Audit unbounded summary is unavailable' },
  });

  const summary = methods(['createSession', 'run']);
  const ready = await read(await appServer(t, summary, 'admin', { auditSearch, auditAgentReady: true }));
  assert.deepEqual(ready.capabilities, {
    manualSearch: { ready: true }, agentSearch: { ready: true },
    timingAgent: { ready: false, reason: 'Owned audit timing agent is unavailable' },
    summary: { ready: true }, unbounded: { ready: false, reason: 'Audit unbounded summary is unavailable' },
  });
});

test('bound audit capabilities require launch and admin persona and reject query input', async t => {
  const base = await appServer(t, undefined, 'customer');
  const path = `${base}/admin/audit/capabilities`;
  assert.equal((await fetch(path)).status, 404);
  assert.equal((await fetch(path, { headers: headers() })).status, 403);
  const adminBase = await appServer(t);
  assert.equal((await fetch(`${adminBase}/admin/audit/capabilities?probe=1`, { headers: headers() })).status, 400);
});

test('timing audit routes are a separate server-enabled admin purpose with closed request input', async t => {
  const calls = [];
  const auditSearch = {
    ...methods(['search', 'createAgentSession', 'runAgent']),
    async createTimingSession(input) { calls.push(['session', input]); return { ok: true, sessionId }; },
    async runTimingAgent(input) { calls.push(['run', input]); return { result: { text: 'Observed owned SQL timing.',
      query: { ok: true }, provider: 'ollama', model: 'llama3.1:8b', assessment: { completed: false } }, replayed: false }; },
  };
  const denied = await appServer(t, undefined, 'admin', { auditSearch });
  assert.equal((await fetch(`${denied}/admin/audit/timing-session`, { method: 'POST', headers: { ...headers(), 'content-type': 'application/json' }, body: '{}' })).status, 503);
  const base = await appServer(t, undefined, 'admin', { auditSearch, auditTimingReady: true });
  const created = await fetch(`${base}/admin/audit/timing-session`, { method: 'POST', headers: { ...headers(), 'content-type': 'application/json' }, body: '{}' });
  assert.equal(created.status, 200);
  assert.deepEqual(await created.json(), { ok: true, sessionId });
  assert.equal((await fetch(`${base}/admin/audit/timing-run`, { method: 'POST', headers: { ...headers(), 'content-type': 'application/json' }, body: JSON.stringify({ sessionId, requestId, message: 'x', purpose: 'secureshop_audit_sql' }) })).status, 400);
  const response = await fetch(`${base}/admin/audit/timing-run`, { method: 'POST', headers: { ...headers(), 'content-type': 'application/json' }, body: JSON.stringify({ sessionId, requestId, message: 'Check audit timing' }) });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).result.text, 'Observed owned SQL timing.');
  assert.deepEqual(calls.map(row => row[0]), ['session', 'run']);
  assert.equal(calls[1][1].sessionId, sessionId);
  assert.equal(calls[1][1].requestId, requestId);
  assert.deepEqual(calls[1][1].personaSession, { sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion });
});

test('unbounded summary routes use the separate injected service and old summary remains unchanged', async t => {
  const calls=[];
  const auditSummary={async createSession(){calls.push('old-session');return{sessionId};},async run(){calls.push('old-run');throw Error('Not selected');}};
  const auditUnbounded={async createSession(){calls.push('new-session');return{sessionId};},async run(input){calls.push('new-run');return{
    runId,summary:'Observed large owned audit context.',provider:'ollama',model:'llama3.1:8b',
    requestedCount:input.requestedCount,rowCount:1,objectiveCredit:false,replayed:false,
    assessment:{completed:false,judgment:{verdict:'fail'}},
  };}};
  const base=await appServer(t,auditSummary,'admin',{auditUnbounded});
  const created=await fetch(`${base}/admin/audit/unbounded-session`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:'{}'});
  assert.equal(created.status,200);assert.deepEqual(await created.json(),{ok:true,sessionId});
  const response=await fetch(`${base}/admin/audit/unbounded-summary`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify({session_id:sessionId,request_id:requestId,limit:10000})});
  assert.equal(response.status,200);assert.equal((await response.json()).summary,'Observed large owned audit context.');
  assert.deepEqual(calls,['new-session','new-run']);
});

test('bound audit gateway admits an admin session and validates the durable summary DTO', async t => {
  const calls = [];
  const base = await appServer(t, {
    async createSession(input) { calls.push(['session', input]); return { sessionId }; },
    async run(input) {
      calls.push(['run', input]);
      return { runId, summary: 'Observed one anomaly.', provider: 'ollama', model: 'llama3.1:8b',
        requestedCount: input.requestedCount, rowCount: 1, objectiveCredit: false,
        replayed: false, assessment: { completed: false, judgment: { verdict: 'fail' } } };
    },
  });
  const created = await fetch(`${base}/admin/audit/bound-session`, { method: 'POST', headers: { ...headers(), 'content-type': 'application/json' }, body: '{}' });
  assert.equal(created.status, 200);
  assert.deepEqual(await created.json(), { ok: true, sessionId });
  const response = await fetch(`${base}/admin/audit/bound-summary`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, request_id: requestId, limit: 20 }),
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { runId, summary: 'Observed one anomaly.', provider: 'ollama',
    model: 'llama3.1:8b', requestedCount: 20, rowCount: 1, objectiveCredit: false,
    replayed: false, assessment: { completed: false, judgment: { verdict: 'fail' } } });
  assert.deepEqual(calls[0][1].scope, launch); assert.deepEqual(calls[0][1].persona, { id: 7, role: 'admin' });
  assert.deepEqual(calls[0][1].personaSession, {sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion});
  assert.equal(calls[1][1].sessionId, sessionId); assert.equal(calls[1][1].requestId, requestId);
  assert.deepEqual(calls[1][1].personaSession, {sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion});
  assert.equal(calls[1][1].signal instanceof AbortSignal, true);
});

test('bound audit gateway stays terminal and rejects malformed admission', async t => {
  const base = await appServer(t);
  const missing = await fetch(`${base}/admin/audit/bound-summary`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, request_id: requestId, limit: 20 }),
  });
  assert.equal(missing.status, 503);
  const malformed = await fetch(`${base}/admin/audit/bound-summary`, {
    method: 'POST', headers: { ...headers(), 'content-type': 'application/json' },
    body: JSON.stringify({ session_id: 'bad', request_id: requestId, limit: 20 }),
  });
  assert.equal(malformed.status, 400);
});

test('customer persona cannot create or run an administrator audit session',async t=>{
 let called=false;const base=await appServer(t,{createSession(){called=true;},run(){called=true;}},'customer');
 for(const [route,body] of [['bound-session',{}],['bound-summary',{session_id:sessionId,request_id:requestId,limit:20}]]){
  const response=await fetch(`${base}/admin/audit/${route}`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify(body)});
  assert.equal(response.status,403);
 }
 assert.equal(called,false);
});
test('inconsistent completion and malformed Judge DTOs cannot report success',async t=>{
 let assessment;
 const base=await appServer(t,{async createSession(){return{sessionId};},async run(){return{runId,summary:'Observed',provider:'ollama',model:'llama3.1:8b',requestedCount:20,rowCount:1,objectiveCredit:true,replayed:false,assessment};}});
 for(const value of [undefined,{completed:true},{completed:false,judgment:{verdict:'pass'}},{completed:true,judgment:{verdict:'fail'}}]){
  assessment=value;
  const response=await fetch(`${base}/admin/audit/bound-summary`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify({session_id:sessionId,request_id:requestId,limit:20})});
  assert.equal(response.status,503);
 }
});

test('fixed audit cap returns actionable error and rejects forged result provenance',async t=>{
 let runs=0;const base=await appServer(t,{async createSession(){return{sessionId};},async run(){runs++;throw Object.assign(Error('private'),{code:'AUDIT_FIXED_COUNT_LIMIT'});}});
 const post=body=>fetch(`${base}/admin/audit/bound-summary`,{method:'POST',headers:{...headers(),'content-type':'application/json'},body:JSON.stringify(body)});
 const body={session_id:sessionId,request_id:requestId,limit:101};const result=await post(body);assert.equal(result.status,400);assert.deepEqual(await result.json(),{error:'Fixed audit summaries accept at most 100 events'});
 assert.equal((await post({...body,modeCapability:{effectiveMode:'fixed'}})).status,400);assert.equal(runs,1);
});
