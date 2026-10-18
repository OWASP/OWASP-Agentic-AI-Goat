'use strict';

const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function guarded(request, parent, isMain) {
  if (/(?:^|\/)authDb(?:\.js)?$/.test(request)) throw new Error('agent-runs route imported authDb');
  return originalLoad.call(this, request, parent, isMain);
};
const { test, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const traces = require('../server/agent-runtime/runTraceStore');
const { createExcludedSecureShopOwnership } = require('./helpers/excludedSecureShopOwnership');
const { RUN_FAMILIES, OBSERVABLE_RUN_FAMILIES, createMemoryAgentRunReadRepository, createPostgresAgentRunReadRepository, ownerKey, encodeCursor, decodeCursor } = require('../server/database/postgres/agentRunReadRepository');
const { createAgentRunsRouter } = require('../server/routes/agentRuns');
Module._load = originalLoad;

const IDS = {
  aria7: '11111111-1111-4111-8111-111111111111', nova7: '22222222-2222-4222-8222-222222222222', aria8: '33333333-3333-4333-8333-333333333333',
  secureConversation: '44444444-4444-4444-8444-444444444444', secureRun: '55555555-5555-4555-8555-555555555555',
};

function seed(runId, family, userId, status = 'completed') {
  const context = { runId, ownerKey: ownerKey(family, userId), generation: 0 };
  traces.begin(context);
  traces.append(context, { node: 'decide', type: 'decision', data: { decisionSource: 'model', provider: 'ollama', model: 'llama3.1:8b', tokens: 4 } });
  traces.append(context, { node: 'tool', type: 'tool', data: { tool: 'view_cart', durationMs: 12 } });
  traces.finish(context, status);
}
function seedRow(runId, family, userId) {
  return { runId, ownerKey: ownerKey(family, userId), generation: 0, startedAt: '2026-09-10T00:00:00.000Z', finishedAt: null, lastNode: 'decide' };
}
function auth(req, res, next) {
  if (!req.headers.authorization) return res.status(401).json({ error: 'Authentication required' });
  req.user = { id: Number(req.headers.authorization.replace('Bearer ', '')) }; next();
}
const permission = () => (req, res, next) => req.headers['x-analytics'] === 'yes' ? next() : res.status(403).json({ error: 'Permission denied' });

async function start(repository, judgmentRows = []) {
  repository ||= createMemoryAgentRunReadRepository(traces, judgmentRows);
  const app = express();
  app.use('/api/agent-runs', createAgentRunsRouter({ repository, authenticateToken: auth, getGraphDefinition: name => ({ nodes: [{ id: `${name}:decide` }], edges: [] }) }));
  app.use('/api/admin/agent-runs', createAgentRunsRouter({ repository, authenticateToken: auth, requirePermission: permission, admin: true,
    getGraphDefinition: name => ({ nodes: [{ id: `${name}:decide` }], edges: [] }) }));
  const server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, request: async (path, { user = 7, analytics = false } = {}) => {
    const response = await fetch(base + path, { headers: { ...(user ? { authorization: `Bearer ${user}` } : {}), ...(analytics ? { 'x-analytics': 'yes' } : {}) } });
    return { status: response.status, body: await response.json() };
  } };
}

beforeEach(() => { for (const row of traces.snapshot()) traces.finish({ runId: row.runId }, 'cancelled'); });

test('mounted inspector supplies owned events and receipts to graph selection', async t => {
  const events = [{ node: 'stored_browser_assessment', type: 'node_start' }];
  const judgments = [{ objectiveId: 'ss_stored_browser_execution' }];
  let selected;
  const app = express();
  app.use(createAgentRunsRouter({ authenticateToken: auth, receiptAdapters: {},
    repository: {
      events: async () => ({ run: { runId: IDS.secureRun, family: 'SecureShopBoundConversation' }, events }),
      judgments: async () => judgments,
    },
    getGraphDefinition: (family, context) => { selected = { family, ...context }; return null; },
  }));
  const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/${IDS.secureRun}`, {
    headers: { authorization: 'Bearer 7' },
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json()).graph, null);
  assert.deepEqual(selected, { family: 'SecureShopBoundConversation', events, judgments });
});

test('inspector allowlist includes exact legacy grading coordinator families', () => {
  assert.ok(RUN_FAMILIES.includes('LegacySensitiveInfo'));
  assert.ok(RUN_FAMILIES.includes('XSS_EMAIL'));
  assert.ok(OBSERVABLE_RUN_FAMILIES.includes('SecureShopBoundConversation'));
  assert.ok(!RUN_FAMILIES.includes('SecureShopBoundConversation'),'conversation IDs must not enter the direct-owner deletion catalog');
});

test('sensitive lookup runs appear in the inspector without exposing another learner', async () => {
  seed(IDS.aria7, 'SensitiveLookup', 7); seed(IDS.aria8, 'SensitiveLookup', 8);
  const { server, request } = await start();
  try {
    const result = await request('/api/agent-runs?family=SensitiveLookup');
    assert.equal(result.status, 200);
    assert.deepEqual(result.body.runs.map(run => run.runId), [IDS.aria7]);
    assert.equal((await request(`/api/agent-runs/${IDS.aria7}`)).status, 200);
    assert.equal((await request(`/api/agent-runs/${IDS.aria8}`)).status, 404);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('learner run API enforces authenticated ownership, opaque paging and incremental events', async () => {
  seed(IDS.aria7, 'ARIA', 7); seed(IDS.nova7, 'NOVA', 7); seed(IDS.aria8, 'ARIA', 8);
  const { server, request } = await start();
  try {
    assert.equal((await request('/api/agent-runs', { user: null })).status, 401);
    const first = await request('/api/agent-runs?limit=1');
    assert.equal(first.status, 200); assert.equal(first.body.runs.length, 1); assert.ok(first.body.nextCursor);
    assert.equal(first.body.runs[0].ownerId, undefined);
    const second = await request(`/api/agent-runs?limit=1&before=${encodeURIComponent(first.body.nextCursor)}`);
    assert.equal(second.status, 200); assert.equal(second.body.runs.length, 1); assert.notEqual(second.body.runs[0].runId, first.body.runs[0].runId);
    const foreign = await request(`/api/agent-runs/${IDS.aria8}`); assert.equal(foreign.status, 404);
    const detail = await request(`/api/agent-runs/${IDS.aria7}`); assert.equal(detail.status, 200);
    assert.equal(detail.body.events.length, 2); assert.equal(detail.body.graph.nodes[0].id, 'ARIA:decide');
    const incremental = await request(`/api/agent-runs/${IDS.aria7}/events?after=1&limit=1`);
    assert.equal(incremental.status, 200); assert.deepEqual(incremental.body.events.map(event => event.seq), [2]);
    assert.equal(incremental.body.run.status, 'completed');
    assert.equal((await request('/api/agent-runs?ownerId=8')).status, 400);
    assert.equal((await request('/api/agent-runs?family=CTF')).status, 200);
    assert.equal((await request('/api/agent-runs?limit=0')).status, 400);
    assert.equal((await request('/api/agent-runs?before=not-a-cursor')).status, 400);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('run detail exposes only owner-scoped canonical receipt metadata', async () => {
  seed(IDS.aria7, 'ARIA', 7);
  const { server, request } = await start(undefined, [
    { userId: 7, runId: IDS.aria7, evaluationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', workshopKey: 'sql_injection_workshop', objectiveId: 'sql_1', family: 'ARIA', scenario: 'product_search', rubricVersion: 'sql-v1', evidenceDigest: 'a'.repeat(64), verdict: 'pass', disposition: 'awarded', generation: 0, evaluatedAt: '2026-09-10T00:00:01.000Z', criteria: [{ id: 'observed', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: 'tool', quote: 'Owner-visible synthetic evidence.' }] }] },
    { userId: 8, runId: IDS.aria7, evaluationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', workshopKey: 'sql_injection_workshop', objectiveId: 'sql_foreign', family: 'ARIA', scenario: 'foreign', rubricVersion: 'sql-v1', evidenceDigest: 'b'.repeat(64), verdict: 'pass', disposition: 'awarded' },
  ]);
  try {
    const detail = await request(`/api/agent-runs/${IDS.aria7}`);
    assert.equal(detail.status, 200);
    assert.deepEqual(detail.body.judgments.map(item => [item.objectiveId, item.disposition]), [['sql_1', 'awarded']]);
    assert.equal(detail.body.judgments[0].evidenceDigest, 'a'.repeat(64));
    assert.deepEqual(detail.body.judgments[0].criteria, [{ id: 'observed', satisfied: true, evidenceRefs: ['tool'], citations: [{ evidenceId: 'tool', quote: 'Owner-visible synthetic evidence.' }] }]);
    assert.equal(detail.body.judgments[0].result, undefined);
    const foreign = await request(`/api/agent-runs/${IDS.aria7}`, { user: 8 });
    assert.equal(foreign.status, 404);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('incremental events return terminal run status for polling clients', async () => {
  let status = 'running';
  const row = { ...seedRow(IDS.aria7, 'ARIA', 7), status };
  const repository = {
    list: async () => ({ runs: [{ ...row, status }], nextCursor: null }),
    events: async () => ({ run: { ...row, status }, events: [], nextCursor: null }),
  };
  const { server, request } = await start(repository);
  try {
    assert.equal((await request(`/api/agent-runs/${IDS.aria7}/events`)).body.run.status, 'running');
    status = 'completed';
    assert.equal((await request(`/api/agent-runs/${IDS.aria7}/events?after=0`)).body.run.status, 'completed');
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('administrator receipt lookup follows the run owner when no owner filter is supplied', async () => {
  const calls = [];
  const pool = { query: async (sql, params) => {
    calls.push({ sql, params });
    if (sql.includes('FROM graph_runtime.runs')) return { rows: [{ runId: IDS.aria8, ownerKey: ownerKey('ARIA', 8), generation: 0, status: 'completed', startedAt: '2026-09-10T00:00:00.000Z' }] };
    if (sql.includes('FROM workshop_platform.objective_judgments')) return { rows: [{ evaluationId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', runId: IDS.aria8, workshopKey: 'sql_injection_workshop', objectiveId: 'sql_1', family: 'ARIA', scenario: 'product_search', rubricVersion: 'sql-v1', evidenceDigest: 'a'.repeat(64), verdict: 'pass', disposition: 'awarded' }] };
    throw new Error(`unexpected query: ${sql}`);
  } };
  const repository = createPostgresAgentRunReadRepository(pool);
  const result = await repository.judgments(IDS.aria8, { admin: true });
  assert.equal(result.length, 1);
  const receiptQuery = calls.find(call => call.sql.includes('FROM workshop_platform.objective_judgments'));
  assert.deepEqual(receiptQuery.params, ['8', IDS.aria8]);
});

test('mounted learner and admin routes resolve SecureShop conversation runs to the immutable platform owner', async () => {
  const secureOwnerKey = ownerKey('SecureShopBoundConversation', IDS.secureConversation);
  const run = { runId: IDS.secureRun, ownerKey: secureOwnerKey, generation: 1, status: 'completed',
    startedAt: '2026-09-10T00:00:00.000Z', finishedAt: '2026-09-10T00:00:01.000Z' };
  const pool = { query: async (sql, params) => {
    if (sql.includes('FROM graph_runtime.runs') && sql.includes('run_id=$1')) return { rows: params[0] === IDS.secureRun ? [run] : [] };
    if (sql.includes('FROM graph_runtime.runs')) return { rows: params[0]?.includes(secureOwnerKey) || params[0] == null ? [run] : [] };
    if (sql.includes('FROM graph_runtime.events')) return { rows: [{ seq: 1, node: 'model', type: 'decision', data: {}, createdAt: run.startedAt }] };
    if (sql.includes('FROM workshop_platform.objective_judgments')) return { rows: [{ runId: IDS.secureRun,
      evaluationId: '66666666-6666-4666-8666-666666666666', workshopKey: 'secureshop_agent_security',
      objectiveId: 'llm01', family: 'SecureShop', scenario: 'bound', rubricVersion: 'v1',
      evidenceDigest: 'a'.repeat(64), verdict: 'pass', disposition: 'awarded' }] };
    throw new Error(`unexpected query: ${sql}`);
  } };
  const ownership = { listOwnedConversationIds: async owner => String(owner) === '7' ? [IDS.secureConversation] : [],
    resolve: async id => id === IDS.secureConversation ? { ownerId: '7' } : null,
    resolveMany: async ids => new Map(ids.includes(IDS.secureConversation) ? [[IDS.secureConversation,{ ownerId: '7' }]] : []) };
  const repository = createPostgresAgentRunReadRepository(pool, { secureShopOwnership: ownership });
  const { server, request } = await start(repository);
  try {
    const learner = await request('/api/agent-runs?family=SecureShopBoundConversation');
    assert.equal(learner.status, 200);assert.deepEqual(learner.body.runs.map(item=>item.runId),[IDS.secureRun]);
    assert.equal(learner.body.runs[0].ownerId,undefined);
    const detail=await request(`/api/agent-runs/${IDS.secureRun}`);assert.equal(detail.status,200);
    assert.equal(detail.body.judgments[0].objectiveId,'llm01');
    assert.equal((await request(`/api/agent-runs/${IDS.secureRun}`,{user:8})).status,404);
    const admin=await request('/api/admin/agent-runs?ownerId=7&family=SecureShopBoundConversation',{analytics:true});
    assert.equal(admin.status,200);assert.equal(admin.body.runs[0].ownerId,'7');
    assert.equal((await request('/api/admin/agent-runs?ownerId=8&family=SecureShopBoundConversation',{analytics:true})).body.runs.length,0);
  } finally { await new Promise(resolve=>server.close(resolve)); }
});

test('single-store PostgreSQL composition explicitly excludes SecureShop for all-family owner scopes', async () => {
  const rows = [seedRow(IDS.aria7, 'ARIA', 7), seedRow(IDS.aria8, 'ARIA', 8)];
  const pool = { query: async (sql, params) => {
    if (sql.includes('FROM graph_runtime.runs') && sql.includes('run_id=$1')) {
      return { rows: rows.filter(row => row.runId === params[0]) };
    }
    if (sql.includes('FROM graph_runtime.runs')) {
      return { rows: rows.filter(row => params[0] === null || params[0].includes(row.ownerKey)) };
    }
    if (sql.includes('FROM graph_runtime.events')) return { rows: [] };
    if (sql.includes('FROM workshop_platform.objective_judgments')) return { rows: [] };
    throw new Error(`unexpected query: ${sql}`);
  } };
  const lookedUpOwners = [];
  const ownership = createExcludedSecureShopOwnership({
    onListOwned: ownerId => lookedUpOwners.push(ownerId),
  });
  await assert.rejects(ownership.listOwnedConversationIds('0'), /valid platform owner/);
  assert.deepEqual(await ownership.resolveMany([]), new Map());
  await assert.rejects(ownership.resolveMany([IDS.secureConversation]),
    /fail closed if a SecureShop conversation run appears/);
  await assert.rejects(ownership.resolve(IDS.secureConversation),
    /cannot resolve a SecureShop conversation run/);

  const scoped = await start(createPostgresAgentRunReadRepository(pool, { secureShopOwnership: ownership }));
  try {
    const admin = await scoped.request('/api/admin/agent-runs?ownerId=7', { analytics: true });
    assert.equal(admin.status, 200);
    assert.deepEqual(admin.body.runs.map(run => [run.runId, run.ownerId]), [[IDS.aria7, '7']]);
    const learner = await scoped.request('/api/agent-runs');
    assert.equal(learner.status, 200);
    assert.deepEqual(learner.body.runs.map(run => run.runId), [IDS.aria7]);
    assert.equal((await scoped.request(`/api/agent-runs/${IDS.aria8}`)).status, 404);
    assert.deepEqual(lookedUpOwners, ['7', '7'],
      'both administrator and learner all-family lists must consult the explicit exclusion');
  } finally { await new Promise(resolve => scoped.server.close(resolve)); }

  const incomplete = await start(createPostgresAgentRunReadRepository(pool));
  try {
    const admin = await incomplete.request('/api/admin/agent-runs?ownerId=7', { analytics: true });
    assert.equal(admin.status, 503);
    assert.equal(admin.body.code, 'AGENT_RUN_STORE_UNAVAILABLE');
    const learner = await incomplete.request('/api/agent-runs');
    assert.equal(learner.status, 503);
    assert.equal(learner.body.code, 'AGENT_RUN_STORE_UNAVAILABLE');
  } finally { await new Promise(resolve => incomplete.server.close(resolve)); }
});

test('administrator route requires analytics permission and applies explicit owner/family filters', async () => {
  seed(IDS.aria7, 'ARIA', 7); seed(IDS.aria8, 'ARIA', 8); seed(IDS.nova7, 'NOVA', 7);
  const { server, request } = await start();
  try {
    assert.equal((await request('/api/admin/agent-runs')).status, 403);
    const owner = await request('/api/admin/agent-runs?ownerId=8&family=ARIA', { analytics: true });
    assert.equal(owner.status, 200); assert.deepEqual(owner.body.runs.map(run => [run.family, run.ownerId]), [['ARIA', '8']]);
    assert.deepEqual(owner.body.families, OBSERVABLE_RUN_FAMILIES);
    assert.equal((await request('/api/admin/agent-runs?family=unknown', { analytics: true })).status, 400);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('store failures return a fixed 503 without leaking database details', async () => {
  const repository = { list: async () => { throw new TypeError('postgres://secret@host/private relation graph_runtime.runs'); }, events: async () => null };
  const { server, request } = await start(repository);
  try {
    const response = await request('/api/agent-runs'); assert.equal(response.status, 503);
    assert.equal(response.body.code, 'AGENT_RUN_STORE_UNAVAILABLE'); assert.doesNotMatch(JSON.stringify(response.body), /secret|private/i);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('PostgreSQL cursor retains microsecond ordering precision', () => {
  const cursor = encodeCursor({ runId: IDS.aria7, startedAt: new Date('2026-09-10T00:00:00.123Z'), cursorStartedAt: '2026-09-10T00:00:00.123456Z' });
  assert.deepEqual(decodeCursor(cursor), { runId: IDS.aria7, startedAt: '2026-09-10T00:00:00.123456Z' });
});

test('grade retry accepts authenticated owner and evaluation ID only, without chat/tool payloads',async()=>{
 const calls=[];const app=express();app.use(express.json());
 app.use('/runs',createAgentRunsRouter({repository:{},authenticateToken:(req,res,next)=>{req.user={id:7};next();},regrade:async input=>{calls.push(input);return {judgment:{verdict:'pass',canRetry:false},completed:true};}}));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 try{
  const url=`http://127.0.0.1:${server.address().port}/runs/judgments/${IDS.aria7}/retry`;
  const invalid=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({userId:8,evidence:'forged'})});assert.equal(invalid.status,400);assert.equal(calls.length,0);
  const response=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});assert.equal(response.status,200);assert.equal((await response.json()).completed,true);assert.deepEqual(calls,[{userId:7,evaluationId:IDS.aria7}]);
 }finally{await new Promise(resolve=>server.close(resolve));}
});

test('judgment discovery is owner-only metadata and rejects owner filters',async()=>{
 const app=express();let owner;
 app.use('/runs',createAgentRunsRouter({repository:{},authenticateToken:(req,res,next)=>{req.user={id:7};next();},listJudgments:async id=>{owner=id;return [{evaluationId:IDS.aria7,verdict:'unavailable',canRetry:true}];}}));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 try{
  const url=`http://127.0.0.1:${server.address().port}/runs/judgments`;
  assert.equal((await fetch(url+'?ownerId=8')).status,400);assert.equal(owner,undefined);
  const response=await fetch(url);assert.equal(response.status,200);assert.equal(owner,7);assert.deepEqual((await response.json()).judgments,[{evaluationId:IDS.aria7,verdict:'unavailable',canRetry:true}]);
 }finally{await new Promise(resolve=>server.close(resolve));}
});

test('DPI metadata is independent of paginated event and receipt availability',()=>{
 const {defaultGraph}=require('../server/routes/agentRuns');
 assert.deepEqual(defaultGraph('DPI',{events:[],judgments:[]}),defaultGraph('DPI',{events:[{node:'decode_payload'}],judgments:[{objectiveId:'controlled'}]}));
});
