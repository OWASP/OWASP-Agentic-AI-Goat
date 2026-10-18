'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');
const path = require('node:path');
const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');

process.env.EXPORT_INTERNALS = '1';

const ROUTE_PATH = path.join(__dirname, '..', 'server', 'routes', 'xssWorkshop.js');
const STORES_PATH = require.resolve('../server/services/postgresPlatformStores');
const JWT_SECRET = 'xss-identity-test-secret-2026-controlled';
const modeScopes = new Map();
const defaultModeScope = () => ({ generation: 0, mode: null, modeStamp: 'fixture-vuln-1' });
const modeScopeFor = userId => modeScopes.get(String(userId)) || defaultModeScope();
let onAiReply = null;
const fixtureIdentityAdapter = {
  repository: {}, jwtSecret: JWT_SECRET,
  validateSession: async token => {
    const decoded = jwt.verify(token, JWT_SECRET);
    return { user:{ id:decoded.userId, username:`student-${decoded.userId}`, role:'student', admin_level:0 }, session:{ id:decoded.userId + 100, user_id:decoded.userId } };
  },
};
const fixtureAdminAuth = createPostgresAdminAuth(fixtureIdentityAdapter);
const fixtureXssLedger = {
  supportsScopedAdmission:true,
  async begin(context) {
    if (!context.scope) return { durableGeneration:'1' };
    return { durableGeneration:'1', scopeBinding:Object.freeze({ runId:context.runId,
      ownerKey:context.ownerKey, ownerId:context.scope.userId, scopeKey:context.scope.scopeKey,
      parentGeneration:'1', childGeneration:'1' }) };
  },
  async assertCurrent() {}, async finish() {}, async checkpoint() {}, async recordEvent() {},
};

const calls = {
  all: [],
  get: [],
  run: [],
  sync: [],
  complete: [],
  reset: [],
  grade: [],
  email: [],
  close: [],
};

const fakeDb = {
  all(sql, params, callback) {
    calls.all.push({ sql, params });
    if (callback) callback(null, []);
    return Promise.resolve([]);
  },
  get(sql, params, callback) {
    calls.get.push({ sql, params });
    if (callback) callback(null, null);
    return Promise.resolve(null);
  },
  run(sql, params, callback) {
    calls.run.push({ sql, params });
    if (callback) callback.call({ changes: 1, lastID: 1 }, null);
    return Promise.resolve({ changes:1, lastID:1 });
  },
  listProgress(owner, callback) { return this.all('SELECT xss progress', [owner], callback); },
  getProfile(owner, callback) { return this.get('SELECT xss profile', [owner], callback); },
  resetProfile(owner, callback) { return this.run('RESET xss profile', [owner], callback); },
  resetProgress(owner, objectives, callback) { return this.run('RESET xss progress', [owner, objectives], callback); },
  listEmails(owner, callback) { return this.all('SELECT xss emails', [owner], callback); },
  async readCurrentProfileField() { return null; },
  async writeScopedManualProfileField({ platformUserId, value }) {
    calls.run.push({ sql:'INSERT INTO xss_workshop_profiles scoped', params:[String(platformUserId), value] });
  },
  async writeModelProfileField({ platformUserId, value }) {
    calls.run.push({ sql:'INSERT INTO xss_workshop_profiles model', params:[String(platformUserId), value] });
  },
  updateAnonymousProfileField(owner, _field, value, callback) {
    return this.run('INSERT INTO xss_workshop_profiles anonymous', [owner, value], callback);
  },
};

let aiResponses = [];
const fakeAiService = {
  getActiveProviderInfo: () => ({ provider: 'test', providerName: 'Test', model: 'test-model' }),
  chatWithMessages: async () => {
    const response = aiResponses.shift() || 'ok';
    onAiReply?.();
    return { response };
  },
};

function loadRouter() {
  const originalLoad = Module._load;
  Module._load = function loadXssDependency(request, parent, isMain) {
    if (parent?.filename === ROUTE_PATH) {
      if (request === '../database/xssWorkshopDb') return fakeDb;
      if (request === '../database/authDb') return { authDb: fakeDb };
      if (request === '../middleware/adminAuth') return fixtureAdminAuth;
      if (request === '../services/postgresIdentityAdapter') return { getPostgresIdentityAdapter: () => fixtureIdentityAdapter };
      if (request === '../services/multiProviderAIService') return fakeAiService;
      if (request === '../services/xssMailProvider') return {
        getXssMailProvider: () => ({ mailbox: { canonicalize: value => value, fetchEmails: async () => ({ success: true, emails: [] }) } }),
        resolveXssMailContext: async () => ({ email: 'student@sharklasers.com', mode: 'external', provider: 'gmail', editable: true, sender: 'fixture@example.invalid' }),
      };
      if (request === '../services/gmailEmailAgentService') return { sendEmail: async (...args) => { calls.email.push(args); return { success: true }; } };
      // This suite verifies identity/projection wiring. Dispatch authenticity is
      // exercised separately with the real dispatch service and durable store.
      if (request === '../services/xssEmailDispatch') return { getXssEmailDispatch: () => ({
        send: async (scope, request) => {
          calls.email.push([request.recipient, 'fixture', request.payload, String(scope.userId)]);
          return { success: true, smtpAccepted: true };
        },
        retrieve: async () => ({ error: 'No owned fixture dispatch' }),
      }) };
      if (request === '../services/xssObjectiveGrader') return { createXssObjectiveGrader: () => ({
        close: async () => { calls.close.push('browser'); },
        begin: async (userId) => ({ userId, workshopKey: 'xss_workshop',
          ...modeScopeFor(userId) }),
        evaluate: async ({ userId, objectiveId }) => {
          calls.grade.push({ userId, objectiveId });
          return { completed: userId !== null, judgment: { objectiveId, verdict: userId !== null ? 'pass' : 'inconclusive', explanation: 'fixture' } };
        },
      }) };
      if (request === '../services/sharkLasersScraper') {
        return {
          isValidDomain: () => true,
          canonicalize: (value) => value,
          fetchEmails: async () => ({ success: true, emails: [] }),
          fetchEmail: async () => ({ success: false }),
        };
      }
      if (request === '../utils/contextLogger') return { error() {} };
      if (request === '../agent-runtime/runCoordinator') {
        const actual = originalLoad.call(this, request, parent, isMain);
        return { ...actual, createRunCoordinator: options => actual.createRunCoordinator({ ...options, ledger:fixtureXssLedger }) };
      }
      if (request === '../agent-runtime/xssOwnerWorkflowRoute') {
        const actual = originalLoad.call(this, request, parent, isMain);
        return { createXssOwnerWorkflowRoute: options => actual.createXssOwnerWorkflowRoute({ ...options,
          validateSession:fixtureIdentityAdapter.validateSession,
          admit:async(owner,work)=>work(Object.freeze({ownerId:Number(owner),check:async()=>{}})),
          pendingProfileReset:async()=>{},
        }) };
      }
      if (request === '../utils/progressSync') {
        return {
          syncObjectiveComplete: async (...args) => { calls.sync.push(args); },
          checkAndMarkWorkshopComplete: async (...args) => { calls.complete.push(args); },
          resetWorkshopProgress: async (...args) => { calls.reset.push(args); },
          getUserWorkshopProgress: async () => [],
          getCanonicalWorkshopCompletions: async () => ({ objectiveIds:[] }),
        };
      }
    }
    return originalLoad.call(this, request, parent, isMain);
  };

  try {
    delete require.cache[ROUTE_PATH];
    return require(ROUTE_PATH);
  } finally {
    Module._load = originalLoad;
    delete require.cache[ROUTE_PATH];
  }
}

function resetCalls() {
  for (const value of Object.values(calls)) value.length = 0;
  aiResponses = [];
  modeScopes.clear();
  onAiReply = null;
}

function bearer(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '5m' });
}

function cookieFrom(response) {
  return response.headers.get('set-cookie')?.split(';', 1)[0] || '';
}

function lastUserKey(kind) {
  return calls[kind].at(-1)?.params?.[0];
}

let server;
let baseUrl;
let sessionStore;
let xssRouter;
let originalStoresModule;

function clearSessionStore() {
  return new Promise((resolve, reject) => {
    sessionStore.clear((error) => error ? reject(error) : resolve());
  });
}

test.before(async () => {
  originalStoresModule = require.cache[STORES_PATH];
  const storesModule = new Module(STORES_PATH);
  storesModule.filename = STORES_PATH;
  storesModule.loaded = true;
  storesModule.exports = { getPostgresPlatformStores: () => ({ progress: {
    getEvaluationScope: async (userId) => ({ ...modeScopeFor(userId) }),
  } }) };
  require.cache[STORES_PATH] = storesModule;
  const app = express();
  sessionStore = new session.MemoryStore();
  app.use(express.json());
  app.use(session({
    secret: 'xss-test-session-secret',
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: { secure: false },
  }));
  app.get('/test/session/:userId', (req, res) => {
    req.session.userId = Number(req.params.userId);
    res.json({ success: true });
  });
  app.use((req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = { id: decoded.userId };
    }
    next();
  });
  xssRouter = loadRouter();
  app.use('/api/workshop/xss', xssRouter);

  server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;
});

test.after(async () => {
  await xssRouter?.close?.();
  if (server) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (originalStoresModule) require.cache[STORES_PATH] = originalStoresModule;
  else delete require.cache[STORES_PATH];
});

test.beforeEach(resetCalls);

test('valid JWT uses platform identity while its teaching cookie cannot retain authority', async () => {
  const progress = await fetch(`${baseUrl}/api/workshop/xss/progress`, {
    headers: { Authorization: `Bearer ${bearer(42)}` },
  });
  assert.equal(progress.status, 200);
  assert.equal(lastUserKey('all'), '42');

  const cookie = cookieFrom(progress);
  assert.ok(cookie, 'the teaching session remains available for anonymous workshop state');
  resetCalls();
  const profile = await fetch(`${baseUrl}/api/workshop/xss/profile`, {
    headers: { Cookie: cookie },
  });
  assert.equal(profile.status, 200);
  assert.match(lastUserKey('get'), /^anon_/, 'cookie-only follow-up cannot reuse platform authority');
});

test('valid JWT overrides conflicting teaching state without promoting that cookie', async () => {
  const seeded = await fetch(`${baseUrl}/test/session/7`);
  const cookie = cookieFrom(seeded);

  const progress = await fetch(`${baseUrl}/api/workshop/xss/progress`, {
    headers: {
      Authorization: `Bearer ${bearer(42)}`,
      Cookie: cookie,
    },
  });
  assert.equal(progress.status, 200);
  assert.equal(lastUserKey('all'), '42');

  const healedCookie = cookieFrom(progress) || cookie;
  const profile = await fetch(`${baseUrl}/api/workshop/xss/profile`, {
    headers: { Cookie: healedCookie },
  });
  assert.equal(profile.status, 200);
  assert.match(lastUserKey('get'), /^anon_/);
  assert.notEqual(lastUserKey('get'), '42');
});

test('valid bearer remains authoritative after teaching-session loss without making its replacement cookie authority', async () => {
  const seeded = await fetch(`${baseUrl}/test/session/7`);
  const staleCookie = cookieFrom(seeded);
  assert.ok(staleCookie);
  await clearSessionStore();

  const recovery = await fetch(`${baseUrl}/api/workshop/xss/progress`, {
    headers: {
      Authorization: `Bearer ${bearer(42)}`,
      Cookie: staleCookie,
    },
  });
  assert.equal(recovery.status, 200);
  assert.equal(lastUserKey('all'), '42');

  const healedCookie = cookieFrom(recovery);
  assert.ok(healedCookie, 'the workshop still persists anonymous teaching state');
  resetCalls();
  aiResponses = ['A formatted response'];
  const cookieOnlyCompletion = await fetch(`${baseUrl}/api/workshop/xss/chat`, {
    method: 'POST',
    headers: {
      Cookie: healedCookie,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ exerciseId: 'reflected', message: 'format this' }),
  });
  assert.equal(cookieOnlyCompletion.status, 200);
  assert.equal(lastUserKey('run'), undefined, 'anonymous inconclusive grading cannot project platform progress');
  assert.equal(calls.grade.at(-1)?.userId, null, 'cookie-only follow-up must not retain platform identity');
});

test('accepted XSS receipt remains successful when family progress projection fails', async () => {
  resetCalls();
  aiResponses = ['A formatted response'];
  xssRouter._internals.setProgressProjectorForTests(async () => { throw new Error('fixture projection unavailable'); });
  try {
    const response = await fetch(`${baseUrl}/api/workshop/xss/chat`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bearer(44)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ exerciseId: 'reflected', message: 'format this' }),
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.completedObjectiveId, 'xss_r1');
    assert.deepEqual(body.projectionPending, ['xss_r1']);
    assert.equal(body.judgments[0].verdict, 'pass');
  } finally {
    xssRouter._internals.setProgressProjectorForTests();
  }
});

test('accepted email-delivery receipt also survives family projection failure', async () => {
  xssRouter._internals.setProgressProjectorForTests(async () => { throw new Error('fixture projection unavailable'); });
  try {
    const response = await fetch(`${baseUrl}/api/workshop/xss/emails/send-attack`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${bearer(45)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fromEmail: 'student@sharklasers.com', payload: '<img src=x onerror=alert(1)>' }),
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.completedObjectiveId, 'xss_e2');
    assert.deepEqual(body.projectionPending, ['xss_e2']);
  } finally {
    xssRouter._internals.setProgressProjectorForTests();
  }
});

test('PostgreSQL progress reconciliation trusts canonical credit and exposes local lag', () => {
  const result = xssRouter._internals.reconcileProgress(
    [{ objective_id: 'xss_r1', completed: 1, completed_at: 'stale' }, { objective_id: 'xss_r2', completed: 1, completed_at: 'local' }],
    [{ workshop_key: 'xss_workshop', objective_id: 'xss_r2', completed: 1, completed_at: 'canonical' },
      { workshop_key: 'xss_workshop', objective_id: 'xss_r3', completed: 1, completed_at: 'accepted' }],
  );
  assert.equal(result.objectives.xss_r1.completed, false, 'stale pre-reset local row cannot restore canonical credit');
  assert.equal(result.objectives.xss_r2.completed, true);
  assert.equal(result.objectives.xss_r3.completed, true);
  assert.deepEqual(result.projectionPending, ['xss_r3']);
  assert.equal(result.projectionUnavailable, false);
  const unavailable = xssRouter._internals.reconcileProgress([], [
    { workshop_key: 'xss_workshop', objective_id: 'xss_r3', completed: 1, completed_at: 'accepted' },
  ], false);
  assert.equal(unavailable.objectives.xss_r3.completed, true);
  assert.deepEqual(unavailable.projectionPending, []);
  assert.equal(unavailable.projectionUnavailable, true);
});

test('direct completion is retired while full reset uses one platform identity', async () => {
  const token = bearer(51);
  const completion = await fetch(`${baseUrl}/api/workshop/xss/progress/complete`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ objectiveId: 'xss_r1' }),
  });
  assert.equal(completion.status, 409);
  assert.equal((await completion.json()).code, 'JUDGED_ATTEMPT_REQUIRED');
  assert.equal(calls.run.length, 0);

  resetCalls();
  const reset = await fetch(`${baseUrl}/api/workshop/xss/progress/reset`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(reset.status, 200);
  assert.equal(lastUserKey('run'), '51');
  assert.equal(calls.reset.at(-1)?.[0], 51);
});

test('session-only and anonymous identities remain anonymous under PostgreSQL platform authority', async () => {
  const seeded = await fetch(`${baseUrl}/test/session/63`);
  const sessionCookie = cookieFrom(seeded);
  await fetch(`${baseUrl}/api/workshop/xss/progress`, { headers: { Cookie: sessionCookie } });
  assert.match(lastUserKey('all'), /^anon_/);

  resetCalls();
  const firstAnonymous = await fetch(`${baseUrl}/api/workshop/xss/progress`);
  const firstKey = lastUserKey('all');
  assert.match(firstKey, /^anon_/);
  const anonymousCookie = cookieFrom(firstAnonymous);

  await fetch(`${baseUrl}/api/workshop/xss/profile`, { headers: { Cookie: anonymousCookie } });
  assert.equal(lastUserKey('get'), firstKey, 'same anonymous session should keep its key');

  await fetch(`${baseUrl}/api/workshop/xss/progress`);
  const secondKey = lastUserKey('all');
  assert.match(secondKey, /^anon_/);
  assert.notEqual(secondKey, firstKey, 'different anonymous sessions should remain isolated');
});

test('anonymous client cannot claim completion directly', async () => {
  const completion = await fetch(`${baseUrl}/api/workshop/xss/progress/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ objectiveId: 'xss_r1' }),
  });
  assert.equal(completion.status, 409);
  assert.equal(calls.run.length, 0);
  assert.equal(calls.sync.length, 0);
  assert.equal(calls.complete.length, 0);
});

test('anonymous email attack is rejected before sending without a platform identity', async () => {
  const completion = await fetch(`${baseUrl}/api/workshop/xss/emails/send-attack`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fromEmail: 'student@sharklasers.com',
      payload: '<img src=x onerror=alert(1)>',
    }),
  });
  assert.equal(completion.status, 401);
  assert.equal(calls.run.length, 0);
  assert.equal(calls.email.length, 0);
  assert.equal((await completion.json()).error, 'Sign in before sending exercise email.');
  assert.equal(calls.sync.length, 0);
  assert.equal(calls.complete.length, 0);
});

test('anonymous full reset stays on its local anon key and never invokes central reset', async () => {
  const progress = await fetch(`${baseUrl}/api/workshop/xss/progress`);
  const anonymousKey = lastUserKey('all');
  const cookie = cookieFrom(progress);
  assert.match(anonymousKey, /^anon_/);

  resetCalls();
  const reset = await fetch(`${baseUrl}/api/workshop/xss/progress/reset`, {
    method: 'POST',
    headers: { Cookie: cookie },
  });
  assert.equal(reset.status, 200);
  assert.equal(lastUserKey('run'), anonymousKey);
  assert.equal(calls.reset.length, 0);
});

test('identity repair preserves raw stored-XSS payload bytes', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  aiResponses = [
    JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: payload } }),
    'Profile updated.',
  ];
  const response = await fetch(`${baseUrl}/api/workshop/xss/chat`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${bearer(72)}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ exerciseId: 'stored_user', userId: 999,
      scope: { userId: 999, scopeKey: 'email' }, message: `Set my bio to ${payload}` }),
  });
  assert.equal(response.status, 200);

  const profileWrite = calls.run.find(({ sql }) => sql.includes('xss_workshop_profiles'));
  assert.ok(profileWrite);
  assert.equal(profileWrite.params[0], '72');
  assert.equal(profileWrite.params[1], payload);
});

test('a mode change after the model decision prevents the stored profile effect', async () => {
  const payload = '<img src=x onerror=alert(1)>';
  aiResponses = [JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: payload } })];
  onAiReply = () => modeScopes.set('73',
    { generation: 0, mode: 'fixed', modeStamp: 'fixture-fixed-2' });
  const response = await fetch(`${baseUrl}/api/workshop/xss/chat`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${bearer(73)}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ exerciseId: 'stored_user', message: `Set my bio to ${payload}` }),
  });
  assert.equal(response.status, 409);
  assert.equal((await response.json()).code, 'XSS_MODE_STALE');
  assert.equal(calls.run.some(({ sql }) => sql.includes('xss_workshop_profiles')), false);
});


test('anonymous inbox metadata and chat are rejected before mailbox/model work', async () => {
  const metadata = await fetch(`${baseUrl}/api/workshop/xss/emails/sharklaser-email`);
  assert.equal(metadata.status, 401);
  const chat = await fetch(`${baseUrl}/api/workshop/xss/chat`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ exerciseId: 'email', message: 'read my inbox' }),
  });
  assert.equal(chat.status, 401);
  assert.equal(calls.grade.length, 0);
  assert.equal(calls.email.length, 0);
});

test('authenticated inbox endpoint exposes provider metadata and rejects a substituted recipient', async () => {
  const headers = { Authorization: `Bearer ${bearer(51)}`, 'Content-Type': 'application/json' };
  const metadata = await fetch(`${baseUrl}/api/workshop/xss/emails/sharklaser-email`, { headers });
  assert.equal(metadata.status, 200);
  assert.deepEqual(await metadata.json(), { email: 'student@sharklasers.com', mode: 'external',
    provider: 'gmail', editable: true, sender: 'fixture@example.invalid' });
  const send = await fetch(`${baseUrl}/api/workshop/xss/emails/send-attack`, {
    method: 'POST', headers,
    body: JSON.stringify({ fromEmail: 'other@sharklasers.com', payload: '<img src=x onerror=alert(1)>' }),
  });
  assert.equal(send.status, 400);
  assert.equal(calls.email.length, 0);
});


test('route exposes its owned grading browser shutdown', async () => {
  await xssRouter.closeBrowser();
  assert.deepEqual(calls.close, ['browser']);
});


test('malformed and oversized email requests fail before delivery or grading', async () => {
  const { MAX_PAYLOAD_BYTES } = require('../server/services/xssEmailCodec');
  for (const [body, status] of [
    [{fromEmail:'student@sharklasers.com',payload:{html:'<img src=x onerror=alert(1)>'}},400],
    [{fromEmail:['student@sharklasers.com'],payload:'<img src=x onerror=alert(1)>'},400],
    [{fromEmail:'student@sharklasers.com',payload:'é'.repeat(MAX_PAYLOAD_BYTES/2+1)},413],
  ]) {
    resetCalls();
    const response = await fetch(`${baseUrl}/api/workshop/xss/emails/send-attack`, {
      method:'POST',headers:{Authorization:`Bearer ${bearer(45)}`,'Content-Type':'application/json'},
      body:JSON.stringify(body),
    });
    assert.equal(response.status,status);
    assert.equal(calls.email.length,0);
    assert.equal(calls.grade.length,0);
    assert.equal(calls.complete.length,0);
  }
});


test('malformed chat and inherited exercise names never reach grading', async () => {
  for (const body of [
    {exerciseId:'reflected',message:{text:'format'}},
    {exerciseId:['reflected'],message:'format'},
    {exerciseId:'reflected',message:'   '},
    {exerciseId:'constructor',message:'format'},
    {exerciseId:'__proto__',message:'format'},
  ]) {
    resetCalls();
    const response=await fetch(`${baseUrl}/api/workshop/xss/chat`,{
      method:'POST',headers:{Authorization:`Bearer ${bearer(45)}`,'Content-Type':'application/json'},body:JSON.stringify(body),
    });
    assert.equal(response.status,400);
    assert.equal(calls.grade.length,0);assert.equal(calls.email.length,0);assert.equal(calls.complete.length,0);
  }
});
