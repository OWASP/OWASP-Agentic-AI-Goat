'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const Module = require('node:module');
const path = require('node:path');
const test = require('node:test');
const express = require('express');
const { createPostgresAdminAuth } = require('../server/middleware/postgresAdminAuth');

const emailRoutePath = path.resolve(__dirname, '../server/routes/emailAgent.js');
const ragRoutePath = path.resolve(__dirname, '../server/routes/ragInjection.js');
const originalLoad = Module._load;
const effects = {
  emailRuns: [],
  ragRuns: [],
  emailStore: [],
  ragStore: [],
  vectorStore: [],
  progressSync: [],
  emailArtifacts: [],
  emailModel: [],
  ragModel: [],
};
const ipiModes=new Map();
let canonicalRows = [];
let failLegacyCompletion = false;
let failLegacyReset = false;
let judgeCompleted = false;
let judgeDurable = false;
let suppressCanonicalSync = false;
let abortOnWorkshopCheck = false;
let abortOnLegacyReset = false;
let ragRunError = null;
let emailGraphError = null;
let emailAdmissionError = null;
let artifactRetireError = null;
let artifactResolveError = null;
let emailFetchError = null;
let sessionRecord;
let sessionSendWork = null;
let sessionResetWait = null;

const fakeEmailStore = {
  async listProgress(userKey) {
    effects.emailStore.push(['listProgress', userKey]);
    return [];
  },
  async resetProgress(userKey) {
    effects.emailStore.push(['resetProgress', userKey]);
    if (abortOnLegacyReset) {
      const error = new Error('reset fence');
      error.name = 'AbortError';
      throw error;
    }
    if (failLegacyReset) throw new Error('legacy reset unavailable');
  },
  async saveConfiguredEmail(userKey, email) {
    effects.emailStore.push(['saveConfiguredEmail', userKey, email]);
  },
  async completeObjective(userKey, objectiveNumber) {
    effects.emailStore.push(['completeObjective', userKey, objectiveNumber]);
    if (failLegacyCompletion) throw new Error('legacy projection unavailable');
  },
  logSentEmail(...args) {
    effects.emailStore.push(['logSentEmail', ...args]);
  },
};

const ARTIFACT_ID = '11111111-1111-4111-8111-111111111111';
const fakeEmailArtifacts = {
  async resolveCurrent(scope) {
    effects.emailArtifacts.push(['resolveCurrent', scope]);
    if (artifactResolveError) throw artifactResolveError;
    if (scope.ownerId !== 41 || scope.ownerKey !== JSON.stringify(['IndirectEmail', '41'])
        || String(scope.generation) !== '7' || scope.artifactId !== ARTIFACT_ID) {
      throw Object.assign(new Error('Email artifact is unavailable'), {
        code: 'EMAIL_ARTIFACT_UNAVAILABLE', statusCode: 409,
      });
    }
    return { artifactId:ARTIFACT_ID, ingestionKind:'manual_entry', sender:'', subject:'Stored subject',
      bodySha256:'a'.repeat(64), modelBodySha256:'b'.repeat(64), modelBody:'Stored exact body',
      modelBodyTruncated:false };
  },
  async retireOwner(scope) {
    effects.emailArtifacts.push(['retireOwner', scope]);
    if (artifactRetireError) throw artifactRetireError;
    return 2;
  },
};

const fakeGmailService = {
  getAllowedDomains: () => ['sharklasers.com'],
  getStatus: () => ({ initialized: false }),
  validateRecipientDomain: () => ({ valid: true }),
  reinitialize: async () => { throw new Error('Gmail must not initialize anonymously'); },
};

const fakeRagVectorStore = {
  modelReady: false,
  getSessionInfo() { return { exists: true, filename: "fixture.txt" }; },
  getCurrentSession(userKey) {
    effects.vectorStore.push(['getCurrentSession', userKey]);
    return { session_id: 'fixture-session', filename: 'fixture.txt', chunks_stored: 1 };
  },
  getActiveSessionsCount(userKey) {
    effects.vectorStore.push(['getActiveSessionsCount', userKey]);
    return 0;
  },
  clearUserSessions(userKey) {
    effects.vectorStore.push(['clearUserSessions', userKey]);
  },
};

const fakeRagProgress = {
  async get(args) {
    effects.ragStore.push(['get', args]);
    return [];
  },
  async reset(args) {
    effects.ragStore.push(['reset', args]);
  },
  async complete(args) {
    effects.ragStore.push(['complete', args]);
  },
};

const fakeRunCoordinator = family => ({
  async run(owner, _options, work) {
    (family === 'RAG' ? effects.ragRuns : effects.emailRuns).push(['run', String(owner)]);
    if (family === 'RAG' && ragRunError) throw ragRunError;
    if (family === 'IndirectEmail' && emailAdmissionError) throw emailAdmissionError;
    return work({ runId:ARTIFACT_ID, ownerKey:JSON.stringify([family, String(owner)]),
      durableGeneration:'7', check: async () => {} });
  },
  async reset(owner, work) {
    if (family === 'IndirectEmail' && sessionResetWait) await sessionResetWait();
    if (family === 'IndirectEmail' && emailAdmissionError) throw emailAdmissionError;
    (family === 'RAG' ? effects.ragRuns : effects.emailRuns).push(['reset', String(owner)]);
    return work();
  },
});

function fixtureSession(token) {
  if (!['valid', 'other'].includes(token)) return null;
  const id = token === 'other' ? 99 : 41;
  return { user: { id, username:`student-${id}`, role:'student', admin_level:0 }, session: { id:id + 100, user_id:id } };
}
const fixtureIdentityAdapter = {
  repository: {}, jwtSecret: 'email-rag-route-fixture-signing-key-2026',
  validateSession: async token => sessionRecord === undefined ? fixtureSession(token) : sessionRecord,
};
const { authenticateToken: fakeAuthenticateToken } = createPostgresAdminAuth(fixtureIdentityAdapter);

const fakeProgressSync = {
  async syncObjectiveComplete(userId, workshopKey, objectiveId) {
    effects.progressSync.push(['syncObjectiveComplete', userId, workshopKey, objectiveId]);
    if (!suppressCanonicalSync) {
      canonicalRows = [{ workshop_key: workshopKey, objective_id: objectiveId, completed: true, completed_at: 'fixture' }];
    }
  },
  async checkAndMarkWorkshopComplete(userId, workshopKey) {
    effects.progressSync.push(['checkAndMarkWorkshopComplete', userId, workshopKey]);
    if (abortOnWorkshopCheck) {
      const error = new Error('reset fence');
      error.name = 'AbortError';
      throw error;
    }
  },
  async getUserWorkshopProgress(userId) {
    effects.progressSync.push(['getUserWorkshopProgress', userId]);
    return canonicalRows;
  },
  async resetWorkshopProgress(userId, workshopKey, options) {
    effects.progressSync.push(['resetWorkshopProgress', userId, workshopKey, options]);
    const objectiveIds = options?.objectiveIds || [];
    canonicalRows = canonicalRows.filter(row => row.workshop_key !== workshopKey || !objectiveIds.includes(row.objective_id));
  },
};

Module._load = function load(request, parent, isMain) {
  if (parent && (parent.filename === emailRoutePath || parent.filename === ragRoutePath)) {
    if (/(?:^|\/)(?:database|authDb|sqlite|postgres)(?:\/|\.js|$)/i.test(request)) {
      throw new Error(`Unexpected database dependency in isolated email/RAG route test: ${request}`);
    }
    if (request === '../services/postgresIdentityAdapter') return {getPostgresIdentityAdapter:()=>fixtureIdentityAdapter};
    if (request === '../middleware/adminAuth') return { authenticateToken: fakeAuthenticateToken };
    if (request === '../agent-runtime/runCoordinator') {
      return { createRunCoordinator: ({ family }) => fakeRunCoordinator(family) };
    }
    if (request === '../services/emailWorkshopStore') return fakeEmailStore;
    if (request === '../services/emailArtifactStore') return fakeEmailArtifacts;
    if (request === '../services/gmailEmailAgentService') return fakeGmailService;
    if (request === '../services/sharkLasersScraper') {
      return { getSupportedDomains: () => [], getTargetSender: () => 'fixture' };
    }
    if (request === '../services/multiProviderAIService') {
      return {
        getActiveProviderInfo: () => ({ provider: 'ollama', providerName: 'Fixture', model: 'fixture' }),
        checkOllamaAvailable: async () => false,
        getOllamaBaseURL: () => 'http://fixture.invalid',
      };
    }
    if (request === '../services/ragVectorStore') return fakeRagVectorStore;
    if (request === '../services/workshopModeService') return {
      WORKSHOP_MODE_CATALOG:{indirect_prompt_injection:{defaultMode:null,allowedModes:['vuln','fixed'],fixedObjectiveIds:['rag_injected_doc','email_understand_defense']}},
      getMode:async({userId,workshopKey})=>{assert.equal(workshopKey,'indirect_prompt_injection');return ipiModes.get(userId)??null;},
      setMode:async({userId,workshopKey,mode})=>{assert.equal(workshopKey,'indirect_prompt_injection');ipiModes.set(userId,mode);return mode;},
    };
    if (request === '../agent-runtime/ragQueryGraph') return {runRagQueryGraph:async input=>{
      effects.ragModel.push(input);return {answer:'Controlled document answer',mode:input.mode};
    }};
    if (request === '../services/ragProgressStore') return {
      createDefaultRagProgressStore: () => fakeRagProgress,
    };
    if (request === '../utils/progressSync') return fakeProgressSync;
    if (request === '../agent-runtime/indirectEmailGraph') {
      return { runIndirectEmailGraph: async (input, deps) => {
        effects.emailModel.push(input);
        if (emailGraphError) throw emailGraphError;
        const vulnerableRead = await deps.readEmailArtifact();
        const secureRead = await deps.readEmailArtifact();
        assert.equal(vulnerableRead.artifactId, secureRead.artifactId);
        return { success:true, sourceArtifact:{ artifactId:vulnerableRead.artifactId,
          ingestionKind:vulnerableRead.ingestionKind, bodySha256:vulnerableRead.bodySha256,
          modelBodySha256:vulnerableRead.modelBodySha256,
          modelBodyTruncated:vulnerableRead.modelBodyTruncated } };
      } };
    }
    if (request === '../agent-runtime/indirectEmailDeliveryGraph') {
      return {
        runEmailSendGraph: async (input,deps) => sessionSendWork ? sessionSendWork(input,deps) : ({ messageId: 'fixture', sentTo: 'fixture', remainingSends: 0 }),
        runEmailFetchGraph: async () => {
          if (emailFetchError) throw emailFetchError;
          return { success: true };
        },
      };
    }
    if (request === '../agent-runtime/indirectObjectiveJudge') {
      return { beginIpiEvaluation: async () => async () => ({ completed: judgeCompleted, durable: judgeDurable, judgment: { verdict: judgeCompleted ? 'pass' : 'fail' } }) };
    }
  }
  return originalLoad.call(this, request, parent, isMain);
};

const emailRouter = require(emailRoutePath);
const ragRouter = require(ragRoutePath);

test.after(() => {
  Module._load = originalLoad;
});

function clearEffects() {
  for (const values of Object.values(effects)) values.length = 0;
}

function makeApp(router, mountPath) {
  const app = express();
  app.use(mountPath, router);
  return app;
}

function request(app, { method, path: requestPath, authorization, body, contentType } = {}) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const payload = body == null ? '' : JSON.stringify(body);
      const headers = {};
      if (authorization) headers.authorization = authorization;
      if (contentType) headers['content-type'] = contentType;
      if (payload) {
        headers['content-type'] ||= 'application/json';
        headers['content-length'] = Buffer.byteLength(payload);
      }
      const req = http.request({ hostname: '127.0.0.1', port: address.port, path: requestPath, method, headers }, res => {
        let responseBody = '';
        res.setEncoding('utf8');
        res.on('data', chunk => { responseBody += chunk; });
        res.on('end', () => {
          server.close(() => resolve({ status: res.statusCode, body: responseBody ? JSON.parse(responseBody) : null }));
        });
      });
      req.on('error', error => server.close(() => reject(error)));
      if (payload) req.write(payload);
      req.end();
    });
    server.on('error', reject);
  });
}

test('anonymous and invalid bearer requests stop before Email Agent or RAG effects', async () => {
  clearEffects();
  const email = makeApp(emailRouter, '/email');
  const rag = makeApp(ragRouter, '/rag');

  const anonymousEmail = await request(email, { method: 'POST', path: '/email/send', body: { recipientEmail: 'student@example.com', scenario: 'role_hijack' } });
  const anonymousRetry = await request(email, { method: 'POST', path: '/email/retry-gmail' });
  const invalidEmail = await request(email, { method: 'POST', path: '/email/save-email', authorization: 'Bearer invalid', body: { tempEmail: 'student@sharklasers.com' } });
  const anonymousUpload = await request(rag, { method: 'POST', path: '/rag/upload', contentType: 'multipart/form-data; boundary=fixture', body: 'ignored' });
  const invalidQuery = await request(rag, { method: 'POST', path: '/rag/query', authorization: 'Bearer invalid', body: { session_id: 'bad', question: 'fixture' } });

  assert.equal(anonymousEmail.status, 401);
  assert.equal(anonymousRetry.status, 401);
  assert.equal(invalidEmail.status, 401);
  assert.equal(anonymousUpload.status, 401);
  assert.equal(invalidQuery.status, 401);
  assert.deepEqual(effects.emailRuns, []);
  assert.deepEqual(effects.ragRuns, []);
  assert.deepEqual(effects.emailStore, []);
  assert.deepEqual(effects.ragStore, []);
  assert.deepEqual(effects.vectorStore, []);
});

test('RAG and email mode endpoints share only the authenticated owner preference',async()=>{
  ipiModes.clear();clearEffects();
  const prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
  try{
    const rag=makeApp(ragRouter,'/rag'),email=makeApp(emailRouter,'/email');
    const read=(app,path,authorization='Bearer valid')=>request(app,{method:'GET',path,authorization});
    assert.equal((await read(rag,'/rag/mode')).body.mode,null);
    assert.equal((await read(email,'/email/mode')).body.mode,null);
    assert.equal((await read(rag,'/rag/mode','Bearer other')).body.mode,null);
    assert.equal((await read(email,'/email/mode?userId=99')).status,400);
    assert.equal((await read(rag,'/rag/mode',null)).status,401);
    assert.equal((await request(rag,{method:'POST',path:'/rag/mode',authorization:'Bearer valid',body:{mode:'fixed',userId:99}})).status,400);
    assert.equal((await request(email,{method:'POST',path:'/email/mode',authorization:'Bearer valid',body:{mode:'unsafe'}})).status,400);
    const setFixed=await request(rag,{method:'POST',path:'/rag/mode',authorization:'Bearer valid',body:{mode:'fixed'}});
    assert.equal(setFixed.status,200);assert.equal(setFixed.body.mode,'fixed');
    assert.deepEqual(setFixed.body.fixedObjectiveIds,['rag_injected_doc','email_understand_defense']);
    assert.equal((await read(email,'/email/mode')).body.mode,'fixed');
    assert.equal((await read(email,'/email/mode','Bearer other')).body.mode,null);
    const ragQuery=await request(rag,{method:'POST',path:'/rag/query',authorization:'Bearer valid',body:{session_id:'12345678-1234-4123-8123-123456789012',question:'What is the policy?',active_objective:'rag_query'}});
    assert.equal(ragQuery.status,200);assert.equal(effects.ragModel.at(-1).mode,'fixed');
    const deniedAttack=await request(rag,{method:'POST',path:'/rag/query',authorization:'Bearer valid',body:{session_id:'12345678-1234-4123-8123-123456789012',question:'What is the policy?',active_objective:'rag_query_injection'}});
    assert.equal(deniedAttack.status,409);assert.equal(deniedAttack.body.code,'IPI_OBJECTIVE_MODE_MISMATCH');
    const summarized=await request(email,{method:'POST',path:'/email/summarize',authorization:'Bearer valid',body:{artifactId:ARTIFACT_ID}});
    assert.equal(summarized.status,200);assert.equal(effects.emailModel.at(-1).mode,'fixed');
    assert.equal((await request(email,{method:'POST',path:'/email/mode',authorization:'Bearer valid',body:{mode:'vuln'}})).status,200);
    assert.equal((await read(rag,'/rag/mode')).body.mode,'vuln');
  }finally{if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;ipiModes.clear();}
});

test('authenticated progress reads and resets are scoped to the bearer identity', async () => {
  clearEffects();
  const email = makeApp(emailRouter, '/email');
  const rag = makeApp(ragRouter, '/rag');

  assert.equal((await request(email, { method: 'GET', path: '/email/progress', authorization: 'Bearer valid' })).status, 200);
  assert.equal((await request(rag, { method: 'GET', path: '/rag/current-session', authorization: 'Bearer valid' })).status, 200);
  assert.equal((await request(email, { method: 'POST', path: '/email/progress/reset', authorization: 'Bearer other' })).status, 200);
  assert.equal((await request(rag, { method: 'POST', path: '/rag/progress/reset', authorization: 'Bearer valid' })).status, 200);

  assert.deepEqual(effects.emailStore, [['resetProgress', '99']]);
  assert.deepEqual(effects.emailArtifacts, [['retireOwner', {
    ownerId: 99, ownerKey: JSON.stringify(['IndirectEmail', '99']),
  }]]);
  assert.deepEqual(effects.vectorStore, [
    ['getCurrentSession', '41'],
    ['clearUserSessions', '41'],
  ]);
  assert.deepEqual(effects.ragStore, [['reset', { userKey: '41', platformUserId: 41 }]]);
  assert.deepEqual(effects.progressSync, [
    ['getUserWorkshopProgress', 41],
    ['resetWorkshopProgress', 99, 'indirect_prompt_injection', { objectiveIds: [
      'email_create_inbox', 'email_send_attack', 'email_retrieve', 'email_trigger_injection', 'email_understand_defense',
    ] }],
  ]);
  assert.deepEqual(effects.emailRuns, [['reset', '99']]);
  assert.deepEqual(effects.ragRuns, [['reset', '41']]);
});

test('summarize admits an opaque artifact before model work and both actor reads stay owner-generation scoped', async () => {
  clearEffects();
  const email = makeApp(emailRouter, '/email');

  for (const body of [
    { artifactId:ARTIFACT_ID, emailBody:'caller override' },
    { emailBody:'raw caller body' },
    { artifactId:'not-a-uuid' },
  ]) {
    const denied = await request(email, { method:'POST', path:'/email/summarize',
      authorization:'Bearer valid', body });
    assert.equal(denied.status, 400);
  }
  assert.deepEqual(effects.emailRuns, []);
  assert.deepEqual(effects.emailArtifacts, []);
  assert.deepEqual(effects.emailModel, []);

  const accepted = await request(email, { method:'POST', path:'/email/summarize',
    authorization:'Bearer valid', body:{ artifactId:ARTIFACT_ID } });
  assert.equal(accepted.status, 200);
  assert.deepEqual(effects.emailArtifacts, Array.from({length:3}, () => ['resolveCurrent', {
    artifactId:ARTIFACT_ID, ownerId:41,
    ownerKey:JSON.stringify(['IndirectEmail', '41']), generation:'7',
  }]));
  assert.deepEqual(effects.emailModel, [{ artifactId:ARTIFACT_ID, userKey:'41', platformUserId:41, mode:null }]);
  assert.deepEqual(accepted.body.sourceArtifact, { artifactId:ARTIFACT_ID,
    ingestionKind:'manual_entry', bodySha256:'a'.repeat(64), modelBodySha256:'b'.repeat(64),
    modelBodyTruncated:false });

  effects.emailModel.length = 0;
  const sibling = await request(email, { method:'POST', path:'/email/summarize',
    authorization:'Bearer other', body:{ artifactId:ARTIFACT_ID } });
  assert.equal(sibling.status, 409);
  assert.equal(sibling.body.errorCode, 'EMAIL_ARTIFACT_UNAVAILABLE');
  assert.deepEqual(effects.emailModel, []);
});

test('email actor protocol and provider failures are typed and cannot be reported as success', async () => {
  clearEffects();
  const email = makeApp(emailRouter, '/email');
  for (const [code,status] of [['EMAIL_SOURCE_REQUIRED',502],['EMAIL_MODEL_UNAVAILABLE',503]]) {
    emailGraphError = Object.assign(new Error('private model detail'), {code,
      statusCode:code==='EMAIL_MODEL_UNAVAILABLE'?503:502});
    const response = await request(email, {method:'POST',path:'/email/summarize',
      authorization:'Bearer valid',body:{artifactId:ARTIFACT_ID}});
    assert.equal(response.status,status);assert.equal(response.body.success,false);
    assert.equal(response.body.errorCode,code);assert.doesNotMatch(response.body.error,/private model detail/);
  }
  emailGraphError = Object.assign(new Error('provider cancelled by reset'), {name:'AbortError'});
  const cancelled = await request(email, {method:'POST',path:'/email/summarize',
    authorization:'Bearer valid',body:{artifactId:ARTIFACT_ID}});
  assert.equal(cancelled.status,409);assert.equal(cancelled.body.success,false);
  assert.deepEqual(Object.keys(cancelled.body).sort(),['error','success']);
  emailGraphError = null;
});

test('missing artifact migration fails fetch and summarize with explicit readiness responses', async () => {
  clearEffects();
  const unavailable = () => Object.assign(new Error('Email artifact storage is not ready'), {
    code:'EMAIL_ARTIFACT_STORAGE_NOT_READY', statusCode:503,
  });
  const email = makeApp(emailRouter, '/email');

  emailFetchError = unavailable();
  const fetch = await request(email, { method:'POST', path:'/email/fetch-sharklasers',
    authorization:'Bearer valid', body:{ tempEmail:'student@sharklasers.com', manualContent:'controlled exact message body' } });
  emailFetchError = null;
  assert.equal(fetch.status, 503);
  assert.equal(fetch.body.success, false);
  assert.equal(fetch.body.errorCode, 'EMAIL_ARTIFACT_STORAGE_NOT_READY');

  artifactResolveError = unavailable();
  const summarize = await request(email, { method:'POST', path:'/email/summarize',
    authorization:'Bearer valid', body:{ artifactId:ARTIFACT_ID } });
  artifactResolveError = null;
  assert.equal(summarize.status, 503);
  assert.equal(summarize.body.success, false);
  assert.equal(summarize.body.errorCode, 'EMAIL_ARTIFACT_STORAGE_NOT_READY');
  assert.deepEqual(effects.emailModel, []);
});

test('Email reset retirement failure is typed and prevents canonical and legacy progress clears', async () => {
  clearEffects();
  artifactRetireError = Object.assign(new Error('Email artifact storage is not ready'), {
    code:'EMAIL_ARTIFACT_STORAGE_NOT_READY', statusCode:503,
  });
  const email = makeApp(emailRouter, '/email');
  const response = await request(email, { method:'POST', path:'/email/progress/reset',
    authorization:'Bearer valid' });
  artifactRetireError = null;
  assert.equal(response.status, 503);
  assert.equal(response.body.errorCode, 'EMAIL_ARTIFACT_STORAGE_NOT_READY');
  assert.deepEqual(effects.progressSync, []);
  assert.deepEqual(effects.emailStore, []);
});

test('Email Agent reads canonical completion after a legacy projection failure and resets canonical state first', async () => {
  clearEffects();
  canonicalRows = [];
  judgeCompleted = true;
  failLegacyCompletion = true;
  const email = makeApp(emailRouter, '/email');

  const completed = await request(email, {
    method: 'POST',
    path: '/email/save-email',
    authorization: 'Bearer valid',
    body: { tempEmail: 'student@sharklasers.com' },
  });
  assert.equal(completed.status, 200);
  assert.equal(completed.body.objectiveCompleted, 1);
  assert.equal(completed.body.projectionPending, true);
  assert.deepEqual(effects.progressSync.slice(0, 3), [
    ['syncObjectiveComplete', 41, 'indirect_prompt_injection', 'email_create_inbox'],
    ['getUserWorkshopProgress', 41],
    ['checkAndMarkWorkshopComplete', 41, 'indirect_prompt_injection'],
  ]);

  canonicalRows = [{ workshop_key: 'indirect_prompt_injection', objective_id: 'email_create_inbox', completed: true, completed_at: 'fixture' }];
  const progress = await request(email, { method: 'GET', path: '/email/progress', authorization: 'Bearer valid' });
  assert.equal(progress.status, 200);
  assert.equal(progress.body.progress[1].completed, true);

  failLegacyCompletion = false;
  failLegacyReset = true;
  canonicalRows.push({ workshop_key: 'indirect_prompt_injection', objective_id: 'rag_upload', completed: true, completed_at: 'rag-fixture' });
  const reset = await request(email, { method: 'POST', path: '/email/progress/reset', authorization: 'Bearer valid' });
  assert.equal(reset.status, 200);
  assert.equal(reset.body.projectionPending, true);
  assert.deepEqual(effects.progressSync.at(-1), ['resetWorkshopProgress', 41, 'indirect_prompt_injection', { objectiveIds: [
    'email_create_inbox', 'email_send_attack', 'email_retrieve', 'email_trigger_injection', 'email_understand_defense',
  ] }]);
  assert.deepEqual(canonicalRows, [{ workshop_key: 'indirect_prompt_injection', objective_id: 'rag_upload', completed: true, completed_at: 'rag-fixture' }]);
  const afterReset = await request(email, { method: 'GET', path: '/email/progress', authorization: 'Bearer valid' });
  assert.equal(afterReset.status, 200);
  assert.equal(afterReset.body.progress[1].completed, false);
  canonicalRows.push({ workshop_key: 'indirect_prompt_injection', objective_id: 'email_create_inbox', completed: '0', completed_at: 'false-fixture' });
  const strictProgress = await request(email, { method: 'GET', path: '/email/progress', authorization: 'Bearer valid' });
  assert.equal(strictProgress.status, 200);
  assert.equal(strictProgress.body.progress[1].completed, false);
  canonicalRows.push({ workshop_key: 'indirect_prompt_injection', objective_id: 'email_send_attack', completed: true });
  abortOnLegacyReset = true;
  const fencedReset = await request(email, { method: 'POST', path: '/email/progress/reset', authorization: 'Bearer valid' });
  assert.equal(fencedReset.status, 409);

  judgeCompleted = true;
  judgeDurable = true;
  canonicalRows = [];
  clearEffects();
  const durable = await request(email, {
    method: 'POST',
    path: '/email/save-email',
    authorization: 'Bearer valid',
    body: { tempEmail: 'student@sharklasers.com' },
  });
  assert.equal(durable.status, 200);
  assert.equal(durable.body.objectiveCompleted, 1);
  assert.equal(effects.progressSync.some(([name]) => name === 'getUserWorkshopProgress'), false);
  judgeCompleted = false;
  judgeDurable = false;
  failLegacyReset = false;
  suppressCanonicalSync = false;
  abortOnWorkshopCheck = false;
  abortOnLegacyReset = false;
});

test('Email Agent never projects or reports completion when canonical acceptance is unavailable or fenced', async () => {
  clearEffects();
  canonicalRows = [];
  judgeCompleted = true;
  suppressCanonicalSync = true;
  const email = makeApp(emailRouter, '/email');

  const unavailable = await request(email, {
    method: 'POST',
    path: '/email/save-email',
    authorization: 'Bearer valid',
    body: { tempEmail: 'student@sharklasers.com' },
  });
  assert.equal(unavailable.status, 500);
  assert.equal(effects.emailStore.some(([name]) => name === 'completeObjective'), false);

  suppressCanonicalSync = false;
  canonicalRows = [{ workshop_key: 'indirect_prompt_injection', objective_id: 'email_create_inbox', completed: true }];
  abortOnWorkshopCheck = true;
  const fenced = await request(email, {
    method: 'POST',
    path: '/email/save-email',
    authorization: 'Bearer valid',
    body: { tempEmail: 'student@sharklasers.com' },
  });
  assert.equal(fenced.status, 409);
  assert.equal(effects.emailStore.filter(([name]) => name === 'completeObjective').length, 0);

  judgeCompleted = false;
  abortOnWorkshopCheck = false;
});

test('health and scenario metadata remain public', async () => {
  clearEffects();
  const email = makeApp(emailRouter, '/email');
  const rag = makeApp(ragRouter, '/rag');
  assert.equal((await request(email, { method: 'GET', path: '/email/scenarios' })).status, 200);
  assert.equal((await request(rag, { method: 'GET', path: '/rag/health' })).status, 200);
});

test('RAG reset cancellation is a conflict while genuine query errors remain server failures',async()=>{
 const app=makeApp(ragRouter,'/rag');
 try {
  ragRunError=Object.assign(new Error('Agent reset invalidated run'),{name:'AbortError'});
  const cancelled=await request(app,{method:'POST',path:'/rag/query',authorization:'Bearer valid',body:{session_id:'12345678-1234-4123-8123-123456789012',question:'When is the review?'}});
  assert.equal(cancelled.status,409);assert.equal(cancelled.body.code,'RUN_INVALIDATED');assert.equal(cancelled.body.error,'Request invalidated by reset');
  ragRunError=new Error('fixture query failure');
  const failed=await request(app,{method:'POST',path:'/rag/query',authorization:'Bearer valid',body:{session_id:'12345678-1234-4123-8123-123456789012',question:'When is the review?'}});
  assert.equal(failed.status,500);
 } finally {ragRunError=null;}
});

test('mounted email coordinator capacity is safe503 across supported run/reset entrances',async()=>{
 emailAdmissionError=Object.assign(Error('private admission detail'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503});
 try{for(const [route,body] of [['save-email',{tempEmail:'owned@sharklasers.com'}],['send',{recipientEmail:'owned@sharklasers.com',scenario:'custom',customBody:'Controlled synthetic email body'}],['fetch-sharklasers',{tempEmail:'owned@sharklasers.com'}],['summarize',{artifactId:ARTIFACT_ID}],['progress/reset',{}]]){
 const r=await request(makeApp(emailRouter,'/email'),{method:'POST',path:'/email/'+route,authorization:'Bearer valid',body});assert.equal(r.status,503,route);assert.equal(r.body.code,'GRAPH_RUN_CAPACITY_EXCEEDED');assert.equal(r.body.error,'Agent capacity is unavailable.');
 }}finally{emailAdmissionError=null;}
});


test('email admitted session fences effects and publication without sockets', async () => {
  const prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
  const handler=emailRouter.stack.find(x=>x.route?.path==='/send').route.stack.at(-1).handle;
  const req={headers:{authorization:'Bearer valid'},user:{id:41},identitySession:{id:71},body:{recipientEmail:'learner@sharklasers.com',scenario:'role_hijack'}};
  const invoke=async()=>{const res={statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}};await handler(req,res);return res;};
  const valid=()=>({user:{id:41},session:{id:71,user_id:41}});
  let effects=0,commits=0;
  try {
    for(const invalid of [null,{user:{id:99},session:{id:71,user_id:99}},{user:{id:41},session:{id:72,user_id:41}}]){
      sessionRecord=invalid;sessionSendWork=async()=>{effects++;return {};};const res=await invoke();assert.equal(res.statusCode,401);assert.equal(effects,0);
    }
    sessionRecord=valid();sessionSendWork=async(_input,{execution})=>{sessionRecord=null;await execution.check();effects++;return {};};assert.equal((await invoke()).statusCode,401);assert.equal(effects,0);
    sessionRecord=valid();let judgeEntered=false,verdictWrites=0;
    sessionSendWork=async(_input,{execution})=>{
      const completion=require('../server/services/objectiveCompletionService').createObjectiveCompletionService({
        progress:{getGeneration:async()=>0},receipts:{beginEvaluation:async()=>({}),recordVerdict:async()=>{verdictWrites++;return {}; }},
        judge:async()=>{judgeEntered=true;await Promise.resolve();sessionRecord=null;return {verdict:'pass',criteria:[],explanation:'controlled'};},
      });
      const evaluate=await require('../server/agent-runtime/indirectObjectiveJudge').beginIpiEvaluation({platformUserId:41,execution,completionService:completion});
      await evaluate('email_send_attack',[{id:'delivery',source:'tool_result',content:{messageId:'controlled',success:true,recipient:'learner@sharklasers.com',body:'controlled',scenario:'role_hijack',emailSubject:'controlled'}}],{delivery_confirmed:true});
      return {};
    };
    assert.equal((await invoke()).statusCode,401);assert.equal(judgeEntered,true);assert.equal(verdictWrites,0);
    sessionRecord=valid();sessionSendWork=async(_input,{execution})=>{await execution.check();effects++;commits++;sessionRecord=null;return {messageId:'committed-before-revocation'};};
    const denied=await invoke();assert.equal(denied.statusCode,401);assert.equal(denied.body.errorCode,'SESSION_REVOKED');assert.equal(commits,1);assert.equal(denied.body.messageId,undefined);
    sessionRecord=valid();sessionSendWork=async(_input,{execution})=>{await execution.check();return {messageId:'current',sentTo:'fixture'};};assert.equal((await invoke()).statusCode,200);
  } finally {sessionRecord=undefined;sessionSendWork=null;if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
});

test('email admitted session fences queued reset without nested run', async()=>{
 const prior=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';clearEffects();
 const handler=emailRouter.stack.find(x=>x.route?.path==='/progress/reset').route.stack.at(-1).handle;
 sessionRecord={user:{id:41},session:{id:71,user_id:41}};sessionResetWait=async()=>{sessionRecord=null;};
 const res={statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}};
 try{await handler({headers:{authorization:'Bearer valid'},user:{id:41},identitySession:{id:71}},res);assert.equal(res.statusCode,401);assert.equal(res.body.errorCode,'SESSION_REVOKED');assert.deepEqual(effects.emailArtifacts,[]);assert.deepEqual(effects.progressSync,[]);assert.deepEqual(effects.emailStore,[]);}finally{sessionResetWait=null;sessionRecord=undefined;if(prior===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=prior;}
});
