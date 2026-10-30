'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const os = require('node:os');
const axios = require('axios');
const { assertOwnedMailpit, assertOwnedWorkspace } = require('./postgres/ipiEmailRenderedQualification.integration.test.js');
const { assertLoopback, configureMailpit, validateFixtureAdapter, installNetworkGuard, readModelDigest, shutdownFixture, REQUIRED_MODEL_DIGEST } = require('./postgres/ipiEmailRenderedFixture.js');
const { runEmailFetchGraph } = require('../server/agent-runtime/indirectEmailDeliveryGraph.js');
const { createIpiMailpitProvider } = require('../server/services/ipiMailpitProvider.js');
const { createPostgresIdentityAdapter } = require('../server/services/postgresIdentityAdapter.js');

const root = path.resolve(__dirname, '..');
const page = fs.readFileSync(path.join(root, 'client/src/pages/challenges/IndirectPromptInjectionChallenge.js'), 'utf8');
const route = fs.readFileSync(path.join(root, 'server/routes/emailAgent.js'), 'utf8');
const fixture = fs.readFileSync(path.join(__dirname, 'postgres/ipiEmailRenderedFixture.js'), 'utf8');
const harness = fs.readFileSync(path.join(__dirname, 'postgres/ipiEmailRenderedQualification.integration.test.js'), 'utf8');
const launcher = fs.readFileSync(path.join(__dirname, 'postgres/run-ipi-email-rendered-isolated.py'), 'utf8');

const objectiveIds = [
  'email_create_inbox', 'email_send_attack', 'email_retrieve',
  'email_trigger_injection', 'email_understand_defense',
];

test('current assembled IPI email qualification is closed over the five canonical UI objectives', async () => {
  assert.equal(assertOwnedMailpit('http://127.0.0.1:8025/'), 'http://127.0.0.1:8025');
  assert.equal(assertLoopback('http://localhost:8025/', 'fixture'), 'http://localhost:8025');
  assert.throws(() => assertLoopback('https://remote.invalid/', 'fixture'));
  assert.throws(() => assertLoopback('http://user:pass@127.0.0.1:8025/', 'fixture'));
  const pool = {}; const progress = {};
  assert.equal(validateFixtureAdapter({ pool, progress }, pool, progress), true);
  assert.throws(() => validateFixtureAdapter({ pool }, pool, progress));
  const repository = { createSession: async () => ({}) };
  const actualAdapter = createPostgresIdentityAdapter({ repository, progress, jwtSecret: 'contract-secret' });
  actualAdapter.pool = pool;
  assert.equal(actualAdapter.repository, repository);
  assert.equal(validateFixtureAdapter(actualAdapter, pool, progress), true);
  const seen = [];
  const guard = installNetworkGuard({ mailpitApiUrl: 'http://127.0.0.1:8025/', ollamaBaseUrl: 'http://127.0.0.1:11434',
    fetchImpl: async input => { seen.push(String(input)); return new Response('{}'); } });
  await global.fetch('http://127.0.0.1:11434/api/tags');
  assert.equal(guard.counters.modelCalls, 0);
  await global.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify({ model: 'llama3.1:8b' }) });
  await assert.rejects(global.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify({ model: 'other' }) }), /Required model pin/);
  await assert.rejects(global.fetch('http://127.0.0.1:11434/api/tags', { method: 'POST' }), /tags must use GET/);
  await assert.rejects(global.fetch('http://user:pass@127.0.0.1:11434/api/tags'), /credentials\/options denied/);
  await assert.rejects(axios.get('https://remote.invalid/api/tags'), /External Axios network denied/);
  let axiosAdapterCalled = false;
  await assert.rejects(axios.get('https://remote.invalid/api/tags', {
    adapter: async () => { axiosAdapterCalled = true; return { data: {}, status: 200, statusText: 'OK', headers: {}, config: {} }; },
  }), /External Axios network denied/);
  assert.equal(axiosAdapterCalled, false);
  let axiosConfig;
  const health = await axios.get('http://127.0.0.1:11434/api/tags', {
    maxRedirects: 7,
    adapter: async config => { axiosConfig = config; return { data: { models: [] }, status: 200, statusText: 'OK', headers: {}, config, request: {} }; },
  });
  assert.deepEqual(health.data, { models: [] });
  assert.equal(axiosConfig.maxRedirects, 0);
  assert.equal(axiosConfig.timeout, 120000);
  await assert.rejects(axios.post('http://127.0.0.1:11434/api/tags', {}, { adapter: async () => ({}) }), /Axios model method denied/);
  await assert.rejects(axios.post('http://127.0.0.1:11434/api/generate', { model: 'wrong' }, { adapter: async () => ({}) }), /Axios required model pin missing/);
  await assert.rejects(global.fetch('http://127.0.0.1:11434/api/tags', { redirect: 'follow' }), /Redirects denied/);
  try { await assert.rejects(global.fetch('https://remote.invalid/'), /External network denied/); }
  finally { guard.restore(); }
  const limited = installNetworkGuard({ mailpitApiUrl: 'http://127.0.0.1:8025/', ollamaBaseUrl: 'http://127.0.0.1:11434', maxCalls: 1,
    fetchImpl: async input => String(input).includes(':8025') ? new Response('{}') : new Response('{}') });
  await global.fetch('http://127.0.0.1:11434/api/tags');
  await global.fetch('http://127.0.0.1:8025/api/v1/search?query=to%3A%22learner%40sharklasers.com%22&limit=50');
  await assert.rejects(global.fetch('http://127.0.0.1:11434/api/tags?query=unexpected'), /Network query denied/);
  await assert.rejects(global.fetch('http://127.0.0.1:8025/api/v1/search?query=a&query=b'), /Network query denied/);
  await assert.rejects(global.fetch('http://127.0.0.1:8025/api/v1/message/1?query=a'), /Network query denied/);
  await global.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify({ model: 'llama3.1:8b' }) });
  await assert.rejects(global.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify({ model: 'llama3.1:8b' }) }), /Generation call bound/);
  let overBudgetDispatch = false;
  await assert.rejects(axios.post('http://127.0.0.1:11434/api/chat', { model: 'llama3.1:8b' }, {
    adapter: async () => { overBudgetDispatch = true; return {}; },
  }), /Generation call bound/);
  assert.equal(overBudgetDispatch, false);
  assert.deepEqual(limited.counters, { modelCalls: 1, mailpitCalls: 1, tagsCalls: 1, transportCalls: 3 });
  limited.restore();
  const controller = new AbortController();
  const abortGuard = installNetworkGuard({ mailpitApiUrl: 'http://127.0.0.1:8025/', ollamaBaseUrl: 'http://127.0.0.1:11434',
    fetchImpl: async (_input, init) => new Promise((resolve, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true })) });
  const aborted = global.fetch('http://127.0.0.1:11434/api/chat', { method: 'POST', body: JSON.stringify({ model: 'llama3.1:8b' }), signal: controller.signal });
  controller.abort();
  await assert.rejects(aborted, /aborted/);
  abortGuard.restore();
  const validTags = JSON.stringify({ models: [{ name: 'llama3.1:8b', digest: REQUIRED_MODEL_DIGEST }] });
  await assert.rejects(readModelDigest({ ollamaBaseUrl: 'http://127.0.0.1:11434', fetchImpl: async () => new Response('nope', { status: 503 }) }), /tags request failed/);
  await assert.rejects(readModelDigest({ ollamaBaseUrl: 'http://127.0.0.1:11434', fetchImpl: async () => new Response('x'.repeat(131073)) }), /too large/);
  await assert.rejects(readModelDigest({ ollamaBaseUrl: 'http://127.0.0.1:11434', fetchImpl: async () => new Response(JSON.stringify({ models: [{ name: 'llama3.1:8b', digest: 'wrong' }] })) }), /digest mismatch/);
  assert.equal(await readModelDigest({ ollamaBaseUrl: 'http://127.0.0.1:11434', fetchImpl: async () => new Response(validTags) }), REQUIRED_MODEL_DIGEST);
  const closed = [];
  const fakeFixture = { network: { counters: { modelCalls: 1 }, restore: () => closed.push('restore') } };
  await assert.rejects(shutdownFixture({ fixture: fakeFixture, server: { close: callback => { closed.push('server'); callback(); } }, identityRuntime: { end: async () => { closed.push('runtime'); throw new Error('runtime close'); } }, identityMigration: { end: async () => closed.push('migration') }, readiness: path.join(os.tmpdir(), `ipi-final-${process.pid}`), modelDigestBefore: 'same', modelDigestFn: async () => 'changed' }), /shutdown failed/);
  assert.deepEqual(closed, ['restore', 'server', 'runtime', 'migration']);
  assert.throws(() => assertOwnedMailpit('https://mailpit.example.invalid/'));
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-ipi-email-rendered-contract-'));
  const source = path.join(parent, 'source'); fs.mkdirSync(source);
  assert.equal(assertOwnedWorkspace(source), fs.realpathSync(source));
  fs.rmSync(parent, { recursive: true, force: true });
  for (const id of objectiveIds) {
    assert.match(page, new RegExp(id), `learner UI must expose ${id}`);
    assert.match(route, new RegExp(id), `server route/judge must expose ${id}`);
  }
  for (const endpoint of [
    '/api/email-agent/save-email', '/api/email-agent/send',
    '/api/email-agent/fetch-sharklasers', '/api/email-agent/summarize',
    '/api/email-agent/progress', '/api/email-agent/progress/reset',
  ]) assert.match(harness, new RegExp(endpoint.replaceAll('/', '\\/')));
  assert.match(page, /manual workshop input and does not prove provider delivery/);
  assert.match(harness, /manual fallback cannot qualify retrieval/);
  assert.match(harness, /IPI_EMAIL_RENDERED_UI === '1'/);
  assert.match(harness, /Mailpit must be loopback-only/);
  assert.doesNotMatch(harness, /guerrillamail\.com\/ajax\.php|smtp\.gmail\.com/);
  assert.doesNotMatch(harness, /--no-sandbox/);
  assert.match(harness, /OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE/);
  assert.match(harness, /authorization: `Bearer/);
  assert.match(harness, /siblingBeforeReset/);
  assert.match(harness, /summaryBody\.safeSummary/);
  assert.match(fixture, /app\.use\('\/api\/workshop', require\('\.\.\/\.\.\/server\/routes\/workshop'\)\)/);
  assert.match(harness, /writeFailureDiagnostics/);
  assert.match(harness, /failedApi/);
  assert.match(launcher, /IPI_RENDERED_EMAIL_DIAGNOSTICS/);
  assert.match(launcher, /diagnostics = root \/ "private-email-diagnostics"/);
  assert.doesNotMatch(launcher, /shutil\.rmtree/);
});

test('rendered harness retains canonical receipt, reset and sibling assertions', () => {
  for (const fragment of [
    'objective_judgments', 'workshop_platform.completions',
    'completedCount, 5', 'completedCount, 0',
    'reset must not leak progress across owners',
  ]) assert.match(harness, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
});

test('owned Mailpit adapter is the production fetch graph provider', async () => {
  const originalFetch = global.fetch;
  const context = {ownerId:7, generation:1};
  const body = 'Owned Mailpit fixture body';
  let provider;
  try {
    let providerAddress;
    const fetcher = async input => {
      const url = new URL(input);
      if (url.pathname === '/api/v1/info') return new Response(JSON.stringify({version:'test'}), {headers:{'content-type':'application/json'}});
      if (url.pathname === '/api/v1/search') return new Response(JSON.stringify({ messages: [{ ID: 'mailpit-1', MessageID:'<smtp-1@example.invalid>', From: { Address: 'indirectpromptinjection@owasp-ai-goat.invalid' }, To: [{ Address: providerAddress }], Subject: 'Owned subject', Created:'2026-09-18T00:00:00Z' }] }), {headers:{'content-type':'application/json'}});
      if (url.pathname === '/api/v1/message/mailpit-1') return new Response(JSON.stringify({ ID: 'mailpit-1', MessageID:'<smtp-1@example.invalid>', From: { Address: 'indirectpromptinjection@owasp-ai-goat.invalid' }, To: [{ Address: providerAddress }], Subject: 'Owned subject', Text: body, HTML: `<p>${body}</p>`, Created: '2026-09-18T00:00:00Z' }), {headers:{'content-type':'application/json'}});
      throw new Error(`Unexpected provider URL: ${url.pathname}`);
    };
    provider = createIpiMailpitProvider({apiUrl:'http://127.0.0.1:8025/', smtpHost:'127.0.0.1', smtpPort:1025, hmacSecret:'d'.repeat(48), fetcher, mailer:{createTransport(){return {verify:async()=>{},sendMail:async()=>({}),close:async()=>{}};}}});
    providerAddress = provider.addressFor(context);
    const listed = await provider.fetchEmails(context);
    assert.equal(listed.emails[0].provider, 'mailpit');
    let stored;
    const controlledJudge = async () => ({ verdict:'pass', criteria:[] });
    const result = await runEmailFetchGraph({ tempEmail: providerAddress, userKey: 'owned', platformUserId: 7, ownerContext: context }, {
      sharkLasersScraper: provider,
      gmailService: provider,
      TARGET_EMAIL: provider.getTargetSender(),
      objectiveJudge: controlledJudge,
      completionService: { beginAttempt:async()=>({attemptId:'controlled-mailpit-attempt'}), evaluate:async packet=>({judgment:await controlledJudge(packet),completed:true}) },
      execution: { ownerKey: 'owned-owner', durableGeneration: 1, runId: 'owned-run', check: async () => {} },
      storeEmailArtifacts: async scope => { stored = scope.artifacts; return scope.artifacts.map((item, index) => ({ ...item, artifactId: `11111111-1111-4111-8111-${String(index + 1).padStart(12, '0')}`, bodySha256: 'a'.repeat(64), modelBody: item.body })); },
      markEmailAgentObjectiveComplete: async () => ({ projectionPending: false }),
    });
    assert.equal(result.emails[0].body, body);
    assert.equal(result.emails[0].providerMessageId, 'mailpit-1');
    assert.equal(stored[0].provider, 'mailpit');
  } finally {
    await provider?.close?.();
  }
});

test('main content profile enforces exact five controlled receipts and closed request budgets',()=>{
  const f=require('./postgres/ipiEmailRenderedFixture');
  const r={profile:f.CONTENT_PROFILE,status:'passed',installedWrites:false,actualModelProof:false,modelCalls:0,mailCalls:0,genuineCredit:0,controlledProjectionCount:5,completionScope:f.CONTENT_SCOPE,cases:f.CONTENT_IDS.map(id=>({id,learnerContent:true,adminPreview:true,independentGates:true,completedProjection:true})),dashboardParity:true,configurationRestored:true,projectionRestored:true,siblingPreserved:true,immutableEvidencePreserved:true,requests:{browser:1000,api:80},cleanup:['restore','browser','mail','rag','routes','server','pools'].map(name=>({name,status:'fulfilled'})),cleanupFailures:[]};
  Object.assign(r,{controlledJudgeCalls:2,controlledSessionOwners:2,sessionPreEffectDenied:true,sessionJudgeCommitDenied:true,sessionPostCommitPublicationDenied:true,sessionPriorCommitPreserved:true,sessionSiblingPreserved:true});
  f.assertContentReceipt(r);for(const mutation of [x=>x.controlledJudgeCalls=3,x=>x.sessionJudgeCommitDenied=false,x=>x.cases.pop(),x=>x.cases[0].independentGates=false,x=>x.mailCalls=1,x=>x.modelCalls=1,x=>x.genuineCredit=1,x=>x.requests.browser=1001,x=>x.requests.api=-1,x=>x.cleanup[0].status='rejected']){const bad=structuredClone(r);mutation(bad);assert.throws(()=>f.assertContentReceipt(bad));}
  assert(f.contentRequestAllowed('http://127.0.0.1:1234/a','http://127.0.0.1:1234',1000));assert(!f.contentRequestAllowed('http://127.0.0.1:1234/a','http://127.0.0.1:1234',1001));assert(!f.contentRequestAllowed('https://example.invalid','http://127.0.0.1:1234',1));
});
test('main content DOM oracle scopes canonical completed cards and foreground solution content',()=>{
  const {JSDOM}=require('../client/node_modules/jsdom'),f=require('./postgres/ipiEmailRenderedFixture');
  const dom=new JSDOM('<div><span class="status-badge">COMPLETED</span><div class="obj-content"><div class="obj-name">Instructor label</div><button>Hint</button><button>Solution</button></div></div><p>Required approach</p><div id="modal"><div><h3>Solution: Canonical</h3><button>Close</button></div><p>Easy</p><p>payload</p><p>reason</p><p>tip</p></div>');
  const prior=global.document;global.document=dom.window.document;
  try{assert(f.contentCard({label:'Instructor label'}));assert(!f.contentCard({label:'stale default'}));document.querySelector('.status-badge').textContent='DONE';assert(!f.contentCard({label:'Instructor label'}));const v={title:'Canonical',difficulty:'Easy',approach:'Required approach',examples:[{prompt:'payload',explanation:'reason'}],tips:['tip']};assert(!f.contentSolution(v));document.querySelector('#modal').append(Object.assign(document.createElement('p'),{textContent:v.approach}));assert(f.contentSolution(v));document.querySelector('.obj-content').append(Object.assign(document.createElement('button'),{textContent:'Hint'}));assert(!f.contentCard({label:'Instructor label'}));}finally{global.document=prior;dom.window.close();}
});
test('main content admission requires identity-only owned URLs without supply-chain fallback',()=>{
  const {validateAuthority}=require('./postgres/codeBotRenderedParityMainV1');const evidence=path.join(root,'backups/private-recovery/codebot-parity/run-contract'),nonce='0123456789ab',owner={owner:'contract',sourceRoot:root,evidenceRoot:evidence,scenario:'codebot-rendered-parity',profile:'ipi-email-five-content',nativePid:process.pid,nativeStarted:true,nonce,containerId:'a'.repeat(64),databasePort:54321};const env={CODEBOT_PARITY_NATIVE:'1',PG_TEST_DISPOSABLE:'yes',CODEBOT_PARITY_SOURCE_ROOT:root,CODEBOT_PARITY_OWNER:'contract',CODEBOT_PARITY_PROFILE:'ipi-email-five-content',IDENTITY_DATABASE_URL:'postgresql://dvaia_identity_runtime@127.0.0.1:54321/owasp_ai_goat_test_codebot_parity_'+nonce+'_identity',IDENTITY_MIGRATION_DATABASE_URL:'postgresql://dvaia_identity_migration@127.0.0.1:54321/owasp_ai_goat_test_codebot_parity_'+nonce+'_identity'};assert.equal(validateAuthority({env,owner,evidence}),54321);assert.throws(()=>validateAuthority({env:{...env,IDENTITY_DATABASE_URL:env.IDENTITY_DATABASE_URL.replace('_identity','_foreign')},owner,evidence}));
});

test('controlled session verdict satisfies actual canonical repository shape without credit',()=>{
 const {controlledSessionVerdict}=require('./postgres/ipiEmailRenderedFixture');
 const {buildIpiRubric}=require('../server/agent-runtime/indirectObjectiveJudge');
 const input={rubric:buildIpiRubric('email_create_inbox'),facts:{inbox_saved:true},evidence:[{id:'saved_inbox',source:'server_observation',content:{address:'owned@example.invalid',domainAccepted:true,saved:true}}],execution:{runId:'11111111-1111-4111-8111-111111111111'}};
 const value=controlledSessionVerdict(input);
 const row={family:value.family,scenario:value.scenario,objective_id:value.objectiveId,rubric_version:value.rubricVersion,evidence_digest:value.evidenceDigest,run_id:value.runId,mode:value.mode};
 assert.equal(require('../server/database/postgres/objectiveJudgmentRepository').resultValue(value,row).verdict,'fail');
});
test('content session observer delegates actual queue and restores owned accessors',async()=>{
 const f=require('./postgres/ipiEmailRenderedFixture'),module=require('../server/agent-runtime/runCoordinator'),completion=require('../server/services/objectiveCompletionService');
 const before=module.createRunCoordinator,beforeService=completion.getObjectiveCompletionService;
 const probe=f.installContentSessionProbe({pool:{query:async()=>{throw Error('Unexpected DB');}},progress:{getGeneration:async()=>0},adapter:{logout:async()=>{throw Error('Unexpected logout');}}});
 try{const control=probe.select({id:41,token:'controlled'},'pending'),real=module.createRunCoordinator({family:'IndirectEmail',ledger:null});let release,entered;const ready=new Promise(r=>entered=r),hold=new Promise(r=>release=r);let second=false;const first=real.run('41',{},async()=>{entered();await hold;});await ready;const next=real.run('41',{},async()=>{second=true;});await control.queueEntered;assert.equal(second,false);release();await Promise.all([first,next]);assert.equal(second,true);assert.equal(probe.calls(),0);}finally{probe.restore();}
 assert.equal(module.createRunCoordinator,before);assert.equal(completion.getObjectiveCompletionService,beforeService);
});


test('IPI master solution waiter matches actual frontend compatibility request',async()=>{
  const {contentToggleRequest}=require('./postgres/ipiEmailRenderedFixture');
  const {mutatePromptInjectionMasterSolution}=require('../client/src/utils/promptInjectionAdminCompatibility');
  for(const enabled of [false,true]){
    const expected=contentToggleRequest('solution',null),calls=[];
    await mutatePromptInjectionMasterSolution({patch:async(url,body)=>{calls.push({method:'PATCH',url,body});return {data:{}};}},'indirect_prompt_injection',enabled);
    assert.equal(calls.length,1);assert.equal(calls[0].method,expected.method);assert.equal(calls[0].url,expected.path);assert.deepEqual(calls[0].body,{[expected.field]:enabled});
  }
  assert.deepEqual(contentToggleRequest('hint',null),{method:'POST',path:'/api/admin/challenges/hints/toggle',field:'showHints'});
  assert.deepEqual(contentToggleRequest('solution','email_create_inbox'),{method:'POST',path:'/api/admin/ipi-workshop/solutions/toggle',field:'enabled'});
  assert.throws(()=>contentToggleRequest('unknown',null));assert.throws(()=>contentToggleRequest('hint','foreign'));
});

test('closed controlled RAG decisions require exact question and retrieved source and cannot infer again',()=>{
 const f=require('./postgres/ipiEmailRenderedFixture'),counts={controlledActorCalls:0},messages=[{role:'system',content:'Controlled graph policy'},{role:'user',content:'Question: '+f.RAG_QUESTION+'\n\nOrdered search observations:\n[]'}];
 const first=f.controlledRagDecision(counts,messages);assert.equal(first.provider,'controlled-rag-ui');assert.equal(first.model,'controlled-no-credit');assert.deepEqual(JSON.parse(first.response),{action:'search_document',query:f.RAG_QUESTION,topK:1});assert.throws(()=>f.controlledRagDecision(counts,messages));assert.equal(counts.controlledActorCalls,1);
 messages[1].content+='\n'+f.RAG_DOCUMENT;assert.deepEqual(JSON.parse(f.controlledRagDecision(counts,messages).response),{action:'answer',answer:f.RAG_ANSWER});assert.throws(()=>f.controlledRagDecision(counts,messages));assert.equal(counts.controlledActorCalls,2);
 const wrong={controlledActorCalls:0};assert.throws(()=>f.controlledRagDecision(wrong,[messages[0],{role:'user',content:'Question: foreign\n'}]));assert.equal(wrong.controlledActorCalls,0);
});
test('single RAG receipt rejects missing lifecycle, model credit and wrong cohort',()=>{
 const f=require('./postgres/ipiEmailRenderedFixture'),r={profile:f.RAG_PROFILE,status:'passed',completionScope:f.RAG_SCOPE,controlledProjectionCount:1,controlledActorCalls:2,controlledJudgeCalls:5,controlledEmbeddingCalls:3,modelCalls:0,mailCalls:0,genuineCredit:0,installedWrites:false,actualModelProof:false,cases:[{id:'rag_query',learnerContent:true,adminPreview:true,independentGates:true,completedProjection:true}],requests:{browser:100,api:12},cleanup:['restore','browser','mail','rag','routes','server','pools'].map(name=>({name,status:'fulfilled'})),cleanupFailures:[]};for(const k of ['uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'])r[k]=true;f.assertRagContentReceipt(r);
 for(const [k,v] of [['modelCalls',1],['genuineCredit',1],['controlledActorCalls',3],['controlledJudgeCalls',0],['resetRetired',false],['nonemptySiblingPreserved',false],['timePreserved',false],['profile',f.CONTENT_PROFILE]])assert.throws(()=>f.assertRagContentReceipt({...r,[k]:v}));
 assert.equal(f.contentToggleRequest('hint','rag_query').path,'/api/admin/workshops/indirect_prompt_injection/hints/rag_query/toggle');
});


test('RAG document audit uses migration authority while runtime table access stays revoked',()=>{
 const fs=require('node:fs'),path=require('node:path');
 const harness=fs.readFileSync(path.join(__dirname,'postgres/ipiEmailRenderedFixture.js'),'utf8');
 const migration=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0082_workshop_rag_sources.sql'),'utf8');
 assert.match(migration,/REVOKE ALL ON ALL TABLES IN SCHEMA workshop_rag FROM PUBLIC,dvaia_identity_runtime/);
 const snapshot=harness.split('const documents=async id=>')[1].split(';')[0];
 assert.match(snapshot,/await migration\.query/);assert.doesNotMatch(snapshot,/await pool\.query/);
 assert.match(snapshot,/WHERE owner_id=\$1 AND family='RAG' ORDER BY document_id/);assert.match(snapshot,/\[id\]/);
});

test('actual RAG frozen bytes are the original clean-grounding service case',()=>{
  const {RAG_ACTUAL_INPUT:input}=require('./postgres/ipiEmailRenderedFixture');
  const original=fs.readFileSync(path.join(__dirname,'postgres/workshopRagAgentActual8b.integration.test.js'),'utf8');
  const match=original.match(/\{id:'clean-grounding',objective:'rag_query',text:'([^']+)',question:'([^']+)',expected:'pass'\}/);
  assert(match);assert.equal(input.document,match[1]);assert.equal(input.question,match[2]);
  assert.equal(fs.statSync(path.join(__dirname,'fixtures/ipiRagQueryActualInput.json')).mode&0o777,0o400);
});

test('actual RAG binder rejects detached actor, source, effect, packet and owner evidence',()=>{
  const {RAG_ACTUAL_INPUT:input,bindRagActualCapture}=require('./postgres/ipiEmailRenderedFixture');
  const sha=x=>require('node:crypto').createHash('sha256').update(x).digest('hex');
  const ownerId=7,ownerKey='["RAG","7"]',runId='00000000-0000-4000-8000-000000000001',documentId='00000000-0000-4000-8000-000000000002',evaluationId='00000000-0000-4000-8000-000000000003';
  const receipt={ownerId,runId,documentId,runtimeFingerprint:'a'.repeat(64),sourceSha256:sha(input.document),graphGeneration:'0'};
  const answer='Receipts must be submitted within 17 days after travel.';
  const packet={rubric:{objectiveId:'rag_query',version:'ipi-rag-evidence-bound-v2',requiredFacts:['real_model']},facts:{real_model:true},evidence:[{id:'question',content:input.question},{id:'context',content:input.document},{id:'raw_response',content:answer},{id:'retrieval_receipts',content:[receipt]}]};
  const system='AUTHORITATIVE RUBRIC:\n'+JSON.stringify(packet.rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+JSON.stringify(packet.facts)+'\n';
  const calls=[{role:'actor',caseId:'owner-query',messages:[{role:'system',content:'Policy'},{role:'user',content:'Question: '+input.question+'\n'}],result:{provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action:'search_document',query:input.question,topK:1})}}, {role:'actor',caseId:'owner-query',messages:[{role:'system',content:'Policy'},{role:'user',content:'Question: '+input.question+'\n'}],result:{provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({action:'answer',answer})}}, {role:'judge',caseId:'owner-query',messages:[{role:'system',content:system},{role:'user',content:JSON.stringify(packet.evidence)}],result:{provider:'ollama',model:'llama3.1:8b',response:JSON.stringify({verdict:'pass',criteria:[]})}}];
  for(const call of calls){call.error=null;call.options={temperature:0,num_predict:call.role==='actor'?1200:900,format:{type:'object'}};}
  const capture={searches:[{input:{question:input.question,limit:1,documentId},result:{receipt}}],input:structuredClone(input),ownerId,embeddingFingerprint:{fingerprint:'a'.repeat(64)},upload:{body:{session_id:documentId}},query:{status:200,body:{presentation_source:'model',raw_model_answer:answer,retrieved_chunks:[{text:input.document}],judgments:[{objectiveId:'rag_query',evaluationId,verdict:'pass',criteria:[]}],completedObjectiveIds:['rag_query']}},judgments:[{objective_id:'rag_query',result_json:{criteria:[]},verdict:'pass',disposition:'awarded',evaluation_id:evaluationId,evidence_digest:sha(JSON.stringify(packet)),run_id:runId,user_id:ownerId,generation:'0'}],packets:[{evaluation_id:evaluationId,packet:JSON.stringify(packet),owner_key:ownerKey,user_id:ownerId,owner_generation:'0'}],runs:[{run_id:runId,status:'completed',owner_key:ownerKey,generation:'0'}],events:[{run_id:runId,node:'rag_search',event_type:'tool'}],effects:[{run_id:runId,status:'completed',owner_key:ownerKey,generation:'0',effect_key:runId+':rag_search:0:'+sha(JSON.stringify({query:input.question,topK:1}))}],modelCalls:calls};
  const rows=calls.map((call,index)=>{const request=JSON.stringify({model:'llama3.1:8b',messages:call.messages,format:call.options.format,options:{temperature:0,num_predict:call.role==='actor'?1200:900}}),response=JSON.stringify({model:'llama3.1:8b',message:{content:call.result.response},done:true,done_reason:'stop'});return {index,kind:'chat',caseId:call.caseId,terminal:'returned',status:200,request,requestSha256:sha(request),requestBytes:Buffer.byteLength(request),response,responseSha256:sha(response),responseBytes:Buffer.byteLength(response),responseComplete:true,responseCaptureTruncated:false};});
  assert.deepEqual(bindRagActualCapture(capture,rows),{actorCalls:2,judgeCalls:1});
  for(const mutate of [c=>{c.ownerId=8;},c=>{c.effects=[];},c=>{c.effects[0].effect_key=c.effects[0].effect_key.slice(runId.length+1);},c=>{c.effects[0].effect_key='foreign-run:'+c.effects[0].effect_key.slice(runId.length+1);},c=>{c.query.body.raw_model_answer='fabricated';},c=>{c.modelCalls[0].result.fallback=true;},c=>{c.packets[0].packet+=' ';},c=>{c.embeddingFingerprint.fingerprint='b'.repeat(64);},c=>{c.input.question+=' changed';}]){const changed=structuredClone(capture);mutate(changed);assert.throws(()=>bindRagActualCapture(changed,rows));}
  const incomplete=structuredClone(rows);incomplete[0].responseComplete=false;assert.throws(()=>bindRagActualCapture(capture,incomplete));
});

test('actual RAG lifecycle negatives deny any additional provider dispatch',()=>{
  const {bindRagNoCallNegative}=require('./postgres/ipiEmailRenderedFixture');
  for(const [name,status] of [['foreign-document',404],['revoked-session',401],['retired-document',404]]){
    const proof={before:{chat:4,tags:1},after:{chat:4,tags:1},response:{status,body:{}}};assert.equal(bindRagNoCallNegative(name,proof),true);
    assert.throws(()=>bindRagNoCallNegative(name,{...proof,after:{chat:5,tags:1}}));
    assert.throws(()=>bindRagNoCallNegative(name,{...proof,response:{status:200}}));
  }
  assert.throws(()=>bindRagNoCallNegative('unadmitted-negative',{}));
});

test('two-card RAG upload/clean profile requires both independent gates and exact controlled scope',()=>{
 const f=require('./postgres/ipiEmailRenderedFixture'),ids=['rag_upload','rag_clean_doc'];
 assert.deepEqual(f.ragContentConfiguration(f.RAG_PROFILE),{ids:['rag_query'],scope:f.RAG_SCOPE});
 assert.deepEqual(f.ragContentConfiguration(f.RAG_UPLOAD_PROFILE),{ids,scope:f.RAG_UPLOAD_SCOPE});
 assert.throws(()=>f.ragContentConfiguration('ipi-rag-all'));
 const r={profile:f.RAG_UPLOAD_PROFILE,status:'passed',completionScope:f.RAG_UPLOAD_SCOPE,controlledProjectionCount:2,controlledActorCalls:2,controlledJudgeCalls:5,controlledEmbeddingCalls:3,modelCalls:0,mailCalls:0,genuineCredit:0,installedWrites:false,actualModelProof:false,cases:ids.map(id=>({id,learnerContent:true,adminPreview:true,independentGates:true,completedProjection:true})),requests:{browser:140,api:16},cleanup:['restore','browser','mail','rag','routes','server','pools'].map(name=>({name,status:'fulfilled'})),cleanupFailures:[]};
 for(const k of ['uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'])r[k]=true;
 f.assertRagContentReceipt(r);
 for(const id of ids){assert(f.contentToggleRequest('hint',id).path.includes(id));assert.deepEqual(f.contentToggleRequest('solution',id),{method:'POST',path:'/api/admin/ipi-workshop/solutions/toggle',field:'enabled'});}
 for(const [key,value] of [['controlledProjectionCount',1],['profile',f.RAG_PROFILE],['completionScope',f.RAG_SCOPE],['modelCalls',1],['genuineCredit',1],['controlledJudgeCalls',4],['dashboardParity',false],['resetReplayExact',false],['timePreserved',false]])assert.throws(()=>f.assertRagContentReceipt({...r,[key]:value}));
 for(const mutate of [c=>c.pop(),c=>c.reverse(),c=>{c[0].id='rag_query';},c=>{c[1].independentGates=false;},c=>{c[0].adminPreview=false;},c=>{c[1].completedProjection=false;}]){const changed=structuredClone(r);mutate(changed.cases);assert.throws(()=>f.assertRagContentReceipt(changed));}
});

test('closed actual email input preserves exact original r7 submission and clean control',()=>{
  const f=require('./postgres/ipiEmailRenderedFixture');
  assert.equal(f.EMAIL_ACTUAL_INPUT.profile,'ipi-email-trigger-actual');
  assert.equal(f.EMAIL_ACTUAL_INPUT.origin.rawSha256,'1dbd50083259562b7a0833a2a34406340aa68363d3e57e8fa9e6497b26a173df');
  assert.equal(cryptoHash(f.EMAIL_ACTUAL_INPUT.attackBody),'2020944c25389f625234aedfac2819538eda7b24e8160d8d759dbc9015f0be52');
  assert.equal(f.EMAIL_ACTUAL_INPUT.cleanBody,'Quarterly planning begins Monday. Finance will publish the agenda Friday.');
  assert(f.emailActorPrompts().vulnerable.includes('{email_body}'));
});
function cryptoHash(text){return require('node:crypto').createHash('sha256').update(text).digest('hex');}
async function emailActorCaptureFixture(){
  const f=require('./postgres/ipiEmailRenderedFixture'),graph=require('../server/agent-runtime/indirectEmailGraph'),id='11111111-1111-4111-8111-111111111111',run='22222222-2222-4222-8222-222222222222',ownerKey=JSON.stringify(['IndirectEmail','41']);
  const artifact={artifactId:id,body:f.EMAIL_ACTUAL_INPUT.cleanBody,modelBody:f.EMAIL_ACTUAL_INPUT.cleanBody,bodySha256:cryptoHash(f.EMAIL_ACTUAL_INPUT.cleanBody),modelBodySha256:cryptoHash(f.EMAIL_ACTUAL_INPUT.cleanBody),modelBodyTruncated:false};
  const c={ownerId:41,modelCalls:[],events:[],effects:[],runs:[{run_id:run,owner_key:ownerKey,generation:'0',status:'completed'}],judgments:[],packets:[],artifacts:[{artifact_id:id,owner_id:41,owner_key:ownerKey,generation:'0',body_text:artifact.body,model_body_text:artifact.modelBody,body_sha256:artifact.bodySha256,model_body_sha256:artifact.modelBodySha256}]};
  const item={id:'clean-control',artifact,request:{artifactId:id},response:{status:200,body:{actorDecisions:{},actorActions:{},judgments:[]}}};const evidence=[{id:'email',source:'tool_result',content:artifact.modelBody}];
  for(const profile of ['vulnerable','secure']){
    const key=run+':email_read_'+profile+'_'+id,receipt={version:1,ownerKey,generation:'0',runId:run,effectKey:key,status:'completed'};c.effects.push({run_id:run,owner_key:ownerKey,generation:'0',effect_key:key,status:'completed'});let n=0;
    const replay=await graph.runActorLoop({profile,artifactId:id,systemPrompt:f.emailActorPrompts()[profile]},{aiService:{chatWithMessages:async(messages,options)=>{const result={response:['{"action":"read_email"}','{"action":"summarize"}',artifact.body][n++],provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false};c.modelCalls.push({role:'actor',caseId:item.id,messages:structuredClone(messages),options:JSON.parse(JSON.stringify({...options,signal:undefined})),result,error:null});return result;}},readEmailArtifact:async()=>artifact,execution:{runId:run,ownerKey,durableGeneration:'0',check:async()=>{},trace:async e=>{if(['decision','tool','error'].includes(e.type))c.events.push({run_id:run,node:e.node,event_type:e.type,metadata:require('../server/agent-runtime/runTraceStore').traceData(e.data)});},effectWithReceipt:async()=>({value:artifact,receipt})}});
    item.response.body[profile==='vulnerable'?'vulnerableSummary':'secureSummary']=replay.response;item.response.body.actorDecisions[profile]=replay.decisions;item.response.body.actorActions[profile]=replay.action;
    evidence.push({id:profile+'_response',source:'assistant_response',content:replay.response},{id:profile+'_observation',source:'server_observation',content:{profile,artifactId:id,bodySha256:artifact.bodySha256,modelBodySha256:artifact.modelBodySha256,modelBodyTruncated:false,receipt}});
  }
  for(const [i,objective]of ['email_trigger_injection','email_understand_defense'].entries()){const evaluation='evaluation-'+i;c.judgments.push({evaluation_id:evaluation,run_id:run,objective_id:objective,verdict:'fail',result_json:{criteria:[]}});c.packets.push({evaluation_id:evaluation,packet:JSON.stringify({evidence:evidence.filter(x=>objective!=='email_trigger_injection'||!x.id.startsWith('secure_'))})});item.response.body.judgments.push({objectiveId:objective,evaluationId:evaluation,verdict:'fail',criteria:[]});}
  return {c,item};
}
test('actual email actor replay regenerates exact production requests and full run-prefixed effects',async()=>{
  const f=require('./postgres/ipiEmailRenderedFixture'),{c,item}=await emailActorCaptureFixture();await f.replayEmailActors(c,item);
  for(const mutate of [x=>x.modelCalls[0].messages[0].content+=' altered',x=>x.modelCalls[1].options.format.properties.action.enum=['read_email'],x=>x.modelCalls[2].result.response='invented output',x=>x.effects[0].effect_key=x.effects[0].effect_key.split(':').slice(1).join(':'),x=>x.effects[0].owner_key='sibling',x=>x.artifacts[0].generation='9',x=>x.events[0].metadata.tool='refuse',x=>x.runs[0].status='failed']){const changed=structuredClone(c);mutate(changed);await assert.rejects(f.replayEmailActors(changed,item));}
});
test('actual email canonical Judge replay binds full saved packet, requests, raw result and normalized receipt',async()=>{
  const f=require('./postgres/ipiEmailRenderedFixture'),judgeModule=require('../server/agent-runtime/objectiveJudge'),repository=require('../server/database/postgres/objectiveJudgmentRepository'),rubric=require('../server/agent-runtime/indirectObjectiveJudge').buildIpiRubric('email_trigger_injection');
  const run='22222222-2222-4222-8222-222222222222',ownerKey=JSON.stringify(['IndirectEmail','41']);
  const packet=JSON.parse(judgeModule.prepareJudgeInput({rubric,evidence:[{id:'email',source:'tool_result',content:f.EMAIL_ACTUAL_INPUT.cleanBody},{id:'vulnerable_response',source:'assistant_response',content:f.EMAIL_ACTUAL_INPUT.cleanBody},{id:'vulnerable_observation',source:'server_observation',content:{receipt:{runId:run}}}],facts:{real_model:true,email_present:true,responses_present:true,artifact_observation_receipts:true}}).packet);
  const calls=[];const judge=judgeModule.createObjectiveJudge({model:{chat:async(messages,_tools,options)=>{const data=JSON.parse(messages[1].content),result={response:JSON.stringify({passages:data.source_passages.map(x=>({sourceQuoteId:x.id,classification:'ordinary_content',obligation:null})),explanation:'No assistant directive in the clean business email.'}),provider:'ollama',model:'llama3.1:8b'};calls.push({role:'judge',caseId:'clean-control',messages:structuredClone(messages),options:JSON.parse(JSON.stringify({...options,signal:undefined})),result,error:null});return result;}}});
  const result=await judge({...packet,execution:{runId:run,ownerId:41,check:async()=>{}}});assert.equal(result.verdict,'fail');assert.equal(calls[0].options.ownerId,41);
  const text=JSON.stringify(packet),row={user_id:41,evaluation_id:'e',run_id:run,objective_id:rubric.objectiveId,family:rubric.family,scenario:rubric.scenario,rubric_version:rubric.version,evidence_digest:cryptoHash(text),mode:rubric.mode,verdict:result.verdict};row.result_json=repository.resultValue(result,row);
  const c={ownerId:41,modelCalls:calls,evaluations:[{caseId:'clean-control',runId:run,packet,callIndexes:[0],result}],judgments:[row],packets:[{evaluation_id:'e',owner_key:ownerKey,owner_generation:'0',packet:text}],runs:[{run_id:run,owner_key:ownerKey,generation:'0',status:'completed'}]};await f.replayEmailJudgments(c);
  for(const mutate of [x=>x.modelCalls[0].messages[0].content+=' changed',x=>x.modelCalls[0].options.num_predict=900,x=>x.modelCalls[0].result.response='{}',x=>x.judgments[0].result_json.verdict='pass',x=>x.packets[0].owner_generation='1',x=>x.evaluations[0].callIndexes=[],x=>x.modelCalls[0].options.ownerId=42,x=>x.ownerId=42]){const changed=structuredClone(c);mutate(changed);await assert.rejects(f.replayEmailJudgments(changed));}
});
test('actual email no-call boundaries reject output leaks and any call delta',()=>{
  const f=require('./postgres/ipiEmailRenderedFixture');
  for(const [name,status]of [['foreign-artifact',409],['revoked-session',401],['retired-artifact',409],['forged-body',400]]){const proof={before:{chat:12},after:{chat:12},response:{status,body:{success:false}}};assert.equal(f.bindEmailNoCallNegative(name,proof),true);assert.throws(()=>f.bindEmailNoCallNegative(name,{...proof,after:{chat:13}}));assert.throws(()=>f.bindEmailNoCallNegative(name,{...proof,response:{status,body:{vulnerableSummary:'leaked'}}}));}
});
test('email lifecycle binder requires nonempty owner/sibling rows, exact retirement and immutable evidence',()=>{
  const f=require('./postgres/ipiEmailRenderedFixture'),rows=[{artifact_id:'a',owner_id:41,retired_at:null},{artifact_id:'b',owner_id:41,retired_at:null}],immutable={judgments:[{evaluation_id:'j'}],packets:[{evaluation_id:'j'}]},sibling={artifacts:[{artifact_id:'s',owner_id:42,retired_at:null}],completions:[],owner:[{generation:'0'}]};
  const c={ownerId:41,siblingId:42,artifacts:rows,...immutable,lifecycle:{wireBefore:{chat:20},wireAfter:{chat:20},reset:{status:200,body:{success:true}},immutableBefore:immutable,immutableAfter:structuredClone(immutable),ownerBefore:rows,ownerAfter:rows.map(x=>({...x,retired_at:'2026-09-30T00:00:00Z'})),generationBefore:'0',generationAfter:'1',siblingBefore:sibling,siblingAfter:structuredClone(sibling),completionsAfter:[]}};
  for(const [name,status]of [['foreign-artifact',409],['revoked-session',401],['retired-artifact',409],['forged-body',400]])c.lifecycle[name]={before:{chat:20},after:{chat:20},response:{status,body:{}}};assert.equal(f.bindEmailLifecycle(c),true);
  for(const mutate of [x=>x.lifecycle.ownerAfter[0].artifact_id='other',x=>x.lifecycle.ownerAfter[0].retired_at=null,x=>x.lifecycle.generationAfter='0',x=>x.lifecycle.siblingBefore.artifacts=[],x=>x.lifecycle.immutableAfter.judgments=[],x=>x.lifecycle.completionsAfter=[{}]]){const changed=structuredClone(c);mutate(changed);assert.throws(()=>f.bindEmailLifecycle(changed));}
});
test('actual email raw wire binds requested options, effective actor context default and raw output',()=>{
  const f=require('./postgres/ipiEmailRenderedFixture'),options={max_tokens:128,temperature:0.2,format:require('../server/agent-runtime/indirectEmailGraph').emailDecisionFormat(false)},messages=[{role:'system',content:f.emailActorPrompts().vulnerable+'\n'+require('../server/agent-runtime/indirectEmailGraph').EMAIL_DECISION_PROTOCOL},{role:'user',content:'Summarize the selected email artifact.'}],response='{"action":"read_email"}';
  const request=JSON.stringify({model:'llama3.1:8b',stream:false,messages,format:options.format,options:{num_predict:128,num_ctx:8192,temperature:0.2}}),raw=JSON.stringify({model:'llama3.1:8b',message:{content:response},done:true,done_reason:'stop'});
  const row={kind:'chat',role:'actor',caseId:'clean-control',status:200,terminal:'returned',request,requestSha256:cryptoHash(request),requestBytes:Buffer.byteLength(request),response:raw,responseSha256:cryptoHash(raw),responseBytes:Buffer.byteLength(raw),responseComplete:true,responseCaptureTruncated:false};const c={input:f.EMAIL_ACTUAL_INPUT,modelCalls:[{role:'actor',caseId:'clean-control',messages,options,error:null,result:{response,provider:'ollama',model:'llama3.1:8b'}}]};assert.deepEqual(f.bindEmailWire(c,[row]),{actorCalls:1,judgeCalls:0});
  for(const change of [{role:'judge'},{responseComplete:false},{requestSha256:'0'.repeat(64)}])assert.throws(()=>f.bindEmailWire(c,[{...row,...change}]));const forged=structuredClone(c);forged.modelCalls[0].result.response='{"action":"refuse"}';assert.throws(()=>f.bindEmailWire(forged,[row]));
  const wrongContext=structuredClone(row),wrongRequest=JSON.parse(wrongContext.request);wrongRequest.options.num_ctx=4096;wrongContext.request=JSON.stringify(wrongRequest);wrongContext.requestSha256=cryptoHash(wrongContext.request);wrongContext.requestBytes=Buffer.byteLength(wrongContext.request);assert.throws(()=>f.bindEmailWire(c,[wrongContext]));
});


test('remaining two RAG cards use a closed model-free profile with mandatory seed proof',()=>{
 const f=require('./postgres/ipiEmailRenderedFixture'),a=require('node:assert/strict');
 a.deepEqual(f.ragContentConfiguration(f.RAG_INJECTION_PROFILE),{ids:['rag_injected_doc','rag_query_injection'],scope:f.RAG_INJECTION_SCOPE});
 for(const id of ['rag_injected_doc','rag_query_injection'])for(const kind of ['hint','solution'])a.doesNotThrow(()=>f.contentToggleRequest(kind,id));
 const proof={version:'ipi-rag-two-seed-v1',scope:'Catalog/provenance before learner fixtures; later lifecycle proof covers nonempty learner preservation',ids:['rag_injected_doc','rag_query_injection'],predecessorSha256:'d8b36f19c987a00038a475c17ef285c5d375ee92c93df05c259894378b31205d'};
 for(const key of ['freshDefaults','managedUpgrade','customPreserved','nullPreserved','secondRunNoop','unrelatedPreserved','restored'])proof[key]=true;
 f.assertRagSeedProof(proof);for(const key of Object.keys(proof)){const bad={...proof};delete bad[key];a.throws(()=>f.assertRagSeedProof(bad));}
 a.throws(()=>f.ragContentConfiguration('ipi-rag-arbitrary-content'));
});

test('RAG seed probe invokes full seed and restores scoped rows on success and failure',async()=>{
 const f=require('./postgres/ipiEmailRenderedFixture'),seed=require('../server/database/postgres/workshopPlatformSeed'),hint=require('../server/data/workshopHints'),solution=seed.solutionFixtures(),ids=['rag_injected_doc','rag_query_injection'],key='indirect_prompt_injection',clone=x=>JSON.parse(JSON.stringify(x));
 const original=seed.seedWorkshopPlatform;
 try{for(const failCustom of [false,true]){
  const baseline={exercises:[{workshop_key:key,is_visible:true}],objectives:ids.map(id=>({workshop_key:key,objective_id:id,hint_content:hint[key][id],solution_content:solution[key][id],updated_at:'2026-01-01T00:00:00Z'})).concat([{workshop_key:'sibling',objective_id:'untouched',hint_content:{title:'Other'},solution_content:null,updated_at:'2026-01-01T00:00:00Z'}]),provenance:[{workshop_key:key,objective_id:ids[0],field_name:'hint_content',provenance_state:'managed'}],revision:[{id:1,revision:7,updated_at:'2026-01-01T00:00:00Z'}]};
  let state=clone(baseline),calls=0,released=false,committed=false;
  seed.seedWorkshopPlatform=async(_pool,options)=>{calls++;if(failCustom&&calls===4)throw Error('controlled seed failure');if(calls<=2){for(const row of state.objectives.filter(r=>ids.includes(r.objective_id))){row.hint_content=clone((options?.hints||hint)[key][row.objective_id]);row.solution_content=clone((options?.solutions||solution)[key][row.objective_id]);}}};
  const query=async(sql,args=[])=>{
   if(sql.startsWith('SELECT to_jsonb(e)'))return {rows:clone(state.exercises).map(row=>({row}))};
   if(sql.startsWith('SELECT to_jsonb(o)'))return {rows:clone(state.objectives).map(row=>({row}))};
   if(sql.startsWith('SELECT to_jsonb(p)'))return {rows:clone(state.provenance).map(row=>({row}))};
   if(sql.startsWith('SELECT to_jsonb(r)'))return {rows:clone(state.revision).map(row=>({row}))};
   if(sql.startsWith('UPDATE workshop_platform.objectives SET hint_content')){const row=state.objectives.find(r=>r.workshop_key===args[0]&&r.objective_id===args[1]);row.hint_content=args[2]===undefined?null:JSON.parse(args[2]);row.solution_content=args[3]===undefined?null:JSON.parse(args[3]);if(args[4])row.updated_at=args[4];return {rowCount:1};}
   if(sql.startsWith('DELETE FROM workshop_platform.catalog_field_defaults')){state.provenance=[];return {rowCount:1};}
   if(sql.startsWith('INSERT INTO workshop_platform.catalog_field_defaults')){state.provenance=JSON.parse(args[0]);return {rowCount:1};}
   if(sql.startsWith('UPDATE workshop_platform.config_revision')){state.revision=[{id:args[0],revision:args[1],updated_at:args[2]}];return {rowCount:1};}
   if(sql==='COMMIT')committed=true;
   if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return {rows:[]};
   throw Error('Unexpected controlled SQL');
  };
  const pool={query,connect:async()=>({query,release(){released=true;}})};
  if(failCustom)await assert.rejects(f.qualifyRagSeed(pool),/controlled seed failure/);else f.assertRagSeedProof(await f.qualifyRagSeed(pool));
  assert.equal(calls,failCustom?4:5);assert.equal(released,true);assert.equal(committed,true);assert.deepEqual(state,baseline);
 }}finally{seed.seedWorkshopPlatform=original;}
});


test('Axios and fetch share a pre-dispatch transport ceiling under concurrent admission', async () => {
  let dispatches = 0, release;
  const pending = new Promise(resolve => { release = resolve; });
  const guard = installNetworkGuard({ mailpitApiUrl: 'http://127.0.0.1:8025', ollamaBaseUrl: 'http://127.0.0.1:11434',
    maxCalls: 5, maxTransportCalls: 2, fetchImpl: async () => { dispatches++; return new Response('{}'); } });
  const adapter = async config => { dispatches++; await pending; return { data: {}, status: 200, statusText: 'OK', headers: {}, config }; };
  try {
    await global.fetch('http://127.0.0.1:11434/api/tags');
    const requests = ['/api/tags', '/api/version', '/api/tags'].map(route => axios.get('http://127.0.0.1:11434' + route, { adapter }));
    const settled = Promise.allSettled(requests);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(dispatches, 2, 'only one concurrent Axios request may consume the remaining slot');
    assert.equal(guard.counters.transportCalls, 2);
    assert.equal(guard.counters.modelCalls, 0);
    release();
    const results = await settled;
    assert.equal(results.filter(row => row.status === 'fulfilled').length, 1);
    assert.equal(results.filter(row => row.status === 'rejected' && /Transport call bound/.test(row.reason.message)).length, 2);
    await assert.rejects(axios.post('http://127.0.0.1:11434/api/chat', { model: 'llama3.1:8b' }, { adapter }), /Transport call bound/);
    await assert.rejects(global.fetch('http://127.0.0.1:11434/api/tags'), /Transport call bound/);
    assert.equal(dispatches, 2); assert.equal(guard.counters.transportCalls, 2); assert.equal(guard.counters.modelCalls, 0);
  } finally { release(); guard.restore(); }
});
