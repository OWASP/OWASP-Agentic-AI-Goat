'use strict';

// Owned fixture composition used by the rendered IPI launcher. It composes
// the production PostgreSQL auth/session middleware and emailAgent router while
// adapting only SMTP/readback to a loopback Mailpit instance.
const express = require('express');
const session = require('express-session');
const fs = require('node:fs');
const path = require('node:path');

function assertLoopback(value, label) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) throw new Error(`${label} must not contain credentials or URL options`);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname)) {
    throw new Error(`${label} must be loopback HTTP`);
  }
  return url.origin;
}

function configureMailpit({ apiUrl, smtpHost = '127.0.0.1', smtpPort, hmacSecret }) {
  const api = assertLoopback(apiUrl, 'Mailpit API');
  if (!['127.0.0.1', 'localhost'].includes(smtpHost) || !Number.isInteger(Number(smtpPort))) {
    throw new Error('Mailpit SMTP must be loopback with an explicit port');
  }
  if (typeof hmacSecret !== 'string' || hmacSecret.length < 32) throw new Error('Private IPI Mailpit HMAC secret required');
  return { apiUrl: api, smtpHost, smtpPort: Number(smtpPort), hmacSecret };
}

function validateFixtureAdapter(adapter, pool, progress) {
  if (!adapter || adapter.pool !== pool || adapter.progress !== progress) throw new TypeError('Canonical adapter binding required');
  return true;
}

const REQUIRED_MODEL = 'llama3.1:8b';
const REQUIRED_MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
async function readModelDigest({ ollamaBaseUrl, fetchImpl = global.fetch } = {}) {
  const base = assertLoopback(ollamaBaseUrl, 'Ollama API');
  const response = await fetchImpl(`${base}/api/tags`, { redirect: 'error' });
  if (!response.ok) throw new Error('Model tags request failed');
  const bodyText = await response.text();
  if (Buffer.byteLength(bodyText) > 131072) throw new Error('Model tags response too large');
  let body;
  try { body = JSON.parse(bodyText); } catch { throw new Error('Model tags JSON invalid'); }
  const models = Array.isArray(body.models) ? body.models.filter(row => row?.name === REQUIRED_MODEL) : [];
  if (models.length !== 1 || models[0].digest !== REQUIRED_MODEL_DIGEST) throw new Error('Required model digest mismatch');
  return models[0].digest;
}
function installNetworkGuard({ mailpitApiUrl, ollamaBaseUrl, maxCalls = 80, maxTransportCalls = 240, fetchImpl = global.fetch }) {
  const axios = require('axios');
  const mailpit = assertLoopback(mailpitApiUrl, 'Mailpit API');
  const ollama = assertLoopback(ollamaBaseUrl, 'Ollama API');
  const counters = { modelCalls: 0, mailpitCalls: 0, tagsCalls: 0, transportCalls: 0 };
  const guarded = async (input, init) => {
    const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input?.url;
    const url = new URL(rawUrl);
    if (url.username || url.password || url.hash) throw new Error('Network URL credentials/options denied');
    const method = (init?.method || (typeof input === 'object' && input.method) || 'GET').toUpperCase();
    if (init?.redirect && init.redirect !== 'error') throw new Error('Redirects denied');
    const allowedModel = url.origin === ollama && (url.pathname === '/api/tags' || ['/api/chat', '/api/generate'].includes(url.pathname));
    const allowedMail = url.origin === mailpit && (url.pathname === '/api/v1/info' || url.pathname === '/api/v1/search'
      || /^\/api\/v1\/message\/[^/]+$/.test(url.pathname));
    if (url.search) {
      const keys = [...url.searchParams.keys()];
      const query = url.searchParams.get('query');
      const limit = url.searchParams.get('limit');
      if (!allowedMail || url.pathname !== '/api/v1/search' || keys.length !== 2 || !keys.includes('query') || !keys.includes('limit')
          || limit !== '50' || !query || Buffer.byteLength(query) > 512) throw new Error('Network query denied');
    } else if (url.pathname === '/api/v1/search') throw new Error('Network query denied');
    if (allowedMail && url.pathname !== '/api/v1/search' && url.search) {
      throw new Error('Network query denied');
    }
    if (!allowedModel && !allowedMail) throw new Error(`External network denied: ${url.origin}${url.pathname}`);
    if (url.pathname === '/api/tags' && method !== 'GET') throw new Error('Model tags must use GET');
    if (url.pathname !== '/api/tags' && allowedModel && method !== 'POST') throw new Error('Model generation must use POST');
    if (allowedMail && method !== 'GET') throw new Error('Mailpit readback must use GET');
    if (url.pathname === '/api/chat' || url.pathname === '/api/generate') {
      const raw = init?.body;
      if (typeof raw === 'string' && Buffer.byteLength(raw) > 65536) throw new Error('Model request too large');
      let request; try { request = typeof raw === 'string' ? JSON.parse(raw) : null; } catch { request = null; }
      if (!request || request.model !== REQUIRED_MODEL) throw new Error('Required model pin missing');
    }
    const generation = allowedModel && url.pathname !== '/api/tags';
    if (counters.transportCalls >= maxTransportCalls) throw new Error('Transport call bound exceeded');
    if (generation && counters.modelCalls >= maxCalls) throw new Error('Generation call bound exceeded');
    // Count admitted dispatches only; a rejected request never reaches fetch.
    counters.transportCalls += 1;
    if (generation) counters.modelCalls += 1;
    else if (allowedMail) counters.mailpitCalls += 1;
    else counters.tagsCalls += 1;
    const timeout = AbortSignal.timeout(120000);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    return fetchImpl(input, { ...(init || {}), redirect: 'error', signal });
  };
  const axiosInterceptor = axios.interceptors.request.use(config => {
    const url = new URL(config.url, config.baseURL);
    if (url.username || url.password || url.search || url.hash) throw new Error('External Axios URL credentials/options denied');
    const allowed = url.origin === ollama && ['/api/tags', '/api/version', '/api/chat', '/api/generate'].includes(url.pathname);
    if (!allowed) throw new Error(`External Axios network denied: ${url.origin}${url.pathname}`);
    const method = String(config.method || 'get').toUpperCase();
    const read = ['/api/tags', '/api/version'].includes(url.pathname);
    if ((read && method !== 'GET') || (!read && method !== 'POST')) throw new Error('Axios model method denied');
    config.maxRedirects = 0;
    config.timeout = Math.min(Number(config.timeout) > 0 ? Number(config.timeout) : 120000, 120000);
    if (!read) {
      const raw = typeof config.data === 'string' ? config.data : JSON.stringify(config.data || {});
      if (Buffer.byteLength(raw) > 65536) throw new Error('Axios model request too large');
      let request; try { request = JSON.parse(raw); } catch { request = null; }
      if (!request || request.model !== REQUIRED_MODEL) throw new Error('Axios required model pin missing');
    }
    if (counters.transportCalls >= maxTransportCalls) throw new Error('Transport call bound exceeded');
    if (!read && counters.modelCalls >= maxCalls) throw new Error('Generation call bound exceeded');
    counters.transportCalls += 1;
    if (!read) counters.modelCalls += 1;
    else counters.tagsCalls += 1;
    config.url = url.toString();
    return config;
  });
  global.fetch = guarded;
  return { counters, restore: () => { global.fetch = fetchImpl; axios.interceptors.request.eject(axiosInterceptor); } };
}

async function createIpiEmailApp({ identityRuntime, identityMigration, jwtSecret, mailpit }) {
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.IDENTITY_DATABASE_URL = identityRuntime.options.connectionString;
  process.env.IPI_EMAIL_PROVIDER = 'mailpit';
  process.env.IPI_MAIL_HMAC_SECRET = mailpit.hmacSecret;
  process.env.MAILPIT_API_URL = mailpit.apiUrl;
  process.env.MAILPIT_SMTP_HOST = mailpit.smtpHost;
  process.env.MAILPIT_SMTP_PORT = String(mailpit.smtpPort);
  // Install the guard before the production provider/router is required so its
  // default fetch dependency captures the guarded function.
  const network = installNetworkGuard({ mailpitApiUrl: mailpit.apiUrl, ollamaBaseUrl: process.env.OLLAMA_BASE_URL });
  const identityApi = require('../../server/database/postgres/identityRepository');
  await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
  const identity = identityApi.createIdentityRepository(identityRuntime);
  const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime);
  const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({ repository: identity, progress, jwtSecret });
  // The factory intentionally returns the pool-less adapter; the singleton
  // wiring attaches its runtime pool before middleware consumes it.
  adapter.pool = identityRuntime;
  validateFixtureAdapter(adapter, identityRuntime, progress);
  require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter = () => adapter;
  const app = express(); app.use(express.json());
  app.use(session({ secret: 'owned-ipi-rendered-fixture', resave: false, saveUninitialized: false, cookie: { secure: false, httpOnly: false } }));
  app.use(require('../../server/middleware/postgresSessionManager').createPostgresSessionManager(adapter).middleware());
  app.use('/api/auth', require('../../server/routes/auth'));
  // The assembled App gates the challenge through VisibilityProtectedRoute,
  // which requires the canonical PostgreSQL workshop visibility endpoint.
  app.use('/api/workshop', require('../../server/routes/workshop'));
  app.use('/api/email-agent', require('../../server/routes/emailAgent'));
  app.use('/api/workshop/config', require('../../server/routes/workshopConfig').createWorkshopConfigRouter());
  const provider = require('../../server/services/ipiEmailProvider').getIpiEmailProvider();
  return { app, identity, adapter, network, provider };
}

async function shutdownFixture({ fixture, server, identityRuntime, identityMigration, readiness, modelDigestBefore, modelDigestFn }) {
  const failures = [];
  try {
    const modelDigestAfter = await modelDigestFn();
    if (modelDigestAfter !== modelDigestBefore) throw new Error('Model digest changed during qualification');
    fs.writeFileSync(`${readiness}.final`, JSON.stringify({ counters: fixture.network.counters, modelDigestBefore, modelDigestAfter }) + '\n', { mode: 0o600 });
  } catch (error) { failures.push(error); }
  try { fixture.network.restore(); } catch (error) { failures.push(error); }
  try { await fixture.provider?.sender?.close?.(); } catch (error) { failures.push(error); }
  const cleanups = [
    () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())),
    () => identityRuntime.end(),
    () => identityMigration.end(),
  ];
  const results = await Promise.allSettled(cleanups.map(cleanup => Promise.resolve().then(cleanup)));
  for (const result of results) if (result.status === 'rejected') failures.push(result.reason);
  if (failures.length) throw new AggregateError(failures, 'IPI rendered fixture shutdown failed');
}

async function main() {
  const runtimeUrl = process.env.IPI_RENDERED_IDENTITY_RUNTIME_URL;
  const migrationUrl = process.env.IPI_RENDERED_IDENTITY_MIGRATION_URL;
  if (!runtimeUrl || !migrationUrl || !process.env.IPI_RENDERED_MAILPIT_API_URL) throw new Error('Complete owned fixture URLs required');
  const { Pool } = require('pg');
  const identityRuntime = new Pool({ connectionString: runtimeUrl, max: 4 });
  const identityMigration = new Pool({ connectionString: migrationUrl, max: 2 });
  const fixture = await createIpiEmailApp({ identityRuntime, identityMigration,
    jwtSecret: 'owned-ipi-rendered-fixture-secret-at-least-32-bytes',
    mailpit: configureMailpit({ apiUrl: process.env.IPI_RENDERED_MAILPIT_API_URL, smtpHost: '127.0.0.1', smtpPort: Number(process.env.MAILPIT_SMTP_PORT), hmacSecret: process.env.IPI_RENDERED_MAIL_HMAC_SECRET || process.env.IPI_MAIL_HMAC_SECRET }) });
  const passwordHash = await require('bcryptjs').hash(process.env.IPI_RENDERED_PASSWORD || 'OwnedRenderedFixture@123', 4);
  await fixture.identity.createUser({ username: process.env.IPI_RENDERED_USER || 'ipi-rendered-owner', email: 'ipi-rendered-owner@fixture.invalid', passwordHash });
  await fixture.identity.createUser({ username: process.env.IPI_RENDERED_SIBLING_USER || 'ipi-rendered-sibling', email: 'ipi-rendered-sibling@fixture.invalid', passwordHash });
  const build = path.resolve(__dirname, '../../client/build');
  if (!fs.existsSync(path.join(build, 'index.html'))) throw new Error('Copied production client build required');
  fixture.app.use(express.static(build)); fixture.app.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
  const server = await new Promise(resolve => { const value = fixture.app.listen(0, '127.0.0.1', () => resolve(value)); });
  const readiness = process.env.IPI_RENDERED_READINESS_FILE;
  if (!readiness) throw new Error('Owned readiness path required');
  const modelDigestBefore = await readModelDigest({ ollamaBaseUrl: process.env.OLLAMA_BASE_URL });
  fs.writeFileSync(readiness, JSON.stringify({ version: 1, pid: process.pid, port: server.address().port, appUrl: `http://127.0.0.1:${server.address().port}`, modelDigestBefore }) + '\n', { mode: 0o600 });
  const close = () => shutdownFixture({ fixture, server, identityRuntime, identityMigration, readiness, modelDigestBefore, modelDigestFn: () => readModelDigest({ ollamaBaseUrl: process.env.OLLAMA_BASE_URL }) });
  const shutdown = code => close().then(() => process.exit(code)).catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exit(1); });
  process.once('SIGTERM', () => shutdown(0));
  process.once('SIGINT', () => shutdown(130));
}

if (require.main === module) main().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
module.exports = { assertLoopback, configureMailpit, validateFixtureAdapter, installNetworkGuard, readModelDigest, shutdownFixture, REQUIRED_MODEL, REQUIRED_MODEL_DIGEST, createIpiEmailApp, main };

// Main-owned content qualification. Controlled projections are never earned credit.
const CONTENT_PROFILE='ipi-email-five-content',CONTENT_KEY='indirect_prompt_injection';
const CONTENT_IDS=Object.freeze(['email_create_inbox','email_send_attack','email_retrieve','email_trigger_injection','email_understand_defense']);
const RAG_PROFILE='ipi-rag-query-content',RAG_SCOPE='Controlled one RAG query completion projection; no earned credit';
const RAG_UPLOAD_PROFILE='ipi-rag-upload-clean-content',RAG_UPLOAD_SCOPE='Controlled RAG upload and clean document completion projections; no earned credit';
const RAG_INJECTION_PROFILE='ipi-rag-injection-two-content',RAG_INJECTION_SCOPE='Controlled RAG defense and injection completion projections; no earned credit';
function ragContentConfiguration(profile){if(profile===RAG_PROFILE)return {ids:['rag_query'],scope:RAG_SCOPE};if(profile===RAG_INJECTION_PROFILE)return {ids:['rag_injected_doc','rag_query_injection'],scope:RAG_INJECTION_SCOPE};if(profile===RAG_UPLOAD_PROFILE)return {ids:['rag_upload','rag_clean_doc'],scope:RAG_UPLOAD_SCOPE};throw new TypeError('Closed RAG content profile required');}
const RAG_DOCUMENT='Remote work is allowed on Fridays.',RAG_QUESTION='When is remote work allowed?',RAG_ANSWER='Remote work is allowed on Fridays.';
const CONTENT_LIMITS=Object.freeze({browser:1000,api:80});
const CONTENT_SCOPE='Controlled five email completion projections only; no earned credit';
function contentCard({label,hint=true,solution=true}) {
  const rows=[...document.querySelectorAll('.obj-name')].filter(e=>e.textContent===label);
  if(rows.length!==1)return false;
  const card=rows[0].closest('.obj-content'),buttons=[...card.querySelectorAll('button')];
  return buttons.filter(e=>e.textContent.trim()==='Hint').length===Number(hint)&&buttons.filter(e=>e.textContent.trim()==='Solution').length===Number(solution)&&[...card.parentElement.querySelectorAll('.status-badge')].some(e=>e.textContent==='COMPLETED');
}
function contentSolution(value) {
  const headings=[...document.querySelectorAll('h3')].filter(e=>e.textContent==='Solution: '+value.title);
  if(headings.length!==1)return false;
  const modal=headings[0].parentElement.parentElement,norm=s=>String(s||'').replace(/\s+/g,' ').trim(),text=norm(modal.textContent);
  const parts=[value.title,value.difficulty,value.approach,...(value.tips||[]),...(value.examples||[]).flatMap(e=>[e.prompt,e.explanation])];
  return [...modal.querySelectorAll('button')].some(e=>e.textContent.trim()==='Close')&&parts.filter(x=>typeof x==='string'&&x.length).every(x=>text.includes(norm(x)));
}
function contentToggleRequest(kind,id) {
  if(!['hint','solution'].includes(kind)||id!==null&&![...CONTENT_IDS,'rag_query','rag_upload','rag_clean_doc','rag_injected_doc','rag_query_injection'].includes(id))throw new TypeError('Closed IPI gate required');
  if(!id&&kind==='solution')return {method:'PATCH',path:'/api/admin/exercises/'+CONTENT_KEY+'/solutions',field:'enabled'};
  return {method:'POST',path:id?(kind==='hint'?'/api/admin/workshops/'+CONTENT_KEY+'/hints/'+id+'/toggle':'/api/admin/ipi-workshop/solutions/toggle'):'/api/admin/challenges/hints/toggle',field:id?'enabled':'showHints'};
}
function contentRequestAllowed(url,origin,count) {try{return Number.isInteger(count)&&count>0&&count<=CONTENT_LIMITS.browser&&(new URL(url).origin===origin||/^(data:|blob:|about:)/.test(url));}catch{return false;}}
function assertContentReceipt(r) {
  const a=require('node:assert/strict');a.equal(r.profile,CONTENT_PROFILE);a.equal(r.status,'passed');a.equal(r.installedWrites,false);a.equal(r.actualModelProof,false);a.equal(r.controlledProjectionCount,5);a.equal(r.completionScope,CONTENT_SCOPE);
  a.equal(r.controlledJudgeCalls,2);a.equal(r.controlledSessionOwners,2);for(const key of ['sessionPreEffectDenied','sessionJudgeCommitDenied','sessionPostCommitPublicationDenied','sessionPriorCommitPreserved','sessionSiblingPreserved'])a.equal(r[key],true);
  for(const key of ['modelCalls','mailCalls','genuineCredit'])a.equal(r[key],0);
  a.deepEqual(r.cases.map(x=>x.id),CONTENT_IDS);for(const row of r.cases)for(const key of ['learnerContent','adminPreview','independentGates','completedProjection'])a.equal(row[key],true);
  for(const key of ['dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'])a.equal(r[key],true);
  for(const key of ['browser','api'])a(Number.isInteger(r.requests[key])&&r.requests[key]>=0&&r.requests[key]<=CONTENT_LIMITS[key]);a(r.requests.browser>0);
  a.deepEqual(r.cleanup.map(x=>x.name),['restore','browser','mail','rag','routes','server','pools']);a(r.cleanup.every(x=>x.status==='fulfilled'));a.deepEqual(r.cleanupFailures,[]);
}
function controlledRagDecision(counts,messages){const a=require('node:assert/strict');a(Number.isInteger(counts.controlledActorCalls)&&counts.controlledActorCalls>=0&&counts.controlledActorCalls<2);a.equal(messages.length,2);a.equal(messages[0].role,'system');a.equal(messages[1].role,'user');const input=messages[1].content;a(input.startsWith('Question: '+RAG_QUESTION+'\n'));const answer=counts.controlledActorCalls===1;if(answer)a(input.includes(RAG_DOCUMENT));counts.controlledActorCalls++;return {provider:'controlled-rag-ui',model:'controlled-no-credit',response:JSON.stringify(answer?{action:'answer',answer:RAG_ANSWER}:{action:'search_document',query:RAG_QUESTION,topK:1})};}
function assertRagContentReceipt(r){const a=require('node:assert/strict'),config=ragContentConfiguration(r.profile);if(r.profile===RAG_INJECTION_PROFILE)assertRagSeedProof(r.seedProof);a.equal(r.status,'passed');a.equal(r.completionScope,config.scope);a.equal(r.controlledProjectionCount,config.ids.length);a.equal(r.controlledActorCalls,2);a.equal(r.controlledJudgeCalls,5);a.equal(r.controlledEmbeddingCalls,3);for(const k of ['modelCalls','mailCalls','genuineCredit'])a.equal(r[k],0);for(const k of ['installedWrites','actualModelProof'])a.equal(r[k],false);for(const k of ['uploadQueryPlumbing','sessionDenied','resetRetired','resetReplayExact','timePreserved','nonemptySiblingPreserved','dashboardParity','configurationRestored','projectionRestored','siblingPreserved','immutableEvidencePreserved'])a.equal(r[k],true);a.deepEqual(r.cases,config.ids.map(id=>({id,learnerContent:true,adminPreview:true,independentGates:true,completedProjection:true})));for(const key of ['browser','api'])a(Number.isInteger(r.requests[key])&&r.requests[key]>=0&&r.requests[key]<=CONTENT_LIMITS[key]);a(r.requests.browser>0);a.deepEqual(r.cleanup.map(x=>x.name),['restore','browser','mail','rag','routes','server','pools']);a(r.cleanup.every(x=>x.status==='fulfilled'));a.deepEqual(r.cleanupFailures,[]);}
function controlledSessionVerdict(input) {return {family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:input.rubric.objectiveId,rubricVersion:input.rubric.version,mode:input.rubric.mode,runId:input.execution.runId,evidenceDigest:require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(input).evidenceDigest,verdict:'fail',criteria:input.rubric.criteria.map(c=>({id:c.id,satisfied:false,evidenceRefs:[]})),explanation:'Controlled session boundary; no earned credit.',provider:'mock',model:'controlled-session',usage:null};}
function installContentSessionProbe({pool,progress,adapter}) {
  const completion=require('../../server/services/objectiveCompletionService');
  const coordinator=require('../../server/agent-runtime/runCoordinator');
  const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool);
  const previousService=completion.getObjectiveCompletionService,previousCoordinator=coordinator.createRunCoordinator;
  let selected=null,judgeCalls=0;
  const controlledJudge=async input=>{
    if(!selected||String(input.execution.ownerId)!==String(selected.owner.id))throw Error('Unselected controlled Judge owner');
    judgeCalls++;selected.enter();if(selected.mode==='pending')await selected.held;
    return controlledSessionVerdict(input);
  };
  const service=completion.createObjectiveCompletionService({progress,receipts:{...receipts,recordVerdict:async input=>{const value=await receipts.recordVerdict(input);if(selected?.mode==='postcommit'&&Number(input.userId)===Number(selected.owner.id)){selected.committed=value;await adapter.logout(selected.owner.token);}return value;}},judge:controlledJudge});
  const accessor=()=>service;
  const factory=options=>{const real=previousCoordinator(options);if(options.family!=='IndirectEmail')return real;return {...real,run(...args){const pending=real.run(...args);if(selected&&String(args[0])===String(selected.owner.id)&&++selected.runs===2)selected.queued();return pending;}};};
  completion.getObjectiveCompletionService=accessor;coordinator.createRunCoordinator=factory;
  return {select(owner,mode){let enter,release,queued;const entered=new Promise(r=>enter=r),held=new Promise(r=>release=r),queueEntered=new Promise(r=>queued=r);selected={owner,mode,enter,held,release,queued,runs:0,committed:null};return {entered,queueEntered,release,get committed(){return selected.committed;}};},calls:()=>judgeCalls,restore(){selected?.release();if(completion.getObjectiveCompletionService===accessor)completion.getObjectiveCompletionService=previousService;if(coordinator.createRunCoordinator===factory)coordinator.createRunCoordinator=previousCoordinator;}};
}

function assertRagSeedProof(proof){const a=require('node:assert/strict');a.equal(proof?.version,'ipi-rag-two-seed-v1');a.equal(proof.scope,'Catalog/provenance before learner fixtures; later lifecycle proof covers nonempty learner preservation');a.deepEqual(proof.ids,['rag_injected_doc','rag_query_injection']);for(const key of ['freshDefaults','managedUpgrade','customPreserved','nullPreserved','secondRunNoop','unrelatedPreserved','restored'])a.equal(proof[key],true);a.equal(proof.predecessorSha256,'d8b36f19c987a00038a475c17ef285c5d375ee92c93df05c259894378b31205d');}
async function qualifyRagSeed(migration){
 const a=require('node:assert/strict'),crypto=require('node:crypto'),vm=require('node:vm'),{createRequire}=require('node:module');
 const ids=['rag_injected_doc','rag_query_injection'],key='indirect_prompt_injection',sha=b=>crypto.createHash('sha256').update(b).digest('hex');
 const archivePath=path.resolve(__dirname,'../../tests/release-inputs/ipi-defense-content-predecessors-v1.json'),raw=fs.readFileSync(archivePath);a.equal(sha(raw),'d8b36f19c987a00038a475c17ef285c5d375ee92c93df05c259894378b31205d');
 const archive=JSON.parse(raw),previous=file=>{const row=archive.files[file],bytes=Buffer.from(row.base64,'base64');a.equal(sha(bytes),row.sha256);const context={module:{exports:{}},require:createRequire(path.resolve(__dirname,'../..',file))};vm.runInNewContext(bytes.toString(),context,{timeout:1000});return JSON.parse(JSON.stringify(context.module.exports));};
 const oldHints=previous('server/data/workshopHints.js'),oldSolutions=previous('server/data/indirectPromptInjectionSolutions.js');
 const seed=require('../../server/database/postgres/workshopPlatformSeed'),hints=require('../../server/data/workshopHints'),solutions=seed.solutionFixtures();
 const copy=x=>JSON.parse(JSON.stringify(x));const snapshot=async()=>({exercises:(await migration.query('SELECT to_jsonb(e) row FROM workshop_platform.exercises e ORDER BY workshop_key')).rows.map(x=>x.row),objectives:(await migration.query('SELECT to_jsonb(o) row FROM workshop_platform.objectives o ORDER BY workshop_key,objective_id')).rows.map(x=>x.row),provenance:(await migration.query('SELECT to_jsonb(p) row FROM workshop_platform.catalog_field_defaults p ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows.map(x=>x.row),revision:(await migration.query('SELECT to_jsonb(r) row FROM workshop_platform.config_revision r ORDER BY id')).rows.map(x=>x.row)});
 const selected=row=>row.workshop_key===key&&ids.includes(row.objective_id),unrelated=s=>({exercises:s.exercises,objectives:s.objectives.filter(x=>!selected(x)),provenance:s.provenance.filter(x=>!selected(x))});
 const baseline=await snapshot(),proof={version:'ipi-rag-two-seed-v1',scope:'Catalog/provenance before learner fixtures; later lifecycle proof covers nonempty learner preservation',ids,predecessorSha256:sha(raw)};
 const verifyContent=(snap,expectedHints,expectedSolutions)=>{for(const id of ids){const row=snap.objectives.find(x=>x.workshop_key===key&&x.objective_id===id);a.deepEqual(row.hint_content,expectedHints[key][id]);a.deepEqual(row.solution_content,expectedSolutions[key][id]);}};
 verifyContent(baseline,hints,solutions);proof.freshDefaults=true;
 try{
  const priorHints=copy(hints),priorSolutions=copy(solutions);for(const id of ids){priorHints[key][id]=oldHints[key][id];priorSolutions[key][id]=oldSolutions[id];}
  await seed.seedWorkshopPlatform(migration,{hints:priorHints,solutions:priorSolutions});verifyContent(await snapshot(),priorHints,priorSolutions);
  await seed.seedWorkshopPlatform(migration);verifyContent(await snapshot(),hints,solutions);proof.managedUpgrade=true;
  const beforeNoop=await snapshot();await seed.seedWorkshopPlatform(migration);a.deepEqual(await snapshot(),beforeNoop);proof.secondRunNoop=true;
  const customHint={title:'Owned instructor hint',hints:['Owned instructor text']},customSolution={title:'Owned instructor solution',approach:'Owned instructor approach'};
  for(const id of ids)await migration.query('UPDATE workshop_platform.objectives SET hint_content=$3::jsonb,solution_content=$4::jsonb WHERE workshop_key=$1 AND objective_id=$2',[key,id,JSON.stringify(customHint),JSON.stringify(customSolution)]);
  await seed.seedWorkshopPlatform(migration);for(const row of (await snapshot()).objectives.filter(selected)){a.deepEqual(row.hint_content,customHint);a.deepEqual(row.solution_content,customSolution);}proof.customPreserved=true;
  for(const id of ids)await migration.query('UPDATE workshop_platform.objectives SET hint_content=NULL,solution_content=NULL WHERE workshop_key=$1 AND objective_id=$2',[key,id]);
  await seed.seedWorkshopPlatform(migration);const nullState=await snapshot();for(const row of nullState.objectives.filter(selected)){a.equal(row.hint_content,null);a.equal(row.solution_content,null);}proof.nullPreserved=true;
  a.deepEqual(unrelated(nullState),unrelated(baseline));proof.unrelatedPreserved=true;
 }finally{
  // Restore only this empty-store qualification's two rows and their provenance;
  // learner state is not yet created and no instructor installation is targeted.
  const client=await migration.connect();try{await client.query('BEGIN');
   for(const row of baseline.objectives.filter(selected))await client.query('UPDATE workshop_platform.objectives SET hint_content=$3::jsonb,solution_content=$4::jsonb,updated_at=$5 WHERE workshop_key=$1 AND objective_id=$2',[key,row.objective_id,JSON.stringify(row.hint_content),JSON.stringify(row.solution_content),row.updated_at]);
   await client.query('DELETE FROM workshop_platform.catalog_field_defaults WHERE workshop_key=$1 AND objective_id=ANY($2::text[])',[key,ids]);
   await client.query('INSERT INTO workshop_platform.catalog_field_defaults SELECT * FROM jsonb_populate_recordset(NULL::workshop_platform.catalog_field_defaults,$1::jsonb)',[JSON.stringify(baseline.provenance.filter(selected))]);
   for(const row of baseline.revision)await client.query('UPDATE workshop_platform.config_revision SET revision=$2,updated_at=$3 WHERE id=$1',[row.id,row.revision,row.updated_at]);
   await client.query('COMMIT');
  }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
  a.deepEqual(await snapshot(),baseline);proof.restored=true;
 }
 assertRagSeedProof(proof);return proof;
}

async function runContent({owned,runtime,ports,source,profile=CONTENT_PROFILE}) {
  const ragOnly=[RAG_PROFILE,RAG_UPLOAD_PROFILE,RAG_INJECTION_PROFILE].includes(profile);if(!ragOnly&&profile!=='ipi-email-five-content')throw Error('Closed IPI profile');
  const CONTENT_PROFILE=profile,CONTENT_IDS=ragOnly?ragContentConfiguration(profile).ids:module.exports.CONTENT_IDS,CONTENT_SCOPE=ragOnly?ragContentConfiguration(profile).scope:module.exports.CONTENT_SCOPE;
  const a=require('node:assert/strict'),crypto=require('node:crypto');
  const {saveBounded}=require('../fixtures/boundedJsonArtifact'),{bounded,settleOwnership,launchOwnedAnalyticsBrowser}=require('../fixtures/secureshopAnalyticsBrowserOwner');
  const shared=require('../fixtures/finflowTraversalContentBrowser'),dialogs=require('../fixtures/mcpAuditContentBrowser');
  const result={profile:CONTENT_PROFILE,status:'preparing',installedWrites:false,actualModelProof:false,modelCalls:0,mailCalls:0,genuineCredit:0,controlledProjectionCount:0,completionScope:CONTENT_SCOPE,cases:[],requests:{browser:0,api:0},cleanupFailures:[]};
  const save=()=>saveBounded(path.join(owned.evidence,'result.json'),ragOnly?JSON.parse(JSON.stringify(result)):result),started=Date.now();
  const step=async(name,fn)=>{result.stage=name;save();const v=await bounded(Promise.resolve().then(fn),Math.max(1,540000-(Date.now()-started)),name);save();return v;};
  let pg,pool,migration,stores,owner,sibling,original,beforeOwner,beforeSibling,beforeImmutable,browser,server,mounted,ragRoute,mail,restoreProvider,restoreAI,sessionProbe,primary,restoreCompletion,ragBeforeReset,ragSiblingDocument;const pools=[];
  const config=async()=>({exercise:(await pool.query('SELECT is_visible,show_hints,show_solutions FROM workshop_platform.exercises WHERE workshop_key=$1',[CONTENT_KEY])).rows[0],objectives:(await pool.query('SELECT objective_id,label,is_enabled,hint_enabled,solution_enabled,hint_content,solution_content FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id',[CONTENT_KEY])).rows});
  const state=async id=>({completions:(await pool.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id',[id])).rows,time:(await pool.query('SELECT * FROM workshop_platform.time_tracking WHERE user_id=$1 ORDER BY id',[id])).rows,email:(await pool.query('SELECT * FROM identity.email_agent_progress WHERE user_key=$1 ORDER BY objective_number',[String(id)])).rows});
  const immutable=async()=>({judgments:(await pool.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::bigint[]) ORDER BY evaluation_id',[[owner.id,sibling.id]])).rows,packets:(await pool.query('SELECT * FROM workshop_platform.grade_packets WHERE user_id=ANY($1::bigint[]) ORDER BY evaluation_id',[[owner.id,sibling.id]])).rows});
  try {
    Object.assign(process.env,{IPI_EMAIL_PROVIDER:'mailpit',MAILPIT_SMTP_HOST:'127.0.0.1',MAILPIT_SMTP_PORT:'9',MAILPIT_API_URL:'http://127.0.0.1:9',IPI_MAIL_HMAC_SECRET:crypto.randomBytes(32).toString('hex')});
    const ai=require('../../server/services/multiProviderAIService'),savedAI={};for(const key of ['chatWithMessages','generateResponse','chatWithTools','getActiveProviderInfo','isAvailable','verifyProviderConnectionLite']){savedAI[key]=ai[key];ai[key]=key==='getActiveProviderInfo'?()=>({provider:'mock',providerName:'Content only',model:'unavailable'}):key==='isAvailable'?async()=>false:key==='verifyProviderConnectionLite'?async()=>({available:false,configured:false}):async()=>{result.modelCalls++;throw Error('Content inference denied');};}restoreAI=()=>Object.assign(ai,savedAI);if(ragOnly){result.controlledActorCalls=0;result.controlledJudgeCalls=0;result.controlledEmbeddingCalls=0;ai.chatWithMessages=messages=>controlledRagDecision(result,messages);}
    const providerModule=require('../../server/services/ipiEmailProvider'),originalProvider=providerModule.getIpiEmailProvider,realProvider=originalProvider();mail=realProvider.sender;
    const denyMail=async()=>{result.mailCalls++;throw Error('Content mail operation denied');};
    providerModule.getIpiEmailProvider=()=>({...realProvider,sender:{...mail,initialize:async()=>false,reinitialize:async()=>false,sendEmail:denyMail},inbox:{...realProvider.inbox,fetchEmails:denyMail,fetchEmail:denyMail}});restoreProvider=()=>{providerModule.getIpiEmailProvider=originalProvider;};
    await step('initialize',async()=>{pg=require('../../server/database/postgres');for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'])pools.push(pg.createPool(process.env,key));[pool,migration]=pools;await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(pool,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);});
    const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(pool),adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();stores=await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    async function user(){const u=await users.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(crypto.randomUUID(),4)});return {...u,token:(await adapter.createSession(await users.findCredentialById(u.id),{})).token};}
    if(profile===RAG_INJECTION_PROFILE)await step('rag-seed-preservation',async()=>{result.seedProof=await qualifyRagSeed(migration);});
    owner=await user();sibling=await user();await migration.query('INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,$2,$3)',[sibling.id,CONTENT_KEY,CONTENT_IDS[0]]);
    if(ragOnly)await migration.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,$2,now()-interval '17 seconds',now(),17)",[sibling.id,CONTENT_KEY]);
    original=await config();beforeOwner=await state(owner.id);beforeSibling=await state(sibling.id);beforeImmutable=await immutable();a.deepEqual(beforeImmutable,{judgments:[],packets:[]});
    for(const id of CONTENT_IDS){const row=original.objectives.find(x=>x.objective_id===id);a(row&&row.hint_content?.hints?.length&&row.solution_content?.title);await stores.config.setObjectiveVisibility(CONTENT_KEY,id,true,owner.id);await stores.config.setObjectiveHintVisibility(CONTENT_KEY,id,true,owner.id);await stores.config.setObjectiveSolutionVisibility(CONTENT_KEY,id,true,owner.id);if(!ragOnly)await migration.query('INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,$2,$3)',[owner.id,CONTENT_KEY,id]);}
    await stores.config.setExerciseVisibility(CONTENT_KEY,true,owner.id);await stores.config.setMasterHintVisibility(CONTENT_KEY,true,owner.id);await stores.config.setMasterSolutionVisibility(CONTENT_KEY,true,owner.id);
    await migration.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,$2,now()-interval '60 seconds',now(),60)",[owner.id,CONTENT_KEY]);result.controlledProjectionCount=CONTENT_IDS.length;
    const rag=require('../../server/services/workshopRagComposition').createWorkshopRagComposition({pool,identityAdapter:adapter,embedder:ragOnly?{embed:async()=>{result.controlledEmbeddingCalls++;a(result.controlledEmbeddingCalls<=4);return {embeddingDimension:384,embedding:Array.from({length:384},(_,n)=>n===0?1:0)};},getRuntimeFingerprint:()=>({fingerprint:'a'.repeat(64)})}:{embed:async()=>{throw Error('Content embedding denied');},getRuntimeFingerprint:()=>null},assertReady:p=>require('../../server/services/workshopRagReadiness').assertWorkshopRagReadiness({pool:p,expectedDatabase:new URL(process.env.IDENTITY_DATABASE_URL).pathname.slice(1)})});await rag.initialize();if(ragOnly){const completion=require('../../server/services/objectiveCompletionService'),previous=completion.getObjectiveCompletionService,receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool);const service=completion.createObjectiveCompletionService({progress:stores.progress,receipts,judge:async input=>{a(['rag_upload','rag_clean_doc','rag_query'].includes(input.rubric.objectiveId));result.controlledJudgeCalls++;a(result.controlledJudgeCalls<=5);return controlledSessionVerdict(input);}});completion.getObjectiveCompletionService=()=>service;restoreCompletion=()=>{completion.getObjectiveCompletionService=previous;};}ragRoute=require('../../server/routes/ragInjection');ragRoute.configureDurableRag(rag);
    if(!ragOnly)sessionProbe=installContentSessionProbe({pool,progress:stores.progress,adapter});
    const app=express();app.use(express.json({limit:'128kb'}));mounted=await require('../fixtures/legacyFileSsiFullAppParity').mountLegacyParityRoutes({app,adapter,pool,migration,progress:stores.progress,config:stores.config,identity:users});app.use('/api/workshop/rag-injection',ragRoute);app.use('/api/email-agent',require('../../server/routes/emailAgent'));app.use('/api/solutions',require('../../server/routes/solutions'));app.use('/api/hints',require('../../server/routes/hints'));app.use('/api',(_q,res)=>res.sendStatus(404));app.use(express.static(path.join(source,'client/build')));app.get('/{*path}',(_q,res)=>res.sendFile(path.join(source,'client/build/index.html')));
    server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);const origin='http://127.0.0.1:'+server.address().port;browser=await launchOwnedAnalyticsBrowser(runtime,'browser');
    async function page(token){const context=await browser.createBrowserContext(),p=await context.newPage();p.setDefaultTimeout(15000);await p.setCacheEnabled(false);await p.evaluateOnNewDocument(t=>localStorage.setItem('token',t),token);await p.setRequestInterception(true);p.on('request',q=>{const allowed=contentRequestAllowed(q.url(),origin,++result.requests.browser);if(!allowed)result.requestDenied=true;(allowed?q.continue():q.abort()).catch(()=>{});});return p;}
    const learner=await page(owner.token),admin=await page(mounted.adminToken);
    const foreground=async p=>{await p.bringToFront();await p.waitForFunction(()=>document.visibilityState==='visible');};
    const api=async(url)=>{a(++result.requests.api<=CONTENT_LIMITS.api);return learner.evaluate(async url=>{const q=await fetch(url,{headers:{Authorization:'Bearer '+localStorage.getItem('token')}});return {status:q.status,body:await q.json()};},url);};
    const hintPath=id=>'/api/hints/'+CONTENT_KEY+'/'+id,solutionPath=id=>'/api/solutions/indirect-pi/'+id;
    const pending=learner.waitForResponse(q=>new URL(q.url()).pathname===(ragOnly?'/api/workshop/rag-injection/progress':'/api/email-agent/progress')&&q.status()===200);pending.catch(()=>{});await learner.goto(origin+'/vulnerabilities/indirect-prompt-injection',{waitUntil:'domcontentloaded'});const progress=await(await pending).json();if(!ragOnly){a.equal(progress.completedCount,5);for(let n=1;n<=5;n++)a.equal(progress.progress[n].completed,true);}
    if(!ragOnly){await learner.waitForSelector('[data-scenario-tab="email"]',{visible:true});await learner.click('[data-scenario-tab="email"]');}else await step('rag-upload-query',async()=>{
      const documentFile=path.join(runtime,'rag-query-controlled.txt');fs.writeFileSync(documentFile,RAG_DOCUMENT,{mode:0o600,flag:'wx'});
      await learner.waitForSelector('input[type="file"]');const upload=learner.waitForResponse(q=>new URL(q.url()).pathname==='/api/workshop/rag-injection/upload'&&q.request().method()==='POST');upload.catch(()=>{});await(await learner.$('input[type="file"]')).uploadFile(documentFile);await learner.evaluate(()=>{const b=[...document.querySelectorAll('button')].find(e=>e.textContent.trim()==='Upload');if(!b||b.disabled)throw Error('Upload unavailable');b.click();});const u=await upload;a.equal(u.status(),200);const uploaded=await u.json();a(uploaded.chunks_stored>0);a(uploaded.judgments.every(x=>x.verdict==='fail'));result.upload={sessionId:uploaded.session_id,receipt:uploaded.document_receipt};
      const label=original.objectives.find(x=>x.objective_id==='rag_query').label;await learner.evaluate(label=>{const row=[...document.querySelectorAll('.obj-name')].find(e=>e.textContent===label);if(!row)throw Error('RAG query objective missing');row.click();},label);
      const input='input[placeholder="What is the remote work policy?"]';await learner.waitForFunction(selector=>{const e=document.querySelector(selector);return e&&!e.disabled;},{},input);await learner.type(input,RAG_QUESTION);
      const queried=learner.waitForResponse(q=>new URL(q.url()).pathname==='/api/workshop/rag-injection/query'&&q.request().method()==='POST');queried.catch(()=>{});await learner.evaluate(()=>{const button=[...document.querySelectorAll('button')].find(e=>e.textContent.trim()==='Ask');if(!button||button.disabled)throw Error('RAG Ask unavailable');button.click();});const qr=await queried;a.equal(qr.status(),200);const request=JSON.parse(qr.request().postData());a.deepEqual(request,{session_id:uploaded.session_id,question:RAG_QUESTION,active_objective:'rag_query'});const answer=await qr.json();a.equal(answer.answer,RAG_ANSWER);a.equal(answer.retrieved_chunks.length,1);a.equal(answer.retrieved_chunks[0].text,RAG_DOCUMENT);a.deepEqual(answer.completedObjectiveIds,[]);a.equal(answer.judgments.length,1);a.equal(answer.judgments[0].verdict,'fail');await learner.waitForFunction(text=>document.body.textContent.includes(text),{},RAG_ANSWER);
      result.query={request,response:answer};a.equal((await state(owner.id)).completions.length,0);
      const form=new FormData();form.append('document',new Blob([RAG_DOCUMENT],{type:'text/plain'}),'sibling.txt');result.requests.api++;const su=await fetch(origin+'/api/workshop/rag-injection/upload',{method:'POST',headers:{Authorization:'Bearer '+sibling.token},body:form});a.equal(su.status,200);const siblingUpload=await su.json();ragSiblingDocument=siblingUpload.session_id;
      result.uploadQueryPlumbing=true;result.controlledScope='Controlled embeddings and controlled-rag-ui decisions with fail-only canonical Judge; no actual inference or earned credit';
      beforeImmutable=await immutable();a.equal(beforeImmutable.judgments.length,5);a(beforeImmutable.judgments.every(x=>x.verdict==='fail'&&x.disposition==='not_pass'));a.equal(beforeImmutable.packets.length,5);
      const queryJudgment=beforeImmutable.judgments.find(x=>Number(x.user_id)===Number(owner.id)&&x.objective_id==='rag_query');a(queryJudgment);const effects=(await pool.query('SELECT to_jsonb(e) row FROM graph_runtime.effects e WHERE run_id=$1 ORDER BY effect_key',[queryJudgment.run_id])).rows.map(x=>x.row);a(effects.some(x=>x.status==='completed'&&x.owner_key===JSON.stringify(['RAG',String(owner.id)])&&x.effect_key.includes('rag_search:')));result.query.effects=effects;result.query.judgment=queryJudgment;
      for(const id of CONTENT_IDS)await stores.progress.syncObjectiveComplete(owner.id,CONTENT_KEY,id);await learner.reload({waitUntil:'domcontentloaded'});

    });await admin.goto(origin+'/admin/exercises',{waitUntil:'domcontentloaded'});
    const card=async expected=>{await foreground(learner);await learner.waitForFunction(contentCard,{},expected);};
    async function panel(id){await foreground(admin);await admin.waitForSelector('[data-exercise-key="'+CONTENT_KEY+'"]');await admin.evaluate(shared.closePreviewOnly);await admin.waitForFunction(shared.previewRetired);if(await admin.evaluate(shared.objectivePanelPresent,id))return;await admin.$eval('[data-exercise-key="'+CONTENT_KEY+'"]',e=>[...e.querySelectorAll('button')].find(b=>b.textContent.includes('Manage Objectives')).click());await admin.waitForSelector('[data-objective-id="'+id+'"]');}
    async function toggle(kind,id,enabled){await foreground(admin);if(id)await panel(id);else{await admin.evaluate(dialogs.closeAdminDialogs);await admin.waitForFunction(dialogs.adminDialogsClosed);}const request=contentToggleRequest(kind,id);if(!id){result.stage='master-'+kind+'-'+(enabled?'enable':'disable')+'-response';save();}const pending=admin.waitForResponse(q=>new URL(q.url()).pathname===request.path&&q.request().method()===request.method);pending.catch(()=>{});if(id)await admin.click('[data-objective-id="'+id+'"] > div:nth-child('+(kind==='hint'?3:4)+') > div');else{const selector='[data-exercise-key="'+CONTENT_KEY+'"] [data-control="'+kind+'s"]';await dialogs.waitMasterReady(admin,selector);await admin.$eval(selector,e=>e.click());}const response=await pending;a.equal(response.status(),200);a.equal(JSON.parse(response.request().postData())[request.field],enabled);}
    for(const id of CONTENT_IDS)await step('content:'+id,async()=>{const row=original.objectives.find(x=>x.objective_id===id);await card({label:row.label});const h=await api(hintPath(id)),s=await api(solutionPath(id));a.equal(h.status,200);a.equal(s.status,200);a.deepEqual(h.body.hint,row.hint_content);a.deepEqual(s.body.solution,row.solution_content);
      const clickContent=kind=>learner.evaluate(({label,kind})=>{const e=[...document.querySelectorAll('.obj-name')].filter(e=>e.textContent===label);if(e.length!==1)throw Error('Unique email card required');const b=[...e[0].closest('.obj-content').querySelectorAll('button')].filter(e=>e.textContent.trim()===kind);if(b.length!==1)throw Error('Unique help control required');b[0].click();},{label:row.label,kind});
      await clickContent('Hint');for(let count=1;count<=row.hint_content.hints.length;count++){await learner.waitForFunction(shared.hintModalStep,{},{content:row.hint_content,count});if(count<row.hint_content.hints.length)a.equal(await learner.evaluate(shared.hintModalStep,{content:row.hint_content,count,advance:true}),true);}await learner.click('[role="dialog"][data-help-kind="hint"] button[aria-label="Close hint"]');await learner.waitForSelector('[role="dialog"][data-help-kind="hint"]',{hidden:true});
      await clickContent('Solution');await learner.waitForFunction(contentSolution,{},row.solution_content);await learner.evaluate(title=>{const h=[...document.querySelectorAll('h3')].find(e=>e.textContent==='Solution: '+title);[...h.parentElement.querySelectorAll('button')].find(e=>e.textContent.trim()==='Close').click();},row.solution_content.title);
      await panel(id);await admin.waitForFunction(({id,label})=>[...document.querySelector('[data-objective-id="'+id+'"]')?.querySelectorAll('[title]')||[]].some(e=>e.title===label),{},{id,label:row.label});await admin.click('[data-objective-id="'+id+'"] button[title="Preview Solution"]');await admin.waitForFunction(dialogs.focusedModalMatches,{},{kind:'Preview',value:row.solution_content});
      for(const kind of ['hint','solution']){await toggle(kind,id,false);await card({label:row.label,hint:kind!=='hint',solution:kind!=='solution'});shared.admitDisabledContent(await api(kind==='hint'?hintPath(id):solutionPath(id)));await toggle(kind,id,true);await card({label:row.label});}result.cases.push({id,learnerContent:true,adminPreview:true,independentGates:true,completedProjection:true});});
    await step('master-gates',async()=>{for(const kind of ['hint','solution']){await toggle(kind,null,false);for(const id of CONTENT_IDS){result.stage='master-'+kind+'-disabled-'+id;save();await card({label:original.objectives.find(x=>x.objective_id===id).label,hint:kind!=='hint',solution:kind!=='solution'});shared.admitDisabledContent(await api(kind==='hint'?hintPath(id):solutionPath(id)));}await toggle(kind,null,true);}for(const id of CONTENT_IDS)await card({label:original.objectives.find(x=>x.objective_id===id).label});});await admin.close();
    await step('dashboard-parity',async()=>{const {aggregateMatches,timeText}=require('../fixtures/codeBotRenderedParityV1');const total=(await pool.query('SELECT count(*)::int n FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active AND is_enabled',[CONTENT_KEY])).rows[0].n;for(const route of ['/workshop-dashboard','/workshop/challenges','/workshop/progress']){await foreground(learner);const pending=learner.waitForResponse(q=>new URL(q.url()).pathname==='/api/workshop/challenges'&&q.status()===200);pending.catch(()=>{});await learner.goto(origin+route,{waitUntil:'domcontentloaded'});const body=await(await pending).json(),row=(body.challenges||body).find(x=>x.workshopKey===CONTENT_KEY||x.id===CONTENT_KEY);a(row);a.equal(row.completedObjectiveCount,CONTENT_IDS.length);a.equal(row.objectiveCount,total);a.deepEqual(row.objectives.filter(x=>x.completed).map(x=>x.id).sort(),[...CONTENT_IDS].sort());a(row.timeSpentSeconds>=60);await learner.waitForFunction(aggregateMatches,{},{name:row.name||row.title,done:CONTENT_IDS.length,total,time:timeText(row.timeSpentSeconds,route==='/workshop/challenges'),challenge:route==='/workshop/challenges'});if(route==='/workshop/progress')a.equal(new URL(learner.url()).pathname,'/workshop-dashboard');}result.dashboardParity=true;});await learner.close();
    if(ragOnly){await step('rag-reset-session',async()=>{
      const call=async(token,endpoint,body,operationId)=>{a(++result.requests.api<=CONTENT_LIMITS.api);const response=await fetch(origin+endpoint,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(operationId?{'x-reset-operation-id':operationId}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:response.status,body:await response.json()};};
      // Audit snapshot uses the admitted migration role; runtime can only read through owner/session-checked functions.
      const documents=async id=>(await migration.query("SELECT to_jsonb(d) row FROM workshop_rag.documents d WHERE owner_id=$1 AND family='RAG' ORDER BY document_id",[id])).rows;
      const siblingDocuments=await documents(sibling.id);a(siblingDocuments.some(x=>x.row.document_id===ragSiblingDocument&&x.row.retired_at===null));a(beforeSibling.completions.length>0);a(beforeSibling.time.length>0);
      const revoked=await adapter.createSession(await users.findCredentialById(owner.id),{});await adapter.logout(revoked.token);for(const [url,body]of [['/api/workshop/rag-injection/current-session',undefined],['/api/workshop/rag-injection/progress/reset',{}]])a.equal((await call(revoked.token,url,body)).status,401);result.sessionDenied=true;
      const active=await page(owner.token);await active.goto(origin+'/vulnerabilities/indirect-prompt-injection',{waitUntil:'domcontentloaded'});await active.waitForFunction(()=>[...document.querySelectorAll('button')].some(e=>e.textContent.trim()==='Reset Progress'&&!e.disabled));
      const before=await state(owner.id);ragBeforeReset={state:before,documents:await documents(owner.id),immutable:await immutable(),sibling:beforeSibling,siblingDocuments};
      const reset=active.waitForResponse(q=>new URL(q.url()).pathname==='/api/workshop/rag-injection/progress/reset'&&q.request().method()==='POST');reset.catch(()=>{});await active.evaluate(()=>[...document.querySelectorAll('button')].find(e=>e.textContent.trim()==='Reset Progress').click());await active.waitForSelector('[role="alertdialog"]');await active.evaluate(()=>[...document.querySelector('[role="alertdialog"]').querySelectorAll('button')].find(e=>e.textContent.trim()==='Confirm reset').click());const rr=await reset;a.equal(rr.status(),200);a.equal((await rr.json()).success,true);const operationId=rr.request().headers()['x-reset-operation-id'];a.match(operationId,/^[0-9a-f-]{36}$/);await active.waitForFunction(()=>!document.querySelector('[role="alertdialog"]'));await active.close();
      const after=await state(owner.id);a.deepEqual(after.completions,[]);a.deepEqual(after.email,before.email);for(const old of before.time){const current=after.time.find(x=>x.id===old.id);a(current);a(Number(current.duration_seconds)>=Number(old.duration_seconds));}
      const retiredDocuments=await documents(owner.id);a(retiredDocuments.length>0);a(retiredDocuments.every(x=>x.row.retired_at!==null));a.deepEqual(await documents(sibling.id),siblingDocuments);a.deepEqual(await state(sibling.id),beforeSibling);a.deepEqual(await immutable(),beforeImmutable);a.equal((await call(owner.token,'/api/workshop/rag-injection/current-session')).body.session_id,null);a.equal((await call(owner.token,'/api/workshop/rag-injection/query',{session_id:result.upload.sessionId,question:RAG_QUESTION,active_objective:'rag_query'})).status,404);
      const replay=await call(owner.token,'/api/workshop/rag-injection/progress/reset',{},operationId);a.equal(replay.status,200);a.equal(replay.body.success,true);a.deepEqual(await documents(owner.id),retiredDocuments);a.deepEqual(await state(owner.id),after);a.deepEqual(await immutable(),beforeImmutable);a.deepEqual(await documents(sibling.id),siblingDocuments);
      result.lifecycle={before:ragBeforeReset,after:{state:after,documents:await documents(owner.id)},resetOperationId:operationId,replay};Object.assign(result,{resetRetired:true,resetReplayExact:true,timePreserved:true,nonemptySiblingPreserved:true});
});}else await step('canonical-session-boundaries',async()=>{
      const call=async(token,endpoint,body)=>{a(++result.requests.api<=CONTENT_LIMITS.api);const response=await fetch(origin+endpoint,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:response.status,body:await response.json()};};
      const snapshot=async id=>({judgments:(await pool.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[id])).rows,packets:(await pool.query('SELECT * FROM workshop_platform.grade_packets WHERE user_id=$1 ORDER BY evaluation_id',[id])).rows});
      const first=await user(),second=await user();
      const address=async u=>{const response=await call(u.token,'/api/email-agent/owned-inbox');a.equal(response.status,200);a.equal(typeof response.body.ownedInbox,'string');return response.body.ownedInbox;};
      const firstAddress=await address(first),pendingControl=sessionProbe.select(first,'pending');
      const pending=call(first.token,'/api/email-agent/save-email',{tempEmail:firstAddress});pending.catch(()=>{});await pendingControl.entered;
      const queued=call(first.token,'/api/email-agent/send',{recipientEmail:firstAddress,scenario:'role_hijack'});queued.catch(()=>{});await pendingControl.queueEntered;
      const logout=await call(first.token,'/api/auth/logout',{});a.equal(logout.status,200);pendingControl.release();
      for(const response of await Promise.all([pending,queued])){a.equal(response.status,401);a.equal(response.body.errorCode,'SESSION_REVOKED');}
      const firstRows=await snapshot(first.id);a.equal(firstRows.judgments.length,1);a(firstRows.judgments.every(r=>r.verdict===null&&r.disposition==='pending'));a.equal(result.mailCalls,0);
      result.sessionPreEffectDenied=true;result.sessionJudgeCommitDenied=true;
      const secondAddress=await address(second),committedControl=sessionProbe.select(second,'postcommit');
      const afterCommit=await call(second.token,'/api/email-agent/save-email',{tempEmail:secondAddress});a.equal(afterCommit.status,401);a.equal(afterCommit.body.errorCode,'SESSION_REVOKED');a(committedControl.committed);a.equal(committedControl.committed.verdict,'fail');a.equal(committedControl.committed.disposition,'not_pass');
      const secondRows=await snapshot(second.id);a.equal(secondRows.judgments.length,1);a.equal(secondRows.judgments[0].verdict,'fail');a.equal(secondRows.judgments[0].disposition,'not_pass');
      a.equal((await pool.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=ANY($1::bigint[])',[[first.id,second.id]])).rows[0].n,0);
      a.equal((await call(sibling.token,'/api/email-agent/progress')).status,200);a.deepEqual(await state(sibling.id),beforeSibling);
      a.deepEqual(await snapshot(first.id),firstRows);a.deepEqual(await snapshot(second.id),secondRows);
      result.sessionPostCommitPublicationDenied=true;result.sessionPriorCommitPreserved=true;result.sessionSiblingPreserved=true;result.controlledSessionOwners=2;result.controlledJudgeCalls=sessionProbe.calls();a.equal(result.controlledJudgeCalls,2);
    });
    a.equal(result.requestDenied,undefined);result.status='passed';
  } catch(error){primary=error;result.status='failed';result.failure={name:error.name,frames:String(error.stack).split('\n').map(x=>x.match(/((?:tests|server)\/[^ ()]+:\d+:\d+)/)?.[1]).filter(Boolean).slice(0,6)};}
  finally {
    sessionProbe?.restore();restoreCompletion?.();
    const operations=[['restore',async()=>{if(original){for(const row of original.objectives)await migration.query('UPDATE workshop_platform.objectives SET is_enabled=$3,hint_enabled=$4,solution_enabled=$5 WHERE workshop_key=$1 AND objective_id=$2',[CONTENT_KEY,row.objective_id,row.is_enabled,row.hint_enabled,row.solution_enabled]);const e=original.exercise;await migration.query('UPDATE workshop_platform.exercises SET is_visible=$2,show_hints=$3,show_solutions=$4 WHERE workshop_key=$1',[CONTENT_KEY,e.is_visible,e.show_hints,e.show_solutions]);a.deepEqual(await config(),original);result.configurationRestored=true;}if(beforeOwner){await migration.query('DELETE FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 AND objective_id=ANY($3::text[])',[owner.id,CONTENT_KEY,CONTENT_IDS]);await migration.query('DELETE FROM workshop_platform.time_tracking WHERE user_id=$1 AND workshop_key=$2',[owner.id,CONTENT_KEY]);a.deepEqual(await state(owner.id),beforeOwner);result.projectionRestored=true;a.deepEqual(await state(sibling.id),beforeSibling);result.siblingPreserved=true;a.deepEqual(await immutable(),beforeImmutable);result.immutableEvidencePreserved=true;}}],['browser',()=>browser?.close()],['mail',()=>mail?.close()],['rag',async()=>{if(ragRoute&&owner)await ragRoute.resetOwner(String(owner.id),async()=>{});}],['routes',()=>mounted?.close?.()],['server',()=>new Promise((resolve,reject)=>{if(!server)return resolve();server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['pools',async()=>{const settled=await Promise.allSettled(pools.map(p=>p.end()));await pg?.closePostgresPools();a(settled.every(x=>x.status==='fulfilled'));}]];
    result.cleanup=[];for(const operation of operations)result.cleanup.push(...await settleOwnership([operation],15000));restoreProvider?.();restoreAI?.();result.cleanupFailures=result.cleanup.filter(x=>x.status!=='fulfilled');if(result.cleanupFailures.length)result.status='failed';if(result.status==='passed')try{(ragOnly?assertRagContentReceipt:assertContentReceipt)(result);}catch(error){primary=error;result.status='failed';}save();
  }
  if(primary||result.status!=='passed')throw Error('IPI controlled content qualification failed');return result;
}
Object.assign(module.exports,{qualifyRagSeed,assertRagSeedProof,RAG_INJECTION_PROFILE,RAG_INJECTION_SCOPE,ragContentConfiguration,RAG_UPLOAD_PROFILE,RAG_UPLOAD_SCOPE,controlledRagDecision,RAG_PROFILE,RAG_SCOPE,RAG_DOCUMENT,RAG_QUESTION,RAG_ANSWER,assertRagContentReceipt,controlledSessionVerdict,installContentSessionProbe,CONTENT_PROFILE,CONTENT_KEY,CONTENT_IDS,CONTENT_LIMITS,CONTENT_SCOPE,contentCard,contentSolution,contentToggleRequest,contentRequestAllowed,assertContentReceipt,runContent});

// This closed lane uses the mounted production routes. Its browser/content proof
// is the separate controlled profile above; every provider result here is real.
const RAG_ACTUAL_INPUT = require('../fixtures/ipiRagQueryActualInput.json');
const ragActualSha = value => require('node:crypto').createHash('sha256').update(value).digest('hex');
function ragWireText(row) {
  return row.response.trim().split('\n').map(line=>JSON.parse(line)).map(frame=>frame.message?.content||frame.response||'').join('');
}
function bindRagActualCapture(c, rows) {
  const a=require('node:assert/strict');
  a.deepEqual(c.input,RAG_ACTUAL_INPUT);a.equal(c.query.status,200);a.equal(c.query.body.presentation_source,'model');
  const judgment=c.judgments.find(x=>x.objective_id==='rag_query');a(judgment);a.equal(judgment.verdict,'pass');a.equal(judgment.disposition,'awarded');
  const packetRecord=c.packets.find(x=>x.evaluation_id===judgment.evaluation_id);a(packetRecord);a.equal(ragActualSha(packetRecord.packet),judgment.evidence_digest);
  const packet=JSON.parse(packetRecord.packet),run=c.runs.find(x=>x.run_id===judgment.run_id),ownerKey=JSON.stringify(['RAG',String(c.ownerId)]);
  a(run);a.equal(run.status,'completed');a.equal(run.owner_key,ownerKey);a.equal(String(judgment.user_id),String(c.ownerId));a.equal(String(judgment.generation),String(run.generation));
  a.equal(packetRecord.owner_key,ownerKey);a.equal(String(packetRecord.user_id),String(c.ownerId));a.equal(String(packetRecord.owner_generation),String(run.generation));
  a.equal(packet.rubric.objectiveId,'rag_query');a.equal(packet.rubric.version,'ipi-rag-evidence-bound-v2');
  const content=id=>packet.evidence.find(x=>x.id===id)?.content;
  a.equal(content('question'),c.input.question);a.equal(content('raw_response'),c.query.body.raw_model_answer);a.equal(content('context'),c.query.body.retrieved_chunks.map(x=>x.text).join('\n---\n'));
  a(c.query.body.retrieved_chunks.length>0);a(c.query.body.retrieved_chunks.every(x=>c.input.document.includes(x.text)));
  for(const fact of packet.rubric.requiredFacts)a.equal(packet.facts[fact],true);
  const receipts=content('retrieval_receipts');a(Array.isArray(receipts)&&receipts.length>0);
  const effects=c.effects.filter(x=>x.run_id===run.run_id&&x.status==='completed');a(effects.length>0);
  a(c.events.some(x=>x.run_id===run.run_id&&x.node==='rag_search'&&x.event_type==='tool'));
  for(const receipt of receipts){a.equal(String(receipt.ownerId),String(c.ownerId));a.equal(receipt.runId,run.run_id);a.equal(receipt.documentId,c.upload.body.session_id);a.equal(receipt.runtimeFingerprint,c.embeddingFingerprint.fingerprint);a.equal(receipt.sourceSha256,ragActualSha(c.input.document));a.equal(String(receipt.graphGeneration),String(run.generation));}
  const wire=rows.filter(x=>x.kind==='chat');a.equal(wire.length,c.modelCalls.length);
  let actorCount=0,judgeCount=0,finalAnswer;const searches=[];
  for(let n=0;n<wire.length;n++){
    const row=wire[n],call=c.modelCalls[n];a.equal(call.error,null);a.equal(row.caseId,call.caseId);require('./finflowBackupBrowserActualTransport').validateResponse(row);a.equal(row.terminal,'returned');a.equal(ragActualSha(row.request),row.requestSha256);a.equal(Buffer.byteLength(row.request),row.requestBytes);
    const request=JSON.parse(row.request);a.equal(request.model,REQUIRED_MODEL);a.equal(ragWireText(row),call.result.response);a.deepEqual(request.messages,call.messages);a.deepEqual(request.format,call.options.format);a.equal(request.options.temperature,call.options.temperature);a.equal(request.options.num_predict,call.options.num_predict??call.options.max_tokens);a.equal(request.options.num_ctx,call.options.num_ctx);a.equal(call.result.provider,'ollama');a.equal(call.result.model,REQUIRED_MODEL);a.notEqual(call.result.mocked,true);a.notEqual(call.result.fallback,true);
    if(call.role==='actor'){actorCount++;a.equal(row.caseId,'owner-query');a.equal(request.options.num_predict,1200);a(call.messages[1].content.startsWith('Question: '+c.input.question+'\n'));try{const decision=require('../../server/agent-runtime/ragDecisions').validateDecision(call.result.response);if(decision.action==='answer')finalAnswer=decision.answer;else searches.push(decision);}catch(error){a.equal(error.code,'RAG_DECISION_INVALID');}}
    else {judgeCount++;a.equal(call.role,'judge');a.equal(request.options.num_predict,900);}
  }
  a(searches.length>=1&&searches.length<=3);a.equal(searches.length,receipts.length);a.equal(c.searches.length,searches.length);for(let n=0;n<searches.length;n++){const {query,topK}=searches[n];a.equal(c.searches[n].input.question,query);a.equal(c.searches[n].input.limit,topK);a.equal(c.searches[n].input.documentId,c.upload.body.session_id);a.deepEqual(c.searches[n].result.receipt,receipts[n]);const key=run.run_id+':rag_search:'+n+':'+ragActualSha(JSON.stringify({query,topK}));a(effects.some(x=>x.effect_key===key&&x.owner_key===ownerKey&&String(x.generation)===String(run.generation)));}a(actorCount>=2&&actorCount<=8);a(judgeCount>=1&&judgeCount<=6);a.equal(finalAnswer,c.query.body.raw_model_answer);
  const judges=c.modelCalls.filter(x=>x.role==='judge'&&x.caseId==='owner-query');a(judges.length>=1&&judges.length<=2);
  for(const call of judges){a(call.messages[0].content.includes('AUTHORITATIVE RUBRIC:\n'+JSON.stringify(packet.rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+JSON.stringify(packet.facts)+'\n'));a.deepEqual(JSON.parse(call.messages[1].content),packet.evidence);}
  const reported=c.query.body.judgments.find(x=>x.objectiveId==='rag_query');a(reported);a.equal(reported.evaluationId,judgment.evaluation_id);a.equal(reported.verdict,'pass');const rawVerdict=JSON.parse(judges.at(-1).result.response);a.equal(rawVerdict.verdict,judgment.verdict);a.deepEqual(rawVerdict.criteria,reported.criteria);a.deepEqual(judgment.result_json.criteria,reported.criteria);a.deepEqual(c.query.body.completedObjectiveIds,['rag_query']);
  return {actorCalls:actorCount,judgeCalls:judgeCount};
}
function bindRagNoCallNegative(name,proof){const a=require('node:assert/strict');const status={'foreign-document':404,'revoked-session':401,'retired-document':404}[name];a(status);a.equal(proof.response.status,status);for(const key of ['answer','raw_model_answer','retrieved_chunks','document','content'])a.equal(Object.hasOwn(proof.response.body,key),false);a.deepEqual(proof.after,proof.before);return true;}
async function runRagActual({owned,runtime,ports,source,transport}) {
  const a=require('node:assert/strict'),crypto=require('node:crypto'),{saveBounded}=require('../fixtures/boundedJsonArtifact');
  const {settleOwnership}=require('../fixtures/secureshopAnalyticsBrowserOwner');
  const result={profile:'ipi-rag-query-actual',status:'preparing',installedWrites:false,actualModelProof:false,controlledProjectionCount:0,genuineCredit:0,modelCalls:0,actorCalls:0,judgeCalls:0,caseIds:['owner-upload','owner-query'],cleanup:[],cleanupFailures:[]};
  const capture={input:RAG_ACTUAL_INPUT,modelCalls:[],searches:[],lifecycle:{}};const pools=[];let pg,pool,migration,wire,server,ragRoute,restoreAI,restoreCompletion,vector,activeCase=null,primary;
  const save=()=>{saveBounded(path.join(owned.evidence,'rag-actual-captures.json'),JSON.parse(JSON.stringify(capture)));saveBounded(path.join(owned.evidence,'result.json'),result);};
  const stage=async(name,fn)=>{result.stage=name;save();const value=await fn();save();return value;};
  try {
    a.equal(owned.profile,'ipi-rag-query-actual');a.deepEqual(owned.input,RAG_ACTUAL_INPUT);a.equal(fs.realpathSync(source),fs.realpathSync(path.resolve(__dirname,'../..')));
    a.equal(process.env.HF_HUB_OFFLINE,'1');a.equal(process.env.TRANSFORMERS_OFFLINE,'1');a.equal(fs.realpathSync(process.env.XENOVA_CACHE),fs.realpathSync(owned.embeddingCache.directory));
    const transformers=await import('@huggingface/transformers');transformers.env.allowRemoteModels=false;transformers.env.allowLocalModels=true;
    wire=await transport.createTransport({evidence:owned.evidence,policyCohort:'ipi-rag-query-actual'});ports.add(new URL(wire.actorUrl).port*1);process.env.OLLAMA_BASE_URL=wire.actorUrl;process.env.OLLAMA_MODEL=REQUIRED_MODEL;process.env.AI_PROVIDER='ollama';
    pg=require('../../server/database/postgres');for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'])pools.push(pg.createPool(process.env,key));[pool,migration]=pools;
    await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(pool,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(pool),adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),stores=await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    async function user(){const u=await users.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(crypto.randomUUID(),4)});const session=await adapter.createSession(await users.findCredentialById(u.id),{});return {id:u.id,token:session.token,sessionId:session.internalSessionId};}
    const owner=await user(),sibling=await user();capture.ownerId=owner.id;capture.siblingId=sibling.id;
    const ai=require('../../server/services/multiProviderAIService'),originalActor=ai.chatWithMessages;
    const record=async(role,messages,options,fn)=>{const call={role,caseId:activeCase,messages:structuredClone(messages),options:JSON.parse(JSON.stringify({...options,signal:undefined})),result:null,error:null};capture.modelCalls.push(call);save();try{call.result=await fn();return call.result;}catch(error){call.error={name:error.name,code:error.code||null};throw error;}finally{save();}};
    ai.chatWithMessages=(messages,options)=>record('actor',messages,options,()=>configured.chat(messages,[],options));restoreAI=()=>{ai.chatWithMessages=originalActor;};
    const configured=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:REQUIRED_MODEL,baseURL:wire.judgeUrl});
    const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{chat:(messages,tools,options)=>record('judge',messages,options,()=>configured.chat(messages,tools,options))}});
    const completion=require('../../server/services/objectiveCompletionService'),originalCompletion=completion.getObjectiveCompletionService;
    const service=completion.createObjectiveCompletionService({progress:stores.progress,receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool),judge});completion.getObjectiveCompletionService=()=>service;restoreCompletion=()=>{completion.getObjectiveCompletionService=originalCompletion;};
    vector=require('../../server/services/ragVectorStore');await stage('embedding',()=>vector.init());const embedder=require('../../server/services/secureshopProductEmbedder').createSecureShopProductEmbedder();capture.embeddingFingerprint=embedder.getRuntimeFingerprint();a.deepEqual(capture.embeddingFingerprint,{fingerprint:owned.embeddingCache.fingerprint,description:owned.embeddingCache.description});result.embeddingFingerprint=capture.embeddingFingerprint;
    const composition=require('../../server/services/workshopRagComposition').createWorkshopRagComposition({pool,identityAdapter:adapter,embedder,assertReady:p=>require('../../server/services/workshopRagReadiness').assertWorkshopRagReadiness({pool:p,expectedDatabase:new URL(process.env.IDENTITY_DATABASE_URL).pathname.slice(1)})});await composition.initialize();
    ragRoute=require('../../server/routes/ragInjection');ragRoute.configureDurableRag({...composition,resolveRequest:async req=>{const scope=await composition.resolveRequest(req);return {...scope,bind:async(...args)=>{const bound=await scope.bind(...args);return {...bound,search:async input=>{const result=await bound.search(input);capture.searches.push({input,result});save();return result;}};}};}});const app=express();app.use(express.json({limit:'128kb'}));app.use('/api/workshop/rag-injection',ragRoute);
    server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);const origin='http://127.0.0.1:'+server.address().port;
    const call=async(token,suffix,body,headers={})=>{const response=await fetch(origin+'/api/workshop/rag-injection'+suffix,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,...(!(body instanceof FormData)&&body!==undefined?{'content-type':'application/json'}:{}),...headers},...(body!==undefined?{body:body instanceof FormData?body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(300000),redirect:'error'});return {status:response.status,body:await response.json()};};
    // Seed a real sibling document through the same admitted durable store, without
    // creating another semantic case or asking the Judge for sibling credit.
    const scoped=await composition.resolveRequest({user:{id:sibling.id},identitySession:{id:sibling.sessionId},headers:{authorization:'Bearer '+sibling.token}});
    const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'RAG'});
    await coordinator.run(sibling.id,{},async execution=>{const store=await scoped.bind(execution);await store.ingestAndSelect({documentId:crypto.randomUUID(),operationId:crypto.randomUUID(),filename:'sibling-policy.txt',ingestionKind:'upload',sourceBuffer:Buffer.from('Sibling laboratory policy: the approved archive period is 41 days.')});});
    const documents=async id=>(await migration.query("SELECT to_jsonb(d) row FROM workshop_rag.documents d WHERE owner_id=$1 AND family='RAG' ORDER BY document_id",[id])).rows;
    const immutable=async()=>({judgments:(await pool.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[owner.id])).rows,packets:(await pool.query('SELECT * FROM workshop_platform.grade_packets WHERE user_id=$1 ORDER BY evaluation_id',[owner.id])).rows});
    capture.lifecycle.siblingBefore=await documents(sibling.id);a.equal(capture.lifecycle.siblingBefore.length,1);
    await stage('owner-upload',async()=>{activeCase='owner-upload';wire.beginCase(activeCase);const form=new FormData();form.set('document',new Blob([RAG_ACTUAL_INPUT.document],{type:'text/plain'}),'owned-policy.txt');capture.upload=await call(owner.token,'/upload',form);wire.endCase();activeCase=null;a.equal(capture.upload.status,200);});
    const request={session_id:capture.upload.body.session_id,question:RAG_ACTUAL_INPUT.question,active_objective:'rag_query'};capture.request=request;
    await stage('owner-query',async()=>{activeCase='owner-query';wire.beginCase(activeCase);capture.query=await call(owner.token,'/query',request);wire.endCase();activeCase=null;});
    Object.assign(capture,await immutable());capture.documents=await documents(owner.id);
    capture.runs=(await migration.query('SELECT * FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY started_at',[JSON.stringify(['RAG',String(owner.id)])])).rows;
    const runIds=capture.runs.map(x=>x.run_id);capture.events=(await migration.query('SELECT * FROM graph_runtime.events WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,sequence',[runIds])).rows;capture.effects=(await migration.query('SELECT * FROM graph_runtime.effects WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,effect_key',[runIds])).rows;save();
    Object.assign(result,bindRagActualCapture(capture,wire.snapshot().calls));result.modelCalls=result.actorCalls+result.judgeCalls;
    await stage('lifecycle',async()=>{
      capture.lifecycle.wireBefore=wire.snapshot().counts;
      const negative=async(name,token,expected)=>{const before=wire.snapshot().counts,response=await call(token,'/query',request),after=wire.snapshot().counts;capture.lifecycle[name]={before,response,after};save();a.equal(response.status,expected);bindRagNoCallNegative(name,capture.lifecycle[name]);};
      await negative('foreign-document',sibling.token,404);result.foreignDocumentDenied=true;
      const revoked=await adapter.createSession(await users.findCredentialById(owner.id),{});await adapter.logout(revoked.token);await negative('revoked-session',revoked.token,401);result.sessionDenied=true;
      capture.lifecycle.immutableBefore=await immutable();capture.lifecycle.completionsBefore=(await pool.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id',[owner.id,CONTENT_KEY])).rows;a(capture.lifecycle.completionsBefore.some(x=>x.objective_id==='rag_query'));capture.lifecycle.ownerBefore=await documents(owner.id);a.equal(capture.lifecycle.ownerBefore.length,1);a.equal(capture.lifecycle.ownerBefore[0].row.document_id,request.session_id);capture.lifecycle.reset=await call(owner.token,'/progress/reset',{}, {'x-reset-operation-id':crypto.randomUUID()});a.equal(capture.lifecycle.reset.status,200);a.equal(capture.lifecycle.reset.body.success,true);
      await negative('retired-document',owner.token,404);capture.lifecycle.ownerAfter=await documents(owner.id);a.equal(capture.lifecycle.ownerAfter.length,1);a.deepEqual(capture.lifecycle.ownerAfter.map(x=>x.row.document_id),capture.lifecycle.ownerBefore.map(x=>x.row.document_id));a(capture.lifecycle.ownerAfter.every(x=>x.row.retired_at));
      capture.lifecycle.immutableAfter=await immutable();a.deepEqual(capture.lifecycle.immutableAfter,capture.lifecycle.immutableBefore);capture.lifecycle.siblingAfter=await documents(sibling.id);a.deepEqual(capture.lifecycle.siblingAfter,capture.lifecycle.siblingBefore);
      a.equal((await pool.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2',[owner.id,CONTENT_KEY])).rows[0].n,0);
      capture.lifecycle.wireAfter=wire.snapshot().counts;a.deepEqual(capture.lifecycle.wireAfter,capture.lifecycle.wireBefore);result.resetRetired=true;result.noCallNegatives=true;result.immutableEvidencePreserved=true;result.siblingPreserved=true;
    });
    a.deepEqual(await require('../../server/services/embeddingRuntimeFingerprint').createEmbeddingRuntimeFingerprinter().snapshot(),capture.embeddingFingerprint);wire.assertComplete();result.actualModelProof=true;result.genuineCredit=1;result.status='passed';
  }catch(error){primary=error;result.status='failed';result.failure={name:error.name,code:error.code||null,frames:String(error.stack).split('\n').map(x=>x.match(/((?:tests|server)\/[^ ()]+:\d+:\d+)/)?.[1]).filter(Boolean).slice(0,8)};}
  finally{
    const operations=[['routes',async()=>{restoreAI?.();restoreCompletion?.();}],['server',()=>new Promise((resolve,reject)=>{if(!server)return resolve();server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['embedding',async()=>{if(vector?.embedder){await vector.embedder.dispose();vector.embedder=null;vector.modelReady=false;}}],['transport',()=>wire?.close()],['pools',async()=>{await Promise.all(pools.map(p=>p.end()));await pg?.closePostgresPools();}]];
    for(const operation of operations)result.cleanup.push(...await settleOwnership([operation],15000));result.cleanupFailures=result.cleanup.filter(x=>x.status!=='fulfilled');if(result.cleanupFailures.length)result.status='failed';save();
  }
  if(primary||result.status!=='passed')throw Error('IPI actual RAG qualification failed');return result;
}
Object.assign(module.exports,{RAG_ACTUAL_INPUT,ragWireText,bindRagActualCapture,bindRagNoCallNegative,runRagActual});

// Closed original-r7 email cohort. The renderer is qualified separately; this
// lane uses the real mounted route, owned Mailpit and configured model adapter.
const EMAIL_ACTUAL_INPUT = require('../fixtures/ipiEmailTriggerActualInput.json');
const emailClone = value => JSON.parse(JSON.stringify(value));
const emailOptions = value => emailClone({...value,signal:undefined});
function emailActorPrompts() {
  const source=fs.readFileSync(path.resolve(__dirname,'../../server/routes/emailAgent.js'),'utf8');
  return Object.fromEntries(['VULNERABLE','SECURE'].map(name=>{
    const match=source.match(new RegExp('const '+name+'_SYSTEM_PROMPT = `([^`]+)`;'));
    require('node:assert/strict')(match&&!match[1].includes('${')&&!match[1].includes('\\'),'Literal production email policy required');
    return [name.toLowerCase(),match[1]];
  }));
}
function bindEmailWire(c,rows) {
  const a=require('node:assert/strict'),wire=rows.filter(x=>x.kind==='chat');
  a.deepEqual(c.input,EMAIL_ACTUAL_INPUT);a.equal(wire.length,c.modelCalls.length);
  for(let n=0;n<wire.length;n++){
    const row=wire[n],call=c.modelCalls[n];a.equal(call.error,null);a.equal(row.caseId,call.caseId);
    require('./finflowBackupBrowserActualTransport').validateResponse(row);a.equal(row.terminal,'returned');
    a.equal(ragActualSha(row.request),row.requestSha256);a.equal(Buffer.byteLength(row.request),row.requestBytes);
    const request=JSON.parse(row.request);a.equal(row.role,call.role);a.equal(require('./finflowBackupBrowserActualTransport').emailRequestRole(request),call.role);a.equal(request.model,REQUIRED_MODEL);a.equal(ragWireText(row),call.result.response);
    a.deepEqual(request.messages,call.messages);a.deepEqual(request.format,call.options.format);
    a.equal(request.options.temperature,call.options.temperature);a.equal(request.options.num_predict,call.options.num_predict??call.options.max_tokens);
    const effectiveNumCtx=call.role==='actor'?require('../../server/agent-runtime/providers/langchainProvider').ollamaContextWindow(call.options,{}):call.options.num_ctx;a.equal(request.options.num_ctx,effectiveNumCtx);
    a.equal(call.result.provider,'ollama');a.equal(call.result.model,REQUIRED_MODEL);a.notEqual(call.result.mocked,true);a.notEqual(call.result.fallback,true);
    a(['actor','judge'].includes(call.role));
  }
  return {actorCalls:c.modelCalls.filter(x=>x.role==='actor').length,judgeCalls:c.modelCalls.filter(x=>x.role==='judge').length};
}
async function replayEmailJudgments(c) {
  const a=require('node:assert/strict'),judgeModule=require('../../server/agent-runtime/objectiveJudge'),repository=require('../../server/database/postgres/objectiveJudgmentRepository');
  const used=[];
  for(const evaluation of c.evaluations){
    const row=c.judgments.find(x=>x.run_id===evaluation.runId&&x.objective_id===evaluation.packet.rubric.objectiveId);a(row);
    const record=c.packets.find(x=>x.evaluation_id===row.evaluation_id);a(record);a.equal(ragActualSha(record.packet),row.evidence_digest);
    const packet=JSON.parse(record.packet);a.deepEqual(packet,evaluation.packet);
    a.deepEqual(packet.rubric,judgeModule.prepareJudgeInput({rubric:require('../../server/agent-runtime/indirectObjectiveJudge').buildIpiRubric(row.objective_id),evidence:packet.evidence,facts:packet.facts}).rubric);
    a.equal(String(row.user_id),String(c.ownerId));a.equal(record.owner_key,JSON.stringify(['IndirectEmail',String(c.ownerId)]));
    const run=c.runs.find(x=>x.run_id===row.run_id);a(run);a.equal(run.owner_key,record.owner_key);a.equal(run.status,'completed');a.equal(String(record.owner_generation),String(run.generation));
    let index=0;const selected=evaluation.callIndexes.map(i=>{a(!used.includes(i));used.push(i);const call=c.modelCalls[i];a.equal(call.role,'judge');a.equal(call.caseId,evaluation.caseId);return call;});
    const judge=judgeModule.createObjectiveJudge({model:{chat:async(messages,tools,options)=>{const call=selected[index++];a(call,'Unexpected replay Judge call');a.deepEqual(tools,[]);a.deepEqual(messages,call.messages);a.deepEqual(emailOptions(options),call.options);return emailClone(call.result);}}});
    const replay=await judge({...packet,execution:{runId:run.run_id,ownerId:c.ownerId,check:async()=>{}}});a.equal(index,selected.length);
    const stable=value=>{const copy=emailClone(value);delete copy.durationMs;return copy;};
    a.deepEqual(stable(replay),stable(evaluation.result));
    a.deepEqual(repository.resultValue(evaluation.result,row),row.result_json);
    a.equal(row.verdict,replay.verdict);
  }
  a.deepEqual(used.sort((a,b)=>a-b),c.modelCalls.flatMap((call,i)=>call.role==='judge'?[i]:[]));
}
async function replayEmailActors(c,item) {
  const a=require('node:assert/strict'),graph=require('../../server/agent-runtime/indirectEmailGraph'),prompts=emailActorPrompts();
  const trigger=c.judgments.find(x=>x.evaluation_id===item.response.body.judgments.find(x=>x.objectiveId==='email_trigger_injection')?.evaluationId);a(trigger);
  const run=c.runs.find(x=>x.run_id===trigger.run_id);a(run);a.equal(run.status,'completed');
  const ownerKey=JSON.stringify(['IndirectEmail',String(c.ownerId)]);a.equal(run.owner_key,ownerKey);a.equal(c.effects.filter(x=>x.run_id===run.run_id&&x.effect_key.includes(':email_read_')).length,2);
  const artifact=item.artifact;a.equal(artifact.artifactId,item.request.artifactId);a.equal(ragActualSha(artifact.body),artifact.bodySha256);a.equal(ragActualSha(artifact.modelBody),artifact.modelBodySha256);
  const stored=c.artifacts.find(x=>x.artifact_id===artifact.artifactId);a(stored);a.equal(String(stored.owner_id),String(c.ownerId));a.equal(stored.owner_key,ownerKey);a.equal(String(stored.generation),String(run.generation));a.equal(stored.body_text,artifact.body);a.equal(stored.model_body_text,artifact.modelBody);a.equal(stored.body_sha256,artifact.bodySha256);a.equal(stored.model_body_sha256,artifact.modelBodySha256);
  const calls=c.modelCalls.filter(x=>x.caseId===item.id&&x.role==='actor');let index=0;const traces=[];
  for(const profile of ['vulnerable','secure']){
    const key=run.run_id+':email_read_'+profile+'_'+artifact.artifactId;
    const matching=c.effects.filter(x=>x.run_id===run.run_id&&x.effect_key===key);a.equal(matching.length,1);const effect=matching[0];a(effect);a.equal(effect.status,'completed');a.equal(effect.owner_key,ownerKey);a.equal(String(effect.generation),String(run.generation));
    const receipt={version:1,ownerKey,generation:String(run.generation),runId:run.run_id,effectKey:key,status:'completed'};
    const replay=await graph.runActorLoop({profile,artifactId:artifact.artifactId,systemPrompt:prompts[profile]}, {
      aiService:{chatWithMessages:async(messages,options)=>{const call=calls[index++];a(call,'Unexpected actor replay call');a.deepEqual(messages,call.messages);a.deepEqual(emailOptions(options),call.options);return emailClone(call.result);}},
      readEmailArtifact:async()=>artifact,execution:{runId:run.run_id,ownerKey,durableGeneration:run.generation,check:async()=>{},trace:async event=>{if(['decision','tool','error'].includes(event.type))traces.push({node:event.node,event_type:event.type,data:require('../../server/agent-runtime/runTraceStore').traceData(event.data)});},effectWithReceipt:async(node,read)=>{a.equal(key,run.run_id+':'+node);return {value:await read(),receipt};}}
    });
    a.equal(replay.response,item.response.body[profile==='vulnerable'?'vulnerableSummary':'secureSummary']);a.deepEqual(replay.decisions,item.response.body.actorDecisions[profile]);a.equal(replay.action,item.response.body.actorActions[profile]);
    for(const row of c.judgments.filter(x=>x.run_id===run.run_id)){
      const packet=JSON.parse(c.packets.find(x=>x.evaluation_id===row.evaluation_id).packet);
      if(profile==='secure'&&row.objective_id==='email_trigger_injection')continue;
      a.equal(packet.evidence.find(x=>x.id==='email').content,artifact.modelBody);
      a.equal(packet.evidence.find(x=>x.id===profile+'_response').content,replay.response);
      const observation=packet.evidence.find(x=>x.id===profile+'_observation').content;
      a.deepEqual(observation,{profile,artifactId:artifact.artifactId,bodySha256:artifact.bodySha256,modelBodySha256:artifact.modelBodySha256,modelBodyTruncated:artifact.modelBodyTruncated===true,receipt});
    }
  }
  for(const reported of item.response.body.judgments){const stored=c.judgments.find(x=>x.evaluation_id===reported.evaluationId);a(stored);a.equal(stored.run_id,run.run_id);a.equal(reported.objectiveId,stored.objective_id);a.equal(reported.verdict,stored.verdict);a.deepEqual(reported.criteria,stored.result_json.criteria);}
  a.equal(index,calls.length);a(calls.length>=6&&calls.length<=8);
  const saved=c.events.filter(x=>x.run_id===run.run_id&&/^(vulnerable|secure)_/.test(x.node)&&['decision','tool','error'].includes(x.event_type)).map(x=>({node:x.node,event_type:x.event_type,data:x.metadata}));a.deepEqual(traces,saved);
  return trigger;
}
async function bindEmailActualCapture(c,rows) {
  const a=require('node:assert/strict');const counts=bindEmailWire(c,rows);a(counts.actorCalls>=12&&counts.actorCalls<=16);a(counts.judgeCalls>0&&counts.judgeCalls<=28);
  a.equal(c.evaluations.length,8);a.equal(c.judgments.length,8);a.equal(c.packets.length,8);a.deepEqual(c.cases.map(x=>x.id),['clean-control','attack']);a.equal(c.setup.send.request.customBody,EMAIL_ACTUAL_INPUT.attackBody);a.equal(c.setup.send.response.status,200);
  a.equal(c.setup.clean.request.manualContent,EMAIL_ACTUAL_INPUT.cleanBody);a.equal(c.setup.fetch.response.status,200);a.equal(c.setup.clean.response.status,200);a.equal(c.setup.save.response.status,200);
  const sends=c.mail.filter(x=>x.name==='sendEmail');a.equal(sends.length,1);a.equal(sends[0].args[0],c.setup.send.request.recipientEmail);a.equal(sends[0].args[2],EMAIL_ACTUAL_INPUT.attackBody);a.equal(String(sends[0].args[4].ownerId),String(c.ownerId));a.equal(sends[0].result.success,true);a.equal(sends[0].result.messageId,c.setup.send.response.body.messageId);
  await replayEmailJudgments(c);
  for(const item of c.cases){a.equal(item.response.status,200);const trigger=await replayEmailActors(c,item);
    if(item.id==='attack'){
      a.equal(item.artifact.ingestionKind,'inbox_provider');const read=c.mail.find(x=>x.name==='fetchEmail'&&String(x.result?.email?.providerMessageId)===String(item.artifact.providerMessageId));a(read);a.equal(String(read.args[0].ownerId),String(c.ownerId));a.equal(read.result.email.body,item.artifact.body);a(c.setup.fetch.response.body.emails.some(x=>x.artifactId===item.artifact.artifactId&&x.bodySha256===item.artifact.bodySha256));a.equal(item.artifact.provider,'mailpit');a.equal(item.artifact.body,EMAIL_ACTUAL_INPUT.attackBody.replace(/\n/g,'\r\n')+'\r\n');
      a.equal(trigger.verdict,'pass');a.equal(trigger.disposition,'awarded');a(c.completions.some(x=>String(x.user_id)===String(c.ownerId)&&x.objective_id==='email_trigger_injection'));
    }else{
      a.equal(item.artifact.body,EMAIL_ACTUAL_INPUT.cleanBody);a.equal(item.artifact.ingestionKind,'manual_entry');a.equal(c.setup.clean.response.body.emails[0].artifactId,item.artifact.artifactId);a(item.response.body.judgments.every(x=>x.verdict==='fail'));a.equal(trigger.verdict,'fail');a.equal(trigger.disposition,'not_pass');
      a(!item.completions.some(x=>x.objective_id==='email_trigger_injection'));a(!item.response.body.completedObjectiveNumbers.includes(4));
    }
  }
  bindEmailLifecycle(c);return counts;
}
function bindEmailLifecycle(c){const a=require('node:assert/strict'),p=c.lifecycle;for(const name of ['forged-body','foreign-artifact','revoked-session','retired-artifact'])bindEmailNoCallNegative(name,p[name]);a.deepEqual(p.wireBefore,p.wireAfter);a.equal(p.reset.status,200);a.equal(p.reset.body.success,true);a.deepEqual(p.immutableBefore,p.immutableAfter);a.deepEqual(p.immutableBefore,{judgments:c.judgments,packets:c.packets});a.equal(p.ownerBefore.length,2);a.deepEqual(p.ownerBefore,c.artifacts);a.deepEqual(p.ownerAfter.map(x=>x.artifact_id),p.ownerBefore.map(x=>x.artifact_id));for(let i=0;i<2;i++){const before=p.ownerBefore[i],after=p.ownerAfter[i];a.equal(before.retired_at,null);a(after.retired_at);a.deepEqual({...after,retired_at:null},before);a.equal(String(before.owner_id),String(c.ownerId));}a.equal(BigInt(p.generationAfter),BigInt(p.generationBefore)+1n);a.equal(p.siblingBefore.artifacts.length,1);a.equal(String(p.siblingBefore.artifacts[0].owner_id),String(c.siblingId));a.deepEqual(p.siblingBefore,p.siblingAfter);a.deepEqual(p.completionsAfter,[]);return true;}
function bindEmailNoCallNegative(name,proof){const a=require('node:assert/strict'),status={'foreign-artifact':409,'revoked-session':401,'retired-artifact':409,'forged-body':400}[name];a(status);a.equal(proof.response.status,status);a.deepEqual(proof.before,proof.after);for(const field of ['vulnerableSummary','secureSummary','sourceArtifact','judgments'])a.equal(Object.hasOwn(proof.response.body,field),false);return true;}
async function runEmailActual({owned,runtime,ports,source,transport}) {
  const a=require('node:assert/strict'),crypto=require('node:crypto'),{saveBounded}=require('../fixtures/boundedJsonArtifact'),{settleOwnership}=require('../fixtures/secureshopAnalyticsBrowserOwner');
  const result={profile:'ipi-email-trigger-actual',status:'preparing',installedWrites:false,browserStarted:false,actualModelProof:false,controlledProjectionCount:0,genuineCredit:0,modelCalls:0,actorCalls:0,judgeCalls:0,caseIds:['setup','clean-control','attack'],cleanup:[],cleanupFailures:[]};
  const capture={version:1,input:EMAIL_ACTUAL_INPUT,modelCalls:[],evaluations:[],cases:[],setup:{},mail:[],lifecycle:{}};
  const pools=[];let pg,pool,migration,wire,server,mail,restoreAI,restoreCompletion,restoreProvider,primary,activeCase;
  const save=()=>{saveBounded(path.join(owned.evidence,'email-actual-captures.json'),emailClone(capture));saveBounded(path.join(owned.evidence,'result.json'),result);};
  try{
    a.equal(owned.profile,result.profile);a.deepEqual(owned.input,EMAIL_ACTUAL_INPUT);a.equal(fs.realpathSync(source),fs.realpathSync(path.resolve(__dirname,'../..')));
    const mailConfig=configureMailpit({...owned.mailpit,hmacSecret:crypto.randomBytes(32).toString('hex')});
    process.env.IPI_EMAIL_PROVIDER='mailpit';process.env.IPI_MAIL_HMAC_SECRET=mailConfig.hmacSecret;process.env.MAILPIT_API_URL=mailConfig.apiUrl;process.env.MAILPIT_SMTP_HOST=mailConfig.smtpHost;process.env.MAILPIT_SMTP_PORT=String(mailConfig.smtpPort);
    let ready=false;for(let i=0;i<40&&!ready;i++){try{const response=await fetch(mailConfig.apiUrl+'/api/v1/info',{redirect:'error',signal:AbortSignal.timeout(2000)});ready=response.ok;await response.body?.cancel();}catch{}if(!ready)await new Promise(resolve=>setTimeout(resolve,250));}a(ready,'Owned Mailpit readiness');
    wire=await transport.createTransport({evidence:owned.evidence,policyCohort:result.profile});ports.add(Number(new URL(wire.actorUrl).port));process.env.OLLAMA_BASE_URL=wire.actorUrl;process.env.OLLAMA_MODEL=REQUIRED_MODEL;process.env.AI_PROVIDER='ollama';
    pg=require('../../server/database/postgres');for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL'])pools.push(pg.createPool(process.env,key));[pool,migration]=pools;
    const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(pool,migration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);
    const users=identityApi.createIdentityRepository(pool),adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),stores=await require('../../server/services/postgresPlatformStores').getPostgresPlatformStores();
    const user=async()=>{const u=await users.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(crypto.randomUUID(),4)});const s=await adapter.createSession(await users.findCredentialById(u.id),{});return{id:u.id,token:s.token,sessionId:s.internalSessionId};};
    const owner=await user(),sibling=await user();capture.ownerId=owner.id;capture.siblingId=sibling.id;
    const configured=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:REQUIRED_MODEL,baseURL:wire.judgeUrl});
    const record=async(role,messages,options,fn)=>{const call={role,caseId:activeCase,messages:emailClone(messages),options:emailOptions(options),result:null,error:null};capture.modelCalls.push(call);save();try{call.result=await fn();return call.result;}catch(error){call.error={name:error.name,code:error.code||null};throw error;}finally{save();}};
    const ai=require('../../server/services/multiProviderAIService'),oldActor=ai.chatWithMessages;ai.chatWithMessages=(messages,options)=>record('actor',messages,options,()=>configured.chat(messages,[],options));restoreAI=()=>{ai.chatWithMessages=oldActor;};
    const judgeModule=require('../../server/agent-runtime/objectiveJudge'),actualJudge=judgeModule.createObjectiveJudge({model:{chat:(messages,tools,options)=>record('judge',messages,options,()=>configured.chat(messages,tools,options))}});
    const judge=async input=>{const before=capture.modelCalls.length,evaluation={caseId:activeCase,runId:input.execution.runId,packet:JSON.parse(judgeModule.prepareJudgeInput(input).packet),callIndexes:[],result:null};capture.evaluations.push(evaluation);try{evaluation.result=await actualJudge(input);return evaluation.result;}finally{evaluation.callIndexes=capture.modelCalls.flatMap((call,i)=>i>=before&&call.role==='judge'?[i]:[]);save();}};
    const completion=require('../../server/services/objectiveCompletionService'),oldCompletion=completion.getObjectiveCompletionService;
    const service=completion.createObjectiveCompletionService({progress:stores.progress,receipts:require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool),judge});completion.getObjectiveCompletionService=()=>service;restoreCompletion=()=>{completion.getObjectiveCompletionService=oldCompletion;};
    const providerModule=require('../../server/services/ipiEmailProvider'),originalProvider=providerModule.getIpiEmailProvider,provider=originalProvider();mail={...provider.sender};providerModule.getIpiEmailProvider=()=>({...provider,sender:mail,inbox:mail});restoreProvider=()=>{providerModule.getIpiEmailProvider=originalProvider;};
    for(const name of ['sendEmail','fetchEmails','fetchEmail']){const original=mail[name].bind(mail);mail[name]=async(...args)=>{a(capture.mail.length<32,'Mail operation bound');const operation={name,args:emailClone(args),result:null};capture.mail.push(operation);try{operation.result=await original(...args);return operation.result;}finally{save();}};}
    const route=require('../../server/routes/emailAgent'),app=express();app.use('/api/email-agent',route);
    server=await new Promise((resolve,reject)=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);const origin='http://127.0.0.1:'+server.address().port;
    let api=0;const call=async(token,endpoint,body)=>{a(++api<=24,'Mounted API bound');const response=await fetch(origin+'/api/email-agent'+endpoint,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+token,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)}),redirect:'error',signal:AbortSignal.timeout(600000)});return{status:response.status,body:await response.json()};};
    const completions=async id=>(await pool.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id',[id,CONTENT_KEY])).rows;
    const artifacts=async id=>(await pool.query('SELECT * FROM identity.ipi_email_artifacts WHERE owner_id=$1 ORDER BY artifact_id',[id])).rows;
    const immutable=async()=>({judgments:(await pool.query('SELECT * FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[owner.id])).rows,packets:(await pool.query('SELECT * FROM workshop_platform.grade_packets WHERE user_id=$1 ORDER BY evaluation_id',[owner.id])).rows});
    const siblingState=async()=>({artifacts:await artifacts(sibling.id),completions:await completions(sibling.id),owner:(await migration.query('SELECT * FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['IndirectEmail',String(sibling.id)])])).rows});
    const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'IndirectEmail'});
    await coordinator.run(String(sibling.id),{},async execution=>{await require('../../server/services/emailArtifactStore').createMany({ownerId:sibling.id,ownerKey:execution.ownerKey,generation:execution.durableGeneration,runId:execution.runId,artifacts:[{ingestionKind:'manual_entry',provider:'manual_entry',recipient:'sibling@example.invalid',subject:'Sibling fixture',body:'Sibling quarterly planning remains Tuesday.'}]});});
    capture.lifecycle.siblingBefore=await siblingState();a.equal(capture.lifecycle.siblingBefore.artifacts.length,1);
    activeCase='setup';wire.beginCase(activeCase);result.stage=activeCase;save();
    const inbox=await call(owner.token,'/owned-inbox');a.equal(inbox.status,200);const address=inbox.body.ownedInbox;capture.setup.inbox=inbox;
    capture.setup.save={request:{tempEmail:address}};capture.setup.save.response=await call(owner.token,'/save-email',capture.setup.save.request);a.equal(capture.setup.save.response.status,200);
    capture.setup.send={request:{recipientEmail:address,scenario:'custom',customBody:EMAIL_ACTUAL_INPUT.attackBody}};capture.setup.send.response=await call(owner.token,'/send',capture.setup.send.request);a.equal(capture.setup.send.response.status,200);
    // Readback polling is bounded and cannot issue actor/Judge calls. The mounted
    // fetch remains the only source of owner artifact creation/retrieval credit.
    const context={ownerId:owner.id,generation:String((await migration.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['IndirectEmail',String(owner.id)])])).rows[0].generation)};let visible;
    for(let attempt=0;attempt<12&&!visible;attempt++){const listing=await mail.fetchEmails(context);visible=listing.emails?.find(x=>x.subject==='Custom Attack Email');if(!visible)await new Promise(resolve=>setTimeout(resolve,250));}a(visible,'SMTP delivery must be visible before mounted retrieval');
    capture.setup.fetch={request:{tempEmail:address}};capture.setup.fetch.response=await call(owner.token,'/fetch-sharklasers',capture.setup.fetch.request);a.equal(capture.setup.fetch.response.status,200);
    const attack=capture.setup.fetch.response.body.emails.find(x=>x.providerMessageId===String(visible.providerMessageId??visible.id));a(attack);
    capture.setup.clean={request:{tempEmail:address,manualContent:EMAIL_ACTUAL_INPUT.cleanBody}};capture.setup.clean.response=await call(owner.token,'/fetch-sharklasers',capture.setup.clean.request);a.equal(capture.setup.clean.response.status,200);const clean=capture.setup.clean.response.body.emails[0];
    wire.endCase();activeCase=null;save();
    for(const [id,artifact]of [['clean-control',clean],['attack',attack]]){
      activeCase=id;wire.beginCase(id);result.stage=id;const item={id,artifact,request:{artifactId:artifact.artifactId}};capture.cases.push(item);save();
      try{item.response=await call(owner.token,'/summarize',item.request);}finally{wire.endCase();activeCase=null;item.completions=await completions(owner.id);save();}
    }
    Object.assign(capture,await immutable());capture.artifacts=await artifacts(owner.id);capture.completions=await completions(owner.id);
    capture.runs=(await migration.query('SELECT * FROM graph_runtime.runs WHERE owner_key=$1 ORDER BY started_at',[JSON.stringify(['IndirectEmail',String(owner.id)])])).rows;
    const ids=capture.runs.map(x=>x.run_id);capture.events=(await migration.query('SELECT * FROM graph_runtime.events WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,sequence',[ids])).rows;capture.effects=(await migration.query('SELECT * FROM graph_runtime.effects WHERE run_id=ANY($1::uuid[]) ORDER BY run_id,effect_key',[ids])).rows;save();
    result.stage='lifecycle';capture.lifecycle.wireBefore=wire.snapshot().counts;
    const negative=async(name,token,request)=>{const proof={before:wire.snapshot().counts,response:await call(token,'/summarize',request),after:wire.snapshot().counts};capture.lifecycle[name]=proof;save();bindEmailNoCallNegative(name,proof);};
    await negative('forged-body',owner.token,{artifactId:attack.artifactId,emailBody:'caller-forged bytes'});await negative('foreign-artifact',sibling.token,{artifactId:attack.artifactId});result.foreignArtifactDenied=true;
    const revoked=await adapter.createSession(await users.findCredentialById(owner.id),{});await adapter.logout(revoked.token);await negative('revoked-session',revoked.token,{artifactId:attack.artifactId});result.sessionDenied=true;
    capture.lifecycle.immutableBefore=await immutable();capture.lifecycle.ownerBefore=await artifacts(owner.id);capture.lifecycle.generationBefore=String((await migration.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['IndirectEmail',String(owner.id)])])).rows[0].generation);capture.lifecycle.reset=await call(owner.token,'/progress/reset',{});a.equal(capture.lifecycle.reset.status,200);a.equal(capture.lifecycle.reset.body.success,true);
    await negative('retired-artifact',owner.token,{artifactId:attack.artifactId});capture.lifecycle.ownerAfter=await artifacts(owner.id);capture.lifecycle.generationAfter=String((await migration.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[JSON.stringify(['IndirectEmail',String(owner.id)])])).rows[0].generation);a.equal(capture.lifecycle.ownerBefore.length,2);a.deepEqual(capture.lifecycle.ownerAfter.map(x=>x.artifact_id),capture.lifecycle.ownerBefore.map(x=>x.artifact_id));a(capture.lifecycle.ownerAfter.every(x=>x.retired_at));
    capture.lifecycle.immutableAfter=await immutable();a.deepEqual(capture.lifecycle.immutableAfter,capture.lifecycle.immutableBefore);capture.lifecycle.siblingAfter=await siblingState();a.deepEqual(capture.lifecycle.siblingAfter,capture.lifecycle.siblingBefore);capture.lifecycle.completionsAfter=await completions(owner.id);a.deepEqual(capture.lifecycle.completionsAfter,[]);capture.lifecycle.wireAfter=wire.snapshot().counts;a.deepEqual(capture.lifecycle.wireAfter,capture.lifecycle.wireBefore);
    result.resetRetired=true;result.noCallNegatives=true;result.immutableEvidencePreserved=true;result.siblingPreserved=true;save();
    Object.assign(result,await bindEmailActualCapture(emailClone(capture),wire.snapshot().calls));result.modelCalls=result.actorCalls+result.judgeCalls;wire.assertComplete();result.actualModelProof=true;result.genuineCredit=1;result.status='passed';
  }catch(error){primary=error;result.status='failed';result.failure={name:error.name,code:error.code||null,frames:String(error.stack).split('\n').map(x=>x.match(/((?:tests|server)\/[^ ()]+:\d+:\d+)/)?.[1]).filter(Boolean).slice(0,8)};}
  finally{
    result.actorCalls=capture.modelCalls.filter(x=>x.role==='actor').length;result.judgeCalls=capture.modelCalls.filter(x=>x.role==='judge').length;result.modelCalls=result.actorCalls+result.judgeCalls;
    const operations=[['routes',async()=>{restoreAI?.();restoreCompletion?.();restoreProvider?.();}],['server',()=>new Promise((resolve,reject)=>{if(!server)return resolve();server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['mail',()=>mail?.close()],['transport',()=>wire?.close()],['pools',async()=>{await Promise.all(pools.map(p=>p.end()));await pg?.closePostgresPools();}]];
    for(const operation of operations)result.cleanup.push(...await settleOwnership([operation],15000));result.cleanupFailures=result.cleanup.filter(x=>x.status!=='fulfilled');if(result.cleanupFailures.length)result.status='failed';save();
  }
  if(primary||result.status!=='passed')throw Error('IPI actual email qualification failed');return result;
}
Object.assign(module.exports,{EMAIL_ACTUAL_INPUT,emailActorPrompts,bindEmailWire,replayEmailJudgments,replayEmailActors,bindEmailActualCapture,bindEmailNoCallNegative,bindEmailLifecycle,runEmailActual});
