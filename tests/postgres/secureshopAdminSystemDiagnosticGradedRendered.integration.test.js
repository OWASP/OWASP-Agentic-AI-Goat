'use strict';
// Opted actual-model/browser System diagnostic grading qualification.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const express = require('express');
const { randomUUID, randomBytes, createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');
const PREFIX = 'PG_SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_';
const STORES = Object.freeze(['IDENTITY','AGENTS','REVIEW','COMMERCE']);
const STORE_NAMES = Object.freeze({IDENTITY:'identity',AGENTS:'secureshop_agents',REVIEW:'secureshop_review',COMMERCE:'secureshop'});
const ASSERTION = 'standalone administrator earns canonical System diagnostic command objective from model-selected isolated execution and saved assessment';
const SCOPE = 'current-main standalone admin diagnostic command execution; original model selection, owned isolated effect, canonical Judge pass, fixed denial, saved recovery and reset';
const FLAGS = Object.freeze(['passed','isolatedStores','genuineAdminUiSession','canonicalObjectiveEnabled','actualModelDiagnosticPrepared','renderedProposalNoEffect','physicalVulnerableConfirm','ownedDiagnosticReceipt','originalAssessmentPost','canonicalJudgePass','genuineCredit','savedAssessmentGetRecovery','noDuplicateDiagnostic','physicalFixedDenial','siblingOperationDenied','siblingAssessmentDenied','resetSessionDenied','immutableHistoryRetained','fixtureCleaned']);
const MODEL = 'llama3.1:8b';
const MODEL_DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const TEMPLATE='/usr/bin/printf', ARGS="'diagnostic-baseline\\n'; /usr/bin/uname -n";
const PROPOSAL_PROMPT=`System diagnostic JSON:${JSON.stringify({cmd_template:TEMPLATE,args:ARGS})}`;
const OBJECTIVE='ss_system_diagnostic_command_execution';
function assertNativeTypedDiagnosticRequest(message, rawRequest) {
  const {currentExplicitSystemDiagnosticRequest}=
    require('../../server/services/secureshopRoleSystemDiagnosticProposal');
  const literal=currentExplicitSystemDiagnosticRequest(message);
  assert.deepEqual(literal,{cmd_template:TEMPLATE,args:ARGS});
  const request=JSON.parse(rawRequest);
  assert.ok(request.messages.some(row=>row.role==='user'
    && JSON.parse(row.content).message===message));
  const branches=request.format?.oneOf;
  assert.ok(Array.isArray(branches));
  assert.ok(branches.some(branch=>branch.properties?.reply));
  const tools=branches.flatMap(branch=>branch.properties?.tool_calls?.items?.oneOf||[]);
  const named=name=>tools.filter(tool=>tool.properties?.tool?.enum?.length===1
    &&tool.properties.tool.enum[0]===name);
  assert.ok(named('users_search').length===1);
  const diagnostic=named('system_diagnostic_prepare');
  assert.equal(diagnostic.length,1);
  assert.deepEqual(diagnostic[0].properties.args.properties.cmd_template.enum,[literal.cmd_template]);
  assert.deepEqual(diagnostic[0].properties.args.properties.args.enum,[literal.args]);
}
function failedAssessmentCapture(outcomes) {
  const entries=outcomes.slice(0,16).map(row=>{
    const bytes=Buffer.from(JSON.stringify(row),'utf8');
    if(bytes.length<=16384)return structuredClone(row);
    return {method:row.method,path:row.path,status:row.status,
      responseBytes:bytes.length,responseSha256:createHash('sha256').update(bytes).digest('hex'),
      responseTruncated:true};
  });
  return {responseCount:outcomes.length,httpResponses:entries,
    responsesTruncated:outcomes.length>entries.length||entries.some(row=>row.responseTruncated===true)};
}
function boundedAssessmentError(phase,error) {
  return {phase,name:String(error?.name||'Error').slice(0,64),
    code:typeof error?.code==='string'?error.code.slice(0,128):null,
    message:String(error?.message||'').slice(0,512),
    stack:typeof error?.stack==='string'?error.stack.slice(0,2048):null};
}
function observeAssessmentFactory(factory,errors) {
  return input=>{
    const original=factory(input);
    const observed=method=>async (...args)=>{
      try { return await original[method].apply(original,args); }
      catch(error) {
        if(errors.length<8)errors.push(boundedAssessmentError(method,error));
        throw error;
      }
    };
    return Object.freeze({...original,runAttempt:observed('runAttempt'),
      readOutcome:observed('readOutcome')});
  };
}
async function failedAssessmentSqlState(identity,agents,outcomes) {
  const post=outcomes.find(row=>row.method==='POST'
    &&row.path==='/agents/admin/assistant/system/diagnostic/assess');
  if(!post?.requestBody)return null;
  const {sessionId,requestId,proposalId}=post.requestBody;
  const key=require('../../server/services/secureshopSystemDiagnosticAssessment')
    .assessmentRequestId(sessionId,requestId,proposalId);
  const state={assessmentRequestId:key};
  const query=async(label,pool,sql,args)=>{
    try { state[label]=(await pool.query(sql,args)).rows; }
    catch(error) { state[label]={queryError:boundedAssessmentError(label,error)}; }
  };
  await query('turnRequests',agents,`SELECT session_id,request_id::text,status,request_hash,
    octet_length(result_json::text) AS result_bytes,
    result_json #>> '{taskMetadata,roleChat,systemDiagnosticOrigin,runId}' AS source_run_id
    FROM secureshop_agents.turn_requests
    WHERE (session_id=$1 AND request_id=$2) OR request_id=$3 LIMIT 4`,
  [sessionId,requestId,key]);
  await query('judgments',identity,`SELECT evaluation_id::text,verdict,disposition,evidence_digest,
    run_id::text,octet_length(packet) AS packet_bytes,
    octet_length(result_json::text) AS result_bytes,
    octet_length(judge_observations::text) AS observations_bytes
    FROM secureshop_auth.assessment_judgments WHERE objective_id=$1
    ORDER BY created_at DESC LIMIT 4`,[OBJECTIVE]);
  const sourceRunId=Array.isArray(state.turnRequests)
    ?state.turnRequests.find(row=>row.session_id===sessionId&&row.request_id===requestId)?.source_run_id:null;
  const assessmentSessions=Array.isArray(state.turnRequests)
    ?state.turnRequests.filter(row=>row.request_id===key).map(row=>row.session_id):[];
  await query('runs',identity,`SELECT run_id::text,owner_key,generation::text,status,last_node
    FROM graph_runtime.runs WHERE run_id=$1 OR owner_key=ANY($2::text[])
    ORDER BY started_at DESC LIMIT 8`,
  [sourceRunId,assessmentSessions.map(id=>JSON.stringify(['SecureShopBoundConversation',id]))]);
  const runIds=Array.isArray(state.runs)?state.runs.map(row=>row.run_id):[];
  await query('effects',identity,`SELECT run_id::text,owner_key,generation::text,effect_key,status
    FROM graph_runtime.effects WHERE run_id=ANY($1::uuid[]) LIMIT 12`,[runIds]);
  return state;
}
const ENABLED = process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_NATIVE === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && STORES.every(store => ['MIGRATION','RUNTIME'].every(role => process.env[`${PREFIX}${store}_${role}_URL`]));
function assertPrivateReceipt(value){
 assert.ok(value && typeof value==='object' && !Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),[...FLAGS,'scope','actorCalls','roleTurns','judgeCalls','executorCalls','errors'].sort());
 for(const flag of FLAGS)assert.equal(value[flag],true,flag);
 assert.equal(value.scope,SCOPE);assert.equal(value.roleTurns,2);
 assert.ok(Number.isSafeInteger(value.actorCalls)&&value.actorCalls>=4&&value.actorCalls<=14);
 assert.ok(Number.isSafeInteger(value.judgeCalls)&&value.judgeCalls>=1&&value.judgeCalls<=3);
 assert.ok(value.actorCalls+value.judgeCalls<=17);
 assert.equal(value.executorCalls,1);assert.deepEqual(value.errors,[]);
}
function assertGradedEvidence({proposal,turn,operation,receipt,assessment}={}){
 const {diagnosticRequestDigest}=require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract');
 const {canonicalDigest}=require('../../server/services/mcp/protocolContext');
 assert.equal(proposal?.cmd_template,TEMPLATE);assert.equal(proposal?.args,ARGS);
 assert.equal(proposal.requestSha256,diagnosticRequestDigest({operationId:proposal.proposalId,
  cmd_template:TEMPLATE,args:ARGS}));
 assert.equal(operation?.operation_id,proposal.proposalId);
 assert.deepEqual(operation.request_json,{operationId:proposal.proposalId,
  cmd_template:TEMPLATE,args:ARGS});
 assert.equal(operation.request_sha256.toString('hex'),proposal.requestSha256);
 assert.equal(receipt?.result?.operationId,proposal.proposalId);
 assert.equal(receipt.result.requestSha256,proposal.requestSha256);
 assert.equal(receipt.result.command,`${TEMPLATE} ${ARGS}`);
 assert.equal(receipt.result.executed,true);assert.equal(receipt.result.exitCode,0);
 assert.equal(Buffer.from(receipt.result.stdout,'base64').toString('utf8'),
  `diagnostic-baseline\nsystem-diag-${operation.target_id.replaceAll('-','')}\n`);
 assert.deepEqual(assessment?.post?.requestBody,{sessionId:turn.sessionId,
  requestId:turn.requestId,proposalId:proposal.proposalId});
 assert.equal(assessment.post.status,200);
 assert.deepEqual(Object.keys(assessment.post.body).sort(),['completed','judgment','replayed']);
 assert.equal(assessment.post.body.completed,true);
 assert.equal(assessment.post.body.replayed,false);
 assert.deepEqual(Object.keys(assessment.post.body.judgment).sort(),
  ['canRetry','evaluationId','verdict']);
 assert.equal(assessment.post.body.judgment.verdict,'pass');
 assert.equal(assessment.post.body.judgment.canRetry,false);
 assert.equal(assessment.saved.status,200);
 assert.equal(assessment.saved.body.completed,true);
 assert.equal(assessment.saved.body.replayed,true);
 assert.deepEqual(assessment.saved.body.judgment,assessment.post.body.judgment);
 assert.equal(assessment.judgment.evaluation_id,assessment.post.body.judgment.evaluationId);
 assert.equal(assessment.judgment.verdict,'pass');
 assert.equal(assessment.judgment.disposition,'awarded');
 assert.equal(assessment.judgment.objective_id,OBJECTIVE);
 assert.equal(assessment.judgment.evidence_digest,assessment.judgeTranscript.header.evidenceDigest);
 assert.equal(assessment.judgment.packet,assessment.judgeTranscript.header.packet);
 assert.equal(assessment.judgment.result_json.provider,'ollama');
 assert.equal(assessment.judgment.result_json.model,MODEL);
 assert.equal(assessment.judgment.result_json.verdict,'pass');
 assert.equal(assessment.contribution.evaluation_id,assessment.judgment.evaluation_id);
 assert.equal(assessment.completion.evaluation_id,assessment.judgment.evaluation_id);
 assert.match(assessment.judgment.evidence_digest,/^[a-f0-9]{64}$/);
 assert.equal(canonicalDigest(JSON.parse(assessment.judgment.packet)),
  canonicalDigest(JSON.parse(assessment.judgeTranscript.header.packet)));
}
function diagnosticDependencies({client,grading,agentsPool,composition,reset,modeAuthority}){
 return Object.freeze({systemDiagnosticClient:client,preparedGrading:grading,agentsPool,
  audit:reset.audit.agents,authenticatePersona:composition.personaAuth.authenticatePersona,modeAuthority});
}
function urlsFromEnvironment() {
  const urls = {}; let nonce; let port;
  for (const store of STORES) {
    for (const role of ['MIGRATION', 'RUNTIME']) {
      const key = `${store}_${role}`;
      const value = new URL(process.env[`${PREFIX}${key}_URL`]);
      assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
      assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
      assert.equal(value.username, `dvaia_${STORE_NAMES[store]}_${role.toLowerCase()}`);
      const match = new RegExp(`^/owasp_ai_goat_test_agent_host_([0-9a-f]{12})_${STORE_NAMES[store]}$`)
        .exec(value.pathname);
      assert.ok(match, `closed disposable database name required for ${key}`);
      nonce ??= match[1]; port ??= value.port;
      assert.equal(match[1], nonce); assert.equal(value.port, port);
      urls[key] = value.href;
    }
    assert.equal(new URL(urls[`${store}_MIGRATION`]).pathname,
      new URL(urls[`${store}_RUNTIME`]).pathname);
  }
  assert.equal(new Set(STORES.map(store => new URL(urls[`${store}_RUNTIME`]).pathname)).size, 4);
  return Object.freeze(urls);
}

async function migrateAndSeed(pools, workspace) {
  for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
    ['AGENTS', 'workshop-migrations/secureshop_agents'],
    ['REVIEW', 'workshop-migrations/secureshop_review'],
    ['COMMERCE', 'workshop-migrations/secureshop']]) {
    await migrate(pools[`${store}_MIGRATION`], path.join(workspace, 'db/postgres', directory));
  }
  await require('../../server/database/postgres/workshopPlatformSeed')
    .seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopAssessmentSeed')
    .seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
  await require('../../server/database/postgres/secureshopStandaloneSeed')
    .seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
  const seed = await pools.COMMERCE_MIGRATION.connect();
  try {
    await seed.query('BEGIN');
    await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
    await seed.query('COMMIT');
  } catch (error) { await seed.query('ROLLBACK'); throw error; }
  finally { seed.release(); }
}

async function listen(app) {
  return await new Promise(resolve => {
    const server = app.listen(0, '127.0.0.1', () => resolve(server));
  });
}
async function closeServer(server) {
  if (server) await new Promise((resolve, reject) =>
    server.close(error => error ? reject(error) : resolve()));
}
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
async function frameFor(page) {
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const iframe = await page.$('iframe[title="SecureShop"]');
    const frame = iframe && await iframe.contentFrame().catch(() => null);
    if (frame && !frame.detached) return frame;
    await sleep(50);
  }
  throw new Error('Standalone SecureShop frame did not mount');
}
async function visibleSetupState(page) {
  return page.evaluate(() => [...document.querySelectorAll('h1,h2,[role="alert"],[role="status"],button')]
    .filter(node => node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden')
    .map(node => String(node.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 160))
    .filter(Boolean).slice(0, 16)).catch(() => []);
}
async function boundedResponse(response, limit = 524288) {
  const reader = response.clone().body?.getReader?.();
  if (!reader) return { bodyUnavailable: true };
  const chunks = []; let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.byteLength;
      if (size > limit) { await reader.cancel().catch(() => {}); return { oversized: true, bytes: size }; }
      chunks.push(Buffer.from(item.value));
    }
    const body = Buffer.concat(chunks, size);
    const bodyUtf8=new TextDecoder('utf-8',{fatal:true}).decode(body);
    return { bytes: size, bodyUtf8,sha256: createHash('sha256').update(body).digest('hex'),
      value: JSON.parse(bodyUtf8) };
  } catch (error) { return { bytes: size, decodeError: error.name || 'response-decode-failed' }; }
  finally { reader.releaseLock?.(); }
}
async function clickButton(frame, label) {
  await frame.waitForFunction(text => [...document.querySelectorAll('button')]
    .some(button => button.textContent.trim() === text && !button.disabled
      &&button.getClientRects().length>0),
  { timeout: 30000 }, label);
  const buttons = await frame.$$('button');
  for (const button of buttons) {
    const match = await button.evaluate((node, text) =>
      node.textContent.trim() === text && !node.disabled&&node.getClientRects().length>0, label);
    if (match) {await button.evaluate(node=>node.scrollIntoView({block:'center'}));
      const hit=await button.evaluate(node=>{const box=node.getBoundingClientRect();
        const found=document.elementFromPoint(box.left+box.width/2,box.top+box.height/2);
        return found===node||node.contains(found);});
      assert.equal(hit,true,`physical button unobstructed: ${label}`);
      await button.click(); return; }
  }
  throw new Error(`Enabled button unavailable: ${label}`);
}
async function loginShop(page, origin, username, password) {
  const landing = await page.goto(`${origin}/secureshop/login`, { waitUntil: 'domcontentloaded' });
  assert.ok([200, 304].includes(landing.status()));
  await page.waitForSelector('#ss-login-user');
  await page.type('#ss-login-user', username); await page.type('#ss-login-pw', password);
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === '/api/secureshop/auth/bootstrap'
      && response.request().method() === 'POST';
  }, { timeout: 30000 });
  await page.click('button[type="submit"]');
  const response = await pending; assert.equal(response.status(), 200);
  const frame = await frameFor(page);
  await frame.waitForSelector('[aria-label="Account menu"]');
  return frame;
}
async function logoutShop(frame, page, origin) {
  await frame.click('[aria-label="Account menu"]');
  const pending = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === '/api/secureshop/auth/logout'
      && response.request().method() === 'POST';
  }, { timeout: 30000 });
  await clickButton(frame, 'Sign out'); assert.equal((await pending).status(), 200);
  await page.waitForFunction(() => location.pathname === '/secureshop');
}

async function recordBrowser(browser, target, executablePath, expectedSha) {
  const pid = browser?.process?.()?.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const real = await fs.realpath(executablePath);
  const actualSha = createHash('sha256').update(await fs.readFile(real)).digest('hex');
  assert.equal(actualSha, expectedSha);
  const startTime = execFileSync('ps', ['-p', String(pid), '-o', 'lstart='], { encoding: 'utf8' }).trim();
  assert.match(startTime, /^\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$/);
  const temp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(temp, JSON.stringify({ schemaVersion: 1, processes: [{
    kind: 'admin_system_diagnostic_graded_browser', pid, startTime,
    executablePath: real, executableSha256: actualSha }] }) + '\n', { mode: 0o600, flag: 'wx' });
  await fs.rename(temp, target);
}

test(ASSERTION, { skip: !ENABLED, timeout: 600000 }, async t => {
  const workspace = path.resolve(process.env.OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE || '');
  assert.equal(workspace, process.cwd(), 'current checkout required; no source copy');
  const build = path.resolve(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_BUILD || '');
  assert.equal(build, path.join(workspace, 'client/build'));
  const executablePath = path.resolve(process.env.PUPPETEER_EXECUTABLE_PATH || '');
  const browserSha = process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_SHA256;
  assert.match(browserSha || '', /^[a-f0-9]{64}$/);
  const recordPath = path.resolve(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_RECORD_PATH || '');
  const evidencePath = path.resolve(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_EVIDENCE_PATH || '');
  assert.equal(path.dirname(recordPath), path.dirname(evidencePath));
  assert.equal(path.dirname(evidencePath), path.resolve(process.env.TMPDIR, '../..'));
  assert.equal(process.env.OLLAMA_MODEL, MODEL);
  assert.equal(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_MODEL_DIGEST,MODEL_DIGEST);
  const diagnosticURL = new URL(process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_EXECUTOR_URL || '');
  assert.equal(diagnosticURL.protocol, 'http:'); assert.equal(diagnosticURL.hostname, '127.0.0.1');
  assert.equal(diagnosticURL.pathname, '/');
  const diagnosticToken = process.env.SECURESHOP_ADMIN_SYSTEM_DIAGNOSTIC_GRADED_BROWSER_EXECUTOR_TOKEN;
  assert.match(diagnosticToken || '', /^[A-Za-z0-9_-]{43,128}$/);
  const urls = urlsFromEnvironment();
  const pools = Object.fromEntries(STORES.flatMap(store => ['MIGRATION','RUNTIME'].map(role =>
    [`${store}_${role}`, new Pool({ connectionString: urls[`${store}_${role}`],
      max: role === 'RUNTIME' ? 12 : 3 })])));
  const leasePool = new Pool({ connectionString: urls.IDENTITY_RUNTIME, max: 3 });
  const status = Object.fromEntries(FLAGS.map(flag => [flag, false]));
  Object.assign(status, { scope: SCOPE, actorCalls: 0, roleTurns: 0, judgeCalls: 0,
    executorCalls: 0, errors: [] });
  const pageErrors = [], requestFailures = [], cleanupErrors = [], modelCalls = [],
    requestLog = [], bootstraps = [], executorWire = [], judgeTranscripts = [],
    savedProposals = [], confirmOutcomes = [], assessmentOutcomes=[],assessmentErrors=[],
    judgeResults=[],turnSpans=[],turns=[];
  let reset, composition, diagnostic, server, browser, page, profile, failure, stage = 'setup',
    actorTransport,judgeTransport,judgeInvocations=0,assessmentEvidence=null,assessmentSqlState=null;
  let confirmPosts = 0, lostAck = 0;
  try {
    await migrateAndSeed(pools, workspace); status.isolatedStores = true;
    const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME;
    const review = pools.REVIEW_RUNTIME, commerce = pools.COMMERCE_RUNTIME;
    const auth = require('../../server/services/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthService({ repository:
        require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(identity);
    const audit = require('../../server/services/secureshopBoundAuditComposition')
      .createSecureShopBoundAuditComposition({ agentsPool: agents, reviewPool: review,
        includeRunArtifacts: true });
    const observedFetch = async (input, init) => {
      const url = new URL(input), method = init?.method || 'GET';
      assert.ok(executorWire.length<16,'bounded isolated executor transport calls');
      const event={method,path:url.pathname,status:null,bytes:null,responseSha256:null};
      executorWire.push(event);
      if (method === 'POST' && url.pathname === '/secureshop/system/diagnostic') {
        const wire = JSON.parse(init?.body || 'null');
        assert.ok(Buffer.byteLength(init.body,'utf8')<=131072);
        event.operationId = wire.request.operationId;
        event.requestSha256 = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract')
          .diagnosticRequestDigest(wire.request);
        event.requestBody=init.body;
      }
      try {
        const response=await fetch(input,init);
        event.status=response.status;
        const observed=await boundedResponse(response);
        event.bytes=observed.bytes??null;
        event.responseSha256=observed.sha256||null;
        if(method==='POST'&&url.pathname==='/secureshop/system/diagnostic'){
          event.responseBody=observed.bodyUtf8??null;
          assert.ok(observed.value,'original isolated executor response must be bounded JSON');
          require('../../sidecars/sandbox-runner/owned-system/diagnostic-wire')
            .validateBoundDiagnosticResult(JSON.parse(init.body),observed.value);
        }
        return response;
      }catch(error){event.error={name:error.name||'Error',code:error.code||null};throw error;}
    };
    const diagnosticClient = require('../../server/services/secureshopSystemDiagnosticClient')
      .createSecureShopSystemDiagnosticClient({ baseURL: diagnosticURL.href,
        token: diagnosticToken, fetchImpl: observedFetch });
    reset = require('../../server/services/secureshopCleanupComposition')
      .createSecureShopCleanupComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, leasePool, audit });
    judgeTransport = await require('./secureshopMailActualTransport')
      .createMailActualTransport({maxHttpCalls:3,allowMetadata:true});
    process.env.OLLAMA_BASE_URL=judgeTransport.judgeUrl;
    process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=MODEL;
    const configuredJudge=require('../../server/agent-runtime/objectiveJudge')
      .createObjectiveJudge({observeExecutionTranscript:value=>judgeTranscripts.push(structuredClone(value))});
    const judge=async input=>{
      assert.ok(++judgeInvocations<=1,'one canonical diagnostic assessment');
      const value=await configuredJudge(input);
      try {
        const bytes=Buffer.from(JSON.stringify(value),'utf8');
        judgeResults.push(bytes.length<=65536?{result:structuredClone(value)}
          :{resultBytes:bytes.length,resultSha256:createHash('sha256').update(bytes).digest('hex')});
      } catch {}
      status.judgeCalls=judgeTransport.calls.filter(call=>call.kind==='judge').length;
      assert.ok(status.judgeCalls>=1&&status.judgeCalls<=3);
      return value;
    };
    require('../../server/agent-runtime/judgeProviderConfiguration')
      .registerConfiguredJudge(judge,()=>require('../../server/agent-runtime/judgeProviderConfiguration')
        .readJudgeProviderConfig(configuredJudge));
    const grading = await require('../../server/services/secureshopGradingBootstrap')
      .createSecureShopGradingBootstrap({ identityPool: identity, agentsPool: agents, progress,
        resetComposition: reset,judge,
        expectedIdentityDatabase: new URL(urls.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(urls.AGENTS_RUNTIME).pathname.slice(1) });
    const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({ repository:
      require('../../server/database/postgres/secureshopSceneRepository')
        .createSecureShopSceneRepository({ pool: identity, launches: reset.launches }),
      reviewPool: review, launches: reset.launches });
    const modeRepository = require('../../server/database/postgres/secureshopModeRepository')
      .createSecureShopModeRepository(identity);
    const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority')
      .createFeatureModeAuthority({ progress: modeRepository, launches: reset.launches });
    const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
      .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority,
        audit: reset.audit.agents });
    actorTransport=await require('./secureshopMailActualTransport')
      .createMailActualTransport({maxHttpCalls:14,allowMetadata:true});
    assert.equal(actorTransport.digest,MODEL_DIGEST);assert.equal(judgeTransport.digest,MODEL_DIGEST);
    const provider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      baseUrl: actorTransport.actorUrl, model: MODEL });
    for (const method of ['chat','finalResponse']) {
      const original = provider[method].bind(provider);
      provider[method] = async input => {
        const result = await original({ ...input, signal: AbortSignal.any([
          AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
        assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
        assert.equal(result.mocked, false); assert.notEqual(result.fallback, true);
        modelCalls.push({ method, offeredTools: (input.tools || []).map(tool => `${tool.agent}.${tool.tool}`),
          stopReason: result.stop_reason || null,
          tools: (result.tool_uses || []).map(tool => ({ name: tool.name, args: tool.args })) });
        return result;
      };
    }
    let diagnosticValue;
    const assessmentModule=require('../../server/services/secureshopSystemDiagnosticAssessment');
    const originalAssessmentFactory=assessmentModule.createSystemDiagnosticAssessment;
    assessmentModule.createSystemDiagnosticAssessment=
      observeAssessmentFactory(originalAssessmentFactory,assessmentErrors);
    try { composition = require('../../server/services/secureshopBoundReviewComposition')
      .createSecureShopBoundReviewComposition({ identityPool: identity, agentsPool: agents,
        reviewPool: review, commercePool: commerce, resetComposition: reset,
        gradingBootstrap: grading, scenes, modeAuthority, toolPolicyRepository,
        getSystemDiagnostic: () => diagnosticValue, fixtures: [],
        requiredObjectives: [OBJECTIVE],
        jwtSecret: 'disposable-diagnostic-chat-persona-secret-at-least-32-bytes',
        agentRuntime: { provider }, judge }); }
    finally { assessmentModule.createSystemDiagnosticAssessment=originalAssessmentFactory; }
    diagnostic = await require('../../server/services/secureshopBoundReviewComposition')
      .createOptionalSystemDiagnosticComposition(diagnosticDependencies({ client: diagnosticClient,
        grading, agentsPool: agents, composition, reset, modeAuthority }));
    diagnosticValue = diagnostic;
    assert.equal(diagnostic.ready, true); assert.equal(composition.roleAssistants.admin.ready, true);
    await composition.repositories.personas.ensureTemplates();
    await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
      .assertBoundToolPolicyReadiness(agents);
    const bootstrap = require('../../server/services/secureshopStandaloneBootstrap')
      .createSecureShopStandaloneBootstrap({ launches: composition.launches,
        personaAuth: composition.personaAuth, authService: auth });
    const standaloneMode = require('../../server/services/secureshopStandaloneMode')
      .createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
    const assessmentCatalog = require('../../server/services/secureshopAssessmentCatalog')
      .createSecureShopAssessmentCatalog({ pool: identity, authService: auth });
    const adminLogin=await auth.login({username:'student_admin',password:'student123'});
    const objective=(await assessmentCatalog.list(adminLogin.context)).objectives
      .find(value=>value.objectiveId===OBJECTIVE);
    assert.equal(objective?.qualification,'native-model');assert.equal(objective.enabled,false);
    assert.equal((await assessmentCatalog.set(adminLogin.context,{objectiveId:OBJECTIVE,
      enabled:true,expectedRevision:objective.revision})).enabled,true);
    status.canonicalObjectiveEnabled=true;
    const tenant=await auth.establishTenantContext(adminLogin.context);
    const siblingId=randomUUID(),siblingName=`diagnostic_sibling_${randomUUID().slice(0,8)}`;
    const siblingPassword='disposable-diagnostic-sibling';
    const siblingHash=await require('bcryptjs').hash(siblingPassword,12);
    const siblingRow=(await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.principals
      (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
      RETURNING owner_id,shop_user_id`,[siblingId,siblingName,
      `${siblingName}@example.invalid`,siblingHash])).rows[0];
    await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
      (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
    [tenant.tenantId,siblingId,siblingRow.shop_user_id]);
    const siblingLogin=await auth.login({username:siblingName,password:siblingPassword});
    const siblingBase=await bootstrap(siblingLogin.context);
    assert.equal(siblingBase.persona.user.role,'admin');
    const protectedReset = require('../../server/services/secureshopStandaloneReset')
      .createSecureShopStandaloneReset({ identityPool: identity, authService: auth,
        launches: composition.launches, scenes, resetCoordinator: reset.launchResetCoordinator,
        preflight: reset.sceneResetPreflight });
    const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
      .createSecureShopStorePublicCatalogRepository({ identityPool: identity, reviewPool: review,
        commercePool: commerce });
    const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
      .createRegisteredAdminResetEnvelope({activeKeyId:'diagnostic-graded-owned',
        keys:new Map([['diagnostic-graded-owned',randomBytes(32)]])});
    const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
      .createRegisteredAdminResetRepository({pool:identity,envelope:resetEnvelope});
    await resetRepository.checkReadiness();
    const mounted = Object.freeze({ ...composition, systemDiagnostic: diagnostic,
      standaloneAuth: Object.freeze({ service: auth, bootstrap, reset: protectedReset,
        registeredAdminReset:require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({repository:resetRepository}),
        mode: standaloneMode, assessmentObjectives: assessmentCatalog,
        assessmentRecovery:require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({identityPool:identity,authService:auth,bootstrap,
            launches:composition.launches,personaAuth:composition.personaAuth,
            personaAuthority:grading.personaAuthority,modeAuthority,scenes,judge}),
        cartImport:require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({bootstrap,launches:composition.launches,
            personaAuth:composition.personaAuth,commerce:composition.commerce}) }),
      publicCatalog });
    const bound = await require('../../server/services/secureshopBoundApplication')
      .createSecureShopBoundApplication({ engine: 'postgres', shopEnabled: true,
        applicationMode:'standalone',
        authenticateToken: (_request, response) => response.sendStatus(401), audit: async () => {},
        agentRuntime: {}, getComposition: async options => {
          assert.equal(options.personaInboxFeature,false);
          assert.equal(options.mcpTrustFeature,false);
          assert.equal(options.ssrfFeature,false);
          return mounted;
        } });
    assert.equal(bound.standaloneReadiness.ready,true);
    assert.ok(Object.values(bound.standaloneReadiness.checks).every(value=>value===true));
    const app = express(); app.use(express.json()); server = await listen(app);
    const origin = `http://127.0.0.1:${server.address().port}`;
    app.use('/api/secureshop/auth', (request, response, next) => {
      const original = response.json.bind(response);
      response.json = value => {
        if (request.method === 'POST' && request.path === '/bootstrap'
          && response.statusCode === 200 && value?.persona?.user?.role === 'admin') {
          bootstraps.push({ launch: value.bearer,
            authorization: `Bearer ${value.persona.token}` });
        }
        return original(value);
      };
      next();
    });
    app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth')
      .createSecureShopStandaloneAuthRouter({ ...mounted.standaloneAuth,
        allowedOrigins: [origin], secureCookies: false }));
    app.use('/api/secureshop', (request, response, next) => {
      const entry = { method: request.method, path: request.path,
        launch: request.get('x-owasp-ai-goat-secureshop-launch') || null,
        authorization: request.get('authorization') || null,
        ...(request.method === 'POST' ? { body: structuredClone(request.body) } : {}) };
      if (/assistant|diagnostic/.test(request.path)) {
        requestLog.push(entry); response.once('finish', () => { entry.status = response.statusCode; });
      }
      if (request.method === 'GET' && /^\/agents\/admin\/assistant\/operations\/[0-9a-f-]{36}\/[0-9a-f-]{36}$/i.test(request.path)) {
        const original = response.json.bind(response);
        response.json = value => {
          if (response.statusCode === 200) savedProposals.push(structuredClone(value));
          return original(value);
        };
      }
      if (request.method === 'POST'
        && request.path === '/agents/admin/assistant/system/diagnostic/confirm') {
        confirmPosts++;
        const original = response.json.bind(response);
        response.json = value => {
          confirmOutcomes.push({ status: response.statusCode,
            state: value?.state || null, code: value?.code || null,
            operationId: value?.operationId || null });
          if (value?.state === 'completed' && lostAck === 0) {
            lostAck++;
            response.status(503);
            return original({ error: 'Controlled diagnostic acknowledgement unavailable',
              code: 'SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN' });
          }
          return original(value);
        };
      }
      if (request.path.startsWith('/agents/admin/assistant/system/diagnostic/assess')) {
        const original=response.json.bind(response);
        response.json=value=>{
          assessmentOutcomes.push({method:request.method,path:request.path,status:response.statusCode,
            body:structuredClone(value),requestBody:request.method==='POST'?structuredClone(request.body):null});
          return original(value);
        };
      }
      next();
    });
    app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch')
      .createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
    app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog')
      .createSecureShopPublicCatalogRouter({ getRepository: () => publicCatalog,
        isAvailable: async () => true }));
    app.use(express.static(build, { setHeaders: response =>
      response.set('Access-Control-Allow-Origin', '*') }));
    app.get(/.*/, (_request, response) => response.sendFile('index.html', { root: build }));

    profile = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-admin-diagnostic-graded-'));
    browser = await require('puppeteer').launch({ headless: true, userDataDir: profile,
      executablePath, args: ['--disable-background-networking'] });
    await recordBrowser(browser, recordPath, executablePath, browserSha);
    page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
    await page.setRequestInterception(true);
    page.on('request', request => request.url().startsWith(`${origin}/`)
      ? request.continue() : request.abort());
    page.on('pageerror', error => pageErrors.push(error.name || 'PageError'));
    page.on('requestfailed', request => {
      const url = new URL(request.url());
      if (url.origin === origin && requestFailures.length < 16) requestFailures.push({
        method: request.method(), path: url.pathname,
        error: String(request.failure()?.errorText || 'request failed').slice(0, 120),
      });
    });
    stage = 'customer-target-preparation';
    let frame = await loginShop(page, origin, 'student_customer', 'student123');
    const product = await frame.evaluate(async () => {
      const response = await fetch('/api/secureshop/products?limit=1');
      if (!response.ok) throw Error('Product target preparation failed'); return response.json();
    });
    assert.ok(Array.isArray(product.products) && product.products.length === 1);
    await logoutShop(frame, page, origin);
    stage = 'admin-physical-login';
    frame = await loginShop(page, origin, 'student_admin', 'student123');
    await frame.waitForSelector('a[href="/secureshop/admin"]');
    await frame.click('a[href="/secureshop/admin"]');
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    assert.equal(bootstraps.length, 1); status.genuineAdminUiSession = true;
    const admissions = async () => (await agents.query(`SELECT operation_id,target_id,request_sha256,request_json
      FROM secureshop_agents.bound_system_diagnostic_admissions ORDER BY operation_id`)).rows;
    assert.deepEqual(await admissions(), []);
    const creditRows=async()=>({
      judgments:(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE objective_id=$1 ORDER BY evaluation_id',[OBJECTIVE])).rows,
      contributions:(await identity.query(`SELECT c.* FROM secureshop_auth.assessment_contributions c
        JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
        WHERE j.objective_id=$1 ORDER BY c.evaluation_id`,[OBJECTIVE])).rows,
      completions:(await identity.query('SELECT * FROM secureshop_auth.assessment_completions WHERE objective_id=$1 ORDER BY evaluation_id',[OBJECTIVE])).rows,
      workshop:(await identity.query('SELECT * FROM workshop_platform.completions WHERE objective_id=$1 ORDER BY objective_id',[OBJECTIVE])).rows,
    });
    const initialCreditRows=await creditRows();
    assert.deepEqual(initialCreditRows,{judgments:[],contributions:[],completions:[],workshop:[]});
    const executorPosts = () => executorWire.filter(row => row.method === 'POST'
      && row.path === '/secureshop/system/diagnostic');
    assert.equal(executorPosts().length, 0);
    const originalMessage = PROPOSAL_PROMPT;
    const prepare = async message => {
      const savedBefore=savedProposals.length;
      const wireStart=actorTransport.calls.length;
      await frame.waitForSelector('[data-testid="admin-role-composer-slot"] textarea');
      await frame.type('[data-testid="admin-role-composer-slot"] textarea', message);
      await clickButton(frame, 'Send to admin assistant');
      const deadline=Date.now()+120000;
      while(savedProposals.length===savedBefore&&Date.now()<deadline)await sleep(50);
      assert.ok(savedProposals.length>savedBefore,
        'new protected turn must publish its own saved proposal before the card');
      await frame.waitForFunction(()=>[...document.querySelectorAll(
        'section[aria-label="Admin System diagnostic confirmation"] button')]
        .some(button=>button.textContent.trim()==='Confirm System diagnostic'&&!button.disabled),
      {timeout:120000});
      const card = await frame.$eval('section[aria-label="Admin System diagnostic confirmation"]', node => ({
        command: node.textContent, html: node.outerHTML.slice(0, 2048),
        enabled: [...node.querySelectorAll('button')].some(button =>
          button.textContent.trim() === 'Confirm System diagnostic' && !button.disabled),
      }));
      assert.equal(card.enabled, true, JSON.stringify(card));
      const saved=savedProposals.at(-1);
      assert.ok(saved?.sessionId&&saved?.requestId);
      turnSpans.push({sessionId:saved.sessionId,requestId:saved.requestId,
        wireStart,wireEnd:actorTransport.calls.length});
      return card;
    };
    stage = 'vulnerable-model-prepare';
    const firstCard = await prepare(originalMessage);
    assertNativeTypedDiagnosticRequest(originalMessage,
      actorTransport.calls[turnSpans[0].wireStart].request);
    assert.ok(firstCard.command.includes(TEMPLATE));
    assert.ok(firstCard.command.includes(ARGS));
    assert.deepEqual(await admissions(), []); assert.equal(executorPosts().length, 0);
    status.renderedProposalNoEffect = true;
    const selectedCalls = () => modelCalls.filter(call => call.method === 'chat'
      && call.stopReason === 'tool_use' && call.offeredTools.includes('admin.system_diagnostic_prepare')
      && call.tools.some(tool => tool.name === 'admin.system_diagnostic_prepare'
        && tool.args?.cmd_template === TEMPLATE && tool.args?.args === ARGS));
    assert.equal(selectedCalls().length, 1);
    assert.ok(modelCalls.some(call => call.stopReason === 'end_turn'));
    status.actualModelDiagnosticPrepared = true;
    stage = 'vulnerable-physical-confirm';
    await clickButton(frame, 'Confirm System diagnostic');
    await frame.waitForFunction(() => [...document.querySelectorAll('button')]
      .some(button => button.textContent.trim() === 'Check saved System diagnostic' && !button.disabled),
    { timeout: 120000 });
    assert.equal(confirmPosts, 1); assert.equal(lostAck, 1);
    assert.equal(executorPosts().length, 1);
    assert.ok(savedProposals.length >= 1 && savedProposals.length <= 4);
    const original = savedProposals.find(value => value?.systemDiagnosticProposal?.action === 'system_diagnostic');
    assert.ok(original && original.status === 'completed' && original.replayed === true
      && original.stopReason === 'end_turn');
    const proposal = original.systemDiagnosticProposal;
    assert.deepEqual(Object.keys(proposal).sort(), ['version','proposalId','action','cmd_template','args',
      'scopeKey','diagnosticCapability','sourceSnapshotSha256','modeCapability',
      'requestSha256','proposalSha256'].sort());
    assert.equal(proposal.cmd_template, TEMPLATE); assert.equal(proposal.args, ARGS);
    assert.equal(proposal.modeCapability.effectiveMode, 'vuln');
    const requestDigest = require('../../sidecars/sandbox-runner/owned-system/diagnostic-contract')
      .diagnosticRequestDigest({ operationId: proposal.proposalId,
        cmd_template: proposal.cmd_template, args: proposal.args });
    assert.equal(proposal.requestSha256, requestDigest);
    const { proposalSha256, ...publicBody } = proposal;
    assert.equal(proposalSha256,
      require('../../server/services/mcp/protocolContext').canonicalDigest(publicBody));
    const turn=(await agents.query(`SELECT status,request_hash,result_json FROM
      secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
    [original.sessionId,original.requestId])).rows;
    assert.equal(turn.length,1);assert.equal(turn[0].status,'completed');
    const meta=turn[0].result_json?.taskMetadata?.roleChat;
    assert.equal(meta?.systemDiagnosticProposal?.proposalId,proposal.proposalId);
    const source=meta?.systemDiagnosticOrigin;
    assert.equal(source?.version,1);assert.match(source.runId,/^[0-9a-f-]{36}$/);
    assert.equal(JSON.parse(source.sourceEnvelope).message,originalMessage);
    assert.ok(Array.isArray(source.traceEventIds)&&source.traceEventIds.length>=4);
    const traced=(await agents.query(`SELECT event_id,kind,agent_ns,tool_name,params_json,result_json,provider
      FROM secureshop_agents.agent_trace WHERE session_id=$1 AND event_id=ANY($2::text[])`,
    [original.sessionId,source.traceEventIds])).rows;
    assert.equal(traced.length,source.traceEventIds.length);
    const byEvent=new Map(traced.map(row=>[row.event_id,row]));
    const ordered=source.traceEventIds.map(id=>byEvent.get(id));
    assert.ok(ordered.every(Boolean));
    const decisions=ordered.filter(row=>row.kind==='model_decision');
    const toolCalls=ordered.filter(row=>row.kind==='local_tool_call'
      &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare');
    const toolResults=ordered.filter(row=>row.kind==='local_tool_result'
      &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare');
    assert.equal(toolCalls.length,1);assert.equal(toolResults.length,1);
    assert.deepEqual(JSON.parse(toolCalls[0].params_json),
      {cmd_template:proposal.cmd_template,args:proposal.args});
    assert.ok(decisions.some(row=>JSON.parse(row.params_json)?.toolCalls?.some(call=>
      call.name==='admin.system_diagnostic_prepare'&&call.args?.cmd_template===proposal.cmd_template
      &&call.args?.args===proposal.args)));
    assert.ok(decisions.some(row=>JSON.parse(row.result_json)?.decision==='final'));
    const rows = await admissions();
    assert.equal(rows.length, 1); assert.equal(rows[0].operation_id, proposal.proposalId);
    assert.equal(rows[0].request_sha256.toString('hex'), requestDigest);
    assert.deepEqual(rows[0].request_json, { operationId: proposal.proposalId,
      cmd_template: proposal.cmd_template, args: proposal.args });
    const completed = (await agents.query(`SELECT state,receipt_json,receipt_sha256 FROM
      secureshop_agents.bound_system_diagnostic_outcomes WHERE operation_id=$1`,
    [proposal.proposalId])).rows;
    assert.equal(completed.length, 1); assert.equal(completed[0].state, 'completed');
    assert.equal(completed[0].receipt_json.result.operationId, proposal.proposalId);
    assert.equal(completed[0].receipt_json.result.requestSha256, proposal.requestSha256);
    assert.equal(completed[0].receipt_json.result.command, `${TEMPLATE} ${ARGS}`);
    assert.equal(completed[0].receipt_json.result.executed, true);
    assert.equal(completed[0].receipt_json.result.exitCode, 0);
    assert.equal(Buffer.from(completed[0].receipt_json.result.stdout, 'base64').toString('utf8'),
      `diagnostic-baseline\nsystem-diag-${rows[0].target_id.replaceAll('-', '')}\n`);
    assert.equal(completed[0].receipt_sha256.toString('hex'),
      require('../../server/services/mcp/protocolContext').canonicalDigest(completed[0].receipt_json));
    status.ownedDiagnosticReceipt = true; status.physicalVulnerableConfirm = true;
    await clickButton(frame,'Check saved System diagnostic');
    await frame.waitForFunction(text=>[...document.querySelectorAll('pre')]
      .some(node=>node.textContent===text),{timeout:120000},
    `diagnostic-baseline\nsystem-diag-${rows[0].target_id.replaceAll('-','')}\n`);
    stage='canonical-assessment';
    const assessmentPath=`/agents/admin/assistant/system/diagnostic/assess/${original.sessionId}/${original.requestId}/${proposal.proposalId}`;
    await clickButton(frame,'Check saved System diagnostic assessment');
    await frame.waitForFunction(()=>[...document.querySelectorAll('section[aria-label="Admin System diagnostic assessment"] button')]
      .some(button=>button.textContent.trim()==='Check System diagnostic objective'&&!button.disabled),
    {timeout:30000});
    const initialAssessment=assessmentOutcomes.find(entry=>entry.method==='GET'&&entry.path===assessmentPath);
    assert.deepEqual(initialAssessment?.body,{completed:false,status:'unconfirmed',modelEvaluated:false});
    assert.deepEqual(await creditRows(),initialCreditRows);
    await clickButton(frame,'Check System diagnostic objective');
    await frame.waitForFunction(()=>[...document.querySelectorAll('section[aria-label="Admin System diagnostic assessment"] [role="status"]')]
      .some(node=>node.textContent.trim()==='Objective completed.'),{timeout:180000});
    const assessmentPosts=assessmentOutcomes.filter(entry=>entry.method==='POST'
      &&entry.path==='/agents/admin/assistant/system/diagnostic/assess');
    assert.equal(assessmentPosts.length,1);
    assert.deepEqual(assessmentPosts[0].requestBody,{sessionId:original.sessionId,
      requestId:original.requestId,proposalId:proposal.proposalId});
    assert.equal(assessmentPosts[0].status,200);
    const graded=assessmentPosts[0].body;
    assert.equal(graded.completed,true);assert.equal(graded.replayed,false);
    assert.equal(graded.judgment?.verdict,'pass');
    assert.match(graded.judgment.evaluationId,/^[0-9a-f-]{36}$/);
    const completedAssessment=assessmentOutcomes.filter(entry=>entry.method==='GET'
      &&entry.path===assessmentPath).at(-1);
    assert.equal(completedAssessment?.status,200);
    assert.equal(completedAssessment.body.completed,true);
    assert.equal(completedAssessment.body.replayed,true);
    assert.deepEqual(completedAssessment.body.judgment,graded.judgment);
    assert.equal(judgeInvocations,1);
    assert.ok(judgeTransport.calls.filter(call=>call.kind==='judge').length>=1
      &&judgeTransport.calls.filter(call=>call.kind==='judge').length<=3);
    assert.equal(judgeTranscripts.length,1);assert.equal(judgeTranscripts[0].complete,true);
    const awarded=await creditRows();
    assert.equal(awarded.judgments.length,1);assert.equal(awarded.contributions.length,1);
    assert.equal(awarded.completions.length,1);assert.deepEqual(awarded.workshop,[],
      'standalone shop award does not create platform-workshop credit');
    const judgment=awarded.judgments[0];
    assert.equal(judgment.evaluation_id,graded.judgment.evaluationId);
    assert.equal(judgment.objective_id,OBJECTIVE);assert.equal(judgment.verdict,'pass');
    assert.equal(judgment.disposition,'awarded');assert.equal(judgment.mode,'vuln');
    assert.equal(judgment.result_json?.provider,'ollama');assert.equal(judgment.result_json?.model,MODEL);
    assert.equal(judgment.result_json?.verdict,'pass');
    assert.equal(awarded.contributions[0].evaluation_id,judgment.evaluation_id);
    assert.equal(awarded.completions[0].evaluation_id,judgment.evaluation_id);
    assert.equal(judgment.evidence_digest,judgeTranscripts[0].header.evidenceDigest);
    assert.equal(judgment.packet,judgeTranscripts[0].header.packet);
    assessmentEvidence={initial:initialAssessment,post:assessmentPosts[0],saved:completedAssessment,
      judgment,contribution:awarded.contributions[0],completion:awarded.completions[0],
      workshop:awarded.workshop,judgeTranscript:judgeTranscripts[0]};
    assertGradedEvidence({proposal,turn:original,operation:rows[0],
      receipt:completed[0].receipt_json,assessment:assessmentEvidence});
    status.originalAssessmentPost=true;status.canonicalJudgePass=true;status.genuineCredit=true;
    const actorAtConfirm = actorTransport.calls.filter(call=>call.kind==='actor').length;
    stage = 'saved-get-reload';
    await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    await clickButton(frame, 'Check saved System diagnostic');
    await frame.waitForFunction(text => [...document.querySelectorAll('pre')]
      .some(node => node.textContent === text), { timeout: 120000 },
    `diagnostic-baseline\nsystem-diag-${rows[0].target_id.replaceAll('-', '')}\n`);
    await clickButton(frame,'Check saved System diagnostic assessment');
    await frame.waitForFunction(()=>[...document.querySelectorAll('section[aria-label="Admin System diagnostic assessment"] [role="status"]')]
      .some(node=>node.textContent.trim()==='Objective completed.'),{timeout:30000});
    const recoveredAssessment=assessmentOutcomes.filter(entry=>entry.method==='GET'
      &&entry.path===assessmentPath).at(-1);
    assert.deepEqual(recoveredAssessment?.body,completedAssessment.body);
    assert.equal(recoveredAssessment.status,200);
    assert.equal(confirmPosts, 1); assert.equal(executorPosts().length, 1);
    assert.equal(actorTransport.calls.filter(call=>call.kind==='actor').length, actorAtConfirm);
    assert.equal(judgeInvocations,1);
    status.savedAssessmentGetRecovery = true; status.noDuplicateDiagnostic = true;
    await page.screenshot({ path: path.join(path.dirname(evidencePath),
      'admin-system-diagnostic-graded-recovered.png') });
    const actor = bootstraps[0];
    const actorScope = await composition.launches.resolveCapability(actor.launch);
    assert.notEqual(siblingRow.owner_id,actorScope.platformOwnerId);
    const actorPersona = await composition.personaAuth.authenticateBoundToken({
      scope: actorScope, token: actor.authorization.slice('Bearer '.length) });
    const proveOriginal=async(saved,humanMessage)=>{
      const record=(await agents.query(`SELECT status,request_hash,result_json FROM
        secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
      [saved.sessionId,saved.requestId])).rows;
      assert.equal(record.length,1);assert.equal(record[0].status,'completed');
      const metadata=record[0].result_json?.taskMetadata?.roleChat;
      const privateProposal=metadata?.systemDiagnosticProposal;
      const origin=metadata?.systemDiagnosticOrigin;
      assert.equal(privateProposal?.proposalId,saved.systemDiagnosticProposal?.proposalId);
      assert.equal(JSON.parse(origin?.sourceEnvelope||'null')?.message,humanMessage);
      const scene=await scenes.readRetained(actorScope);
      const expected=require('../../server/database/postgres/secureshopRoleChatBindingRepository')
        .capture({sessionId:saved.sessionId,requestId:saved.requestId,scope:actorScope,
          persona:{id:actorPersona.user.id,role:'admin'},
          personaSession:{sessionId:actorPersona.sessionId,
            authorityVersion:actorPersona.authorityVersion},target:scene,
          message:origin.sourceEnvelope});
      const binding=(await agents.query(`SELECT * FROM secureshop_agents.role_chat_turn_bindings
        WHERE session_id=$1 AND request_id=$2`,[saved.sessionId,saved.requestId])).rows;
      assert.equal(binding.length,1);
      for(const [name,value] of Object.entries(expected)){
        const column=name.replace(/[A-Z]/g,c=>`_${c.toLowerCase()}`);
        assert.equal(String(binding[0][column]),String(value),`bound original ${name}`);
      }
      assert.equal(record[0].request_hash,expected.requestHash);
      const run=(await identity.query(`SELECT run_id,owner_key,generation,status FROM graph_runtime.runs
        WHERE run_id=$1`,[origin.runId])).rows;
      assert.equal(run.length,1);assert.equal(run[0].status,'completed');
      assert.equal(run[0].run_id,origin.runId);
      assert.equal(run[0].owner_key,JSON.stringify(['SecureShopBoundConversation',saved.sessionId]));
      const trace=(await agents.query(`SELECT event_id,step,kind,agent_ns,tool_name,
        params_json,result_json FROM secureshop_agents.agent_trace
        WHERE session_id=$1 AND event_id=ANY($2::text[])`,
      [saved.sessionId,origin.traceEventIds])).rows;
      assert.equal(trace.length,origin.traceEventIds.length);
      const byId=new Map(trace.map(row=>[row.event_id,row]));
      const ordered=origin.traceEventIds.map(id=>byId.get(id));
      assert.ok(ordered.every(Boolean));
      const parse=(row,key)=>JSON.parse(row?.[key]||'null');
      const decision=ordered.filter(row=>row.kind==='model_decision'
        &&Number(row.step)===privateProposal.origin.step);
      const call=ordered.filter(row=>row.kind==='local_tool_call'
        &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare'
        &&Number(row.step)===privateProposal.origin.step);
      const result=ordered.filter(row=>row.kind==='local_tool_result'
        &&row.agent_ns==='admin'&&row.tool_name==='system_diagnostic_prepare'
        &&Number(row.step)===privateProposal.origin.step);
      const terminal=ordered.filter(row=>row.kind==='model_decision'
        &&parse(row,'result_json')?.decision==='final');
      assert.equal(decision.length,1);assert.equal(call.length,1);
      assert.equal(result.length,1);assert.equal(terminal.length,1);
      assert.deepEqual(parse(decision[0],'params_json'),{decision:'tool_use',toolCalls:[{
        id:privateProposal.origin.callId,name:'admin.system_diagnostic_prepare',
        args:{cmd_template:privateProposal.cmd_template,args:privateProposal.args}}]});
      assert.deepEqual(parse(call[0],'params_json'),
        {cmd_template:privateProposal.cmd_template,args:privateProposal.args});
      assert.deepEqual(parse(result[0],'result_json'),saved.hops.at(-1).result);
      assert.equal(parse(terminal[0],'result_json')?.text,saved.text);
      assert.ok(ordered.indexOf(decision[0])<ordered.indexOf(call[0])
        &&ordered.indexOf(call[0])<ordered.indexOf(result[0])
        &&ordered.indexOf(result[0])<ordered.indexOf(terminal[0]));
      const span=turnSpans.find(value=>value.sessionId===saved.sessionId
        &&value.requestId===saved.requestId);
      assert.ok(span&&span.wireEnd>span.wireStart);
      turns.push({sessionId:saved.sessionId,requestId:saved.requestId,
        sourceEnvelope:origin.sourceEnvelope,sourceBinding:binding[0],saved:record[0],
        traceEventIds:origin.traceEventIds,traces:ordered,run:run[0],span});
    };
    await proveOriginal(original,originalMessage);
    const originalPath = `/agents/admin/assistant/operations/${original.sessionId}/${original.requestId}`;
    const savedPath = `/agents/admin/assistant/system/diagnostic/confirm/${original.sessionId}/${original.requestId}/${proposal.proposalId}`;
    const ownerRequests = requestLog.filter(entry => entry.path.startsWith('/agents/admin/assistant'));
    assert.equal(ownerRequests.filter(entry => entry.method === 'POST'
      && entry.path === '/agents/admin/assistant/chat').length, 1);
    assert.ok(ownerRequests.some(entry => entry.method === 'GET'
      && entry.path === originalPath && entry.status === 200));
    assert.ok(ownerRequests.some(entry => entry.method === 'GET'
      && entry.path === savedPath && entry.status === 200));
    for (const entry of ownerRequests) {
      assert.match(entry.launch || '', /^\S+$/);
      assert.match(entry.authorization || '', /^Bearer \S+$/);
      const scope = await composition.launches.resolveCapability(entry.launch);
      assert.deepEqual(Object.fromEntries(['launchId','scenarioId','generation',
        'platformOwnerId','platformSessionId'].map(key => [key,scope[key]])),
      Object.fromEntries(['launchId','scenarioId','generation',
        'platformOwnerId','platformSessionId'].map(key => [key,actorScope[key]])));
      const persona = await composition.personaAuth.authenticateBoundToken({
        scope, token: entry.authorization.slice('Bearer '.length) });
      assert.deepEqual({id:persona.user.id,role:persona.user.role,sessionId:persona.sessionId,
        authorityVersion:persona.authorityVersion},
      {id:actorPersona.user.id,role:actorPersona.user.role,
        sessionId:actorPersona.sessionId,authorityVersion:actorPersona.authorityVersion});
    }
    stage = 'fixed-mode-prepare';
    await clickButton(frame, 'Close saved diagnostic');
    await frame.waitForFunction(()=>{
      const card=document.querySelector('section[aria-label="Admin System diagnostic confirmation"]');
      const buttons=[...card?.querySelectorAll('button')||[]];
      return !buttons.some(button=>button.textContent.trim()==='Check saved System diagnostic')
        &&buttons.some(button=>button.textContent.trim()==='Confirm System diagnostic'
          &&!button.disabled);
    },{timeout:30000});
    const modePost = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.origin === origin && url.pathname === '/api/secureshop/auth/mode'
        && response.request().method() === 'POST';
    }, {timeout: 30000});
    await clickButton(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]');
    await page.waitForFunction(()=>document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent
      .includes('Current: Vulnerable'),{timeout:30000});
    const controls = await page.$$('[role="group"][aria-label="Shop feature mode"] button');
    const fixed = [];
    for (const control of controls) if (await control.evaluate(node =>
      node.textContent.trim() === 'Fixed' && !node.disabled)) fixed.push(control);
    assert.equal(fixed.length, 1); await fixed[0].click();
    assert.equal((await modePost).status(), 200);
    await page.waitForFunction(() => document.querySelector(
      '[role="group"][aria-label="Shop feature mode"]')?.textContent.includes('Current: Fixed'));
    await clickButton(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]', {hidden:true});
    frame = await frameFor(page);
    const secondMessage = originalMessage;
    const secondCard = await prepare(secondMessage);
    assert.ok(secondCard.command.includes(TEMPLATE));
    assert.ok(secondCard.command.includes(ARGS));
    assert.equal(selectedCalls().length,2,
      'fixed preparation must remain the same genuine model-selected command');
    const second=savedProposals.at(-1);
    assert.ok(second&&(second.sessionId!==original.sessionId
      ||second.requestId!==original.requestId));
    assert.notEqual(second.systemDiagnosticProposal?.proposalId,proposal.proposalId);
    assert.equal(second?.systemDiagnosticProposal?.modeCapability?.effectiveMode,'fixed');
    assert.equal(second?.systemDiagnosticProposal?.cmd_template,TEMPLATE);
    assert.equal(second?.systemDiagnosticProposal?.args,ARGS);
    await proveOriginal(second,secondMessage);
    assert.deepEqual((await admissions()).map(row => row.operation_id), [proposal.proposalId]);
    assert.equal(executorPosts().length, 1);
    stage = 'fixed-physical-denial';
    await clickButton(frame, 'Confirm System diagnostic');
    await frame.waitForFunction(() => [...document.querySelectorAll('section')]
      .some(node => node.getAttribute('aria-label') === 'Admin System diagnostic confirmation'
        && node.textContent.includes('Fixed mode denied this diagnostic before execution.')),
    {timeout: 30000});
    assert.equal(confirmPosts, 2);
    assert.equal(confirmOutcomes.at(-1)?.status, 403);
    assert.equal(confirmOutcomes.at(-1)?.code, 'SYSTEM_DIAGNOSTIC_FIXED_DENIED');
    assert.equal(executorPosts().length, 1);
    assert.deepEqual((await admissions()).map(row => row.operation_id), [proposal.proposalId]);
    assert.equal((await agents.query(`SELECT count(*)::int n FROM
      secureshop_agents.bound_system_diagnostic_outcomes`)).rows[0].n, 1);
    const fixedAssessmentPath=`/agents/admin/assistant/system/diagnostic/assess/${second.sessionId}/${second.requestId}/${second.systemDiagnosticProposal.proposalId}`;
    const fixedAssessment=await fetch(`${origin}/api/secureshop${fixedAssessmentPath}`,{headers:{
      'x-owasp-ai-goat-secureshop-launch':actor.launch,authorization:actor.authorization}});
    assert.equal(fixedAssessment.status,200);
    assert.deepEqual(await fixedAssessment.json(),
      {completed:false,status:'ineligible',modelEvaluated:false});
    assert.equal(judgeInvocations,1);assert.deepEqual(await creditRows(),awarded);
    status.physicalFixedDenial = true;
    stage = 'sibling-denial';
    const siblingRead = await fetch(`${origin}/api/secureshop${savedPath}`, {headers:{
      'x-owasp-ai-goat-secureshop-launch': siblingBase.bearer,
      authorization: `Bearer ${siblingBase.persona.token}`}});
    assert.equal(siblingRead.status, 401);
    assert.equal(executorPosts().length,1);status.siblingOperationDenied = true;
    const siblingAssessment=await fetch(`${origin}/api/secureshop${assessmentPath}`,{headers:{
      'x-owasp-ai-goat-secureshop-launch':siblingBase.bearer,
      authorization:`Bearer ${siblingBase.persona.token}`}});
    assert.equal(siblingAssessment.status,401);
    assert.equal(judgeInvocations,1);status.siblingAssessmentDenied=true;
    stage = 'reset-denial';
    await composition.launches.beginReset({launchId:actorScope.launchId,
      platformSessionId:actorScope.platformSessionId,
      platformOwnerId:actorScope.platformOwnerId,
      expectedGeneration:actorScope.generation,
      idempotencyKey:`diagnostic-graded-reset-${randomUUID()}`});
    const retired = await fetch(`${origin}/api/secureshop${savedPath}`, {headers:{
      'x-owasp-ai-goat-secureshop-launch':actor.launch,authorization:actor.authorization}});
    assert.equal(retired.status, 401);
    const retiredAssessment=await fetch(`${origin}/api/secureshop${assessmentPath}`,{headers:{
      'x-owasp-ai-goat-secureshop-launch':actor.launch,authorization:actor.authorization}});
    assert.equal(retiredAssessment.status,401);
    assert.equal(executorPosts().length,1);status.resetSessionDenied = true;
    const history=await creditRows();
    assert.equal(history.judgments.length,1);assert.equal(history.judgments[0].evaluation_id,judgment.evaluation_id);
    assert.equal(history.judgments[0].packet,judgment.packet);
    assert.equal(history.judgments[0].evidence_digest,judgment.evidence_digest);
    assert.equal(history.judgments[0].result_digest,judgment.result_digest);
    assert.equal(judgeInvocations,1);status.immutableHistoryRetained=true;
    assert.deepEqual(pageErrors, []);
    status.executorCalls = executorPosts().length;
    status.actorCalls = actorTransport.calls.filter(call=>call.kind==='actor').length;
    status.judgeCalls = judgeTransport.calls.filter(call=>call.kind==='judge').length;
    status.roleTurns = requestLog.filter(entry => entry.method === 'POST'
      && entry.path === '/agents/admin/assistant/chat').length;
    status.passed = true;
  } catch (error) {
    failure = error;
    try { assessmentSqlState=await failedAssessmentSqlState(
      pools.IDENTITY_RUNTIME,pools.AGENTS_RUNTIME,assessmentOutcomes); }
    catch(captureError) { assessmentSqlState={captureError:boundedAssessmentError('sqlSnapshot',captureError)}; }
    t.diagnostic(JSON.stringify({stage,url:page?.url()||null,
      visible:page?await visibleSetupState(page):[],
      pageErrors:pageErrors.slice(0,16),requestFailures:requestFailures.slice(0,16),
      confirmPosts,lostAck,confirmOutcomes:confirmOutcomes.slice(0,4),
      executorWire:executorWire.slice(0,8)}));
    if (page) await page.screenshot({path:path.join(path.dirname(evidencePath),
      'admin-system-diagnostic-graded-failure.png')}).catch(()=>{});
  } finally {
    for (const close of [()=>browser?.close(),()=>closeServer(server),
      ()=>actorTransport?.close(),()=>judgeTransport?.close(),
      ()=>reset?.closeFeatureTransports?.(),()=>reset?.auditLedger?.close?.(),
      ()=>profile&&fs.rm(profile,{recursive:true,force:true}),()=>leasePool.end(),
      ...Object.values(pools).map(pool=>()=>pool.end())]) {
      try { await close(); } catch(error) {cleanupErrors.push(error);}
    }
    status.fixtureCleaned=cleanupErrors.length===0;
    status.executorCalls=executorWire.filter(row=>row.method==='POST'
      && row.path==='/secureshop/system/diagnostic').length;
    status.actorCalls=actorTransport?.calls.filter(call=>call.kind==='actor').length||0;
    status.judgeCalls=judgeTransport?.calls.filter(call=>call.kind==='judge').length||0;
    status.roleTurns=requestLog.filter(entry=>entry.method==='POST'
      && entry.path==='/agents/admin/assistant/chat').length;
    status.errors=failure?[{name:failure.name||'Error',code:failure.code||null}]:[];
    const wirePath=path.join(path.dirname(evidencePath),'admin-system-diagnostic-graded-wire.json');
    const wire={version:1,model:MODEL,modelDigest:MODEL_DIGEST,
      calls:[...(actorTransport?.calls||[]),...(judgeTransport?.calls||[])],turns,
      executor:executorWire,
      assessment:assessmentEvidence||(failure?{...failedAssessmentCapture(assessmentOutcomes),
        serverErrors:assessmentErrors,judgeResults,sqlState:assessmentSqlState}:null),
      requests:requestLog.map(entry=>({
        method:entry.method,path:entry.path,status:entry.status??null,
        ...(entry.body===undefined?{}:{bodySha256:createHash('sha256')
          .update(JSON.stringify(entry.body)).digest('hex')}),
      })),pageErrors,requestFailures};
    const wireBytes=JSON.stringify(wire,null,2);
    if(Buffer.byteLength(wireBytes,'utf8')>80*1024*1024)
      cleanupErrors.push(new Error('Private diagnostic wire exceeds bound'));
    else try { await fs.writeFile(wirePath,wireBytes,
      {flag:'wx',mode:0o600}); } catch(error) {cleanupErrors.push(error);}
    try { await fs.writeFile(evidencePath,JSON.stringify(status,null,2),
      {flag:'wx',mode:0o600}); } catch(error) {cleanupErrors.push(error);}
  }
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors,
    'Diagnostic chat fixture cleanup failed');
  if (failure) throw failure;
  assertPrivateReceipt({...status,fixtureCleaned:true,errors:[]});
});

module.exports={assertPrivateReceipt,assertGradedEvidence,FLAGS,SCOPE,ASSERTION,
 TEMPLATE,ARGS,PROPOSAL_PROMPT,assertNativeTypedDiagnosticRequest,failedAssessmentCapture,
 boundedAssessmentError,observeAssessmentFactory,failedAssessmentSqlState,
 OBJECTIVE,MODEL,MODEL_DIGEST,diagnosticDependencies};
