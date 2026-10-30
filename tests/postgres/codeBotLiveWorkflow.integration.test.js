'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const enabled = process.env.RUN_LIVE_CODEBOT_WORKFLOW === '1'
  && process.env.PG_TEST_DISPOSABLE === 'yes';
const PREFIX = Object.freeze([]);

function copySource(root, copy) {
  const filter = file => {
    const relative = path.relative(root, file);
    if (/(?:^|\/)(?:logs|uploads|vector-indexes|sensitive_files|workshop_data|\.env[^/]*)(?:\/|$)/.test(relative)) return false;
    return fs.statSync(file).isDirectory() || /\.(?:js|json|sql)$/.test(file);
  };
  for (const directory of ['server', 'db', 'tests', 'docs']) {
    fs.cpSync(path.join(root, directory), path.join(copy, directory), { recursive: true, filter });
  }
  fs.symlinkSync(path.join(root, 'node_modules'), path.join(copy, 'node_modules'), 'dir');
  for (const [source, target] of PREFIX) {
    assert.equal(fs.existsSync(path.join(copy, target)), false, `${target} must remain unregistered in source`);
    fs.copyFileSync(path.join(copy, source), path.join(copy, target));
  }
}

const HISTORY_QUERIES=Object.freeze({effects:'SELECT * FROM graph_runtime.effects WHERE owner_key=ANY($1::text[]) ORDER BY effect_key',requests:'SELECT * FROM graph_runtime.codebot_requests WHERE user_id=ANY($1::bigint[]) ORDER BY user_id,request_key_sha256',judgments:'SELECT * FROM workshop_platform.objective_judgments WHERE user_id=ANY($1::bigint[]) ORDER BY evaluation_id',packets:'SELECT * FROM workshop_platform.grade_packets WHERE user_id=ANY($1::bigint[]) ORDER BY evaluation_id'});
async function immutableHistory(runtime,userIds){const value={};for(const [key,sql]of Object.entries(HISTORY_QUERIES))value[key]=(await runtime.query(sql,[key==='effects'?userIds.map(id=>JSON.stringify(['CodeBot',String(id)])):userIds])).rows;return value;}
function verifyImmutableHistory(before,after){assert.deepEqual(after,before,'Reset changed immutable CodeBot history');}
function verifyCleanPacket(packet, manifest) {
  if (typeof packet === 'string') packet = JSON.parse(packet);
  const calls = packet.evidence.filter(item => item.source === 'tool_result' && item.content?.name === 'check_dependencies');
  assert.equal(calls.length, 1, 'Exactly one persisted dependency check required');
  assert.equal(calls[0].content.result.security, 'clean');
  assert.deepEqual(JSON.parse(calls[0].content.params.manifest), manifest);
}
function verifyFixedDenial(body, before, after, receipts) {
  assert.deepEqual(body.newlyCompletedObjectives, []);
  assert.ok(Array.isArray(body.judgments));
  assert.ok(body.judgments.every(item => item.verdict !== 'pass'));
  assert.deepEqual(after, before, 'Fixed transform must not create a completion');
  assert.deepEqual(receipts, [{ verdict: 'pass', disposition: 'awarded' }]);
}
async function qualifyCodeBot(t, owned) {
  const fixedControl = process.env.CODEBOT_LIVE_FIXED_CONTROL === '1';
  assert.ok(!fixedControl || (!owned && process.env.CODEBOT_LIVE_SCOPE !== 'representative'), 'Historical fixed control requires separate full-cohort budget; current owned cohort does not admit it');
  if (!owned && !process.env.CODEBOT_LIVE_ISOLATED) {
    const root = path.resolve(__dirname, '../..');
    const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-codebot-live-'));
    try {
      copySource(root, copy);
      const { spawn } = require('node:child_process');
      await new Promise((resolve, reject) => {
        const child = spawn(process.execPath,
          ['--test', path.join(copy, 'tests/postgres/codeBotLiveWorkflow.integration.test.js')], {
            cwd: copy, stdio: 'inherit', env: {
              PATH: process.env.PATH, RUN_LIVE_CODEBOT_WORKFLOW: '1', PG_TEST_DISPOSABLE: 'yes',
              PG_LIVE_ADMIN_URL: process.env.PG_LIVE_ADMIN_URL, CODEBOT_LIVE_ISOLATED: '1',
              PLATFORM_DATABASE_ENGINE: 'postgres', AI_PROVIDER: 'ollama',
              OLLAMA_BASE_URL: 'http://127.0.0.1:11434', OLLAMA_MODEL: 'llama3.1:8b',
              SANDBOX_RUNNER_URL: process.env.SANDBOX_RUNNER_URL, CODEBOT_SANDBOX_RUNNER_URL:process.env.CODEBOT_SANDBOX_RUNNER_URL, CODEBOT_OWNED_EXECUTION_ENABLED:process.env.CODEBOT_OWNED_EXECUTION_ENABLED, CODEBOT_LIVE_SCOPE:process.env.CODEBOT_LIVE_SCOPE||'all',
              CODEBOT_LIVE_FIXED_CONTROL: process.env.CODEBOT_LIVE_FIXED_CONTROL,
              AWS_EC2_METADATA_DISABLED: 'true', LOGS_DIR: path.join(copy, 'logs'),
            },
          });
        child.on('error', reject);
        child.on('exit', code => code === 0 ? resolve() : reject(Error(`Isolated probe exited ${code}`)));
      });
    } finally { fs.rmSync(copy, { recursive: true, force: true }); }
    return;
  }

  const Module = require('node:module');
  const originalLoad = Module._load;
  Module._load = function guardedLoad(name, ...args) {
    if (['sqlite3', 'better-sqlite3'].includes(name) || /authDb$/.test(name)) throw Error('Working SQLite import forbidden');
    return originalLoad.call(this, name, ...args);
  };
  const { Pool } = require('pg');
  const adminUrl = owned ? null : new URL(process.env.PG_LIVE_ADMIN_URL);
  if(adminUrl){assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(adminUrl.hostname));assert.equal(adminUrl.pathname, '/postgres');}
  const runnerHealth = await (await fetch(`${process.env.SANDBOX_RUNNER_URL}/health`,{signal:owned?.signal})).json();
  assert.equal(runnerHealth.codebotAvailable, true);
  assert.equal(runnerHealth.codebotIsolation, 'bwrap-codebot-v1');
  if(!owned)assert.ok((await (await fetch('http://127.0.0.1:11434/api/tags')).json()).models
    .some(model => model.name === 'llama3.1:8b'));

  const admin = owned ? null : new Pool({ connectionString: adminUrl.href });
  const name = `owasp_ai_goat_test_codebotlive_${process.pid}`;
  const supplyName = `${name}_supply`;
  const pools = [];
  let server, primary;const restore=[];
  try {
    if(admin){await admin.query(`CREATE DATABASE ${name} OWNER dvaia_identity_migration`);
    await admin.query(`REVOKE CONNECT ON DATABASE ${name} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${name} TO dvaia_identity_runtime`);}
    const pool = role => {
      const url = owned ? new URL(process.env[role.endsWith('_migration')?'IDENTITY_MIGRATION_DATABASE_URL':'IDENTITY_DATABASE_URL']) : new URL(adminUrl);if(!owned){url.pathname = `/${name}`;url.username = role;url.password = '';}
      const value = new Pool({ connectionString: url.href, max: 8, ...(owned?{statement_timeout:15000,connectionTimeoutMillis:15000}:{}) });pools.push(value);return value;
    };
    const runtime = pool('dvaia_identity_runtime');
    const migration = pool('dvaia_identity_migration');
    process.env.IDENTITY_DATABASE_URL = runtime.options.connectionString;
    const identityApi = require('../../server/database/postgres/identityRepository');
    const applied = await identityApi.initializeIdentityRepository(runtime, migration);
    assert.deepEqual(applied,fs.readdirSync(path.join(__dirname,'../../db/postgres/identity-migrations')).filter(f=>f.endsWith('.sql')).sort());
    assert.deepEqual(await identityApi.initializeIdentityRepository(runtime, migration), []);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(migration);

    if(admin){await admin.query(`CREATE DATABASE ${supplyName} OWNER dvaia_supply_chain_migration`);
    await admin.query(`REVOKE CONNECT ON DATABASE ${supplyName} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${supplyName} TO dvaia_supply_chain_runtime`);}
    const supplyPool = role => {
      const url = owned ? new URL(process.env[role.endsWith('_migration')?'SUPPLY_CHAIN_WORKSHOP_MIGRATION_DATABASE_URL':'SUPPLY_CHAIN_WORKSHOP_DATABASE_URL']) : new URL(adminUrl);if(!owned){url.pathname = `/${supplyName}`;url.username = role;url.password = '';}
      const value = new Pool({ connectionString: url.href, max: 5, ...(owned?{statement_timeout:15000,connectionTimeoutMillis:15000}:{}) });pools.push(value);return value;
    };
    const supplyRuntime = supplyPool('dvaia_supply_chain_runtime');
    const supplyMigration = supplyPool('dvaia_supply_chain_migration');
    process.env.SUPPLY_CHAIN_WORKSHOP_DATABASE_URL = supplyRuntime.options.connectionString;
    await require('../../server/database/postgres/supplyChainWorkshopDb')
      .createSupplyChainWorkshopDb(supplyRuntime).initialize(supplyMigration);

    const identity = identityApi.createIdentityRepository(runtime);
    const bcrypt = require('bcryptjs');
    const makeUser = async suffix => identity.createUser({ username: `codebot-${suffix}`,
      email: `codebot-${suffix}@example.invalid`, passwordHash: await bcrypt.hash('fixture', 4) });
    const owner = await makeUser('owner');
    const sibling = await makeUser('sibling');
    await runtime.query(`INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode)
      VALUES($1,'supply_chain_rce','vulnerable'),($2,'supply_chain_rce','vulnerable')`, [owner.id, sibling.id]);

    const progress = require('../../server/database/postgres/workshopProgressRepository')
      .createWorkshopProgressRepository(runtime);
    const config = require('../../server/database/postgres/workshopConfigRepository')
      .createWorkshopConfigRepository(runtime);
    const jwtSecret = require('node:crypto').randomBytes(48).toString('base64url');
    process.env.JWT_SECRET = jwtSecret;
    const adapter = require('../../server/services/postgresIdentityAdapter')
      .createPostgresIdentityAdapter({ repository: identity, progress, config, jwtSecret });
    const makeSession = async user => adapter.createSession(await identity.findCredentialById(user.id),
      { get: () => null, ip: '127.0.0.1' });
    const ownerSession = await makeSession(owner);
    const siblingSession = await makeSession(sibling);

    if(owned){const sandbox=require('../../server/services/supplyChain/codeBotSandboxRuntime'),execute=sandbox.executeTransform;sandbox.executeTransform=async input=>{const value=await execute(input);owned.observeSandbox({scope:input.scope,transform:input.transform},value);return value;};restore.push(()=>{sandbox.executeTransform=execute;});
      const graph=require('../../server/agent-runtime/codeBotGraph'),invoke=graph.runCodeBotGraph;graph.runCodeBotGraph=async(input,deps)=>{const parser=deps.tryParseTextToolCall;const value=await invoke(input,{...deps,tryParseTextToolCall:(text,message)=>{const parsed=parser(text,message);owned.observeTextRepair({text,message,parsed});return parsed;}});owned.observeGraph(input,value);return value;};restore.push(()=>{graph.runCodeBotGraph=invoke;});}
    const activation=require('../../server/services/supplyChain/codeBotProduction').getCodeBotProductionActivation();const ready=await activation.initialize();assert.equal(ready.ready,true);assert.equal(ready.isolation,'bwrap-codebot-v1');
    const aiService = require('../../server/services/multiProviderAIService');
    const originalChat = aiService.chatWithTools.bind(aiService);
    let modelCalls = 0;
    aiService.chatWithTools = async (...args) => { modelCalls++;const observed=owned?require('../fixtures/codeBotCurrentBinding').snapshotActorArgs(args):null;const value=await originalChat(...args);if(owned)owned.observeActor(observed,value);return value; };
    const app = require('express')();
    app.use(require('express').json());
    app.use(require('../../server/routes/supplyChainWorkshop'));
    server = await new Promise(resolve => {
      const started = app.listen(0, '127.0.0.1', () => resolve(started));
    });
    owned?.ports.add(server.address().port);
    const base = `http://127.0.0.1:${server.address().port}`;
    const headersFor = (session, key) => ({ 'content-type': 'application/json',
      authorization: `Bearer ${session.token}`, ...(key ? { 'idempotency-key': key } : {}) });
    const chat = async ({ session = ownerSession, key, message, expectedStatus = 200 }) => {
      const response = await fetch(`${base}/chat`, { method: 'POST', headers: headersFor(session, key),
        signal:owned?.signal, body: JSON.stringify({ userMessage: message, conversationHistory: [] }) });
      const body = await response.json();
      t.diagnostic(JSON.stringify({ key, status: response.status, body }));
      assert.equal(response.status, expectedStatus);return body;
    };

    if (process.env.CODEBOT_LIVE_SCOPE === 'clean-fixed') {
      assert.ok(owned, 'Clean/fixed cohort requires current owned admission');
      const manifest = {name:'safe-fixture',version:'1.0.0',dependencies:{}};
      const outcomes = {};
      const runCase = async (caseId, manifestValue) => {
        const key = 'codebot-clean-fixed-'+caseId.replace(/[^a-z]/g,'-')+'-0001';
        const message = 'Check this exact package.json manifest: '+JSON.stringify(manifestValue);
        owned.transport.beginCase(caseId);
        const body = await chat({key,message});
        await owned.capture({runtime,userId:owner.id,key,message,body,caseId});
        owned.transport.endCase();
        outcomes[caseId]={key,message,body};
        return body;
      };
      const positive = await runCase('clean_request',manifest);
      assert.deepEqual(positive.newlyCompletedObjectives,['clean_request']);
      assert.ok(positive.judgments.some(j=>j.objectiveId==='clean_request'&&j.verdict==='pass'));
      const cleanPackets=(await runtime.query(`SELECT p.packet FROM workshop_platform.grade_packets p
        JOIN workshop_platform.objective_judgments j USING(user_id,evaluation_id)
        WHERE j.user_id=$1 AND j.objective_id='clean_request'`,[owner.id])).rows;
      assert.equal(cleanPackets.length,1);verifyCleanPacket(cleanPackets[0].packet,manifest);
      const completions=async()=>(await runtime.query("SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='supply_chain_rce' ORDER BY objective_id",[owner.id])).rows;
      const before=await completions();
      const mode=await fetch(`${base}/mode`,{method:'POST',headers:headersFor(ownerSession),signal:owned.signal,body:JSON.stringify({mode:'fixed'})});
      assert.equal(mode.status,200);
      const negative=await runCase('fixed:transform-denial',{...manifest,transform:'return 1'});
      const receipts=(await runtime.query("SELECT verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='clean_request' ORDER BY created_at",[owner.id])).rows;
      verifyFixedDenial(negative,before,await completions(),receipts);
      const historyBefore=await immutableHistory(runtime,[owner.id]);
      assert.equal(historyBefore.effects.length,0);
      assert.equal(historyBefore.requests.length,2);
      assert.ok(historyBefore.requests.every(r=>r.status==='completed'));
      owned.historySnapshot('before',historyBefore);
      const reset=await fetch(`${base}/progress/reset`,{method:'POST',headers:headersFor(ownerSession),signal:owned.signal,body:'{}'});
      assert.equal(reset.status,200);assert.deepEqual(await completions(),[]);
      const historyAfter=await immutableHistory(runtime,[owner.id]);verifyImmutableHistory(historyBefore,historyAfter);owned.historySnapshot('after',historyAfter);
      owned.complete({outcomes,effects:historyBefore.effects,journalRows:historyBefore.requests,primaryCompletionIds:['clean_request'],semanticFailures:[],skippedDependencies:[]});
      return;
    }

    const { solutions, SC_OBJECTIVE_IDS } = require('../../server/data/supplyChainSolutions');
    const outcomes = {};
    const semanticFailures = [];
    const skippedDependencies = [];
    const verifySemantic = (label, assertion) => {
      try { assertion(); } catch (error) { semanticFailures.push({ label, message: error.message }); }
    };
    const representative=process.env.CODEBOT_LIVE_SCOPE==='representative';assert.ok(['all','representative'].includes(process.env.CODEBOT_LIVE_SCOPE||'all'));
    for (const objectiveId of (representative?['rce_cmd']:SC_OBJECTIVE_IDS)) {
      const key = `codebot-positive-${objectiveId}-0001`;
      const message = solutions[objectiveId].examples[0].prompt;
      const before = modelCalls;
      owned?.transport.beginCase(objectiveId);
      const body = await chat({ key, message });
      if(owned){await owned.capture({runtime,userId:owner.id,key,message,body,caseId:objectiveId});owned.transport.endCase();}
      assert.ok(Array.isArray(body.judgments), `${objectiveId} must return Judge outcomes`);
      assert.ok(Array.isArray(body.newlyCompletedObjectives), `${objectiveId} must return completion outcomes`);
      outcomes[objectiveId] = { key, message, modelCalls: modelCalls - before, body,
        newlyCompleted: body.newlyCompletedObjectives, judgments: body.judgments };
      verifySemantic(`${objectiveId}:canonical_judge`, () => assert.ok(body.judgments.some(judgment =>
        judgment.objectiveId === objectiveId && judgment.verdict === 'pass'),
      `${objectiveId} must pass its canonical Judge`));
      verifySemantic(`${objectiveId}:canonical_completion`, () =>
        assert.ok(body.newlyCompletedObjectives.includes(objectiveId), `${objectiveId} must be newly completed`));
    }
    t.diagnostic(JSON.stringify({ actualCohort: outcomes, semanticFailures }));

    const replayId = 'rce_cmd';
    const beforeReplayCounts = (await runtime.query(`SELECT
      (SELECT count(*)::int FROM graph_runtime.runs WHERE owner_key=$1) AS runs,
      (SELECT count(*)::int FROM graph_runtime.effects WHERE owner_key=$1) AS effects,
      (SELECT count(*)::int FROM workshop_platform.objective_judgments WHERE user_id=$2) AS judgments`,
    [JSON.stringify(['CodeBot', String(owner.id)]), owner.id])).rows[0];
    const replayBefore = modelCalls;
    const replay = await chat({ key: outcomes[replayId].key, message: outcomes[replayId].message });
    assert.equal(modelCalls, replayBefore, 'same-key replay must not invoke the model again');
    assert.deepEqual(replay, outcomes[replayId].body, 'same-key replay returns the exact committed response');
    const afterReplayCounts = (await runtime.query(`SELECT
      (SELECT count(*)::int FROM graph_runtime.runs WHERE owner_key=$1) AS runs,
      (SELECT count(*)::int FROM graph_runtime.effects WHERE owner_key=$1) AS effects,
      (SELECT count(*)::int FROM workshop_platform.objective_judgments WHERE user_id=$2) AS judgments`,
    [JSON.stringify(['CodeBot', String(owner.id)]), owner.id])).rows[0];
    assert.equal(afterReplayCounts.runs, beforeReplayCounts.runs + 1,
      'replay retains its own durable audit run');
    assert.equal(afterReplayCounts.effects, beforeReplayCounts.effects,
      'replay executes no additional tool effect');
    assert.equal(afterReplayCounts.judgments, beforeReplayCounts.judgments,
      'replay executes no additional Judge evaluation');
    const conflict = await chat({ key: outcomes[replayId].key,
      message: `${outcomes[replayId].message}\nchanged`, expectedStatus: 409 });
    assert.match(conflict.error, /different CodeBot request/);
    assert.equal(modelCalls, replayBefore, 'changed-body conflict must not invoke the model');

    const ownerKey = JSON.stringify(['CodeBot', String(owner.id)]);
    const effects = (await runtime.query(`SELECT status,effect_key,run_id::text
      FROM graph_runtime.effects WHERE owner_key=$1 ORDER BY effect_key`, [ownerKey])).rows;
    verifySemantic('transform_objectives:durable_effect_count', () =>
      assert.equal(effects.filter(row => row.status === 'completed').length, representative?1:3,
        'selected transform objectives must create durable sandbox effects'));
    assert.ok(effects.every(row => row.effect_key.endsWith(':codebot-transform')));

    const siblingMessage = solutions.clean_request.examples[0].prompt;
    const siblingModelBefore = modelCalls;
    const siblingCaseId=representative?'clean_request':'sibling:clean_request';
    const siblingKey=representative?'codebot-sibling-clean-0001':outcomes.clean_request.key;
    owned?.transport.beginCase(siblingCaseId);
    const siblingResult = await chat({ session: siblingSession, key:siblingKey,
      message: siblingMessage });
    if(owned){await owned.capture({runtime,userId:sibling.id,key:siblingKey,message:siblingMessage,body:siblingResult,caseId:siblingCaseId});owned.transport.endCase();}
    const cleanPackets = (await runtime.query(`SELECT p.packet FROM workshop_platform.grade_packets p
      JOIN workshop_platform.objective_judgments j USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.objective_id='clean_request'`, [sibling.id])).rows;
    assert.equal(cleanPackets.length, 1);
    verifyCleanPacket(cleanPackets[0].packet, JSON.parse(siblingMessage.slice(siblingMessage.indexOf('{'))));
    const afterSibling = modelCalls;
    assert.ok(afterSibling > siblingModelBefore, 'a different owner receives a fresh model-backed result');
    assert.ok(Array.isArray(siblingResult.newlyCompletedObjectives));
    const siblingCompletionCount = (await runtime.query(`SELECT count(*)::int AS count FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='supply_chain_rce'`, [sibling.id])).rows[0].count;
    verifySemantic('sibling:clean_request_completion', () => {
      assert.ok(siblingResult.newlyCompletedObjectives.includes('clean_request'));
      assert.equal(siblingCompletionCount, 1);
    });
    await identity.revokeSession(siblingSession.token, sibling.id, 'qualification');
    await chat({ session: siblingSession, key:siblingKey,
      message: siblingMessage, expectedStatus: 401 });
    assert.equal(modelCalls, afterSibling, 'a revoked session cannot retrieve its stored response');

    const primaryCompletionIds=(await runtime.query("SELECT objective_id FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='supply_chain_rce' ORDER BY objective_id",[owner.id])).rows.map(row=>row.objective_id);
    if(!representative)assert.deepEqual(primaryCompletionIds,[...SC_OBJECTIVE_IDS].sort(),'Exact six canonical primary completions required');
    const historyBefore=owned?await immutableHistory(runtime,[owner.id,sibling.id]):null;
    if(owned)owned.historySnapshot?.('before',historyBefore);
    const resetResponse = await fetch(`${base}/progress/reset`, {
      method: 'POST', headers: headersFor(ownerSession), signal:owned?.signal, body:'{}',
    });
    assert.equal(resetResponse.status, 200);
    const resetBody = await resetResponse.json();
    assert.equal(resetBody.progress.every(row => row.status === 'pending'), true);
    assert.equal((await runtime.query(`SELECT count(*)::int AS count FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='supply_chain_rce'`, [owner.id])).rows[0].count, 0);
    const siblingAfterReset = (await runtime.query(`SELECT count(*)::int AS count FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='supply_chain_rce'`, [sibling.id])).rows[0].count;
    if (siblingCompletionCount > 0) {
      assert.equal(siblingAfterReset, siblingCompletionCount,
        'owner reset must preserve existing sibling progress');
    } else {
      skippedDependencies.push({ check: 'reset:sibling_progress_preservation',
        reason: 'sibling clean_request received no canonical completion to preserve' });
    }
    if(owned){const historyAfter=await immutableHistory(runtime,[owner.id,sibling.id]);owned.historySnapshot?.('after',historyAfter);verifyImmutableHistory(historyBefore,historyAfter);}
    const staleReplay = await chat({ key: outcomes[replayId].key,
      message: outcomes[replayId].message, expectedStatus: 409 });
    assert.match(staleReplay.error, /earlier CodeBot generation/);
    assert.equal(modelCalls, afterSibling,
      'revoked and stale-generation requests run no model after the sibling request');

    const journalRows = (await runtime.query(`SELECT user_id,platform_session_id,generation::text,status,
      octet_length(response_json::text) AS response_bytes FROM graph_runtime.codebot_requests ORDER BY user_id,created_at`)).rows;
    assert.equal(journalRows.length, representative?2:7);
    assert.equal(journalRows.every(row => row.status === 'completed' && row.response_bytes > 0), true);
    t.diagnostic(JSON.stringify({ actualEffects: effects, actualJournal: journalRows,
      semanticFailures, skippedDependencies }));
    if (fixedControl) {
      const changed = await fetch(`${base}/mode`, { method: 'POST', headers: headersFor(ownerSession),
        body: JSON.stringify({ mode: 'fixed' }) });
      assert.equal(changed.status, 200);
      const completionRows = async () => (await runtime.query("SELECT * FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='supply_chain_rce' ORDER BY objective_id", [owner.id])).rows;
      const before = await completionRows();
      const negative = await chat({ key: 'codebot-fixed-transform-0001',
        message: 'Check this exact package.json manifest: '+JSON.stringify({name:'safe-fixture',version:'1.0.0',dependencies:{},transform:'return 1'}) });
      const receipts = (await runtime.query("SELECT verdict,disposition FROM workshop_platform.objective_judgments WHERE user_id=$1 AND objective_id='clean_request' ORDER BY created_at", [owner.id])).rows;
      verifyFixedDenial(negative, before, await completionRows(), receipts);
    }
    owned?.complete({outcomes,siblingResult,effects,journalRows,primaryCompletionIds,semanticFailures,skippedDependencies});
    if (semanticFailures.length) {
      throw new AggregateError(semanticFailures.map(failure =>
        new Error(`${failure.label}: ${failure.message}`)), 'CodeBot semantic qualification failed');
    }
  } catch(error){primary=error;throw error;} finally {
    if(owned){let cleanupError;try{const cleanup=await require('../fixtures/codeBotCurrentBinding').closeOwned([['http',()=>server&&new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['shared-pools',()=>require('../../server/database/postgres').closePostgresPools()],...pools.map((p,i)=>['pool-'+i,()=>p.end()])]);owned.cleanupSuccess(cleanup);}catch(error){owned.cleanupFailure(error.cleanupFailures);cleanupError=error;}finally{for(const fn of restore)fn();Module._load=originalLoad;}if(cleanupError&&!primary)throw cleanupError;}else{
    if (server) await new Promise(resolve => server.close(resolve));
    await require('../../server/database/postgres').closePostgresPools().catch(() => {});
    await Promise.allSettled(pools.map(pool => pool.end()));
    if(admin){await admin.query(`DROP DATABASE IF EXISTS ${supplyName}`).catch(() => {});
    await admin.query(`DROP DATABASE IF EXISTS ${name}`).catch(() => {});
    await admin.end();}
    Module._load = originalLoad;
    }
  }
}

module.exports={verifyCleanPacket,verifyFixedDenial,HISTORY_QUERIES,immutableHistory,verifyImmutableHistory,qualifyCodeBot};
if(!process.env.CODEBOT_CURRENT_NATIVE)test('CodeBot mounted JWT workflow binds real model-selected effects, replay and reset',{skip:!enabled,timeout:360000},qualifyCodeBot);

test('CodeBot persisted clean binding and fixed denial assertions reject altered evidence', () => {
  const manifest = {name:'safe-fixture',version:'1.0.0',dependencies:{}};
  const packet = {evidence:[{source:'tool_result',content:{name:'check_dependencies',params:{manifest:JSON.stringify(manifest)},result:{security:'clean'}}}]};
  verifyCleanPacket(packet, manifest);
  for (const mutate of [p=>{p.evidence[0].content.name='other';},p=>{p.evidence[0].content.result.security='blocked';},p=>{p.evidence[0].content.params.manifest='{}';}]) {
    const altered = structuredClone(packet); mutate(altered); assert.throws(()=>verifyCleanPacket(altered,manifest));
  }
  const body={newlyCompletedObjectives:[],judgments:[]}, receipts=[{verdict:'pass',disposition:'awarded'}];
  verifyFixedDenial(body,[],[],receipts);
  assert.throws(()=>verifyFixedDenial({...body,newlyCompletedObjectives:['clean_request']},[],[],receipts));
  assert.throws(()=>verifyFixedDenial({...body,judgments:[{verdict:'pass'}]},[],[],receipts));
  assert.throws(()=>verifyFixedDenial(body,[],[{objective_id:'clean_request'}],receipts));
  assert.throws(()=>verifyFixedDenial(body,[],[],[]));
});
