'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');
const MODEL = 'llama3.1:8b';
const WORKSHOP = 'sensitive_info_disclosure';
const enabled = process.env.FINFLOW_ENUM_MULTITURN_NATIVE === '1';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const parse = value => { try { return JSON.parse(value); } catch { return null; } };
function text(call) {
  const body = parse(call.raw);
  if (typeof body?.response === 'string') return body.response;
  if (typeof body?.message?.content === 'string') return body.message.content;
  return call.raw.split(/\r?\n/).map(parse).filter(Boolean).map(row => row.response || row.message?.content || '').join('');
}
function prompt(request) {
  return request?.prompt || (request?.messages || []).map(row => `${row.role}\n${row.content}`).join('\n');
}
function phase(value) {
  if (/AUTHORITATIVE RUBRIC:|EVALUATION DATA \(JSON\):|You evaluate an educational security exercise/.test(value)) return 'judge';
  if (/Select exactly one FinFlow action from the catalog/.test(value)) return 'decision';
  if (/Respond based on the actual results/.test(value)) return 'response';
  return 'other';
}
function judgeDiagnostics(call, assistantResponse) {
  const decoded = parse(text(call));
  const envelope = parse(call.raw) || call.raw.split(/\r?\n/).map(parse).filter(Boolean).at(-1) || {};
  const criteria = Array.isArray(decoded?.criteria) ? decoded.criteria : decoded && typeof decoded === 'object' ? [decoded] : [];
  return {
    parsedJSONValid: decoded !== null,
    evalCount: Number.isSafeInteger(envelope.eval_count) ? envelope.eval_count : null,
    outputTokens: Number.isSafeInteger(envelope.usage?.completion_tokens) ? envelope.usage.completion_tokens : null,
    doneReason: typeof envelope.done_reason === 'string' && /^[a-z_]{1,40}$/.test(envelope.done_reason) ? envelope.done_reason : null,
    criteria: criteria.map(item => ({
      id: typeof item.id === 'string' && /^[a-z0-9_]{1,100}$/.test(item.id) ? item.id : null,
      satisfied: typeof item.satisfied === 'boolean' ? item.satisfied : null,
      citations: (Array.isArray(item.citations) ? item.citations : []).map(citation => ({
        quoteCharacters: typeof citation.quote === 'string' ? citation.quote.length : null,
        quoteBytes: typeof citation.quote === 'string' ? Buffer.byteLength(citation.quote) : null,
        exactAssistantGrounding: typeof citation.quote === 'string' && citation.quote.length > 0 && assistantResponse.includes(citation.quote),
      })),
    })),
  };
}
function binding(variable, database, role) {
  const url = new URL(process.env[variable]);
  assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, `/${database}`); assert.equal(url.username, role);
  assert.equal(url.search, ''); assert.equal(url.hash, '');
}

function bindCapture(capture, rows) {
  const {ownerId,request,response,run,trace,judgment,packetRecord,packet}=capture;
  assert.equal(response.status,200);assert(run&&judgment&&packetRecord&&packet);assert(trace.length>0);
  const ownerKey=JSON.stringify(['FinFlow',String(ownerId)]);
  assert.equal(run.owner_key,ownerKey);assert.equal(run.run_id,response.body.run.runId);
  assert(trace.every(x=>x.run_id===run.run_id&&x.owner_key===ownerKey));
  assert.equal(String(judgment.user_id),String(ownerId));assert.equal(judgment.run_id,run.run_id);assert.equal(String(judgment.generation),String(run.generation));
  assert.equal(packetRecord.owner_key,ownerKey);assert.equal(String(packetRecord.owner_generation),String(run.generation));
  assert.equal(packetRecord.evaluation_id,judgment.evaluation_id);assert.equal(String(packetRecord.user_id),String(ownerId));
  assert.equal(typeof packetRecord.packet,'string');assert.equal(sha(packetRecord.packet),judgment.evidence_digest);assert.deepEqual(JSON.parse(packetRecord.packet),packet);
  assert.equal(packet.rubric.objectiveId,'admin_enum');assert(['finflow-admin-catalog-v2','finflow-admin-catalog-v3'].includes(packet.rubric.version));
  const selection=packet.rubric.version==='finflow-admin-catalog-v3'?require('../../server/agent-runtime/finflowAdminCatalogSelection').prepare(packet):null;
  assert.equal(packet.rubric.mode,capture.caseId.startsWith('fixed:')?'fixed':'vuln');
  assert(packet.evidence.some(x=>x.source==='assistant_response'&&x.content===response.body.response));
  assert(packet.evidence.some(x=>x.source==='student_input'&&x.content===request.userMessage));
  const reported=response.body.judgments.find(x=>x.objectiveId==='admin_enum');assert(reported);assert.equal(reported.evaluationId||reported.receiptId,judgment.evaluation_id);
  assert.equal(reported.verdict,judgment.verdict);assert.equal(reported.provider,'ollama');assert.equal(reported.model,MODEL);assert(!['unavailable','inconclusive'].includes(judgment.verdict));
  const decoded=rows.filter(x=>!['tags','version'].includes(x.kind)).map(row=>{
    require('./finflowBackupBrowserActualTransport').validateResponse(row);assert.equal(row.terminal,'returned');assert.equal(sha(row.request),row.requestSha256);assert.equal(Buffer.byteLength(row.request),row.requestBytes);
    const request=JSON.parse(row.request);assert.equal(request.model,MODEL);return {row,request,output:text({raw:row.response})};
  });
  assert.deepEqual(rows.map(x=>x.index),capture.wireIndexes);
  const decisions=decoded.filter(x=>x.row.kind==='generate'&&x.request.format==='json'),summaries=decoded.filter(x=>x.row.kind==='generate'&&x.request.format!=='json'),judges=decoded.filter(x=>x.row.kind==='chat');
  assert(decisions.length>0);for(const x of decisions)assert(x.request.prompt.includes('\nRequest: '+JSON.stringify(request.userMessage)));
  assert(summaries.length>0);assert.equal(summaries.at(-1).output,response.body.response);assert(judges.length>=1&&judges.length<=2);
  for(const x of judges){assert.equal(x.request.messages.length,2);const [system,user]=x.request.messages;assert.equal(system.role,'system');assert.equal(user.role,'user');assert(system.content.includes('AUTHORITATIVE RUBRIC:\n'+JSON.stringify(packet.rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+JSON.stringify(packet.facts)+'\n'));assert.deepEqual(JSON.parse(user.content),selection?selection.payload:packet.evidence);if(selection){assert.deepEqual(x.request.format,selection.format);assert(system.content.startsWith(require('../../server/agent-runtime/finflowAdminCatalogSelection').POLICY));}}
  const rawVerdict=parse(judges.at(-1).output);assert(rawVerdict);
  const resolved=selection?selection.resolve(rawVerdict):null;
  const verdict=resolved?resolved.value:rawVerdict;
  if(resolved){assert.deepEqual(reported.finflowCatalogSelection,resolved.audit);assert.deepEqual(judgment.result_json.finflowCatalogSelection,resolved.audit);require('../../server/agent-runtime/finflowAdminCatalogSelection').normalizeAudit(resolved.audit,{...reported,evidenceDigest:judgment.evidence_digest});}
  assert(verdict);assert.equal(verdict.verdict,judgment.verdict);assert.deepEqual(verdict.criteria,reported.criteria);
  if(reported.completed){
    assert.equal(judgment.disposition,'awarded');for(const key of packet.rubric.requiredFacts)assert.equal(packet.facts[key],true);
    const observation=packet.evidence.find(x=>x.id==='admin_catalog_observation').content,w=observation.witness;
    assert.equal(w.ownerKey,ownerKey);assert.equal(w.runId,run.run_id);assert.equal(String(w.generation),String(run.generation));assert.equal(w.provider,'ollama');assert.equal(w.model,MODEL);assert.equal(w.requestSha256,sha(request.userMessage));
    assert.equal(w.toolCount,8);assert(decisions.some(x=>parse(x.output)?.action==='admin_catalog_observation'));assert.equal(observation.catalog.length,8);
    const digest=require('../../server/services/finflowAdminCatalogObservation')._internals.digest;assert.equal(w.outputSha256,digest(observation.catalog));
  }else assert.equal(judgment.disposition,'not_pass');
  return true;
}

async function runQualification(ownedOptions) {
  const {owned,runtime,ports,source}=ownedOptions||{};
  if(owned){assert.equal(owned.profile,'actual-admin-enum');assert.equal(source,fs.realpathSync(path.resolve(__dirname,'../..')));assert.equal(fs.realpathSync(process.cwd()),runtime);assert(ports instanceof Set);assert.equal(fs.realpathSync(runtime),runtime);}
  // Fail before importing any application singleton or creating a connection.
  assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
  if(!owned)assert.equal(fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE), fs.realpathSync(process.cwd()));
  assert.equal(process.env.PLATFORM_DATABASE_ENGINE, 'postgres');
  assert.equal(process.env.WORKSHOP_DATABASE_ENGINE, 'postgres');
  if(!owned){
  binding('IDENTITY_DATABASE_URL', 'dvaia_test_finflow_enum_identity', 'dvaia_identity_runtime');
  binding('IDENTITY_MIGRATION_DATABASE_URL', 'dvaia_test_finflow_enum_identity', 'dvaia_identity_migration');
  binding('FINFLOW_WORKSHOP_DATABASE_URL', 'dvaia_test_finflow_enum_store', 'dvaia_finflow_runtime');
  binding('FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL', 'dvaia_test_finflow_enum_store', 'dvaia_finflow_migration');
  assert.equal(process.env.AI_PROVIDER, 'ollama');
  assert.equal(process.env.OLLAMA_BASE_URL, 'http://127.0.0.1:11434');
  assert.equal(process.env.OLLAMA_MODEL, MODEL);
  assert.equal(process.env.JUDGE_PROVIDER, 'ollama'); assert.equal(process.env.JUDGE_MODEL, MODEL);
  }
  const workspace = owned?source:fs.realpathSync(process.cwd());
  const evidencePath = owned?path.join(owned.evidence,'result.json'):process.env.FINFLOW_ENUM_MULTITURN_EVIDENCE_PATH;
  assert.ok(path.isAbsolute(evidencePath || ''));
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true, mode: 0o700 });
  const evidenceParent = fs.realpathSync(path.dirname(evidencePath));
  if(!owned)assert.ok(evidenceParent !== workspace && !evidenceParent.startsWith(`${workspace}${path.sep}`));
  assert.equal(fs.existsSync(evidencePath), false, 'Do not overwrite previous evidence');
  const sequence = JSON.parse(fs.readFileSync(path.join(workspace, 'tasks/finflow-admin-enum-multiturn-exploration-2026-09-19.json'), 'utf8')).successfulSequence;
  assert.equal(sequence.length, 2); assert.ok(sequence.every(value => typeof value === 'string' && value.length > 0));
  if(owned)assert.deepEqual(owned.input.successfulSequence,sequence);
  const evidence = { ...(owned?{profile:'actual-admin-enum',scope:'eight-turn-admin-enum-actual-native',sourceRoot:source,installedWrites:false,actualModelProof:false,modelWireVerified:false,cleanupFailures:[]}:{}), model: MODEL, status: 'incomplete', sequenceSha256: sequence.map(sha), cases: [], failures: [] };
  const captures={profile:'actual-admin-enum',cases:[],reset:null};
  const persist = () => { if(owned){const {saveBounded}=require('../fixtures/boundedJsonArtifact');saveBounded(evidencePath,evidence);saveBounded(path.join(owned.evidence,'admin-enum-captures.json'),captures);return;}  const pending = `${evidencePath}.${process.pid}.pending`; fs.writeFileSync(pending, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 }); fs.renameSync(pending, evidencePath); };
  const check = (row, key, value) => { row.checks[key] = value === true; if (value !== true) evidence.failures.push(`${row.name}:${key}`); };
  const originalLoad = Module._load, originalFetch = globalThis.fetch;
  const calls = [], pools = []; let server, closePools, proxy, primary;
  persist();
  Module._load = function (request, parent, isMain) {
    if (/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(request)) throw Error('SQLite import forbidden in native qualification');
    return originalLoad.call(this, request, parent, isMain);
  };
  globalThis.fetch = async (input, init) => {
    const url = String(input?.url || input);
    if (!/^http:\/\/(?:127\.0\.0\.1|localhost):11434\//.test(url)) return originalFetch(input, init);
    const rawRequest = init?.body != null ? String(init.body) : input instanceof Request ? await input.clone().text() : '';
    const response = await originalFetch(input, init), raw = await response.clone().text();
    calls.push({ status: response.status, request: parse(rawRequest), raw, requestSha256: sha(rawRequest), responseSha256: sha(raw) });
    return response;
  };
  try {
    if(owned){proxy=await require('./finflowBackupBrowserActualTransport').createTransport({evidence:owned.evidence,policyCohort:'admin-enum'});ports.add(Number(new URL(proxy.actorUrl).port));Object.assign(process.env,{AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',OLLAMA_BASE_URL:proxy.actorUrl,OLLAMA_MODEL:MODEL,JUDGE_MODEL:MODEL,JUDGE_CONTEXT_TOKENS:'32768',LMSTUDIO_BASE_URL:proxy.actorUrl+'/denied',AWS_EC2_METADATA_DISABLED:'true',OPENAI_API_KEY:'',ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'',AWS_ACCESS_KEY_ID:'',AWS_SECRET_ACCESS_KEY:'',AWS_PROFILE:'',AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'',AWS_WEB_IDENTITY_TOKEN_FILE:''});}
    const tags = owned?JSON.parse(proxy.snapshot().calls[0].response):await originalFetch(`${process.env.OLLAMA_BASE_URL}/api/tags`).then(r => r.json());
    const installed = tags.models?.find(row => row.name === MODEL || row.model === MODEL);
    assert.ok(installed?.digest, 'Configured actual model must be installed');
    if(owned)assert.equal(installed.digest,require('./finflowBackupBrowserActualTransport').DIGEST);
    evidence.modelDigest = installed.digest; persist();
    const postgres = require('../../server/database/postgres'); closePools = postgres.closePostgresPools;
    const pool = name => { const value = postgres.createPool(process.env, name); pools.push(value); return value; };
    const identityRuntime = pool('IDENTITY_DATABASE_URL'), identityMigration = pool('IDENTITY_MIGRATION_DATABASE_URL');
    const finflowRuntime = pool('FINFLOW_WORKSHOP_DATABASE_URL'), finflowMigration = pool('FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL');
    const api = require('../../server/database/postgres/identityRepository');
    await api.initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    await require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(finflowRuntime).initialize(finflowMigration);
    const identity = api.createIdentityRepository(identityRuntime);
    const progress = require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identityRuntime);
    const adapter = require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({ repository: identity, progress, jwtSecret: process.env.JWT_SECRET });
    const passwordHash = await require('bcryptjs').hash('OwnedQualification@fixture', 4), actors = [];
    for (let i = 0; i < 4; i++) {
      const user = await identity.createUser({ username: `enum-multiturn-${i}`, email: `enum-multiturn-${i}@fixture.invalid`, passwordHash });
      const session = await adapter.createSession(await identity.findCredentialById(user.id), { get: () => null, ip: '127.0.0.1' });
      actors.push({ user, session });
    }
    const config = require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identityRuntime);
    await config.setExerciseVisibility(WORKSHOP, true, actors[0].user.id);
    await config.setObjectiveVisibility(WORKSHOP, 'admin_enum', true, actors[0].user.id);
    const express = require('express'), app = express(); app.use(express.json({ limit: '128kb' }));
    app.use('/api/workshop/sensitive-info', require('../../server/routes/sensitiveInfoWorkshop'));
    server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
    if(owned)ports.add(server.address().port);
    const base = `http://127.0.0.1:${server.address().port}/api/workshop/sensitive-info`;
    const http = async (actor, endpoint, body = {}) => {
      const result = await originalFetch(`${base}${endpoint}`, { method: 'POST', headers: { authorization: `Bearer ${actor.session.token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) });
      return { status: result.status, body: await result.json() };
    };
    const state = async actor => ({ generation: await progress.getGeneration(actor.user.id, WORKSHOP), rows: (await identityRuntime.query('SELECT objective_id,completed_at::text FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id', [actor.user.id, WORKSHOP])).rows });
    const definitions = require('../../server/services/sensitiveInfoWorkshopAgent').ADMIN_TOOL_SCHEMAS;
    assert.equal(definitions.length, 8);
    for (const value of sequence) assert.ok(definitions.every(row => !value.includes(row.function.name)), 'Candidate must not supply the restricted names');
    for (let i = 0; i < actors.length; i++) {
      const actor = actors[i], fixed = i === 3, row = { name: fixed ? 'fixed' : `fresh-owner-${i + 1}`, checks: {}, turns: [] };
      evidence.cases.push(row); persist();
      const init = await http(actor, '/init'); check(row, 'initialized', init.status === 200);
      if (fixed) { const mode = await http(actor, '/mode', { mode: 'fixed' }); check(row, 'fixed_mode_set', mode.status === 200 && mode.body.mode === 'fixed'); }
      const history = [];
      for (let turn = 0; turn < 2; turn++) {
        const caseId=row.name+':turn-'+(turn+1);if(proxy)proxy.beginCase(caseId);
        const start = calls.length, request={ userMessage: sequence[turn], objectiveId: 'admin_enum', conversationHistory: structuredClone(history) };
        const result = await http(actor, '/chat', request);
        if(proxy)proxy.endCase();
        const wire=proxy?proxy.snapshot().calls.filter(x=>x.caseId===caseId):[];
        const observed = proxy?wire.filter(x=>!['tags','version'].includes(x.kind)).map(x=>({...x,raw:x.response,request:JSON.parse(x.request)})):calls.slice(start), response = result.body?.response || '', judgment = result.body?.judgments?.find(value => value.objectiveId === 'admin_enum');
        const selected = observed.filter(call => phase(prompt(call.request)) === 'decision').map(call => parse(text(call))?.action);
        const receipts = result.body?.run?.runId ? (await identityRuntime.query('SELECT evaluation_id,objective_id,verdict,disposition,evidence_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 AND run_id=$2 ORDER BY evaluation_id', [actor.user.id, result.body.run.runId])).rows : [];
        const turnRow = { turn: turn + 1, status: result.status, responseSha256: sha(response), responseCharacters: response.length, historySha256: sha(JSON.stringify(history)), selectedActions: selected, namesDisclosed: definitions.filter(value => response.includes(value.function.name)).length, verdict: judgment?.verdict || null, completed: judgment?.completed === true, receiptCount: receipts.length, receiptsSha256: sha(JSON.stringify(receipts)), calls: observed.map(call => ({ phase: phase(prompt(call.request)), status: call.status, model: call.request?.model, requestSha256: call.requestSha256, responseSha256: call.responseSha256 })) };
        turnRow.judgeDiagnostics = observed.filter(call => phase(prompt(call.request)) === 'judge').map(call => judgeDiagnostics(call, response));
        turnRow.validationTrace = result.body?.run?.runId ? (await identityRuntime.query(
          `SELECT node,event_type,metadata->>'validationCode' AS validation_code,metadata->>'errorCode' AS error_code
           FROM graph_runtime.events WHERE run_id=$1 AND (metadata ? 'validationCode' OR metadata ? 'errorCode') ORDER BY sequence`,
          [result.body.run.runId])).rows.map(value => Object.fromEntries(Object.entries(value).map(([key, content]) =>
            [key, typeof content === 'string' && /^[a-zA-Z0-9_:-]{1,160}$/.test(content) ? content : null]))) : [];
        if(owned){
          const runId=result.body?.run?.runId||null,ownerKey=JSON.stringify(['FinFlow',String(actor.user.id)]);
          const run=runId?(await identityRuntime.query('SELECT to_jsonb(r) row FROM graph_runtime.runs r WHERE run_id=$1 AND owner_key=$2',[runId,ownerKey])).rows[0]?.row||null:null;
          const trace=runId?(await identityRuntime.query('SELECT to_jsonb(e) row FROM graph_runtime.events e WHERE run_id=$1 AND owner_key=$2 ORDER BY sequence',[runId,ownerKey])).rows.map(x=>x.row):[];
          const pair=runId?(await identityRuntime.query('SELECT to_jsonb(j) judgment,to_jsonb(p) packet_record FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.run_id=$2',[actor.user.id,runId])).rows:[];
          const packetRecord=pair[0]?.packet_record||null,packet=typeof packetRecord?.packet==='string'?JSON.parse(packetRecord.packet):packetRecord?.packet||null;
          const capture={caseId,ownerId:actor.user.id,request,response:result,run,trace,judgment:pair[0]?.judgment||null,packetRecord,packet,wireIndexes:wire.map(x=>x.index)};captures.cases.push(capture);persist();
          try{bindCapture(capture,wire);check(row,`turn_${turn+1}_packet_wire_binding`,true);}catch(error){check(row,`turn_${turn+1}_packet_wire_binding`,false);capture.bindingError={name:error.name,messageSha256:sha(String(error.message))};}
          if(turn===0)check(row,'benign_first_turn_no_credit',judgment?.verdict!=='pass'&&judgment?.completed!==true&&(await state(actor)).rows.length===0);
        }
        row.turns.push(turnRow); persist();
        check(row, `turn_${turn + 1}_http`, result.status === 200 && response.length > 0);
        check(row, `turn_${turn + 1}_actual_model`, observed.length >= 3 && observed.every(call => call.status === 200 && call.request?.model === MODEL && text(call).trim()) && observed.some(call => phase(prompt(call.request)) === 'judge'));
        check(row, `turn_${turn + 1}_judge_provenance`, judgment?.provider === 'ollama' && judgment?.model === MODEL);
        check(row, `turn_${turn + 1}_persisted_receipt`, receipts.some(value => value.evaluation_id === (judgment?.evaluationId || judgment?.receiptId) && value.objective_id === 'admin_enum' && value.verdict === judgment?.verdict && value.disposition === (judgment?.completed ? 'awarded' : 'not_pass') && /^[a-f0-9]{64}$/.test(value.evidence_digest)));
        if (turn === 1) {
          check(row, 'generated_history_used', observed.filter(call => phase(prompt(call.request)) === 'decision').some(call => prompt(call.request).includes(JSON.stringify(history[1].content).slice(1, -1))));
          const responseCalls = observed.filter(call => phase(prompt(call.request)) === 'response');
          if (!fixed) {
            check(row, 'fresh_catalog_selected', selected.length === 1 && selected[0] === 'admin_catalog_observation');
            check(row, 'authoritative_catalog_received', responseCalls.some(call => prompt(call.request).includes('Actual authoritative administrative catalog observation') && definitions.every(value => prompt(call.request).includes(value.function.name))));
            check(row, 'eight_names', turnRow.namesDisclosed === 8);
            check(row, 'real_judge_pass', judgment?.verdict === 'pass' && judgment?.completed === true && judgment?.criteria?.some(value => value.id === 'learner_facing_admin_catalog_names_and_purposes' && value.satisfied === true) && judgment?.criteria?.some(value => value.id === 'model_selected_admin_catalog_observation' && value.satisfied === true));
            check(row, 'canonical_credit', result.body?.newlyCompletedObjectives?.includes('admin_enum') && (await state(actor)).rows.some(value => value.objective_id === 'admin_enum'));
          } else {
            check(row, 'fixed_catalog_unavailable', !selected.includes('admin_catalog_observation') && responseCalls.every(call => !prompt(call.request).includes('Actual authoritative administrative catalog observation')));
            check(row, 'fixed_denied_credit', judgment?.verdict !== 'pass' && judgment?.completed !== true && !result.body?.newlyCompletedObjectives?.includes('admin_enum') && (await state(actor)).rows.length === 0);
          }
        }
        history.push({ role: 'user', content: sequence[turn] }, { role: 'assistant', content: response }); persist();
      }
    }
    const resetRow = { name: 'owner-reset', checks: {} }; evidence.cases.push(resetRow);
    const before = await Promise.all(actors.map(state));
    const reset = await http(actors[0], '/progress/reset'); const after = await Promise.all(actors.map(state));
    if(owned){captures.reset={before,after,response:reset};persist();}
    check(resetRow, 'reset_success', reset.status === 200 && after[0].rows.length === 0 && after[0].generation === before[0].generation + 1);
    check(resetRow, 'siblings_preserved', JSON.stringify(before.slice(1)) === JSON.stringify(after.slice(1)));
    check(resetRow, 'sibling_credit_nonempty', before[1].rows.some(value => value.objective_id === 'admin_enum') && before[2].rows.some(value => value.objective_id === 'admin_enum'));
    if(proxy){proxy.assertComplete();evidence.counts=proxy.snapshot().counts;}
    evidence.status = evidence.failures.length ? 'failed' : owned?'checks-passed-cleanup-pending':'qualified'; persist();
    assert.deepEqual(evidence.failures, [], 'Actual-model qualification did not satisfy every criterion; inspect hash-only evidence');
  } catch (error) {
    primary=error;evidence.status = 'failed'; evidence.error = { name: error.name, code: error.code || null, messageSha256: sha(String(error.message)) }; persist(); throw error;
  } finally {
    globalThis.fetch = originalFetch; Module._load = originalLoad;
    if(owned){
      const outcomes=await require('../fixtures/secureshopAnalyticsBrowserOwner').settleOwnership([['http',()=>server&&new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['finflow',()=>closePools&&require('../../server/services/sensitiveInfoResetComposition').closeSensitiveInfoResetComposition()],['pools',async()=>{if(closePools)await closePools();await Promise.all(pools.map(pool=>pool.end()));}],['transport',()=>proxy?.close()]],10000);
      evidence.cleanupFailures=outcomes.filter(x=>x.status!=='fulfilled').map(x=>({name:x.name,code:'CLEANUP_FAILED'}));if(proxy)evidence.counts=proxy.snapshot().counts;
      if(!primary&&!evidence.cleanupFailures.length){evidence.status='passed';evidence.actualModelProof=true;evidence.modelWireVerified=true;}else evidence.status='failed';persist();
    }else{
    if (server) await new Promise(resolve => server.close(resolve));
    await require('../../server/services/sensitiveInfoResetComposition').closeSensitiveInfoResetComposition().catch(() => {});
    if (closePools) await closePools();
    await Promise.allSettled(pools.map(pool => pool.end())); persist();
    }
  }
  if(owned&&evidence.cleanupFailures.length)throw Error('FINFLOW_ENUM_CLEANUP_FAILED');return evidence;
}
async function runOwned(options){assert(options?.owned);return runQualification(options);}
module.exports={runOwned,bindCapture};
if(require.main===module)test('mounted FinFlow multi-turn admin catalog uses actual actor, Judge, persisted credit and owner reset', {skip:!enabled,timeout:1800000},()=>runQualification());
