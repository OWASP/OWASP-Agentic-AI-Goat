'use strict';
// Import-safe qualification composition. The launcher owns admission, stores,
// browser process, model transport, disk bounds and physical teardown.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { verifySameBackupDownload } = require('./finflowBackupBrowserEvidence');
const OBJECTIVES = Object.freeze(['admin_backup', 'admin_dl_backup']);
const ROUTES = Object.freeze(['/api/auth', '/api/workshop/config', '/api/workshop/sensitive-info', '/api/workshop', '/api/changes', '/api/solutions', '/api/hints']);
function assertStoreEnvironment(env) {
  assert.equal(env.PG_TEST_DISPOSABLE, 'yes');
  assert.equal(env.PLATFORM_DATABASE_ENGINE, 'postgres'); assert.equal(env.WORKSHOP_DATABASE_ENGINE, 'postgres');
  const names = new Set(), ports = new Set();
  for (const [prefix, suffix] of [['IDENTITY', 'identity'], ['FINFLOW_WORKSHOP', 'finflow']]) {
    const runtime = new URL(env[`${prefix}_DATABASE_URL`]), migration = new URL(env[`${prefix}_MIGRATION_DATABASE_URL`]);
    for (const u of [runtime, migration]) {
      assert.equal(u.protocol, 'postgresql:'); assert.equal(u.hostname, '127.0.0.1');
      assert.match(u.pathname, new RegExp(`^/owasp_ai_goat_test_finflow_browser_[a-f0-9]{12}_${suffix}$`));
      assert.ok(u.port && !u.search && !u.hash); ports.add(u.port);
    }
    assert.equal(runtime.pathname, migration.pathname); assert.notEqual(runtime.username, migration.username);
    assert.ok(runtime.username && migration.username); names.add(runtime.pathname);
  }
  assert.equal(names.size, 2); assert.equal(ports.size, 1);
}
function createBrowserApp({ buildRoot }) {
  assertStoreEnvironment(process.env);
  const expected = path.resolve(__dirname, '../../client/build');
  assert.equal(fs.realpathSync(buildRoot), expected); assert.ok(fs.statSync(path.join(expected, 'index.html')).isFile());
  const express = require('express'), app = express(); app.use(express.json({ limit: '128kb' }));
  const auth = require('../../server/routes/auth');
  app.use('/api/auth', auth);
  app.use('/api/workshop/config', require('../../server/routes/workshopConfig').createWorkshopConfigRouter());
  app.use('/api/workshop/sensitive-info', require('../../server/routes/sensitiveInfoWorkshop'));
  app.use('/api/workshop', require('../../server/routes/workshop'));
  app.use('/api/changes', require('../../server/routes/changeRevisions').createChangeRevisionsRouter({
    store: require('../../server/services/changeRevisionService'), authenticateToken: require('../../server/middleware/adminAuth').authenticateToken }));
  app.use('/api/solutions', require('../../server/routes/solutions')); app.use('/api/hints', require('../../server/routes/hints'));
  // Real unmounted API 404, not synthetic CTF configuration or SPA HTML success.
  // Navbar's existing failure path hides CTF; no CTF database is touched.
  app.use('/api', (_req, res) => res.sendStatus(404));
  app.use(express.static(expected)); app.get('/workshop/sensitive-info', (_req, res) => res.sendFile(path.join(expected, 'index.html')));
  return { app, close: () => auth.close() };
}
function contentBlockedPaths(profile){return ['/api/workshop/sensitive-info/chat','/api/workshop/sensitive-info/progress/complete',...(profile==='controlled-admin-enum-content'?[]:['/api/workshop/sensitive-info/progress/reset'])];}
async function createTraversalContentApp({buildRoot,adapter,pool,migration,progress,config,identity,profile}) {
  assertStoreEnvironment(process.env);const expected=path.resolve(__dirname,'../../client/build');assert.equal(fs.realpathSync(buildRoot),expected);
  const express=require('express'),app=express();app.use(express.json({limit:'128kb'}));
  const mounted=await require('./legacyFileSsiFullAppParity').mountLegacyParityRoutes({app,adapter,pool,migration,progress,config,identity});
  app.post(contentBlockedPaths(profile),(_q,res)=>res.status(403).json({error:'Model-free traversal content profile'}));
  app.use('/api/workshop/sensitive-info',require('../../server/routes/sensitiveInfoWorkshop'));
  app.use('/api/solutions',require('../../server/routes/solutions'));app.use('/api/hints',require('../../server/routes/hints'));
  app.use('/api',(_q,res)=>res.sendStatus(404));app.use(express.static(expected));app.get('/{*path}',(_q,res)=>res.sendFile(path.join(expected,'index.html')));
  return {app,adminToken:mounted.adminToken,close:mounted.close};
}
function assertJudgment({ objectiveId, ownerId, generation, run, trace, judgment, packet, call }) {
  assert.ok(OBJECTIVES.includes(objectiveId));
  assert.equal(run.owner_key, JSON.stringify(['FinFlow', String(ownerId)])); assert.equal(Number(run.generation), Number(generation));
  assert.equal(run.run_id, call.resourceMetadata.runId); assert.equal(run.provider, 'ollama'); assert.equal(run.model, 'llama3.1:8b');
  assert.equal(run.decision_source, 'model'); assert.ok(['completed', 'failed'].includes(run.status));
  assert.ok(trace.some(x => x.metadata?.provider === 'ollama' && x.metadata?.model === 'llama3.1:8b'));
  assert.equal(judgment.objective_id, objectiveId); assert.equal(String(judgment.user_id), String(ownerId)); assert.equal(judgment.run_id, run.run_id);
  assert.equal(judgment.verdict, 'pass'); assert.equal(judgment.disposition, 'awarded');
  const result = judgment.result_json; assert.equal(result.provider, 'ollama'); assert.equal(result.model, 'llama3.1:8b');
  assert.equal(packet.rubric.objectiveId, objectiveId); assert.equal(packet.rubric.version, 'finflow-structured-backup-v2'); assert.equal(packet.rubric.criterionScoped, true);
  assert.deepEqual(packet.rubric.requiredFacts, ['vulnerable_mode', 'required_observation', 'trusted_customer_policy_violation', 'trusted_backup_resource_receipt']);
  for (const fact of packet.rubric.requiredFacts) assert.equal(packet.facts[fact], true);
  const expected = [['customer_policy_violated', 'server_observation'], [objectiveId === 'admin_backup' ? 'backup_create_succeeded' : 'backup_download_succeeded', 'server_observation'], [objectiveId === 'admin_backup' ? 'backup_path_returned' : 'backup_contents_returned', 'tool_result']];
  assert.deepEqual(packet.rubric.criteria.map(x => [x.id, x.allowedSources?.[0]]), expected);
  assert.equal(packet.rubric.criteria.length, 3); assert.deepEqual(result.criteria.map(x => x.id), packet.rubric.criteria.map(x => x.id));
  for (const criterion of result.criteria) {
    const spec = packet.rubric.criteria.find(x => x.id === criterion.id);
    assert.equal(criterion.satisfied, true); assert.equal(spec.allowedSources.length, 1);
    assert.ok(criterion.evidenceRefs.length > 0);
    for (const ref of criterion.evidenceRefs) assert.equal(packet.evidence.find(x => x.id === ref)?.source, spec.allowedSources[0]);
  }
  const action = objectiveId === 'admin_backup' ? 'backup_created' : 'backup_downloaded';
  const pair = packet.evidence.find(x => x.id.startsWith('customer_policy_resource_pair_') && x.content?.resource?.action === action);
  assert.equal(pair?.source, 'server_observation');
  const resource = pair.content.resource, policy = pair.content.policyAction, m = call.resourceMetadata;
  for (const x of [resource, policy]) { assert.equal(String(x.ownerId), String(ownerId)); assert.equal(x.runId, run.run_id); }
  assert.equal(String(resource.generation), String(generation)); assert.equal(policy.policyViolation, true);
  assert.equal(resource.resourceReceipt.backupId, m.backupId);
  assert.equal(resource.resourceReceipt.requestedPath, m.virtualPath || m.requestedPath);
  const tool = packet.evidence.find(x => x.id === pair.content.toolEvidenceId);
  assert.equal(tool?.source, 'tool_result'); assert.equal(tool.content.result, call.result);
}
function createDatabaseInspector({ identityPool, finflowPool, ownerId, backupRoot }) {
  const seen = [];
  return async ({ objectiveId, body, call }) => {
    assert.equal(objectiveId, OBJECTIVES[seen.length]);
    const runId = body.run?.runId; assert.equal(runId, call.resourceMetadata.runId);
    const ownerKey = JSON.stringify(['FinFlow', String(ownerId)]);
    const run = (await identityPool.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1 AND owner_key=$2', [runId, ownerKey])).rows[0]; assert.ok(run);
    const trace = (await identityPool.query('SELECT metadata FROM graph_runtime.events WHERE run_id=$1 AND owner_key=$2 ORDER BY sequence', [runId, ownerKey])).rows;
    const rows = (await identityPool.query('SELECT to_jsonb(j) judgment,to_jsonb(p) packet_record FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id) WHERE j.user_id=$1 AND j.run_id=$2', [ownerId, runId])).rows;
    assert.equal(rows.length, 1); const judgment = rows[0].judgment;
    const raw = rows[0].packet_record.packet, packet = typeof raw === 'string' ? JSON.parse(raw) : raw;
    assert.equal(rows[0].packet_record.evaluation_id, judgment.evaluation_id);
    const artifact = (await finflowPool.query('SELECT * FROM finflow.backup_artifacts WHERE owner_id=$1 AND generation=$2 AND backup_id=$3', [ownerId, run.generation, call.resourceMetadata.backupId])).rows[0];
    assert.equal(artifact?.status, 'ready'); assert.equal(artifact.retired_at, null);
    assert.match(artifact.file_token, /^[a-f0-9-]{36}$/);
    const root = fs.realpathSync(backupRoot), file = path.join(root, 'artifacts', artifact.file_token, 'artifact.bak');
    assert.equal(fs.realpathSync(file), file); const st = fs.lstatSync(file);
    assert.ok(st.isFile() && st.nlink === 1 && st.size <= 16 * 1024 * 1024);
    const physicalBytes = fs.readFileSync(file);
    const evidence = { ownerId, generation: run.generation, run, trace, judgment, packet, physicalBytes };
    if (objectiveId === 'admin_dl_backup') {
      const read = (await finflowPool.query('SELECT * FROM finflow.backup_reads WHERE owner_id=$1 AND generation=$2 AND run_id=$3', [ownerId, run.generation, runId])).rows;
      assert.equal(read.length, 1); const r = read[0];
      evidence.read = { ownerId:r.owner_id, generation:r.generation, runId:r.run_id, operationId:r.operation_id, backupId:r.backup_id, requestedPath:r.requested_path, contentSha256:r.content_sha256, byteLength:r.byte_length };
      assert.equal(artifact.run_id, seen[0].runId); assert.equal(artifact.operation_id, seen[0].operationId);
    }
    assert.equal(artifact.content_sha256, call.resourceMetadata.contentSha256);
    assert.equal(Number(artifact.byte_length), physicalBytes.length);
    const completions = (await identityPool.query('SELECT objective_id FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key=$2 ORDER BY objective_id', [ownerId, 'sensitive_info_disclosure'])).rows.map(x => x.objective_id);
    assert.deepEqual(completions, [...seen.map(x => x.objectiveId), objectiveId].sort());
    assertJudgment({ ...evidence, objectiveId, call });
    seen.push({ objectiveId, runId, operationId:call.resourceMetadata.operationId });
    return evidence;
  };
}
function completedCardVisible({ label, done, total }) {
  const name = [...document.querySelectorAll('.obj-name')].find(x => x.textContent === label);
  const card = name?.parentElement?.parentElement, icon = card?.querySelector('.obj-icon');
  const progress = [...document.querySelectorAll('span')].find(x => x.textContent === 'Progress');
  const text = progress?.parentElement?.textContent?.replace(/\s+/g, ' ').trim();
  return Boolean(card?.querySelector('.status-badge')?.textContent === 'DONE'
    && icon?.querySelector('svg') && getComputedStyle(icon).backgroundColor === 'rgb(34, 197, 94)'
    && text === `Progress${done} / ${total} ${Math.round(done / total * 100)}%`
    && document.querySelector('textarea:not([disabled])'));
}
function categoryTab({label,click=false}) {
  const matches=[...document.querySelectorAll('button')].filter(button=>[...button.childNodes].filter(node=>node.nodeType===3).map(node=>node.textContent).join('').trim()===label);
  if(matches.length!==1)return false;
  if(click)matches[0].click();
  return true;
}
async function admitInitialResponses(initResponse,progressResponse,total) {
  const init=await initResponse;assert.equal(init.status(),200,'FINFLOW_INIT_HTTP_FAILED');
  const initialized=await init.json();assert.equal(initialized.success,true,'FINFLOW_INIT_NOT_READY');
  const progress=await progressResponse;assert.equal(progress.status(),200,'FINFLOW_PROGRESS_HTTP_FAILED');
  const body=await progress.json();assert(Array.isArray(body.progress));assert.equal(body.progress.length,total);
  const labels={};
  for(const id of OBJECTIVES){
    const initializedRows=initialized.objectives?.filter(row=>row.id===id),rows=body.progress.filter(row=>row.id===id);
    assert.equal(initializedRows?.length,1);assert.equal(rows.length,1);
    assert.equal(typeof initializedRows[0].label,'string');assert(initializedRows[0].label.length>0);
    labels[id]=initializedRows[0].label;assert.equal(rows[0].label,labels[id],'FINFLOW_PROGRESS_LABEL_MISMATCH');
  }
  return labels;
}
async function bounded(promise, ms, label) {
  let timer; try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Error(label)), ms); })]); }
  finally { clearTimeout(timer); }
}
async function runBrowserChain({ browser, origin, sessionToken, labels, prompts, expectedTotal, downloadDirectory, inspect, beforeTurn = async () => {}, afterTurn = async () => {}, timeoutMs = 600000 }) {
  assert.equal(new URL(origin).hostname, '127.0.0.1'); assert.equal(new URL(origin).origin, origin);
  assert.ok(Number.isSafeInteger(expectedTotal) && expectedTotal >= 2);
  assert.ok(typeof sessionToken === 'string' && sessionToken.length > 20); assert.equal(typeof inspect, 'function');
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 600000);
  for (const id of OBJECTIVES) { assert.ok(typeof labels[id] === 'string' && labels[id]); assert.equal(typeof prompts[id], id === 'admin_backup' ? 'string' : 'function'); }
  const stat = fs.lstatSync(downloadDirectory); assert.ok(stat.isDirectory() && !stat.isSymbolicLink()); assert.equal(stat.uid, process.getuid()); assert.equal(stat.mode & 0o077, 0);
  assert.equal(fs.realpathSync(downloadDirectory), path.resolve(downloadDirectory)); assert.deepEqual(fs.readdirSync(downloadDirectory), []);
  const deadline = Date.now() + timeoutMs, remaining = () => { const left = deadline - Date.now(); assert.ok(left > 0, 'browser chain deadline'); return left; };
  const context = await browser.createBrowserContext(); let primary, result, cleanup;
  try {
    const page = await context.newPage(); page.setDefaultTimeout(15000); const denied = []; let browserRequests = 0;
    await page.setRequestInterception(true);
    page.on('request', request => {
      try { assert.ok(++browserRequests <= 400, 'browser HTTP ceiling'); const u = new URL(request.url()); if (u.origin !== origin && !['data:', 'blob:'].includes(u.protocol)) { denied.push(u.origin); return void request.abort(); } remaining(); void request.continue(); }
      catch { denied.push('request-deadline'); void request.abort(); }
    });
    await page.evaluateOnNewDocument(token => localStorage.setItem('token', token), sessionToken);
    const initResponse=page.waitForResponse(r=>r.url()===origin+'/api/workshop/sensitive-info/init'&&r.request().method()==='POST',{timeout:15000});
    const progressResponse=page.waitForResponse(r=>r.url()===origin+'/api/workshop/sensitive-info/progress/current'&&r.request().method()==='GET',{timeout:15000});
    initResponse.catch(()=>{});progressResponse.catch(()=>{});
    await page.goto(origin + '/workshop/sensitive-info', { waitUntil: 'domcontentloaded', timeout: remaining() });
    labels=await bounded(admitInitialResponses(initResponse,progressResponse,expectedTotal),15000,'FinFlow initialization deadline');
    await page.waitForFunction(categoryTab, { timeout: remaining() },{label:'Admin Exploitation'});
    assert.equal(await page.evaluate(categoryTab,{label:'Admin Exploitation',click:true}),true);
    const turns = [];
    for (const objectiveId of OBJECTIVES) {
      await page.waitForFunction(label => [...document.querySelectorAll('.obj-name')].some(x => x.textContent === label), { timeout: remaining() }, labels[objectiveId]);
      await page.evaluate(label => [...document.querySelectorAll('.obj-name')].find(x => x.textContent === label).parentElement.parentElement.click(), labels[objectiveId]);
      const prompt = objectiveId === 'admin_backup' ? prompts[objectiveId] : prompts[objectiveId](turns[0].call.resourceMetadata.virtualPath);
      assert.ok(typeof prompt === 'string' && prompt.length > 0);
      await page.waitForSelector('textarea:not([disabled])', { timeout: remaining() });
      await beforeTurn(objectiveId);
      const response = page.waitForResponse(r => r.url() === origin + '/api/workshop/sensitive-info/chat' && r.request().method() === 'POST', { timeout: remaining() });
      response.catch(() => {}); // Retain rejection for await without an unhandled branch if typing fails.
      await page.click('textarea'); const modifier = process.platform === 'darwin' ? 'Meta' : 'Control'; await page.keyboard.down(modifier); await page.keyboard.press('A'); await page.keyboard.up(modifier);
      await page.keyboard.press('Backspace'); await page.type('textarea', prompt); await page.keyboard.press('Enter');
      const http = await response; assert.equal(http.status(), 200);
      assert.equal(JSON.parse(http.request().postData()).objectiveId, objectiveId);
      const body = await http.json(); assert.equal(body.mode, 'vulnerable'); assert.deepEqual(body.newlyCompletedObjectives, [objectiveId]);
      const name = objectiveId === 'admin_backup' ? 'admin_create_backup' : 'admin_download_backup';
      const calls = body.toolCalls.filter(x => x.name === name && x.success === true); assert.equal(calls.length, 1);
      const evidence = await inspect({ objectiveId, body, call: calls[0] });
      assertJudgment({ ...evidence, objectiveId, call: calls[0] });
      await page.waitForFunction(completedCardVisible, { timeout: remaining() }, { label: labels[objectiveId], done: turns.length + 1, total: expectedTotal });
      turns.push({ body, call: calls[0], evidence });
      const screenshot = path.join(path.dirname(downloadDirectory), objectiveId + '.png');
      await page.screenshot({ path: screenshot, fullPage: true });
      assert.ok(fs.statSync(screenshot).size <= 8 * 1024 * 1024, 'bounded screenshot');
      await afterTurn(objectiveId);
    }
    const client = await page.createCDPSession();
    await client.send('Browser.setDownloadBehavior', { behavior: 'allowAndName', downloadPath: downloadDirectory, eventsEnabled: true, browserContextId: context.id });
    let started;
    const completed = new Promise((resolve, reject) => {
      client.on('Browser.downloadWillBegin', event => { if (started) return reject(Error('multiple browser downloads')); started = event; });
      client.on('Browser.downloadProgress', event => { if (event.state === 'canceled') reject(Error('browser download canceled')); if (event.state === 'completed') { if (!started || started.guid !== event.guid) reject(Error('download identity mismatch')); else resolve(started); } });
    });
    completed.catch(() => {});
    const filename = turns[1].call.resourceMetadata.requestedPath.split('/').at(-1);
    await page.waitForFunction(name => [...document.querySelectorAll('button')].some(x => x.textContent.trim() === '⬇ Download ' + name), { timeout: remaining() }, filename);
    await page.evaluate(name => [...document.querySelectorAll('button')].find(x => x.textContent.trim() === '⬇ Download ' + name).click(), filename);
    const event = await bounded(completed, remaining(), 'download deadline'); assert.match(event.guid, /^[a-f0-9-]+$/);
    const file = path.join(downloadDirectory, event.guid), downloaded = fs.lstatSync(file);
    assert.ok(downloaded.isFile() && !downloaded.isSymbolicLink() && downloaded.nlink === 1 && downloaded.size <= 16 * 1024 * 1024);
    assert.deepEqual(denied, []);
    result = verifySameBackupDownload({ create: turns[0].call, download: turns[1].call, read: turns[1].evidence.read,
      physicalBytes: turns[1].evidence.physicalBytes, browserBytes: fs.readFileSync(file), browserFilename: event.suggestedFilename });
  } catch (error) { primary = error; }
  finally { try { await bounded(context.close(), 10000, 'browser context cleanup deadline'); } catch (error) { cleanup = error; } }
  if (primary && cleanup) throw new AggregateError([primary, cleanup], 'chain and context cleanup failed');
  if (primary) throw primary; if (cleanup) throw cleanup;
  return result;
}
module.exports = { contentBlockedPaths, OBJECTIVES, ROUTES, assertStoreEnvironment, createBrowserApp, createTraversalContentApp, assertJudgment, createDatabaseInspector, completedCardVisible, categoryTab, admitInitialResponses, runBrowserChain };
