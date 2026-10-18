'use strict';

// D08/D10 direct Audit page qualification. The caller owns Q61-style disposable
// stores, the separate owned audit SQL cluster, a qualified current build, the
// real Ollama/Judge transports, server, browser, and their cleanup. This helper
// neither starts a service nor supplies model output.
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { canonicalDigest } = require('../../server/services/mcp/protocolContext');

const MODEL = 'llama3.1:8b';
const SCOPE = 'current-main detached administrator direct Audit Search and Summarize; owned SQL effect, genuine bounded summary and Judge, exact same-key replay, sibling/reset fences';
const FLAGS = Object.freeze([
  'directSearchRendered', 'ownedSearchEffect', 'searchExactReplay',
  'directSummaryRendered', 'genuineSummarySource', 'canonicalAssessmentRetained',
  'summaryExactReplay', 'siblingDenied', 'resetDenied', 'noDuplicateEffects',
]);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function assertDirectAuditContext(c) {
  assert.ok(c && Object.getPrototypeOf(c) === Object.prototype);
  for (const key of ['page', 'frame', 'origin', 'scope', 'principal', 'headers', 'peer',
    'identity', 'agents', 'control', 'audit', 'backend', 'launches', 'modeAuthority',
    'assessmentCatalog', 'configurationAdminContext', 'errorEvidence', 'actorCalls', 'judgeCalls'])
    assert.ok(c[key], `Direct Audit requires ${key}`);
  assert.equal(typeof c.page.waitForResponse, 'function');
  assert.equal(typeof c.frame.waitForSelector, 'function');
  assert.equal(typeof c.identity.query, 'function');
  assert.equal(typeof c.agents.query, 'function');
  assert.equal(typeof c.control.query, 'function');
  assert.equal(typeof c.audit.agents.append, 'function');
  assert.equal(typeof c.backend.target, 'function');
  assert.equal(typeof c.launches.beginReset, 'function');
  assert.equal(typeof c.modeAuthority.capture, 'function');
  assert.equal(typeof c.modeAuthority.assertToken, 'function');
  assert.equal(typeof c.assessmentCatalog.list, 'function');
  assert.equal(typeof c.errorEvidence, 'function');
  assert.equal(typeof c.actorCalls, 'function');
  assert.equal(typeof c.judgeCalls, 'function');
  assert.equal(new URL(c.origin).hostname, '127.0.0.1');
  assert.equal(c.scope.platformOwnerId > 0, true);
  assert.equal(c.principal.user.role, 'admin');
  assert.equal(c.peer.scope.platformOwnerId !== c.scope.platformOwnerId, true,
    'sibling must be a distinct real platform owner');
  for (const value of [c.headers, c.peer.headers]) {
    assert.match(value['x-dvaia-secureshop-launch'], /\S/);
    assert.match(value.authorization, /^Bearer \S+$/);
  }
  assert.equal(typeof c.evidence?.save, 'function');
}

function assertDirectAuditReceipt(value) {
  assert.ok(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(), ['scope', 'searchOperationId', 'summaryRunId',
    'actorCalls', 'judgeCalls', ...FLAGS].sort());
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  assert.match(value.searchOperationId, UUID);
  assert.match(value.summaryRunId, UUID);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 2 && value.actorCalls <= 12);
  assert.ok(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 1 && value.judgeCalls <= 12);
  return value;
}

async function appendOwned(audit, agents, scope, persona, actor, action) {
  const eventId = randomUUID(), transaction = await agents.connect();
  try {
    await transaction.query('BEGIN');
    await audit.agents.append(transaction, { eventId, scope, persona, actor, action,
      target: `direct-audit:${eventId}`, paramsJson: JSON.stringify({ version: 1, sourceId: eventId }),
      outcome: 'completed', sourceKind: 'qualification', sourceId: eventId });
    await transaction.query('COMMIT');
  } catch (error) { await transaction.query('ROLLBACK'); throw error; }
  finally { transaction.release(); }
  return eventId;
}

async function button(frame, label) {
  await frame.waitForFunction(text => [...document.querySelectorAll('button')]
    .some(node => node.textContent.trim() === text && !node.disabled), { timeout: 30000 }, label);
  for (const node of await frame.$$('button')) {
    if (!(await node.evaluate((element, text) => element.textContent.trim() === text && !element.disabled, label))) continue;
    await node.scrollIntoView();
    assert.equal(await node.evaluate(element => {
      const rect = element.getBoundingClientRect();
      const hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return rect.width > 0 && rect.height > 0 && (hit === element || element.contains(hit));
    }), true, `Physical ${label} button must be hittable`);
    await node.click(); return;
  }
  throw new Error(`No enabled physical ${label} button`);
}

function responseWait(page, origin, suffix, timeout = 30000) {
  // Attach success/failure handlers immediately: an earlier UI failure must
  // not produce an unhandled timeout that obscures owned-resource cleanup.
  return page.waitForResponse(response => response.request().method() === 'POST'
    && response.url() === `${origin}/api/secureshop/admin/audit/${suffix}`,
  { timeout }).then(response => ({ response }), error => ({ error }));
}
async function consumeWait(wait) {
  const observed = await wait;
  if (observed.error) throw observed.error;
  const body = await observed.response.json();
  assert.equal(observed.response.status(), 200);
  return { request: JSON.parse(observed.response.request().postData()), body };
}
async function effects(identity, agents, control) {
  const [manual, remote, targets, runs] = await Promise.all([
    identity.query('SELECT count(*)::int AS n FROM identity.secureshop_audit_manual_operations'),
    control.query('SELECT count(*)::int AS n FROM owned_audit_queries'),
    control.query('SELECT count(*)::int AS n FROM owned_audit_targets'),
    agents.query('SELECT count(*)::int AS n FROM secureshop_agents.bound_audit_runs'),
  ]);
  return { manual: manual.rows[0].n, remote: remote.rows[0].n,
    targets: targets.rows[0].n, runs: runs.rows[0].n };
}
async function samePost(origin, suffix, headers, request) {
  const response = await fetch(`${origin}/api/secureshop/admin/audit/${suffix}`, {
    method: 'POST', headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(request), signal: AbortSignal.timeout(15000),
  });
  return { status: response.status, body: await response.json() };
}

async function qualifyDirectAudit(c) {
  assertDirectAuditContext(c);
  const { page, frame, origin, scope, principal, headers, peer, identity, agents,
    control, audit, backend, launches, modeAuthority, assessmentCatalog,
    configurationAdminContext, errorEvidence, actorCalls, judgeCalls, evidence } = c;
  const flags = Object.fromEntries(FLAGS.map(key => [key, false]));
  const startActors = actorCalls(), startJudges = judgeCalls();
  assert.ok(Number.isSafeInteger(startActors) && Number.isSafeInteger(startJudges));
  const objectives = (await assessmentCatalog.list(configurationAdminContext)).objectives;
  for (const id of ['ss_audit_sql_extraction', 'ss_audit_instruction_followed'])
    assert.equal(objectives.find(row => row.objectiveId === id)?.enabled, true,
      `Supported administrator configuration must enable ${id}`);
  for (const feature of ['audit', 'audit_summary']) {
    const token = modeAuthority.assertToken(await modeAuthority.capture(scope, feature));
    assert.equal(token.snapshot.mode, 'vuln', `${feature} must use the vulnerable teaching mode`);
    await token.assertCurrent();
  }
  assert.equal((await backend.target({ binding: scope })).missing, true,
    'Direct Audit must start before this owner target is provisioned');

  // The matching token is unique to this disposable scope. It cannot select a
  // pre-existing fixture row or hide SQL wildcard behavior behind a broad name.
  const username = `direct_audit_${randomUUID().replaceAll('-', '')}`;
  const matchId = await appendOwned(audit, agents, scope, principal.user, username, 'direct_audit_match');
  const otherId = await appendOwned(audit, agents, scope, principal.user,
    `other_${randomUUID().replaceAll('-', '')}`, 'direct_audit_nonmatch');
  // Establish a legitimate, separate peer target before measuring isolation.
  // A peer's first Search may otherwise provision its own target before the
  // globally reused operation UUID is rejected by the manual journal.
  const peerWarmup = await samePost(origin, 'search-by-user', peer.headers,
    { username: `peer_warmup_${randomUUID().replaceAll('-', '')}`, operationId: randomUUID() });
  assert.equal(peerWarmup.status, 200); assert.equal(peerWarmup.body.ok, true);
  assert.equal(peerWarmup.body.count, 0);
  assert.match((await backend.target({ binding: peer.scope })).target, /^audit_[a-f0-9]{32}$/);
  const baseline = await effects(identity, agents, control);
  await frame.waitForSelector('a[href="/secureshop/admin/audit"]', { timeout: 30000 });
  await frame.click('a[href="/secureshop/admin/audit"]');
  await frame.waitForSelector('input[aria-label="Search by user"]', { timeout: 30000 });
  await frame.waitForFunction(() => {
    const search = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Search');
    const summary = document.querySelector('button[aria-label="Summarize anomalies"]');
    return search && summary && !summary.disabled;
  }, { timeout: 30000 });
  await frame.type('input[aria-label="Search by user"]', username);
  const searchWait = responseWait(page, origin, 'search-by-user');
  await button(frame, 'Search');
  const search = await consumeWait(searchWait);
  assert.deepEqual(Object.keys(search.request).sort(), ['operationId', 'username']);
  assert.equal(search.request.username, username);
  assert.match(search.request.operationId, UUID);
  assert.equal(search.body.ok, true);
  assert.equal(search.body.count, 1);
  assert.equal(search.body.events.length, 1);
  assert.equal(search.body.events[0].id, `agents:${matchId}`);
  assert.notEqual(search.body.events[0].id, `agents:${otherId}`);
  assert.match(search.body.sql, /secureshop_agents\.audit_events/);
  const renderedEvents = JSON.stringify(search.body.events, null, 2).slice(0, 4000);
  await frame.waitForFunction((sql, events) => [...document.querySelectorAll('section')]
    .some(section => section.querySelector('h2')?.textContent.includes('Search by user')
      && section.querySelector('code')?.textContent === sql
      && section.querySelector('pre.ss-mono')?.textContent === events),
  { timeout: 30000 }, search.body.sql, renderedEvents);
  flags.directSearchRendered = true;

  const manual = (await identity.query(`SELECT operation_id,request_json,request_sha256,receipt_json,receipt_sha256
    FROM identity.secureshop_audit_manual_operations WHERE operation_id=$1`, [search.request.operationId])).rows;
  assert.equal(manual.length, 1);
  assert.equal(manual[0].request_json.username, username);
  assert.equal(manual[0].request_sha256, canonicalDigest(manual[0].request_json));
  assert.equal(manual[0].receipt_sha256, canonicalDigest(manual[0].receipt_json));
  assert.deepEqual(manual[0].receipt_json.result, search.body);
  const target = await backend.target({ binding: scope });
  assert.match(target.target, /^audit_[a-f0-9]{32}$/);
  const remote = (await control.query('SELECT state,request_sha256,receipt FROM owned_audit_queries WHERE target=$1 AND operation_id=$2',
    [target.target, search.request.operationId])).rows;
  assert.equal(remote.length, 1); assert.equal(remote[0].state, 'completed');
  assert.equal(remote[0].receipt.requestSha256, remote[0].request_sha256);
  assert.deepEqual(remote[0].receipt.result, search.body);
  const afterSearch = await effects(identity, agents, control);
  assert.deepEqual(afterSearch, { manual: baseline.manual + 1, remote: baseline.remote + 1,
    targets: baseline.targets + 1, runs: baseline.runs });
  assert.equal(actorCalls(), startActors); assert.equal(judgeCalls(), startJudges);
  flags.ownedSearchEffect = true;

  const searchReplay = await samePost(origin, 'search-by-user', headers, search.request);
  assert.equal(searchReplay.status, 200); assert.deepEqual(searchReplay.body, search.body);
  assert.deepEqual(await effects(identity, agents, control), afterSearch);
  assert.equal(actorCalls(), startActors); flags.searchExactReplay = true;

  const sessionWait = responseWait(page, origin, 'bound-session');
  const summaryWait = responseWait(page, origin, 'bound-summary', 240000);
  await button(frame, 'Summarize anomalies');
  const session = await consumeWait(sessionWait), summary = await consumeWait(summaryWait);
  assert.deepEqual(session.request, {}); assert.match(session.body.sessionId, UUID);
  assert.deepEqual(Object.keys(summary.request).sort(), ['limit', 'request_id', 'session_id']);
  assert.equal(summary.request.session_id, session.body.sessionId);
  assert.equal(summary.request.limit, 5000);
  assert.match(summary.request.request_id, UUID);
  assert.match(summary.body.runId, UUID);
  assert.equal(summary.body.provider, 'ollama'); assert.equal(summary.body.model, MODEL);
  assert.equal(summary.body.replayed, false);
  assert.ok(summary.body.rowCount >= 2 && summary.body.rowCount <= 5000);
  assert.equal(summary.body.objectiveCredit, false, 'benign summary must not earn exploit credit');
  assert.equal(summary.body.assessment.completed, false);
  await frame.waitForFunction(text => [...document.querySelectorAll('section')]
    .some(section => section.querySelector('h2')?.textContent.includes('Audit summary')
      && section.querySelector('pre.ss-mono')?.textContent === text),
  { timeout: 30000 }, summary.body.summary.slice(0, 8000));
  flags.directSummaryRendered = true;

  const runs = (await agents.query(`SELECT run_id,request_id,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id,summary,provider,model,requested_count,row_count
    FROM secureshop_agents.bound_audit_runs WHERE run_id=$1`, [summary.body.runId])).rows;
  assert.equal(runs.length, 1);
  const run = runs[0];
  assert.equal(run.request_id, summary.request.request_id);
  assert.equal(run.launch_id, scope.launchId);
  assert.equal(run.scenario_id, scope.scenarioId);
  assert.equal(Number(run.generation), scope.generation);
  assert.equal(run.original_platform_owner_id, scope.platformOwnerId);
  assert.equal(run.original_platform_session_id, scope.platformSessionId);
  assert.equal(run.summary, summary.body.summary);
  assert.equal(run.provider, 'ollama'); assert.equal(run.model, MODEL);
  assert.equal(Number(run.requested_count), 5000);
  assert.equal(Number(run.row_count), summary.body.rowCount);
  const refs = (await agents.query('SELECT artifact,bytes,sha256 FROM secureshop_agents.bound_audit_run_artifacts WHERE run_id=$1', [run.run_id])).rows;
  assert.deepEqual(refs.map(r => r.artifact).sort(), ['effects', 'log', 'messages', 'sources', 'traces']);
  const chunks = (await agents.query("SELECT content FROM secureshop_agents.bound_audit_run_chunks WHERE run_id=$1 AND artifact='log' ORDER BY ordinal", [run.run_id])).rows;
  const log = Buffer.concat(chunks.map(row => row.content));
  assert.equal(log.length, Number(refs.find(ref => ref.artifact === 'log').bytes));
  assert.equal(hash(log), refs.find(ref => ref.artifact === 'log').sha256.toString('hex'));
  assert.ok(log.toString('utf8').includes(matchId) && log.toString('utf8').includes(otherId));
  flags.genuineSummarySource = true;
  const judgments = (await identity.query(`SELECT result_json,judge_observations,execution_json
    FROM secureshop_auth.assessment_judgments WHERE run_id=$1`, [run.run_id])).rows;
  assert.equal(judgments.length, 1);
  assert.equal(judgments[0].execution_json.runId, run.run_id);
  assert.ok(judgments[0].judge_observations);
  assert.equal(judgments[0].result_json.verdict, summary.body.assessment.judgment.verdict);
  assert.equal(judgments[0].result_json.provider, 'ollama');
  assert.equal(judgments[0].result_json.model, MODEL);
  assert.ok(judgeCalls() > startJudges && judgeCalls() - startJudges <= 12);
  assert.ok(actorCalls() > startActors && actorCalls() - startActors <= 12);
  flags.canonicalAssessmentRetained = true;

  const beforeReplay = { effects: await effects(identity, agents, control), actors: actorCalls(), judges: judgeCalls() };
  const summaryReplay = await samePost(origin, 'bound-summary', headers, summary.request);
  assert.equal(summaryReplay.status, 200);
  assert.deepEqual(summaryReplay.body, { ...summary.body, replayed: true });
  assert.deepEqual({ effects: await effects(identity, agents, control), actors: actorCalls(), judges: judgeCalls() }, beforeReplay);
  flags.summaryExactReplay = true;

  for (const [suffix, request, method, code, identifier] of [
    ['search-by-user', search.request, 'search', 'AUDIT_QUERY_CONFLICT', search.request.operationId],
    ['bound-summary', summary.request, 'run', 'CONVERSATION_UNAVAILABLE', summary.request.request_id],
  ]) {
    const beforeErrors = errorEvidence().length;
    const denied = await samePost(origin, suffix, peer.headers, request);
    assert.equal(denied.status, 503, 'the bound gateway intentionally hides the internal denial code');
    assert.deepEqual(denied.body, { error: 'Bound SecureShop operation unavailable' });
    const observed = errorEvidence().slice(beforeErrors);
    assert.deepEqual(observed, [{ method, identifier, code }],
      'the caller must capture the original error from the real service wrapper before gateway projection');
  }
  assert.deepEqual({ effects: await effects(identity, agents, control), actors: actorCalls(), judges: judgeCalls() }, beforeReplay);
  flags.siblingDenied = true;
  await launches.beginReset({ launchId: scope.launchId, platformSessionId: scope.platformSessionId,
    platformOwnerId: scope.platformOwnerId, expectedGeneration: scope.generation,
    idempotencyKey: `direct-audit-${randomUUID()}` });
  for (const [suffix, request] of [['search-by-user', search.request], ['bound-summary', summary.request]]) {
    const denied = await samePost(origin, suffix, headers, request);
    assert.equal(denied.status, 401, 'reset must fence the old launch before service execution');
    assert.deepEqual(denied.body, { error: 'SecureShop launch unavailable' });
  }
  assert.deepEqual({ effects: await effects(identity, agents, control), actors: actorCalls(), judges: judgeCalls() }, beforeReplay);
  flags.resetDenied = true; flags.noDuplicateEffects = true;

  const receipt = { scope: SCOPE, searchOperationId: search.request.operationId,
    summaryRunId: run.run_id, actorCalls: actorCalls() - startActors,
    judgeCalls: judgeCalls() - startJudges, ...flags };
  assertDirectAuditReceipt(receipt);
  await evidence.save(receipt);
  return receipt;
}

module.exports = { SCOPE, FLAGS, assertDirectAuditContext, assertDirectAuditReceipt, qualifyDirectAudit };
