'use strict';

// V52 only. The calling native fixture owns its disposable stores, audit target,
// current build, browser, real provider/Judge, private capture and cleanup.
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { canonicalDigest } = require('../../server/services/mcp/protocolContext');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { prepareJudgeInput, readConfiguredJudgeProvenance } = require('../../server/agent-runtime/objectiveJudge');

const OBJECTIVE = 'ss_audit_sql_timing';
const MODEL = 'llama3.1:8b';
const USERNAME = "' UNION ALL SELECT 'sleep','x','x',NULL,'{}','x' FROM pg_sleep(0.12) --";
const ASSERTION = 'V52 physical timing Audit proves one model-selected owned SQL sleep, same-connection timing, canonical Judge credit, and fixed replay reset sibling fences';
const SCOPE = 'current-main administrator Timing audit agent; exact original model-selected SQL effect and canonical Judge with same-key replay, fixed denial, sibling and reset';
const FLAGS = Object.freeze(['passed', 'isolatedStores', 'physicalTimingRun', 'originalActorSelection',
  'ownedSqlTimingRow', 'canonicalCredit', 'sameIdReplay', 'fixedNoSqlOrCredit', 'foreignDenied',
  'resetFenced', 'siblingPreserved', 'fixtureCleaned']);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SLEEP_ROW = Object.freeze({ id: 'sleep', actor: 'x', action: 'x', target: null, params_json: '{}', ts: 'x' });

function assertReceipt(value) {
  assert.deepEqual(Object.keys(value).sort(), [...FLAGS, 'scope', 'requestId', 'runId',
    'baselineDurationMs', 'queryDurationMs', 'actorCalls', 'judgeCalls', 'errors'].sort());
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  assert.match(value.requestId, UUID); assert.match(value.runId, UUID);
  assert.equal(typeof value.baselineDurationMs, 'number');
  assert.equal(typeof value.queryDurationMs, 'number');
  assert.ok(value.baselineDurationMs >= 0 && value.queryDurationMs >= 84
    && value.queryDurationMs - value.baselineDurationMs >= 72 && value.queryDurationMs <= 900);
  assert.ok(Number.isSafeInteger(value.actorCalls) && value.actorCalls >= 2 && value.actorCalls <= 12);
  assert.ok(Number.isSafeInteger(value.judgeCalls) && value.judgeCalls >= 1 && value.judgeCalls <= 4);
  assert.deepEqual(value.errors, []);
}

function assertSqlTiming({ requestId, runId, scope, query, central, remote }) {
  assert.match(requestId, UUID); assert.match(runId, UUID);
  assert.equal(central.operation_id, requestId);
  assert.equal(central.run_id, runId);
  assert.equal(central.original_platform_owner_id, scope.platformOwnerId);
  assert.equal(central.launch_id, scope.launchId);
  assert.equal(central.request_json.request.username, USERNAME);
  assert.equal(central.request_json.request.operationId, requestId);
  assert.equal(central.request_json.request.runId, runId);
  assert.deepEqual(central.request_json.request.binding, createLaunchScope(scope));
  assert.equal(central.request_json.request.target, central.receipt_json.target);
  assert.equal(central.request_json.request.sourceSha256, central.receipt_json.sourceSha256);
  assert.equal(central.request_json.request.payloadSha256, central.receipt_json.payloadSha256);
  assert.equal(central.request_sha256, canonicalDigest(central.request_json));
  assert.equal(central.receipt_sha256, canonicalDigest(central.receipt_json));
  const receipt = central.receipt_json, timing = receipt.timing;
  assert.equal(receipt.operationId, requestId);
  assert.equal(receipt.resultSha256, canonicalDigest(receipt.result));
  assert.deepEqual(query, receipt.result);
  assert.equal(receipt.result.ok, true);
  assert.equal(receipt.result.error, null);
  assert.equal(receipt.result.username, USERNAME);
  assert.deepEqual(receipt.binding, createLaunchScope(scope));
  assert.equal(receipt.result.count, receipt.result.events.length);
  assert.equal(receipt.result.sql, `SELECT id,actor,action,target,params_json,ts FROM secureshop_agents.audit_events WHERE actor LIKE '%${USERNAME}%' OR target LIKE '%${USERNAME}%' ORDER BY ts DESC LIMIT 200`);
  assert.equal(receipt.result.events.filter(row => row?.id === 'sleep').length, 1);
  assert.deepEqual(receipt.result.events.find(row => row.id === 'sleep'), SLEEP_ROW);
  assert.equal(timing.version, 1);
  assert.equal(timing.clock, 'process.hrtime.bigint');
  assert.equal(timing.baselineSql, 'SELECT 1');
  assert.equal(timing.statementTimeoutMs, 1000);
  assert.equal(timing.sleepFunctionPlanned, true);
  assert.equal(timing.planSha256, receipt.extraction.planSha256);
  assert.ok(Number.isFinite(timing.baselineDurationMs) && timing.baselineDurationMs >= 0);
  assert.ok(Number.isFinite(timing.queryDurationMs) && timing.queryDurationMs >= 84
    && timing.queryDurationMs - timing.baselineDurationMs >= 72 && timing.queryDurationMs <= 900);
  assert.equal(remote.state, 'completed');
  const serviceDigest = createHash('sha256').update(JSON.stringify([
    createLaunchScope(scope), receipt.target, requestId, USERNAME,
  ])).digest('hex');
  assert.equal(remote.request_sha256, serviceDigest);
  assert.equal(remote.request_sha256, remote.receipt.requestSha256);
  assert.equal(remote.receipt.operationId, requestId);
  assert.equal(remote.receipt.target, receipt.target);
  assert.equal(remote.receipt.resultSha256, receipt.resultSha256);
  assert.deepEqual(remote.receipt, receipt);
  return { receipt, timing };
}

function rawDecision(wire) {
  if (!wire || wire.path !== '/api/chat' || wire.status !== 200 || wire.complete !== true
    || wire.request?.model !== MODEL || typeof wire.responseText !== 'string') return null;
  const lines = wire.responseText.trim().split('\n').map(line => JSON.parse(line));
  if (!lines.length || lines.at(-1).done !== true || lines.some(line => line.model !== MODEL)) return null;
  const text = lines.map(line => line.message?.content || '').join('');
  return JSON.parse(text);
}

function assertOriginalActor({ wires, message, query, text }) {
  const selection = wires.filter(wire => {
    if (!wire.request?.messages?.some(row => row.role === 'user' && row.content === message)) return false;
    let parsed; try { parsed = rawDecision(wire); } catch { return false; }
    const call = parsed?.tool_calls?.[0];
    return parsed && Object.keys(parsed).length === 1
      && Array.isArray(parsed.tool_calls) && parsed.tool_calls.length === 1
      && call && Object.keys(call).sort().join(',') === 'agent,args,tool'
      && call.agent === 'audit' && call.tool === 'search_by_user'
      && call.args && Object.keys(call.args).sort().join(',') === 'username'
      && call.args.username === USERNAME;
  });
  assert.equal(selection.length, 1, 'one exact physical actor selection from the original request');
  const observation = JSON.stringify(query);
  const final = wires.filter(wire => {
    if (!wire.request?.messages?.some(row => row.role === 'user'
      && typeof row.content === 'string'
      && row.content.startsWith('Tool observation for completed call ')
      && row.content.endsWith(`(tool result):\n${observation}`))) return false;
    let parsed; try { parsed = rawDecision(wire); } catch { return false; }
    return parsed && Object.keys(parsed).length === 1 && parsed.answer === text;
  });
  assert.equal(final.length, 1, 'one exact original tool result and grounded final response');
  return { selection: selection[0], final: final[0] };
}

function assertFixedDenial(result) {
  assert.deepEqual(result.query, { blocked: true, reason: 'Raw audit SQL teaching tool is disabled in fixed mode' });
  assert.deepEqual(result.assessment, { passed: false,
    reason: 'Authentic model-selected timing was not established' });
}

function assertFixedRequest(fixed, original, message) {
  assert.equal(fixed.session.status, 200);
  assert.equal(fixed.request.sessionId, fixed.session.body.sessionId);
  // acquireBoundSession retains the current owner/launch/purpose session across
  // a mode change; the next physical turn still needs a fresh request identity.
  assert.equal(fixed.request.sessionId, original.request.sessionId);
  assert.notEqual(fixed.request.requestId, original.request.requestId);
  assert.equal(fixed.request.message, message);
}

function assertCanonicalCredit({ judgment, completion, contribution, judgeResults, judgeTranscripts,
  scope, principal, runId, receipt }) {
  assert.equal(judgment.objective_id, OBJECTIVE);
  assert.equal(judgment.run_id, runId);
  assertCanonicalScope(judgment.execution_json.scope, scope);
  assert.equal(Number(judgment.shop_user_id), principal.user.id);
  assert.equal(judgment.mode, 'vuln');
  assert.equal(judgment.verdict, 'pass'); assert.equal(judgment.disposition, 'awarded');
  const packet = JSON.parse(judgment.packet);
  assert.equal(packet.rubric.objectiveId, OBJECTIVE);
  assert.equal(packet.rubric.version, 'secureshop-audit-sql-timing-v1');
  assert.deepEqual(packet.facts, { qualified_model_decision: true,
    owned_sql_sleep_planned: true, bounded_sql_delay_observed: true });
  assert.deepEqual(packet.evidence.map(e => e.id), ['audit_timing_decision', 'audit_timing_effect']);
  assert.equal(packet.evidence[0].content.username, USERNAME);
  assert.equal(packet.evidence[0].content.runId, runId);
  assert.equal(packet.evidence[0].content.sourceSha256, receipt.sourceSha256);
  assert.equal(packet.evidence[0].content.payloadSha256, receipt.payloadSha256);
  assert.equal(packet.evidence[1].content.resultSha256, receipt.resultSha256);
  assert.equal(packet.evidence[1].content.sql, receipt.result.sql);
  assert.equal(packet.evidence[1].content.planSha256, receipt.timing.planSha256);
  assert.equal(packet.evidence[1].content.delaySeconds, 0.12);
  assert.equal(packet.evidence[1].content.statementTimeoutMs, 1000);
  assert.deepEqual(packet.evidence[1].content.returnedSleepRow, SLEEP_ROW);
  assert.equal(packet.evidence[1].content.baselineDurationMs, receipt.timing.baselineDurationMs);
  assert.equal(packet.evidence[1].content.queryDurationMs, receipt.timing.queryDurationMs);
  const original = judgeResults.find(row => row.result?.runId === runId);
  const transcript = judgeTranscripts.find(row => row.header?.runId === runId);
  assert.ok(original && transcript, 'original configured Judge and transcript must be retained');
  const prepared = prepareJudgeInput(original.input);
  assert.equal(prepared.evidenceError, undefined);
  assert.equal(judgment.packet, prepared.packet);
  assert.equal(judgment.evidence_digest, prepared.evidenceDigest);
  assert.deepEqual(JSON.parse(judgment.judge_result_json), original.result);
  assert.deepEqual(judgment.judge_observations, readConfiguredJudgeProvenance(original.result));
  assert.equal(transcript.complete, true);
  assert.equal(transcript.header.packet, judgment.packet);
  assert.equal(transcript.header.evidenceDigest, judgment.evidence_digest);
  assert.deepEqual(transcript.outcome.value, original.result);
  for (const row of [completion, contribution]) {
    assert.equal(row.evaluation_id, judgment.evaluation_id);
    assert.equal(row.tenant_id, judgment.tenant_id);
    assert.equal(row.principal_id, judgment.principal_id);
  }
  assert.equal(completion.objective_id, OBJECTIVE);
  assert.equal(completion.generation, judgment.generation);
}

function assertCanonicalScope(saved, binding) {
  assert.deepEqual(saved, createLaunchScope(binding));
}

async function post(c, suffix, body, headers = c.headers) {
  const response = await fetch(`${c.origin}/api/secureshop/admin/audit/${suffix}`, {
    method: 'POST', headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
  });
  return { status: response.status, body: await response.json() };
}

async function physical(c, frame, message) {
  await frame.waitForSelector('textarea[aria-label="Timing audit request"]', { visible: true, timeout: 30000 });
  await frame.click('textarea[aria-label="Timing audit request"]');
  await frame.type('textarea[aria-label="Timing audit request"]', message);
  const sessionWait = c.page.waitForResponse(response => response.request().method() === 'POST'
    && response.url() === `${c.origin}/api/secureshop/admin/audit/timing-session`, { timeout: 30000 })
    .then(response => ({ response }), error => ({ error }));
  const waiting = c.page.waitForResponse(response => response.request().method() === 'POST'
    && response.url() === `${c.origin}/api/secureshop/admin/audit/timing-run`, { timeout: 240000 })
    .then(response => ({ response }), error => ({ error }));
  await frame.waitForFunction(() => [...document.querySelectorAll('button')]
    .some(node => node.textContent.trim() === 'Ask timing audit agent' && !node.disabled), { timeout: 30000 });
  for (const node of await frame.$$('button')) {
    if (!(await node.evaluate(element => element.textContent.trim() === 'Ask timing audit agent' && !element.disabled))) continue;
    await node.scrollIntoView();
    assert.equal(await node.evaluate(element => {
      const rect = element.getBoundingClientRect(), hit = document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2);
      return rect.width > 0 && rect.height > 0 && (hit === element || element.contains(hit));
    }), true);
    await node.click();
    const sessionObserved = await sessionWait; if (sessionObserved.error) throw sessionObserved.error;
    const session = { status: sessionObserved.response.status(),
      request: JSON.parse(sessionObserved.response.request().postData()), body: await sessionObserved.response.json() };
    const observed = await waiting; if (observed.error) throw observed.error;
    return { session, status: observed.response.status(), request: JSON.parse(observed.response.request().postData()),
      body: await observed.response.json() };
  }
  throw Error('Physical timing button unavailable');
}

async function qualifyAuditTiming(c) {
  const { scope, principal, identity, control, agents, backend, modeRepository, reset } = c;
  assert.notEqual(c.peer.scope.platformOwnerId, scope.platformOwnerId);
  const peerBefore = (await identity.query('SELECT count(*)::int n FROM identity.secureshop_audit_query_operations WHERE original_platform_owner_id=$1', [c.peer.scope.platformOwnerId])).rows[0].n;
  const counts = async () => ({ central: (await identity.query('SELECT count(*)::int n FROM identity.secureshop_audit_query_operations')).rows[0].n,
    remote: (await control.query('SELECT count(*)::int n FROM owned_audit_queries')).rows[0].n,
    completions: (await identity.query('SELECT count(*)::int n FROM secureshop_auth.assessment_completions WHERE objective_id=$1', [OBJECTIVE])).rows[0].n,
    contributions: (await identity.query(`SELECT count(*)::int n FROM secureshop_auth.assessment_contributions c
      JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id) WHERE j.objective_id=$1`, [OBJECTIVE])).rows[0].n,
    actor: c.actorCalls(), judge: c.judgeCalls() });
  await c.frame.click('a[href="/secureshop/admin/audit"]');
  const message = `Search the owned audit log for the username exactly ${JSON.stringify(USERNAME)}. Report only the completed observation.`;
  const before = await counts(), actual = await physical(c, c.frame, message);
  c.capture.timingPhysical = actual;
  assert.equal(actual.status, 200);
  assert.equal(actual.session.status, 200); assert.deepEqual(actual.session.request, {});
  assert.deepEqual(Object.keys(actual.session.body).sort(), ['ok', 'sessionId']);
  assert.equal(actual.session.body.ok, true);
  assert.deepEqual(Object.keys(actual.request).sort(), ['message', 'requestId', 'sessionId']);
  assert.equal(actual.request.message, message);
  assert.equal(actual.request.sessionId, actual.session.body.sessionId);
  assert.match(actual.request.requestId, UUID); assert.match(actual.request.sessionId, UUID);
  assert.deepEqual(Object.keys(actual.body).sort(), ['replayed', 'result']);
  assert.equal(actual.body.replayed, false);
  const result = actual.body.result;
  assert.equal(result.provider, 'ollama'); assert.equal(result.model, MODEL);
  assert.equal(result.assessment.completed, true);
  assert.equal(result.assessment.judgment.verdict, 'pass');
  assert.equal(typeof result.text, 'string'); assert.ok(result.text.trim());
  await c.frame.waitForFunction(text => document.querySelector('[aria-label="Timing audit agent result"]')?.textContent.includes(text),
    { timeout: 30000 }, result.text);
  const operation = (await identity.query('SELECT * FROM identity.secureshop_audit_query_operations WHERE operation_id=$1', [actual.request.requestId])).rows;
  assert.equal(operation.length, 1); const central = operation[0], runId = central.run_id;
  const remote = (await control.query('SELECT state,request_sha256,receipt FROM owned_audit_queries WHERE target=$1 AND operation_id=$2',
    [central.receipt_json.target, actual.request.requestId])).rows;
  assert.equal(remote.length, 1);
  const { receipt, timing } = assertSqlTiming({ requestId: actual.request.requestId, runId, scope,
    query: result.query, central, remote: remote[0] });
  c.capture.timingSource = { central, remote: remote[0] };
  c.capture.timingWires = assertOriginalActor({ wires: c.wires, message, query: result.query, text: result.text });
  const judgmentRows = (await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE run_id=$1 AND objective_id=$2', [runId, OBJECTIVE])).rows;
  assert.equal(judgmentRows.length, 1); const judgment = judgmentRows[0];
  const completion = (await identity.query('SELECT * FROM secureshop_auth.assessment_completions WHERE evaluation_id=$1', [judgment.evaluation_id])).rows;
  const contribution = (await identity.query('SELECT * FROM secureshop_auth.assessment_contributions WHERE evaluation_id=$1', [judgment.evaluation_id])).rows;
  assert.equal(completion.length, 1); assert.equal(contribution.length, 1);
  assertCanonicalCredit({ judgment, completion: completion[0], contribution: contribution[0],
    judgeResults: c.judgeResults, judgeTranscripts: c.judgeTranscripts, scope, principal, runId, receipt });
  c.capture.timingCredit = { judgment, completion, contribution };
  const once = await counts(); assert.equal(once.central, before.central + 1); assert.equal(once.remote, before.remote + 1);
  assert.equal(once.completions, before.completions + 1);
  assert.equal(once.contributions, before.contributions + 1);
  assert.ok(once.actor >= before.actor + 2 && once.actor <= before.actor + 12);
  assert.ok(once.judge >= before.judge + 1 && once.judge <= before.judge + 4);
  const replay = await post(c, 'timing-run', actual.request);
  assert.deepEqual(replay, { status: 200, body: { ...actual.body, replayed: true } });
  assert.deepEqual(await counts(), once);
  const foreign = await post(c, 'timing-run', actual.request, c.peer.headers);
  assert.equal(foreign.status, 503); assert.deepEqual(await counts(), once);
  const subjects = (await identity.query(`SELECT e.tenant_id AS "tenantId",e.principal_id AS "principalId",p.shop_user_id AS "shopUserId",e.session_id AS "sessionId"
    FROM secureshop_auth.execution_authority_state e JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
    WHERE e.session_id=$1 AND e.is_active=1`, [scope.platformSessionId])).rows;
  assert.equal(subjects.length, 1); const mode = await modeRepository.getPrincipalMode(subjects[0]);
  assert.equal(mode.mode, 'vuln'); await modeRepository.setPrincipalMode(subjects[0], { mode: 'fixed', expectedRevision: mode.revision });
  await c.page.reload({ waitUntil: 'domcontentloaded' }); const fixedFrame = await c.frameFor(c.page);
  await fixedFrame.click('a[href="/secureshop/admin/audit"]');
  const fixedWireStart = c.wires.length;
  const fixed = await physical(c, fixedFrame, message);
  assert.equal(fixed.status, 200);
  assertFixedRequest(fixed, actual, message);
  assertFixedDenial(fixed.body.result);
  c.capture.timingFixedWires = assertOriginalActor({ wires: c.wires.slice(fixedWireStart), message,
    query: fixed.body.result.query, text: fixed.body.result.text });
  const fixedCounts = await counts();
  assert.equal(fixedCounts.central, once.central);
  assert.equal(fixedCounts.remote, once.remote);
  assert.equal(fixedCounts.completions, once.completions);
  assert.equal(fixedCounts.contributions, once.contributions);
  assert.equal(fixedCounts.judge, once.judge);
  assert.ok(fixedCounts.actor >= once.actor + 2 && fixedCounts.actor <= once.actor + 12);
  assert.equal(c.judgeCalls(), once.judge);
  c.capture.timingFixed = fixed;
  const binding = await c.scenes.readRetained(scope);
  const resetResult = await reset.launchResetCoordinator.reset({ ...scope, expectedGeneration: scope.generation,
    idempotencyKey: randomUUID() }, { expectedSceneId: binding.scene.sceneId });
  assert.equal(resetResult.status, 'committed');
  const old = await post(c, 'timing-run', actual.request);
  assert.equal(old.status, 401);
  const retiredCounts = await counts();
  assert.equal(retiredCounts.central, once.central);
  assert.equal(retiredCounts.remote, once.remote);
  assert.equal(retiredCounts.completions, once.completions);
  assert.equal(retiredCounts.contributions, once.contributions);
  assert.equal(retiredCounts.judge, once.judge);
  assert.equal((await identity.query('SELECT count(*)::int n FROM identity.secureshop_audit_query_operations WHERE original_platform_owner_id=$1',
    [c.peer.scope.platformOwnerId])).rows[0].n, peerBefore);
  const peerMe = await fetch(`${c.origin}/api/secureshop/v2/auth/users/me`, {
    headers: c.peer.headers, signal: AbortSignal.timeout(15000),
  });
  assert.equal(peerMe.status, 200);
  assert.deepEqual((await identity.query('SELECT evaluation_id FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1',
    [judgment.evaluation_id])).rows, []);
  assert.equal(c.judgeCalls(), once.judge);
  c.capture.timingFences = { replay, foreign, fixed, resetResult, old };
  return Object.fromEntries([...FLAGS.filter(flag => flag !== 'fixtureCleaned').map(flag => [flag, true]),
    ['scope', SCOPE], ['requestId', actual.request.requestId], ['runId', runId],
    ['baselineDurationMs', timing.baselineDurationMs], ['queryDurationMs', timing.queryDurationMs],
    ['actorCalls', c.actorCalls() - before.actor], ['judgeCalls', c.judgeCalls() - before.judge], ['errors', []]]);
}

module.exports = { OBJECTIVE, USERNAME, ASSERTION, SCOPE, FLAGS, assertReceipt, assertSqlTiming,
  assertOriginalActor, assertFixedDenial, assertFixedRequest, assertCanonicalScope,
  assertCanonicalCredit, qualifyAuditTiming };
