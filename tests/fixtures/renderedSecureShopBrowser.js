'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createConversationBinding } = require('../../server/services/secureshopConversationBinding');
const WORKSHOP = 'secureshop_agent_security';
const OBJECTIVE = 'ss_stored_browser_execution';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const FACTS=['learner_review_persisted','owner_bound_submission','actual_review_card_rendered','attributed_browser_execution','observable_browser_effect','completed_browser_effect','current_after_browser','vulnerable_mode'];
const sha = value => createHash('sha256').update(value).digest('hex');

const captureFailures = new WeakMap();
const safeRead = read => { try { return read(); } catch { return null; } };
const boundedMilliseconds = value => Number.isFinite(value)
  ? Math.min(86400000, Math.max(0, Math.round(value * 1000) / 1000)) : null;

// Only records made by this module can be projected. Never inspect arbitrary
// error properties here or publish response/request contents or identifiers.
function getStoredBrowserResponseFailure(error) {
  const row = error && (typeof error === 'object' || typeof error === 'function')
    ? captureFailures.get(error) : null;
  if (!row) return null;
  const terminal = row.events?.get(row.request);
  return Object.freeze({
    scope: 'rendered_stored_browser_response_capture', responseLabel: row.label,
    category: row.category, status: row.status, method: row.method,
    frameRelation: row.frameRelation, requestEventsSupported: row.events !== null,
    responseAtMs: row.responseAtMs, bodyReadStartedAtMs: row.bodyReadStartedAtMs,
    bodyReadFailedAtMs: row.bodyReadFailedAtMs,
    requestTerminal: terminal?.kind || 'unknown', requestTerminalAtMs: terminal?.atMs ?? null,
    requestFailureCategory: terminal?.category || null,
  });
}

// Read-only verification of a real submission and its automatic browser
// assessment. The application supplies the marker; this helper never injects it.
function createRenderedBrowserEvidence({ identityRuntime, reviewRuntime, agentsRuntime, binding: input, renderer }) {
  const binding = createConversationBinding(input, { id: input.shopUserId, role: input.role });
  assert.equal(binding.role, 'customer');
  for (const pool of [identityRuntime, reviewRuntime, agentsRuntime]) assert.equal(typeof pool?.query, 'function');
  for (const key of ['sourceSha256', 'artifactSha256']) assert.match(renderer?.[key], /^[a-f0-9]{64}$/);
  async function snapshot() {
    return (await identityRuntime.query(`SELECT j.*,p.packet,c.evaluation_id AS credited
      FROM workshop_platform.objective_judgments j
      JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      LEFT JOIN workshop_platform.objective_contributions c USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.workshop_key=$2 AND j.objective_id=$3
        AND j.platform_launch_id=$4 AND j.platform_launch_generation=$5
      ORDER BY j.created_at,j.evaluation_id`, [binding.platformOwnerId, WORKSHOP, OBJECTIVE,
      binding.launchId, binding.generation])).rows;
  }
  async function verify({ before, productId, reviewId, requestId, body, response }) {
    for (const id of [productId, reviewId]) assert.ok(Number.isSafeInteger(id) && id > 0);
    assert.match(requestId, UUID);
    assert.equal(response.completed, true);assert.equal(response.replayed, false);
    assert.equal(response.reviewId, reviewId);assert.equal(response.productId, productId);
    const rows = (await reviewRuntime.query(`SELECT r.*,t.launch_id,t.scenario_id,t.generation,
      t.original_platform_owner_id,t.original_platform_session_id FROM secureshop_review.reviews r
      JOIN secureshop_review.review_targets t USING(target_id)
      WHERE r.id=$1 AND t.launch_id=$2 AND t.generation=$3`, [reviewId, binding.launchId, binding.generation])).rows;
    assert.equal(rows.length, 1);const source = rows[0];
    assert.equal(source.source_kind, 'learner');assert.equal(source.source_version,1);assert.equal(Number(source.submitted_by_shop_user_id),binding.shopUserId);assert.equal(source.submitted_by_shop_role,binding.role);assert.equal(source.launch_id,binding.launchId);assert.equal(Number(source.generation),binding.generation);assert.match(source.submission_id,UUID);assert.equal(source.body, body);
    assert.equal(Number(source.product_id), productId);
    assert.equal(source.scenario_id, binding.scenarioId);
    assert.equal(Number(source.original_platform_owner_id), binding.platformOwnerId);
    assert.equal(Number(source.original_platform_session_id), binding.platformSessionId);
    assert.equal(source.body_sha256.toString('hex'), sha(body));
    const fresh = (await snapshot()).filter(row => !before.some(old => old.evaluation_id === row.evaluation_id));
    assert.equal(fresh.length, 1);const judgment = fresh[0];
    assert.equal(judgment.user_id,binding.platformOwnerId);assert.equal(judgment.workshop_key,WORKSHOP);assert.equal(judgment.objective_id,OBJECTIVE);assert.equal(judgment.platform_launch_id,binding.launchId);assert.equal(judgment.platform_scenario_id,binding.scenarioId);assert.equal(Number(judgment.platform_launch_generation),binding.generation);
    assert.equal(judgment.verdict, 'pass');assert.equal(judgment.result_json.verdict,'pass');assert.ok(judgment.result_json.criteria?.length>0&&judgment.result_json.criteria.every(row=>row.satisfied===true));assert.equal(judgment.credited, judgment.evaluation_id);
    assert.equal(judgment.result_json.provider, 'ollama');assert.equal(judgment.result_json.model, 'llama3.1:8b');
    assert.equal(response.judgment.evaluationId, judgment.evaluation_id);
    assert.equal(sha(judgment.packet), judgment.evidence_digest);
    const packet = JSON.parse(judgment.packet);
    assert.equal(packet.rubric.objectiveId, OBJECTIVE);assert.equal(packet.rubric.version,'secureshop-stored-browser-v1');
    const records = packet.evidence.filter(row => row.id === 'stored_browser_receipt' && row.source === 'server_observation');
    assert.equal(records.length, 1);const proof = records[0].content;assert.equal(proof.receiptVersion,'secureshop-stored-browser-v1');
    assert.deepEqual(proof.component, { id: 'SecureShop.ReviewCard', sourceSha256: renderer.sourceSha256, artifactSha256: renderer.artifactSha256 });
    assert.deepEqual(response.component, proof.component);
    assert.equal(proof.source.reviewId, reviewId);assert.equal(proof.source.productId, productId);
    assert.equal(proof.source.submissionId, source.submission_id);assert.equal(proof.source.bodySha256, sha(body));
    assert.equal(proof.source.requestSha256, source.request_sha256.toString('hex'));
    for (const key of ['targetEventExecuted','targetEffectObserved','syntheticCookieOnly','finalCookieIsSyntheticOnly']) assert.equal(proof.browser[key], true);
    assert.equal(proof.browser.provenance, 'isolated_qualification_browser');
    assert.ok(Array.isArray(proof.browser.markers)&&proof.browser.markers.length>0);for(const marker of proof.browser.markers){assert.ok(['alert','confirm','prompt','window_open'].includes(marker.kind));assert.ok(typeof marker.value==='string'&&marker.value.length<=200);}assert.equal(response.browser.executed,true);assert.equal(response.browser.reason,proof.browser.reason);assert.equal(proof.currentAfterBrowser, true);
    assert.deepEqual(Object.keys(proof.facts).sort(),[...FACTS].sort());assert.deepEqual(packet.facts, proof.facts);assert.ok(Object.values(proof.facts).every(value => value === true));
    const receipt = proof.execution.effectReceipt;
    assert.equal(receipt.version,1);assert.equal(proof.execution.runId,judgment.run_id);assert.equal(receipt.runId, judgment.run_id);assert.equal(receipt.status, 'completed');
    assert.equal(receipt.effectKey, `${requestId}:stored-browser:${reviewId}`);
    const runs=(await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1',[judgment.run_id])).rows;assert.equal(runs.length,1);const run=runs[0];assert.equal(run.status,'completed');assert.equal(receipt.ownerKey,run.owner_key);assert.equal(String(receipt.generation),String(run.generation));
    const owner=JSON.parse(run.owner_key);assert.equal(owner.length,2);assert.equal(owner[0],'SecureShopBoundConversation');assert.equal(run.owner_key,JSON.stringify(['SecureShopBoundConversation',String(owner[1])]));
    // Session/journal live in the dedicated agents store; require it explicitly
    // rather than querying the review pool or accepting a caller boolean.
    const sessions=(await agentsRuntime.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[owner[1]])).rows;assert.equal(sessions.length,1);const session=sessions[0];assert.equal(session.authority_mode,'launch_bound');assert.equal(session.binding_state,'active');assert.equal(Number(session.user_id),binding.shopUserId);assert.equal(session.role,binding.role);assert.equal(session.platform_launch_id,binding.launchId);assert.equal(session.platform_scenario_id,binding.scenarioId);assert.equal(Number(session.platform_launch_generation),binding.generation);assert.equal(Number(session.original_platform_owner_id),binding.platformOwnerId);assert.equal(Number(session.original_platform_session_id),binding.platformSessionId);
    const turns=(await agentsRuntime.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[owner[1],requestId])).rows;assert.equal(turns.length,1);assert.equal(turns[0].status,'completed');const {replayed,...published}=response;assert.deepEqual(turns[0].result_json,published);
    const effects = (await identityRuntime.query(`SELECT status FROM graph_runtime.effects
      WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4`,
    [judgment.run_id, receipt.ownerKey, receipt.generation, receipt.effectKey])).rows;
    assert.deepEqual(effects, [{ status: 'completed' }]);
    return { objectiveId: OBJECTIVE, runId: judgment.run_id, evaluationId: judgment.evaluation_id, reviewId, requestId };
  }
  return Object.freeze({ snapshot, verify });
}

async function runRenderedStoredBrowser({ page, frame, origin, productId, body, evidence, timeoutMs = 420000 }) {
  assert.ok(Number.isSafeInteger(productId) && productId > 0);
  assert.ok(typeof body === 'string' && body.length > 0);
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 420000);
  const before = await evidence.snapshot();
  const base = `/api/secureshop/products/${productId}/reviews`;
  const matches = (response, predicate) => new URL(response.url()).origin === origin
    && response.request().method() === 'POST' && predicate(new URL(response.url()).pathname);
  const started = performance.now();
  const elapsed = () => boundedMilliseconds(performance.now() - started);
  const events = typeof page.on === 'function' && typeof page.off === 'function' ? new WeakMap() : null;
  const noteTerminal = (request, kind) => {
    if (!events || !request || (typeof request !== 'object' && typeof request !== 'function')) return;
    const text = kind === 'failed' ? safeRead(() => request.failure()?.errorText) : null;
    events.set(request, { kind, atMs: elapsed(), category: kind !== 'failed' ? null
      : text === 'net::ERR_ABORTED' ? 'aborted' : text === 'net::ERR_BLOCKED_BY_CLIENT' ? 'blocked_by_client' : 'other' });
  };
  const onFinished = request => noteTerminal(request, 'finished');
  const onFailed = request => noteTerminal(request, 'failed');
  try {
    if (events) { page.on('requestfinished', onFinished);page.on('requestfailed', onFailed); }
    // Calling json immediately still lets Puppeteer await its body-loaded event.
    // Preserve the original failure while retaining only bounded observations.
    const capture = (label, pending) => pending.then(async response => {
      const request = safeRead(() => response.request());
      const status = safeRead(() => response.status());
      const method = safeRead(() => request.method());
      const responseFrame = safeRead(() => response.frame());
      const mainFrame = safeRead(() => page.mainFrame());
      const row = { label, request, events,
        status: Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
        method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) ? method : 'unknown',
        frameRelation: !responseFrame ? 'unknown' : responseFrame === frame ? 'supplied_frame'
          : responseFrame === mainFrame ? 'main_frame' : 'other_frame',
        responseAtMs: elapsed(), bodyReadStartedAtMs: null };
      row.bodyReadStartedAtMs = elapsed();
      try { return { response, body: await response.json() }; }
      catch (error) {
        row.bodyReadFailedAtMs = elapsed();
        const message = safeRead(() => error.message);
        row.category = typeof message === 'string' && message.includes('Network.getResponseBody')
          ? 'response_body_protocol_failure' : 'body_read_failure';
        if (error && (typeof error === 'object' || typeof error === 'function')) captureFailures.set(error, row);
        throw error;
      }
    });
    const posted = capture('submission', page.waitForResponse(response => matches(response, pathname => pathname === base), { timeout: timeoutMs }));
    const assessed = capture('assessment', page.waitForResponse(response => matches(response, pathname => new RegExp(`^${base}/[1-9]\\d*/browser-attempt$`).test(pathname)), { timeout: timeoutMs }));
    void posted.catch(() => {});void assessed.catch(() => {});
    await frame.waitForSelector('textarea[aria-label="Review body"]', { timeout: timeoutMs });
    await frame.$eval('textarea[aria-label="Review body"]', (textarea, value) => {
      Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, value);
      textarea.dispatchEvent(new Event('input', { bubbles: true }));
    }, body);
    await frame.waitForFunction(value => {
      const textarea = document.querySelector('textarea[aria-label="Review body"]');
      return textarea?.value === value && textarea.closest('form')?.querySelector('button[type="submit"]')?.disabled === false;
    }, { timeout: timeoutMs, polling: 100 }, body);
    await frame.$eval('textarea[aria-label="Review body"]', textarea => textarea.closest('form').querySelector('button[type="submit"]').click());
    const { response: submission, body: submitted } = await posted;assert.equal(submission.status(), 200);
    assert.equal(submitted.ok, true);
    assert.equal(JSON.parse(submission.request().postData()).body, body);
    const { response: assessment, body: assessmentBody } = await assessed;assert.equal(assessment.status(), 200);
    const reviewId = Number(submitted.review_id);
    assert.equal(new URL(assessment.url()).pathname, `${base}/${reviewId}/browser-attempt`);
    const requestId = JSON.parse(assessment.request().postData()).request_id;
    const result = await evidence.verify({ before, productId, reviewId, requestId, body, response: assessmentBody });
    await frame.waitForFunction(() => document.querySelector('textarea[aria-label="Review body"]')?.value === '', { timeout: timeoutMs, polling: 100 });
    return { ...result, scope: 'rendered_stored_browser_positive', resetVerified: false, negativeVerified: false };
  } finally {
    if (events) { page.off('requestfinished', onFinished);page.off('requestfailed', onFailed); }
  }
}
module.exports = { createRenderedBrowserEvidence, runRenderedStoredBrowser, getStoredBrowserResponseFailure };
