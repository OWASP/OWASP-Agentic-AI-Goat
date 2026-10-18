'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { normalizeListingCreateInput, listingCreateRequestDigest,
  listingCreateSourceDigest, escapeListingHtml } = require('../server/services/secureshopListingCreateContract');
const { proposalId } = (() => {
  const p = require('../server/services/secureshopRoleListingCreateProposal');
  return { proposalId: (sessionId, requestId, step, callId) =>
    p.createRoleListingCreateProposal({ sessionId, requestId, step, callId,
      preview: fixturePreview(sessionId, requestId, step, callId) }).proposalId };
})();
const { originalSource, createListingRawBrowserEvidenceAdapter } =
  require('../server/services/secureshopListingRawBrowserEvidence');
const { rawListingAssessmentRequestId, RAW_LISTING_BROWSER_RUBRIC,
  matchesPreparedObservation } =
  require('../server/services/secureshopListingRawBrowserAssessment');
const { createListingRawBrowserAssessment } =
  require('../server/services/secureshopListingRawBrowserAssessment');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const sha = value => createHash('sha256').update(value).digest('hex');
const U = () => randomUUID();

function fixturePreview(sessionId, requestId, step, callId, mode = 'vuln', scope = {
  launchId: U(), scenarioId: U(), generation: 1,
  platformOwnerId: 7, platformSessionId: 8 }) {
  const authoredHtml = '<img src=x onerror="globalThis.__ownedListingMarker=1">';
  const listing = normalizeListingCreateInput({ name: 'Owned book', price: 12.50,
    presentation: 'html', description: authoredHtml });
  const source = { version: 1, kind: 'merchant_authored_html', listing,
    authoredHtml, storedHtml: mode === 'vuln' ? authoredHtml : escapeListingHtml(authoredHtml),
    preparation: { sessionId, requestId, step, callId,
      message: `Publish this exact authored HTML: ${authoredHtml}` },
    execution: { version: 1, featureId: 'listings',
      policyVersion: 'owned-listing-import-v1', mode, generation: 1,
      modeStamp: 'v1', scope } };
  const scopeKey = sha('owned-scope');
  const requestSha256 = listingCreateRequestDigest({ version: 2, listing, source,
    scopeKey, currency: 'USD', initialStock: 0, status: 'active' });
  return { version: 2, listing, currency: 'USD', initialStock: 0,
    status: 'active', scopeKey, requestSha256, source };
}
function fixture(mode = 'vuln', scope) {
  const sessionId = U(), requestId = U(), callId = 'original-tool-call', step = 1;
  const preview = fixturePreview(sessionId, requestId, step, callId, mode, scope);
  const operationId = proposalId(sessionId, requestId, step, callId);
  const selectedArgs = { listing: { name: preview.listing.name,
    description: preview.listing.description, price: preview.listing.price,
    presentation: 'html' } }; // The real model may omit optional category.
  const observation = { content: [{ type: 'text', text: JSON.stringify({
    status: 'prepared_for_confirmation', preview }) }] };
  const selected = { event_id: U(), session_id: sessionId, kind: 'model_decision',
    actor: 'supervisor', step, provider: 'ollama',
    params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{
      id: callId, name: 'merchant.listing_create_prepare', args: selectedArgs }] }),
    result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, fallback: false }) };
  const observed = { event_id: U(), session_id: sessionId, kind: 'local_tool_result',
    actor: 'task→supervisor', step, agent_ns: 'merchant',
    tool_name: 'listing_create_prepare', result_json: JSON.stringify(observation) };
  const terminal = { event_id: U(), session_id: sessionId, kind: 'terminal',
    actor: 'supervisor', step: 2, provider: 'ollama',
    result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false,
      fallback: false, stopReason: 'end_turn', steps: 2, hops: 1 }) };
  const sourceSha256 = sha('effective-owned-product-source');
  const receipt = { version: 2, operationId, productId: 31, status: 'completed',
    scopeKey: preview.scopeKey, requestSha256: preview.requestSha256,
    sourceSha256, receiptSha256: sha('immutable-operation'), replayed: true,
    source: preview.source, sourceDocumentSha256: listingCreateSourceDigest(preview.source) };
  const sourceRead = { receipt, product: { productId: 31,
    descriptionHtml: preview.source.storedHtml, sourceSha256 } };
  const original = { sessionId, requestId, binding: { request_hash: sha('turn') },
    turn: { requestHash: sha('turn'), requestVersion: 1,
      result: { stopReason: 'end_turn', steps: 2, hops: [{ tool: 'merchant.listing_create_prepare',
        step, params: selectedArgs, result: observation }] } },
    traceEvents: [selected, observed, terminal],
    proposal: { version: 1, proposalId: operationId, preview,
      origin: { step, callId } }, sourceRead };
  return { original, operationId, sourceRead };
}

test('raw source requires the original selected model tool and normalized optional listing arguments', () => {
  const { original, operationId } = fixture();
  const verified = originalSource(original, operationId, () => true);
  assert.equal(verified.source.kind, 'merchant_authored_html');
  assert.equal(verified.receipt.operationId, operationId);
  const bad = structuredClone(original);
  bad.traceEvents[0].params_json = JSON.stringify({ decision: 'tool_use', toolCalls: [{
    id: original.proposal.origin.callId, name: 'merchant.listing_create_prepare',
    args: { listing: { ...original.proposal.preview.listing, name: 'Other book' } } }] });
  assert.throws(() => originalSource(bad, operationId, () => true),
    { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
  assert.throws(() => originalSource(original, operationId, () => false),
    { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
});

test('original tool text joins the trace byte-exactly while protected JSONB key order may change', () => {
  const { original, operationId } = fixture();
  const reorder = value => Array.isArray(value) ? value.map(reorder)
    : value && Object.getPrototypeOf(value) === Object.prototype
      ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reorder(item)]))
      : value;
  const retained = structuredClone(original);
  retained.proposal.preview = reorder(retained.proposal.preview);
  retained.sourceRead.receipt.source = reorder(retained.sourceRead.receipt.source);
  assert.equal(originalSource(retained, operationId, () => true).receipt.operationId, operationId);
  const changed = mutate => { const copy = structuredClone(retained); mutate(copy); return copy; };
  const deny = value => assert.throws(() => originalSource(value, operationId, () => true),
    { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
  deny(changed(value => { value.turn.result.hops[0].result.content[0].text = '{"status":'; }));
  deny(changed(value => { const block = value.turn.result.hops[0].result.content[0];
    block.text = JSON.stringify({ ...JSON.parse(block.text), extra: true }); }));
  deny(changed(value => { const block = value.turn.result.hops[0].result.content[0];
    block.text = JSON.stringify({ status: 'prepared_for_confirmation',
      preview: { ...JSON.parse(block.text).preview, status: 'deleted' } }); }));
  deny(changed(value => { value.turn.result.hops[0].result.content.push({ type: 'text', text: 'extra' }); }));
  deny(changed(value => { value.turn.result.hops[0].result.content[0].extra = true; }));
  deny(changed(value => { const trace = JSON.parse(value.traceEvents[1].result_json);
    trace.content[0].text = JSON.stringify(JSON.parse(trace.content[0].text), null, 2);
    value.traceEvents[1].result_json = JSON.stringify(trace); }));
});

test('Judge observation guard compares decoded producer JSON across JSONB key order without accepting changed text', () => {
  const { original, sourceRead } = fixture();
  const receipt = sourceRead.receipt;
  const observation = JSON.parse(original.traceEvents[1].result_json);
  const reordered = value => Array.isArray(value) ? value.map(reordered)
    : value && Object.getPrototypeOf(value) === Object.prototype
      ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reordered(item)]))
      : value;
  assert.equal(matchesPreparedObservation(observation, receipt, reordered(receipt.source)), true);
  const changed = mutate => { const copy = structuredClone(observation); mutate(copy); return copy; };
  assert.equal(matchesPreparedObservation(changed(value => { value.content[0].text = '{'; }), receipt, receipt.source), false);
  assert.equal(matchesPreparedObservation(changed(value => { value.content[0].extra = true; }), receipt, receipt.source), false);
  assert.equal(matchesPreparedObservation(changed(value => { value.content.push({ type: 'text', text: '{}' }); }), receipt, receipt.source), false);
  assert.equal(matchesPreparedObservation(changed(value => {
    const decoded = JSON.parse(value.content[0].text);
    decoded.preview.status = 'deleted'; value.content[0].text = JSON.stringify(decoded);
  }), receipt, receipt.source), false);
  assert.equal(matchesPreparedObservation(changed(value => {
    const decoded = JSON.parse(value.content[0].text);
    decoded.extra = true; value.content[0].text = JSON.stringify(decoded);
  }), receipt, receipt.source), false);
});

test('actual renderer and receipted browser effect are required; source mutation fails closed', async () => {
  const { original, operationId, sourceRead } = fixture();
  const timestamp = new Date('2026-10-12T23:12:08.061Z');
  for (const row of original.traceEvents) row.ts = new Date(timestamp);
  let renders = 0, qualifications = 0;
  const adapter = createListingRawBrowserEvidenceAdapter({
    browserQualification: { async qualify(markup, { eventSource }) {
      qualifications++; assert.ok(markup.includes(eventSource));
      return { executed: true, targetEventExecuted: true, targetEffectObserved: true,
        syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true,
        markers: [{ kind: 'owned synthetic marker' }], blockedRequests: [] };
    } },
    async renderProductDescription({ description_html }) {
      renders++; return `<article>${description_html}</article>`;
    }, componentSourceDigest: sha('component-source'),
    componentArtifactDigest: sha('component-artifact') });
  const verified = adapter.verify(original, operationId, () => true);
  const requestId = U(), execution = { runId: U(), ownerKey: 'owner', durableGeneration: '2' };
  const boundary = { identity: execution, async check() {},
    async effectWithReceipt(node, callback) {
      return { value: await callback(), receipt: { version: 1, status: 'completed',
        runId: execution.runId, ownerKey: execution.ownerKey,
        generation: execution.durableGeneration, effectKey: `${requestId}:${node}` } };
    } };
  const handle = await adapter.capture({ verified, boundary, execution, requestId });
  const candidates = adapter.build({ original, before: sourceRead, after: structuredClone(sourceRead),
    handle, execution, qualifyModel: () => true });
  assert.equal(renders, 1); assert.equal(qualifications, 1);
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].objectiveId, RAW_LISTING_BROWSER_RUBRIC.objectiveId);
  const raw = candidates[0].evidence[0].content;
  for (const row of [raw.selected, raw.observation, raw.terminal])
    assert.equal(row.ts, timestamp.toISOString(), 'PostgreSQL Date remains an exact JSON timestamp');
  const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
  const rubric = { ...RAW_LISTING_BROWSER_RUBRIC, mode: 'vuln' };
  const evidence = [{ id: 'listing_raw_audit', source: 'server_observation', content: raw },
      { id: 'listing_raw_outcome', source: 'server_observation', content: {
        kind: 'saved_merchant_authored_html', productId: raw.productId,
        observedOutcome: 'The saved merchant-authored product description produced an attributed observable browser effect.',
        component: raw.component.id, markers: raw.browser.markers } }];
  const facts = { ...candidates[0].facts, listing_raw_consistency_verified: true };
  const prepared = prepareJudgeInput({ rubric, evidence, facts });
  assert.equal(prepared.evidenceError, undefined,
    'actual PostgreSQL timestamps must reach the bounded canonical Judge packet');
  assert.ok(Buffer.byteLength(prepared.packet) < 24000);
  const unprojected = structuredClone(evidence);
  unprojected[0].content.selected.ts = new Date(timestamp);
  assert.match(prepareJudgeInput({ rubric, evidence: unprojected, facts }).evidenceError?.message || '',
    /Evidence must be plain JSON/, 'the original PostgreSQL Date reproduces the pre-Judge rejection');
  const badTimestamp = structuredClone(original);
  badTimestamp.traceEvents[0].ts = { substituted: true };
  const badVerified = adapter.verify(badTimestamp, operationId, () => true);
  const badHandle = await adapter.capture({ verified: badVerified, boundary, execution, requestId });
  assert.deepEqual(adapter.build({ original: badTimestamp, before: sourceRead, after: sourceRead,
    handle: badHandle, execution, qualifyModel: () => true }), [],
  'malformed timestamp metadata must not enter the canonical packet');
  assert.equal(adapter.build({ original, before: sourceRead,
    after: { ...sourceRead, product: { ...sourceRead.product, descriptionHtml: 'changed' } },
    handle, execution, qualifyModel: () => true }).length, 0);
  assert.equal(adapter.build({ original, before: sourceRead, after: sourceRead,
    handle: Object.freeze({}), execution, qualifyModel: () => true }).length, 0);
});

test('assessment request identity is stable per operation and domain separated', () => {
  const first = U(), second = U();
  assert.equal(rawListingAssessmentRequestId(first), rawListingAssessmentRequestId(first));
  assert.notEqual(rawListingAssessmentRequestId(first), rawListingAssessmentRequestId(second));
  assert.notEqual(rawListingAssessmentRequestId(first), first);
  assert.throws(() => rawListingAssessmentRequestId('not-an-operation'));
});

test('saved outcome uses only the bound listingRewrite row and never invokes a browser or model', async () => {
  const { original, operationId, sourceRead } = fixture();
  let activeOriginal = original, activeSourceRead = sourceRead;
  const scope = sourceRead.receipt.source.execution.scope;
  const persona = { id: 11, role: 'merchant' };
  const personaSession = { sessionId: U(), authorityVersion: '1',
    expiresAt: '2026-10-12T23:00:00.000Z' };
  const binding = { ...scope, shopUserId: persona.id, role: persona.role };
  const sessionId = U(), requestId = rawListingAssessmentRequestId(operationId);
  const message = JSON.stringify([RAW_LISTING_BROWSER_RUBRIC.objectiveId,
    'merchant_authored_html', operationId, original.sessionId, original.requestId,
    sourceRead.receipt.source.execution, personaSession.sessionId, personaSession.authorityVersion]);
  const request = createTurnRequest({ sessionId, requestId, binding, message });
  const evaluationId = U(), tenantId = U(), principalId = U(), runId = U();
  const judgment = { verdict: 'pass' }, serialized = JSON.stringify(judgment);
  const canonical = { evaluation_id: evaluationId, tenant_id: tenantId,
    principal_id: principalId, current_tenant_id: tenantId,
    current_principal_id: principalId, current_membership_version: '1',
    workshop_key: 'secureshop_agent_security', objective_id: RAW_LISTING_BROWSER_RUBRIC.objectiveId,
    rubric_version: RAW_LISTING_BROWSER_RUBRIC.version,
    scenario: RAW_LISTING_BROWSER_RUBRIC.scenario, shop_user_id: persona.id,
    owner_key: JSON.stringify(['SecureShopBoundConversation', sessionId]),
    owner_generation: '1', live_owner_generation: '1', run_id: runId,
    generation: 1, mode: 'vuln', mode_stamp: 'v1',
    evidence_digest: sha('packet'), packet: { version: 1, source: 'raw-listing' }, verdict: 'pass',
    disposition: 'awarded', result_json: judgment, result_serialized: serialized,
    result_digest: sha(serialized), child_id: null, child_row: null,
    execution_json: { tenantId, principalId, shopUserId: persona.id,
      membershipVersion: '1', scope, personaSessionId: personaSession.sessionId,
      personaAuthorityVersion: personaSession.authorityVersion, role: persona.role,
      runId, ownerKey: JSON.stringify(['SecureShopBoundConversation', sessionId]),
      ownerGeneration: '1' } };
  let rows = [], reads = 0, browserCalls = 0, canonicalRows = [canonical];
  const service = createListingRawBrowserAssessment({
    launches: { async assertCurrent() {} },
    conversationRepository: { async getBoundSession() {} },
    coordinator: { async run() { throw Error('GET must not run a coordinator'); } },
    journal: { async claim() { throw Error('GET must not claim'); }, async complete() {}, async markUncertain() {} },
    agentsPool: { async query() { reads++; return { rows }; } },
    readOriginal: async () => activeOriginal,
    catalog: { async readMerchantListingCreateSource() { return activeSourceRead; } },
    modeAuthority: { async capture() { return { snapshot: activeSourceRead.receipt.source.execution,
      async assertCurrent() {} }; }, assertToken(value) { return value; } },
    identityPool: { async query() { return { rows: canonicalRows }; } },
    personaAuthority: { async capture() { return { binding: { ...scope,
      personaId: persona.id, role: persona.role,
      sessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion },
      async assertRemoteAdmission() {} }; } },
    personaBindings: { async capture() {} },
    receipts: { async beginEvaluation() {}, async recordVerdict() {} },
    progress: { async getGeneration() {} },
    publicationModes: { async getEvaluationScope() {
      return { generation: 1, mode: 'vuln', modeStamp: 'v1' };
    } },
    judge: async () => { throw Error('GET must not Judge'); }, qualifyModel: () => true,
    browserQualification: { async qualify() { browserCalls++; } },
    productRenderer: { async renderProductDescription() { browserCalls++; },
      sourceSha256: sha('component-source'), artifactSha256: sha('component-artifact') },
  });
  assert.deepEqual(await service.readOutcome({ scope, persona, personaSession, operationId }),
    { operationId, completed: false, status: 'unconfirmed', modelEvaluated: false });
  rows = [{ session_id: sessionId, request_id: requestId, status: 'completed',
    request_hash: request.hash, request_version: 1,
    result_json: { operationId, completed: true,
      judgment: { verdict: 'pass', evaluationId, canRetry: false } } }];
  const recovered = await service.readOutcome({ scope, persona, personaSession, operationId });
  assert.equal(recovered.operationId, operationId);
  assert.equal(recovered.completed, true); assert.equal(recovered.replayed, true);
  assert.equal(reads, 2); assert.equal(browserCalls, 0);
  await assert.rejects(service.readOutcome({ scope, persona,
    personaSession: { ...personaSession, sessionId: U() }, operationId }),
  { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
  await assert.rejects(service.readOutcome({ scope, persona,
    personaSession: { ...personaSession, authorityVersion: '2' }, operationId }),
  { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
  assert.equal(reads, 2); assert.equal(browserCalls, 0);
  const childId = U(), childResult = { verdict: 'pass' };
  canonicalRows = [{ ...canonical, child_id: childId, child_row: {
    ...canonical, evaluation_id: childId, result_json: childResult,
    result_serialized: JSON.stringify(childResult),
    result_digest: sha(JSON.stringify(childResult)),
    packet: structuredClone(canonical.packet),
    execution_json: { ...canonical.execution_json, runId: U() },
    child_id: undefined, child_row: undefined } }];
  assert.notEqual(canonicalRows[0].child_row.packet, canonical.packet);
  const retried = await service.readOutcome({ scope, persona, personaSession, operationId });
  assert.equal(retried.completed, true);
  assert.equal(retried.judgment.evaluationId, childId);
  assert.equal(browserCalls, 0);
  canonicalRows[0].child_row.packet.source = 'tampered';
  await assert.rejects(service.readOutcome({ scope, persona, personaSession, operationId }),
    { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
  canonicalRows[0].child_row.packet = structuredClone(canonical.packet);
  rows[0].request_hash = sha('foreign request');
  await assert.rejects(service.readOutcome({ scope, persona, personaSession, operationId }),
    { code: 'LISTING_RAW_BROWSER_EVIDENCE_UNAVAILABLE' });
  const fixed = fixture('fixed', scope);
  activeOriginal = fixed.original; activeSourceRead = fixed.sourceRead;
  const beforeFixedReads = reads;
  assert.deepEqual(await service.runAttempt({ scope, persona, personaSession,
    operationId: fixed.operationId }),
  { operationId: fixed.operationId, completed: false, status: 'ineligible', modelEvaluated: false });
  assert.equal(reads, beforeFixedReads); assert.equal(browserCalls, 0);
});

test('same operation reuses the canonical bound session and completed request without a second browser effect', async () => {
  const { original, operationId, sourceRead } = fixture();
  const reorder = value => Array.isArray(value) ? value.map(reorder)
    : value && Object.getPrototypeOf(value) === Object.prototype
      ? Object.fromEntries(Object.entries(value).reverse().map(([key, item]) => [key, reorder(item)]))
      : value;
  original.proposal.preview = reorder(original.proposal.preview);
  sourceRead.receipt.source = reorder(sourceRead.receipt.source);
  const scope = sourceRead.receipt.source.execution.scope,
    persona = { id: 11, role: 'merchant' },
    personaSession = { sessionId: U(), authorityVersion: '1' };
  const counts = { session: 0, claim: 0, effect: 0, browser: 0, judge: 0 };
  let session = null, saved = null;
  const fence = { binding: { ...scope, personaId: persona.id,
    role: persona.role, ...personaSession },
  async assertRemoteAdmission() {}, async withPersonaEffect(work) { return work(); } };
  const service = createListingRawBrowserAssessment({
    launches: { async assertCurrent() {} },
    conversationRepository: {
      async acquireBoundSession(input) { counts.session++; session ||= { id: input.id,
        purpose: input.purpose, state: 'active', binding: input.binding };
      return session; }, async activateBoundSession() { return true; },
      async getBoundSession() { return session; } },
    coordinator: { async run(_id, options, work) {
      const decision = await options.admit(); if (decision.skip) return decision.value;
      return work({ runId: U(), ownerKey: JSON.stringify(['SecureShopBoundConversation', session.id]),
        durableGeneration: '1', signal: options.signal, async check() {},
        async effectWithReceipt(node, callback) { counts.effect++;
          return { value: await callback(), receipt: { version: 1, status: 'completed',
            runId: this.runId, ownerKey: this.ownerKey, generation: '1',
            effectKey: `${options.idempotencyKey}:${node}` } }; } }); } },
    journal: { async claim(input) { counts.claim++;
      return saved ? { status: 'completed', result: saved } : { status: 'claimed', claimId: U() }; },
    async complete(input) { saved = structuredClone(input.result); }, async markUncertain() {} },
    agentsPool: { async query() { return { rows: [] }; } },
    readOriginal: async () => original,
    catalog: { async readMerchantListingCreateSource() { return sourceRead; } },
    modeAuthority: { async capture() { return { snapshot: sourceRead.receipt.source.execution,
      async assertCurrent() {} }; }, assertToken(value) { return value; } },
    identityPool: { async query(sql) { if (sql.includes('secureshop_authority_owners'))
      return { rows: [{ realm: 'platform', shop_tenant_id: null }] };
      return { rows: [{ objective_id: RAW_LISTING_BROWSER_RUBRIC.objectiveId }] }; } },
    personaAuthority: { async capture() { return fence; } },
    personaBindings: { async capture() { return { token: 'controlled' }; } },
    receipts: { async beginEvaluation(input) { return { ...input, verdict: null }; },
      async recordVerdict({ evaluationId, result }) { return { evaluationId,
        result, verdict: result.verdict, disposition: result.verdict === 'pass' ? 'awarded' : 'not_pass' }; } },
    progress: { async getGeneration() { return 1; },
      async getEvaluationScope() { return { generation: 1, mode: 'vuln', modeStamp: 'v1' }; } },
    publicationModes: { async getEvaluationScope() {
      return { generation: 1, mode: 'vuln', modeStamp: 'v1' }; } },
    judge: async input => { counts.judge++;
      const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
      return { family: input.rubric.family, scenario: input.rubric.scenario,
        objectiveId: input.rubric.objectiveId, rubricVersion: input.rubric.version,
        mode: input.rubric.mode, evidenceDigest: prepareJudgeInput(input).evidenceDigest,
        verdict: 'pass', criteria: [], explanation: 'Controlled Judge',
        provider: 'controlled', model: 'controlled' }; },
    qualifyModel: () => true,
    browserQualification: { async qualify() { counts.browser++;
      return { executed: true, targetEventExecuted: true, targetEffectObserved: true,
        syntheticCookieOnly: true, finalCookieIsSyntheticOnly: true,
        markers: [{ kind: 'owned synthetic marker' }], blockedRequests: [] }; } },
    productRenderer: { async renderProductDescription(product) {
      return `<article>${product.description_html}</article>`; },
    sourceSha256: sha('component-source'), artifactSha256: sha('component-artifact') },
  });
  const input = { scope, persona, personaSession, operationId };
  const first = await service.runAttempt(input);
  assert.equal(first.operationId, operationId);
  assert.equal(first.completed, true);
  const second = await service.runAttempt(input);
  assert.equal(second.replayed, true);
  assert.equal(counts.browser, 1); assert.equal(counts.effect, 1);
  assert.equal(counts.judge, 1); assert.equal(counts.claim, 2);
  assert.equal(counts.session, 2); // acquire returns the same session for this binding/purpose.
});
