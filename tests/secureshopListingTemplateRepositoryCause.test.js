'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, createHmac, randomUUID } = require('node:crypto');
const { createListingTemplateRepository } = require('../server/database/postgres/secureshopListingTemplateRepository');
const { listingTemplateRequestDigest } = require('../server/services/secureshopListingTemplateContract');
const { createSceneBinding, authorizeSceneMerchant } = require('../server/services/secureshopSceneBinding');

const sha = value => createHash('sha256').update(value).digest('hex');

function fixture({ appendError, admissionFenceError, effectAfterError } = {}) {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 17, platformSessionId: 23 };
  const persona = { id: 1000000001, role: 'merchant' };
  const personaSession = { sessionId: randomUUID(), authorityVersion: '1' };
  const request = { version: 1, operationId: randomUUID(), productId: 7 };
  const context = { templateSource: 'Plain template', title: 'Owned product',
    description: 'Synthetic description', price: 12 };
  const targetId = randomUUID(), grantId = randomUUID(), capabilityKey = Buffer.alloc(32, 7);
  const requestSha256 = listingTemplateRequestDigest(request);
  const secret = createHmac('sha256', capabilityKey).update(JSON.stringify([
    'listing-template.v1', request.operationId, targetId, grantId, requestSha256,
  ])).digest('hex');
  const row = { operation_id: request.operationId, product_id: request.productId,
    target_id: targetId, grant_id: grantId, mode: 'vuln',
    launch_id: scope.launchId, scenario_id: scope.scenarioId, generation: scope.generation,
    platform_owner_id: scope.platformOwnerId, platform_session_id: scope.platformSessionId,
    merchant_id: persona.id, persona_session_id: personaSession.sessionId,
    authority_version: personaSession.authorityVersion, request_sha256: requestSha256,
    context_json: context, context_sha256: sha(JSON.stringify(context)),
    context_hash_actual: sha(JSON.stringify(context)), source_sha256: sha(context.templateSource),
    capability_sha256: sha(secret), grant_current: true, redacted_at: null };
  const target = authorizeSceneMerchant(createSceneBinding({ ...scope, targetId }, {
    sceneId: randomUUID(), sceneGeneration: 1, grantId, execution: scope,
    withLease: work => work(),
  }), persona.id);
  let appended = 0;
  const client = { release() {}, async query(sql) {
    if (sql.includes('SELECT o.*')) return { rows: [row] };
    if (sql.includes('FROM secureshop_review.owned_listing_template_events')) return { rows: [] };
    if (sql.includes('append_owned_listing_template_event')) {
      appended++;
      throw appendError;
    }
    return { rows: [] };
  } };
  const binding = { ...scope, personaId: persona.id, role: persona.role, ...personaSession };
  let insideEffect = false, nestedAdmissions = 0, effectChecks = 0;
  const fence = { binding, async assertRemoteAdmission() {
    if (insideEffect) nestedAdmissions++;
    if (admissionFenceError) throw admissionFenceError;
  }, async withCrossStoreEffect(work) {
    effectChecks++;
    insideEffect = true;
    try {
      const result = await work();
      if (effectAfterError) throw effectAfterError;
      return result;
    } finally { insideEffect = false; effectChecks++; }
  } };
  const repository = createListingTemplateRepository({ pool: { async connect() { return client; } },
    catalog: { async prepareTarget() { return target; } },
    personaAuthority: { capture() { return fence; } }, launches: { async assertCurrent() {} },
    capabilityKey });
  return { repository, raw: { scope, persona, personaSession, request }, appended: () => appended,
    nestedAdmissions: () => nestedAdmissions, effectChecks: () => effectChecks };
}

test('attempted template event failure stays uncertain while retaining private original cause', async () => {
  const sqlError = Object.assign(new Error('column does not exist'), { code: '42703' });
  const f = fixture({ appendError: sqlError });
  await assert.rejects(f.repository.advance(f.raw, 'running', null), error => {
    assert.equal(error.code, 'LISTING_TEMPLATE_OUTCOME_UNCERTAIN');
    assert.equal(error.message, 'Owned listing template unavailable');
    assert.equal(error.cause, sqlError);
    assert.equal(Object.keys(error).includes('cause'), false);
    assert.equal(JSON.stringify(error).includes('column does not exist'), false);
    return true;
  });
  assert.equal(f.appended(), 1);
});

test('remote template execution uses its held authority fence without recursive admission', async () => {
  const f = fixture();
  let executed = 0;
  const result = await f.repository.withBoundExecution(f.raw, async () => {
    executed++;
    return { saved: true };
  });
  assert.deepEqual(result, { saved: true });
  assert.equal(executed, 1);
  assert.equal(f.effectChecks(), 2);
  assert.equal(f.nestedAdmissions(), 0);
});

test('post-effect authority failure stays uncertain without executing the remote callback again', async () => {
  const uncertain = Object.assign(new Error('Original authority changed after effect'), {
    code: 'PERSONA_EFFECT_OUTCOME_UNCERTAIN', executionBoundary: true,
  });
  const f = fixture({ effectAfterError: uncertain });
  let executed = 0;
  await assert.rejects(f.repository.withBoundExecution(f.raw, async () => {
    executed++;
    return { saved: true };
  }), error => error === uncertain);
  assert.equal(executed, 1);
  assert.equal(f.nestedAdmissions(), 0);
  assert.equal(f.effectChecks(), 2);
});
