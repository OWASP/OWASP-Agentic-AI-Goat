'use strict';

// Assertion adapter for a future rendered V15 caller. Every input must come from
// the original physical request, protected SQL/source reader, or retained audit
// artifact. This module neither creates an audit source nor runs a model/Judge.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { createAuditSourceManifest } = require('../../server/services/secureshopAuditSourceManifest');
const { prepareSecureShopAuditJudgePacket, AUDIT_INSTRUCTION_OBJECTIVE } = require('../../server/services/secureshopAuditJudgePacket');
const { prepareJudgeInput, readConfiguredJudgeProvenance } = require('../../server/agent-runtime/objectiveJudge');

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const obligations = Object.freeze(['two authenticated physical shop sessions on one retained scene',
  'original merchant listing event and both persisted scene grants',
  'immutable audit artifacts and actual qualified model chain',
  'configured Judge and canonical credit', 'fixed projection, saved replay, reset and sibling fences',
  'owned browser, provider and database cleanup']);

const EVENT_FIELDS = Object.freeze(['id', 'store', 'ts', 'actor', 'action', 'target',
  'params_json', 'outcome', 'source_kind', 'source_id']);
function assertV15SceneSource({ merchant, admin, physicalSave, persisted, event, productId, description }) {
  const merchantScope = createLaunchScope(merchant.scope);
  const adminScope = createLaunchScope(admin.scope);
  assert.equal(merchant.persona.role, 'merchant');
  assert.equal(admin.persona.role, 'admin');
  assert.match(admin.subject?.tenantId, UUID);
  assert.match(admin.subject?.principalId, UUID);
  assert.equal(admin.subject.shopUserId, admin.persona.id);
  assert.notEqual(merchantScope.launchId, adminScope.launchId);
  assert.notEqual(merchantScope.platformSessionId, adminScope.platformSessionId);
  assert.equal(merchantScope.platformOwnerId, adminScope.platformOwnerId);
  assert.match(merchant.personaSession.sessionId, UUID);
  assert.match(admin.personaSession.sessionId, UUID);
  assert.notEqual(merchant.personaSession.sessionId, admin.personaSession.sessionId);
  assert.ok(Number.isSafeInteger(productId) && productId > 0);
  assert.ok(typeof description === 'string' && description.length > 0);
  assert.equal(physicalSave.method, 'PUT');
  assert.equal(physicalSave.path, `/api/secureshop/merchant/products/${productId}`);
  assert.equal(physicalSave.status, 200);
  assert.equal(physicalSave.body?.patch?.description, description);
  assert.equal(event.sceneSource?.version, 2);
  assert.deepEqual(event.sceneSource.sourceExecution, merchantScope);
  assert.deepEqual(event.sceneSource.consumerExecution, adminScope);
  assert.equal(event.sceneSource.product.productId, productId);
  assert.equal(event.sceneSource.product.merchantId, merchant.persona.id);
  assert.equal(event.sceneSource.scene.sceneId, merchant.scene.sceneId);
  assert.equal(event.sceneSource.scene.sceneId, admin.scene.sceneId);
  assert.equal(event.sceneSource.scene.sceneGeneration, merchant.scene.sceneGeneration);
  assert.equal(event.sceneSource.scene.sceneGeneration, admin.scene.sceneGeneration);
  assert.equal(event.sceneSource.scene.targetId, merchant.scene.targetId);
  assert.equal(event.sceneSource.scene.targetId, admin.scene.targetId);
  assert.deepEqual(event.sceneSource.sourceGrant, merchant.grant);
  assert.deepEqual(event.sceneSource.consumerGrant, admin.grant);
  assert.deepEqual(event.sceneSource.scene.birth, createLaunchScope(merchant.scene.birth));
  assert.deepEqual(event.sceneSource.scene.birth, createLaunchScope(admin.scene.birth));
  assert.equal(JSON.parse(event.params_json).description, description);
  assert.deepEqual(persisted?.event,
    Object.fromEntries(EVENT_FIELDS.map(key => [key, event[key]])),
    'The original completed SQL event must match the source adapter row');
  assert.deepEqual(persisted.eventExecution, merchantScope,
    'The durable event must independently name the merchant execution');
  assert.equal(persisted.eventMerchantId, merchant.persona.id);
  assert.equal(persisted.eventShopRole, 'merchant');
  assert.deepEqual(persisted.sourceGrant, merchant.grant);
  assert.deepEqual(persisted.sourceExecution, merchantScope,
    'The durable source grant must independently name the merchant execution');
  assert.deepEqual(persisted.consumerGrant, admin.grant);
  assert.deepEqual(persisted.consumerExecution, adminScope,
    'The durable consumer grant must independently name the admin execution');
  assert.deepEqual(persisted.product,
    { productId, merchantId: merchant.persona.id, targetId: event.sceneSource.scene.targetId },
    'The product ownership row must independently match the source and scene');
  const expected = createAuditSourceManifest([event], { consumerScope: adminScope });
  assert.equal(expected.rowCount, 1);
  assert.equal(expected.sources[0].version, 2);
  return Object.freeze({ entry: expected.sources[0], logText: expected.logText,
    merchantScope, adminScope, adminSubject: admin.subject, actualQualification: false, obligations });
}

async function bytesFrom(evidence, name) {
  const ref = evidence.artifacts?.[name];
  assert.ok(Number.isSafeInteger(ref?.bytes) && ref.bytes >= 0 && ref.bytes <= 1024 * 1024);
  assert.match(ref.sha256, /^[0-9a-f]{64}$/);
  const chunks = []; let size = 0;
  for await (const part of evidence.readArtifact(name)) {
    assert.ok(Buffer.isBuffer(part)); size += part.length;
    assert.ok(size <= ref.bytes, `${name} exceeded its immutable reference`); chunks.push(part);
  }
  const raw = Buffer.concat(chunks);
  assert.equal(size, ref.bytes); assert.equal(sha(raw), ref.sha256);
  return raw;
}

async function assertV15AuditArtifacts({ source, evidence, physicalSummary, mode, qualifyModel, check }) {
  assert.ok(source?.entry?.version === 2);
  assert.ok(['vuln', 'fixed'].includes(mode));
  assert.equal(typeof qualifyModel, 'function'); assert.equal(typeof check, 'function');
  assert.equal(typeof evidence?.readArtifact, 'function');
  assert.equal(physicalSummary?.method, 'POST');
  assert.equal(physicalSummary.path, '/api/secureshop/agents/admin/assistant/audit/job/run');
  assert.ok([200, 202].includes(physicalSummary.status));
  for (const key of ['sessionId', 'requestId', 'proposalId'])
    assert.match(physicalSummary.body?.[key], UUID);
  assert.equal(physicalSummary.savedResult?.runId, evidence.runId);
  assert.equal(physicalSummary.renderedText, evidence.summary);
  const [log, sources] = await Promise.all([bytesFrom(evidence, 'log'), bytesFrom(evidence, 'sources')]);
  assert.equal(evidence.rowCount > 0, true);
  const list = JSON.parse(sources.toString('utf8'));
  assert.ok(Array.isArray(list) && list.length === evidence.rowCount);
  if (mode === 'vuln') {
    assert.equal(list.filter(row => row.id === source.entry.id).length, 1);
    assert.deepEqual(list.find(row => row.id === source.entry.id), source.entry);
    assert.ok(log.toString('utf8').includes(source.logText));
  } else {
    const matches = list.filter(row => row.id === source.entry.id && row.version === 2);
    assert.equal(matches.length, 1);
    assert.deepEqual(matches[0].original, source.entry);
    assert.equal(log.toString('utf8').includes(source.entry.event.params_json), false,
      'Fixed model log must not contain raw merchant event text');
    assert.ok(log.toString('utf8').includes(`sha256:${source.entry.sha256}`));
  }
  const packet = await prepareSecureShopAuditJudgePacket(evidence, { qualifyModel, check, mode });
  const prepared = prepareJudgeInput(packet);
  assert.equal(prepared.evidenceError, undefined);
  assert.equal(packet.rubric.objectiveId, AUDIT_INSTRUCTION_OBJECTIVE);
  assert.equal(packet.rubric.mode, mode);
  assert.equal(packet.evidence.find(row => row.id === 'audit_provenance').content.sourcesSha256,
    evidence.artifacts.sources.sha256);
  return Object.freeze({ source, packet, prepared, evidence, mode, actualQualification: false, obligations });
}

function assertV15Judge({ validated, judgment, completion, contribution, rawJudge, transcript }) {
  assert.equal(validated.mode, 'vuln');
  const { evidence, prepared, source } = validated;
  assert.ok(Number.isSafeInteger(judgment.generation) && judgment.generation >= 0,
    'Judgment generation must be a nonnegative integer');
  assert.ok(Number.isSafeInteger(completion.generation) && completion.generation >= 0,
    'Completion generation must be a nonnegative integer');
  assert.equal(completion.generation, judgment.generation, 'Completion generation must match judgment');
  assert.equal(completion.objective_id, judgment.objective_id, 'Completion objective must match judgment');
  assert.equal(judgment.objective_id, AUDIT_INSTRUCTION_OBJECTIVE);
  assert.equal(judgment.run_id, evidence.runId);
  assert.deepEqual(judgment.execution_json?.scope, source.adminScope);
  assert.equal(judgment.tenant_id, source.adminSubject.tenantId);
  assert.equal(judgment.principal_id, source.adminSubject.principalId);
  assert.equal(Number(judgment.shop_user_id), source.adminSubject.shopUserId);
  assert.equal(judgment.packet, prepared.packet);
  assert.equal(judgment.evidence_digest, prepared.evidenceDigest);
  assert.equal(sha(judgment.packet), judgment.evidence_digest);
  assert.equal(judgment.verdict, 'pass');
  assert.equal(judgment.disposition, 'awarded');
  assert.equal(rawJudge.verdict, 'pass');
  assert.equal(rawJudge.runId, evidence.runId);
  assert.equal(rawJudge.evidenceDigest, judgment.evidence_digest);
  assert.equal(rawJudge.criteria.filter(row => row.id === 'redirected_output' && row.satisfied === true).length, 1);
  assert.deepEqual(JSON.parse(judgment.judge_result_json), rawJudge);
  const proof = readConfiguredJudgeProvenance(rawJudge);
  assert.ok(proof);
  assert.equal(proof.runId, evidence.runId);
  assert.equal(proof.evidenceDigest, judgment.evidence_digest);
  assert.deepEqual(judgment.judge_observations, proof);
  assert.equal(sha(judgment.judge_result_json), proof.resultSha256);
  for (const row of [completion, contribution]) {
    assert.equal(row.evaluation_id, judgment.evaluation_id);
    assert.equal(row.tenant_id, judgment.tenant_id);
    assert.equal(row.principal_id, judgment.principal_id);
  }
  assert.equal(transcript.complete, true);
  assert.equal(transcript.header.packet, judgment.packet);
  assert.equal(transcript.header.evidenceDigest, judgment.evidence_digest);
  assert.equal(transcript.header.runId, evidence.runId);
  assert.deepEqual(transcript.outcome.value, rawJudge);
  assert.ok(transcript.calls.length > 0);
  return Object.freeze({ actualQualification: false, obligations });
}

function assertV15Fences({ owner, replay, reset, sibling, fixed }) {
  const scope = createLaunchScope(owner);
  const counts = value => {
    assert.deepEqual(Object.keys(value || {}).sort(),
      ['sourceReads', 'modelCalls', 'effects', 'judgeCalls'].sort());
    for (const count of Object.values(value)) assert.ok(Number.isSafeInteger(count) && count >= 0);
  };
  assert.match(replay.requestId, UUID);
  assert.match(replay.runId, UUID);
  assert.equal(replay.before.status, 200);
  assert.equal(replay.after.status, 200);
  assert.equal(replay.before.value.runId, replay.runId);
  assert.equal(replay.after.value.runId, replay.runId);
  counts(replay.beforeCounters); counts(replay.afterCounters);
  assert.deepEqual(replay.after.value, replay.before.value);
  assert.deepEqual(replay.afterCounters, replay.beforeCounters,
    'Saved GET must add no source reads, model calls, effects or Judge calls');
  assert.equal(reset.before.status, 200);
  assert.equal(reset.before.value.runId, replay.runId);
  assert.equal(reset.receipt.status, 'committed');
  assert.equal(reset.receipt.toGeneration, scope.generation + 1);
  assert.equal(reset.oldSessionBefore.status, 200);
  assert.equal(reset.oldSessionBefore.value.ok, true);
  assert.equal(reset.oldSessionBefore.value.user.id, reset.adminShopUserId);
  assert.equal(reset.oldSession.status, 401);
  assert.equal(reset.savedAfter.status, 401);
  assert.equal(reset.sceneSourceAfter.code, 'STALE_LAUNCH');
  assert.ok(Array.isArray(reset.immutableBefore) && reset.immutableBefore.length > 0);
  assert.deepEqual(reset.immutableAfter, reset.immutableBefore);
  assert.deepEqual(reset.activeContributionsAfter, []);
  counts(reset.beforeCounters); counts(reset.afterCounters);
  assert.deepEqual(reset.afterCounters, reset.beforeCounters);
  assert.notEqual(createLaunchScope(sibling.scope).platformOwnerId, scope.platformOwnerId);
  assert.equal(sibling.before.status, 200);
  assert.deepEqual(sibling.after, sibling.before);
  assert.ok(Array.isArray(sibling.rowsBefore) && sibling.rowsBefore.length > 0);
  assert.deepEqual(sibling.rowsAfter, sibling.rowsBefore);
  assert.equal(fixed.sourceAdmitted, true);
  assert.ok(Array.isArray(fixed.creditBefore) && Array.isArray(fixed.creditAfter));
  assert.deepEqual(fixed.creditAfter, fixed.creditBefore);
  return Object.freeze({ actualQualification: false, obligations });
}

module.exports = { assertV15SceneSource, assertV15AuditArtifacts, assertV15Judge, assertV15Fences };
