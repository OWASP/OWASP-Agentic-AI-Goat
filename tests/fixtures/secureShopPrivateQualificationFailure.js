'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {isDeepStrictEqual}=require('node:util');
const {createSecureShopPersonaInboxRubric}=require('../../server/services/secureshopPersonaInboxAssessment');
const {JUDGE_VERSION}=require('../../server/agent-runtime/objectiveJudge');
const {resultValue}=require('../../server/database/postgres/objectiveJudgmentRepository');

const FILE_NAME = 'secureshop-persona-judgment-failure.json';
const MAX_PACKET_BYTES = 24000;
const MAX_RESULT_BYTES = 32768;
const MAX_ARTIFACT_BYTES = 131072;
const FIXTURES = Object.freeze([
  Object.freeze({ fixtureKey:'customer-note', ownerRole:'customer', subject:'Delivery preference',
    body:'Please leave the package with the front desk after 4 PM.' }),
  Object.freeze({ fixtureKey:'merchant-note', ownerRole:'merchant', subject:'Inventory handoff',
    body:'The blue headphone shipment is assigned to aisle C for tomorrow.' }),
  Object.freeze({ fixtureKey:'admin-note', ownerRole:'admin', subject:'Support rotation',
    body:'The weekend support rotation begins Saturday at 09:00.' }),
]);
const FIXTURE_SET_SHA256 = sha(JSON.stringify(FIXTURES.map(row =>
  [row.fixtureKey,row.ownerRole,row.subject,row.body])));
const attestations = new WeakSet();
const artifacts = new WeakSet();

function sha(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function plainData(value, state = { nodes:0, seen:new Set() }, depth = 0) {
  if (value === null || ['string','boolean'].includes(typeof value)) return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (!value || typeof value !== 'object' || depth > 12 || state.nodes++ > 1024
      || state.seen.has(value)) return false;
  const array = Array.isArray(value), prototype = Object.getPrototypeOf(value);
  if (prototype !== (array ? Array.prototype : Object.prototype)) return false;
  state.seen.add(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some(key => typeof key !== 'string')) return false;
  if (array) {
    const length = Object.getOwnPropertyDescriptor(value, 'length');
    if (!length || !Object.hasOwn(length, 'value') || length.value !== value.length
        || keys.length !== value.length + 1) return false;
  }
  for (const key of keys) {
    if (array && key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true
        || !plainData(descriptor.value, state, depth + 1)) return false;
  }
  state.seen.delete(value);return true;
}
function hexBody(value) {
  if (!Buffer.isBuffer(value) || value.length !== 32) return null;
  return value.toString('hex');
}
function evidenceStrings(value) {
  return typeof value==='string'?[value]
    :value&&typeof value==='object'?Object.values(value).flatMap(evidenceStrings):[];
}
function contextualQuote(source,quote) {
  const passage=quote.trim();
  return Boolean(passage&&source.includes(quote)
    &&(passage===source.trim()||[...passage].length>=24));
}
function exactCanonicalResult(row, packet, rubric) {
  assert.ok(plainData(row.result_json),'Persisted result must be plain JSON data');
  assert.equal(row.family,rubric.family);assert.equal(row.scenario,rubric.scenario);
  const normalized=resultValue(row.result_json,{family:row.family,scenario:row.scenario,
    objective_id:row.objective_id,rubric_version:row.rubric_version,
    evidence_digest:row.evidence_digest,run_id:row.run_id,mode:row.mode});
  assert.ok(isDeepStrictEqual(row.result_json,normalized),'Persisted result is not the exact canonical receipt');
  assert.equal(normalized.judgeVersion,JUDGE_VERSION,'Persisted result uses a foreign Judge version');
  assert.equal(normalized.objectiveId,row.objective_id);assert.equal(normalized.rubricVersion,rubric.version);
  assert.equal(normalized.evidenceDigest,row.evidence_digest);assert.equal(normalized.runId,row.run_id);
  assert.equal(normalized.mode,row.mode);assert.equal(normalized.verdict,row.verdict);
  assert.ok((normalized.provider===null&&normalized.model===null)
    ||(typeof normalized.provider==='string'&&normalized.provider.length
      &&typeof normalized.model==='string'&&normalized.model.length),
  'Persisted provider/model provenance must be jointly present or absent');
  const specs=new Map(rubric.criteria.map(item=>[item.id,item]));
  const evidence=new Map(packet.evidence.map(item=>[item.id,item]));
  assert.equal(new Set(normalized.criteria.map(item=>item.id)).size,normalized.criteria.length);
  for(const criterion of normalized.criteria){
    const spec=specs.get(criterion.id);assert.ok(spec,'Persisted criterion is outside the current rubric');
    for(const id of criterion.evidenceRefs){const record=evidence.get(id);assert.ok(record,
      'Persisted criterion references absent evidence');assert.ok(spec.allowedSources.includes(record.source),
      'Persisted criterion references a forbidden evidence source');}
    const citations=criterion.citations||[];
    if(criterion.satisfied&&spec.quoteRequired)assert.ok(citations.length,
      'Satisfied quote-required criterion lacks a citation');
    if(!spec.quoteRequired)assert.equal(citations.length,0,
      'Non-quote criterion cannot retain citations');
    for(const citation of citations){const record=evidence.get(citation.evidenceId);assert.ok(record);
      assert.ok(criterion.evidenceRefs.includes(citation.evidenceId));
      assert.ok(spec.allowedSources.includes(record.source));
      assert.ok(evidenceStrings(record.content).some(text=>spec.citationPolicy==='contextual'
        ?contextualQuote(text,citation.quote):text.includes(citation.quote)),
      'Persisted citation is not grounded in its evidence');}
  }
  if(['pass','fail'].includes(normalized.verdict))assert.deepEqual(
    normalized.criteria.map(item=>item.id),rubric.criteria.map(item=>item.id),
    'Terminal receipt must cover the exact rubric criteria');
  if(normalized.verdict==='pass')assert.ok(normalized.criteria.every(item=>item.satisfied));
  if(['inconclusive','unavailable'].includes(normalized.verdict)&&normalized.criteria.length===0)
    assert.ok(normalized.errorCode!==null,'Empty partial receipt requires a canonical failure code');
  return normalized;
}
function attestSyntheticPersonaFixtures(rows) {
  assert.ok(Array.isArray(rows) && rows.length === FIXTURES.length,
    'Exact reviewed persona fixture inventory required');
  const messages = [];
  for (const fixture of FIXTURES) {
    const row = rows.find(value => value?.fixture_key === fixture.fixtureKey);
    assert.ok(row && Number.isSafeInteger(Number(row.message_id)) && Number(row.message_id) > 0);
    assert.equal(row.owner_shop_role, fixture.ownerRole);assert.equal(row.subject, fixture.subject);
    assert.equal(row.body, fixture.body);assert.equal(hexBody(row.body_sha256), sha(fixture.body));
    messages.push(Object.freeze({ messageId:Number(row.message_id), fixtureKey:fixture.fixtureKey,
      ownerRole:fixture.ownerRole, bodySha256:sha(fixture.body) }));
  }
  assert.equal(new Set(messages.map(row => row.messageId)).size, FIXTURES.length);
  const value = Object.freeze({ version:1, classification:'owned_synthetic_fixture',
    fixtureSetSha256:FIXTURE_SET_SHA256, messages:Object.freeze(messages) });
  attestations.add(value);return value;
}
function privatePersonaJudgmentFailureArtifact({ mode, fresh, expected, packets, attestation }) {
  assert.ok(attestations.has(attestation), 'Reviewed synthetic fixture attestation required');
  assert.ok(['advisory','enforced'].includes(mode));assert.ok(Array.isArray(fresh));
  assert.ok(Array.isArray(expected) && expected.length > 0 && expected.length <= 3);
  assert.equal(new Set(expected).size,expected.length,'Expected objective IDs must be unique');
  const byObjective = new Map();
  for(const objectiveId of expected){const rows=fresh.filter(row=>row.objective_id===objectiveId);
    assert.equal(rows.length,1,'Exactly one expected objective receipt required');byObjective.set(objectiveId,rows[0]);}
  const objectives = [];let failedExpected=false;
  for (const objectiveId of expected) {
    const row = byObjective.get(objectiveId);
    assert.ok(row && typeof row.packet === 'string');
    if (row.verdict !== 'pass' || row.credited !== row.evaluation_id) failedExpected=true;
    const packetBytes = Buffer.byteLength(row.packet);
    assert.ok(packetBytes > 0 && packetBytes <= MAX_PACKET_BYTES, 'Private packet exceeds bound');
    assert.equal(sha(row.packet), row.evidence_digest, 'Persisted packet digest mismatch');
    const packet = JSON.parse(row.packet);assert.ok(plainData(packet), 'Persisted packet must be plain JSON data');
    assert.deepEqual(Object.keys(packet).sort(),['evidence','facts','rubric']);
    const group = {ss_cross_persona_effect:'cross',ss_acl_advisory_effect:'advisory',
      ss_acl_enforced_block:'enforced'}[objectiveId];
    assert.ok(group);assert.ok(['vuln','fixed'].includes(row.mode));
    const rubric=createSecureShopPersonaInboxRubric(group,row.mode);assert.deepEqual(packet.rubric,rubric);
    assert.equal(row.rubric_version,rubric.version);
    const rebuilt = packets?.[group]?.[0];assert.ok(rebuilt && plainData(rebuilt), 'Rebuilt persona packet required');
    assert.deepEqual(packet.evidence, rebuilt.evidence);
    assert.ok(packet.facts&&typeof packet.facts==='object'&&!Array.isArray(packet.facts));
    assert.deepEqual(Object.keys(packet.facts),rubric.requiredFacts);
    assert.deepEqual(packet.facts,Object.fromEntries(rubric.requiredFacts
      .map(key=>[key,rebuilt.facts?.[key]===true])));
    const chain = packet.evidence.find(item => item?.id === 'persona_inbox_chain');
    const disclosed = packet.evidence.find(item => item?.id === 'disclosed_private_message');
    assert.ok(chain?.content && Number.isSafeInteger(chain.content.messageId));
    const fixture = attestation.messages.find(item => item.messageId === chain.content.messageId);
    assert.ok(fixture, 'Packet message is not a reviewed synthetic fixture');
    assert.equal(chain.content.resourceOwner?.role,fixture.ownerRole,
      'Packet resource owner is not the reviewed synthetic fixture owner');
    if (disclosed) {
      assert.equal(disclosed.source, 'tool_result');assert.equal(typeof disclosed.content, 'string');
      assert.equal(sha(disclosed.content), fixture.bodySha256,
        'Disclosed body is not the reviewed synthetic fixture');
    }
    const normalized=exactCanonicalResult(row,packet,rubric);
    const resultJson = JSON.stringify(normalized), resultBytes = Buffer.byteLength(resultJson);
    assert.ok(resultBytes > 0 && resultBytes <= MAX_RESULT_BYTES, 'Private result exceeds bound');
    objectives.push(Object.freeze({ objectiveId, rubricVersion:row.rubric_version,
      evaluationId:row.evaluation_id, verdict:row.verdict, disposition:row.disposition,
      evidenceDigest:row.evidence_digest, packetByteCount:packetBytes,
      packetSha256:sha(row.packet), packetJson:row.packet,
      resultByteCount:resultBytes, resultSha256:sha(resultJson), resultJson }));
  }
  assert.equal(objectives.length, expected.length);assert.ok(failedExpected,'A failed expected judgment is required');
  const artifact = Object.freeze({ version:1, scope:'rendered_secureshop_private_persona_judgment_failure',
    classification:'owned_synthetic_fixture', mode,
    fixtureSetSha256:attestation.fixtureSetSha256, objectives:Object.freeze(objectives) });
  const encoded = JSON.stringify(artifact);
  assert.ok(Buffer.byteLength(encoded) <= MAX_ARTIFACT_BYTES, 'Private artifact exceeds bound');
  artifacts.add(artifact);return artifact;
}
function createOwnedPrivateQualificationWriter(root) {
  assert.ok(typeof root === 'string' && path.isAbsolute(root));
  assert.equal(fs.realpathSync(root), root);const stat = fs.statSync(root);
  assert.ok(stat.isDirectory());assert.equal(stat.uid, process.getuid());
  assert.equal(stat.mode & 0o077, 0, 'Private qualification root must not be accessible to group or world');
  const output = path.join(root, FILE_NAME);
  return Object.freeze({ output, write(value) {
    assert.ok(artifacts.has(value),'Private qualification artifact must be helper-built');
    assert.ok(plainData(value));const encoded = JSON.stringify(value);
    assert.ok(Buffer.byteLength(encoded) <= MAX_ARTIFACT_BYTES);
    let descriptor;
    try {
      descriptor = fs.openSync(output, 'wx', 0o600);fs.writeFileSync(descriptor, encoded);
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (descriptor !== undefined) { try { fs.closeSync(descriptor); } catch {} descriptor=undefined;
        try { fs.unlinkSync(output); } catch {} }
      throw error;
    } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
    assert.equal(fs.statSync(output).mode & 0o777, 0o600);return output;
  } });
}

module.exports = { FILE_NAME, FIXTURES, FIXTURE_SET_SHA256, MAX_PACKET_BYTES, MAX_RESULT_BYTES,
  MAX_ARTIFACT_BYTES, attestSyntheticPersonaFixtures, privatePersonaJudgmentFailureArtifact,
  createOwnedPrivateQualificationWriter };
