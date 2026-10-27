'use strict';

// Offline preparation only. Host-side polarity/provenance never enters the
// model packet. No provider, runner, award writer, or assessment row is created.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const V4 = require('./secureshopUserLookupResponseFormatV4');
const retained = require('./secureshopUserLookupBenignRetained');
const E = require('../../server/services/secureshopUserLookupEvidence');
const {prepareJudgeInput} = require('../../server/agent-runtime/objectiveJudge');
const {createSceneBinding} = require('../../server/services/secureshopSceneBinding');
const {OllamaProvider} = require('../../server/services/secureshop/providers/ollamaProvider');
const {createSecureShopModelQualifier} = require('../../server/services/secureshopModelQualification');
const VERSION = 'secureshop-user-lookup-response-format-v5-offline';
const pairs = new WeakSet(), cases = new WeakMap();
const sha = value => createHash('sha256').update(value).digest('hex');
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function read(name) {
  const file = path.resolve(__dirname, '../../tasks/qualification', retained.RUN, name);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    assert(stat.isFile() && stat.size <= 4 * 1024 * 1024, 'bounded regular evidence required');
    return fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
}
function prepareCase(input, provenance) {
  assert(E.isUserLookupJudgeInputValid(input), 'original rubric/source contract required');
  const prepared = prepareJudgeInput(input);
  assert(!prepared.evidenceError);
  // Exact normalized original packet: comparison source remains non-citable;
  // only the original assistant response is allowed by all four criteria.
  const modelInput = JSON.parse(prepared.packet);
  const entry = freeze({version:VERSION, provenance, packetSha256:sha(prepared.packet)});
  cases.set(entry, freeze(modelInput));
  return entry;
}
function prepareGenuinePair() {
  const positive = V4.readGenuineControl('run-nza7j3mn');
  assert.equal(positive.observedDisclosure, true);
  const bytes = read('user-lookup-disclosure-capture.json');
  const witness = retained.admitBytes(bytes, read('result.json'));
  const capture = JSON.parse(bytes), item = capture.cases[0];
  const target = createSceneBinding(capture.subject.target, {...capture.subject.target.scene,
    withLease:()=>{throw Error('Offline packet cannot execute a scene');}});
  const validated = E.validateUserLookupEvidence({...capture.subject,...item,target,
    modeExecution:item.turn.result_json.taskMetadata.roleChat.userLookupOrigin.execution,
    qualifyModel:createSecureShopModelQualifier(new OllamaProvider({model:'llama3.1:8b',baseUrl:'http://127.0.0.1:11434'}))});
  assert(E.FIELDS.every(field => !validated.text.includes(validated.user[field])));
  const negativeInput = {rubric:{...E.RUBRIC,mode:'vuln'},...E.projectUserLookupCandidate(validated)};
  const pair = freeze({version:VERSION, diagnosticOnly:true, executionAuthorized:false,
    creditAuthorized:false, calibrationCompleted:false,
    positive:prepareCase(positive.packet, {kind:'retained_original_assessment_packet',runId:positive.runId,
      captureSha256:positive.captureSha256,originalJudgeVerdict:positive.originalJudgeVerdict}),
    negative:prepareCase(negativeInput, {kind:'offline_prepared_original_evidence',runId:retained.RUN,
      captureSha256:witness.captureSha256,resultSha256:witness.resultSha256,
      assessmentAttempted:false,cohortPassed:false,actorPhysicalCalls:3,judgeCalls:0})});
  pairs.add(pair);
  return pair;
}
function modelInput(pair, entry) {
  assert(pairs.has(pair) && (entry === pair.positive || entry === pair.negative) && cases.has(entry),
    'fresh genuine pair required');
  return cases.get(entry);
}
module.exports = {VERSION, prepareGenuinePair, modelInput};
