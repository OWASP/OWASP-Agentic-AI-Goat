'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const D = require('./fixtures/secureshopPolicyV27GenuinePairDiagnostic');
const sha = value => createHash('sha256').update(value).digest('hex');

if (process.env.V27_RETAINED_PAIR_DIAGNOSTIC !== undefined &&
    process.env.V27_RETAINED_PAIR_DIAGNOSTIC !== '1')
  throw Error('V27 retained pair diagnostic must be explicitly selected');
const retained = process.env.V27_RETAINED_PAIR_DIAGNOSTIC === '1' ? test : test.skip;

test('portable admission remains offline and unmounted', () => {
  assert.equal(D.VERSION, 'secureshop-policy-v27-genuine-adoption-pair-v1');
  assert.equal(D.CAPTURE_SHA256.length, 64);
  assert.equal(D.CASES.baseline.responseSha256.length, 64);
  assert.notEqual(D.CASES.baseline.responseSha256, D.CASES.attack.responseSha256);
  const source = fs.readFileSync(require.resolve('./fixtures/secureshopPolicyV27GenuinePairDiagnostic'), 'utf8');
  assert(!source.includes("require('../../server/"));
  assert(!source.includes('createObjectiveJudge'));
  assert(!source.includes('createLangChainProvider'));
  assert.throws(() => D.inspectUnpinnedForControlledTest({}), /AssertionError/);
});

retained('requested genuine clean/attack originals retain exact source, actor, tool and effect lineage', () => {
  const pair = D.readGenuinePair();
  const formatted = D.formatGenuineAdoptionPair(pair);
  assert.equal(pair.captureSha256, sha(fs.readFileSync(D.CAPTURE)));
  assert.equal(formatted.baseline.expectedAdoption, false);
  assert.equal(formatted.attack.expectedAdoption, true);
  assert.equal(formatted.originals.baseline.originalFinalResponse, pair.baseline.originalFinalResponse);
  assert.equal(formatted.originals.attack.originalPolicyBody, pair.attack.originalPolicyBody);
  assert.equal(formatted.originalCriterion.id, 'policy_instruction_adopted');
  assert.equal(formatted.originalRubricVersion, 'secureshop-policy-final-html-v1');
  assert.equal(formatted.browserNegativeEstablished, false);
  assert.equal(formatted.canonicalQualificationEstablished, false);
  assert.equal(formatted.semanticJudgeResult, null);
  assert.equal(formatted.noModelCallPerformed, true);
  assert.equal(formatted.creditAuthorized, false);
  assert.equal(pair.originalAttackJudgment.verdict, 'fail');
  assert.equal(pair.baseline.originalActorWire.length, 2);
  assert.equal(pair.attack.originalActorWire.length, 2);
});

retained('requested retained parser rejects substituted source, response, actor, tool, effect and packet', () => {
  const original = JSON.parse(fs.readFileSync(D.CAPTURE));
  const mutations = [
    value => { value.cases[0].original.proof.request.policyHtml += ' altered'; },
    value => { value.cases[0].original.html += ' altered'; },
    value => { value.cases[0].original.proof.turn.result_json.text += ' altered'; },
    value => { value.cases[0].original.proof.traces[4].params_json = '{}'; },
    value => { value.cases[0].original.proof.traces[5].result_json = '{}'; },
    value => { value.cases[0].original.proof.effect.status = 'pending'; },
    value => { value.cases[0].original.proof.run.run_id = 'other'; },
    value => { value.wire[0].response += ' altered'; },
    value => { value.wire[1].request += ' altered'; },
    value => { value.transcripts[0].header.packet = '{}'; },
    value => { value.cases[1].original.html = value.cases[0].original.html; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(original);
    mutate(value);
    assert.throws(() => D.inspectUnpinnedForControlledTest(value));
  }
  const pair = D.readGenuinePair();
  const relabeled = structuredClone(pair);
  relabeled.baseline.originalFinalResponse = pair.attack.originalFinalResponse;
  assert.throws(() => D.formatGenuineAdoptionPair(relabeled));
});
