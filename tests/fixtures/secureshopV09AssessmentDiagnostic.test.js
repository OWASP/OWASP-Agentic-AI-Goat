'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { installV09AssessmentDiagnostic, describeError } = require('./secureshopV09AssessmentDiagnostic');

test('V09 assessment diagnostic records bounded packet metadata and restores factories', async () => {
  const secret = 'raw-private-evidence-must-not-be-recorded';
  const candidate = { evidence: [{ content: secret }], facts: { observed: true } };
  const originalBuilder = () => candidate;
  const thrown = Object.assign(new Error('outer private detail'), {
    code: 'OUTER_CODE',
    cause: Object.assign(new Error('inner private detail'), { code: 'INNER_CODE' }),
  });
  const originalFactory = () => Object.freeze({
    readOutcome: async () => ({ completed: false }),
    runAttempt: async () => { throw thrown; },
  });
  const evidence = {
    MAIL_HTML_INJECTION_RUBRIC: { objectiveId: 'controlled-v09' },
    buildMailHtmlInjectionCandidate: originalBuilder,
  };
  const assessment = { createMailHtmlInjectionAssessment: originalFactory };
  const records = [];
  const restore = installV09AssessmentDiagnostic({
    modules: { evidence, assessment },
    record: value => records.push(value),
    prepareJudgeInput: () => ({
      packet: secret,
      evidenceDigest: 'a'.repeat(64),
      evidenceError: Object.assign(new Error('packet too large'), { code: 'EVIDENCE_SIZE_LIMIT' }),
    }),
  });
  assert.equal(evidence.buildMailHtmlInjectionCandidate({}), candidate);
  const service = assessment.createMailHtmlInjectionAssessment({});
  await assert.rejects(service.runAttempt({ private: secret }), error => error === thrown);
  assert.deepEqual(records.map(value => value.phase),
    ['candidate', 'run_attempt_entered', 'run_attempt_threw']);
  assert.equal(records[0].packetBytes, Buffer.byteLength(secret));
  assert.equal(records[0].evidenceDigest, 'a'.repeat(64));
  assert.deepEqual(records[0].evidenceError,
    [{ name: 'Error', code: 'EVIDENCE_SIZE_LIMIT', message: 'packet too large' }]);
  assert.deepEqual(records[2].error, [
    { name: 'Error', code: 'OUTER_CODE', message: 'outer private detail' },
    { name: 'Error', code: 'INNER_CODE', message: 'inner private detail' },
  ]);
  assert.equal(JSON.stringify(records).includes(secret), false);
  restore();
  restore();
  assert.equal(evidence.buildMailHtmlInjectionCandidate, originalBuilder);
  assert.equal(assessment.createMailHtmlInjectionAssessment, originalFactory);
});

test('V09 diagnostics cannot alter a successful assessment when recording fails', async () => {
  const candidate = { evidence: [], facts: {} };
  const originalBuilder = () => candidate;
  const outcome = Object.freeze({ completed: false, status: 'ineligible', modelEvaluated: false });
  const originalFactory = () => Object.freeze({ runAttempt: async () => outcome });
  const evidence = {
    MAIL_HTML_INJECTION_RUBRIC: { objectiveId: 'controlled-v09' },
    buildMailHtmlInjectionCandidate: originalBuilder,
  };
  const assessment = { createMailHtmlInjectionAssessment: originalFactory };
  const restore = installV09AssessmentDiagnostic({
    modules: { evidence, assessment },
    record: () => { throw new Error('diagnostic sink unavailable'); },
    prepareJudgeInput: () => ({ packet: '{}', evidenceDigest: 'b'.repeat(64) }),
  });
  assert.equal(evidence.buildMailHtmlInjectionCandidate({}), candidate);
  assert.equal(await assessment.createMailHtmlInjectionAssessment({}).runAttempt({}), outcome);
  restore();
});

test('V09 error descriptions are depth and field bounded', () => {
  const fourth = Object.assign(new Error('fourth'), { code: 'FOURTH' });
  const third = Object.assign(new Error('x'.repeat(400)), { code: 'C'.repeat(100), cause: fourth });
  const second = Object.assign(new Error('second'), { code: 'SECOND', cause: third });
  const first = Object.assign(new Error('first'), { code: 'FIRST', cause: second });
  const value = describeError(first);
  assert.equal(value.length, 3);
  assert.equal(value[2].message.length, 240);
  assert.equal(value[2].code.length, 80);
  assert.equal(JSON.stringify(value).includes('fourth'), false);
});
