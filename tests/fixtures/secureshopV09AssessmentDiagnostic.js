'use strict';

const SHA = /^[a-f0-9]{64}$/;
const DEFAULT_MAX_RECORDS = 12;
const clean = (value, limit) => typeof value === 'string' ? value.slice(0, limit) : '';
function describeError(error) {
  const chain = [];
  for (let current = error, depth = 0; current && depth < 3; current = current.cause, depth += 1) {
    chain.push(Object.freeze({
      name: clean(current.name, 80),
      code: clean(current.code, 80) || null,
      message: clean(current.message, 240),
    }));
  }
  return Object.freeze(chain);
}
function resultShape(value) {
  if (!value || typeof value !== 'object') return Object.freeze({ type: typeof value });
  return Object.freeze({
    completed: value.completed === true,
    replayed: value.replayed === true,
    status: typeof value.status === 'string' ? value.status.slice(0, 80) : null,
    verdict: typeof value.judgment?.verdict === 'string' ? value.judgment.verdict.slice(0, 40) : null,
  });
}
function installV09AssessmentDiagnostic({ record, modules, prepareJudgeInput, maximumRecords = DEFAULT_MAX_RECORDS } = {}) {
  if (typeof record !== 'function' || !Number.isSafeInteger(maximumRecords)
      || maximumRecords < 1 || maximumRecords > 32) {
    throw new TypeError('Bounded V09 assessment diagnostic required');
  }
  const evidencePath = require.resolve('../../server/services/secureshopMailHtmlInjectionEvidence');
  const assessmentPath = require.resolve('../../server/services/secureshopMailHtmlInjectionAssessment');
  const injected = modules !== undefined;
  if (injected && (!modules?.evidence || !modules?.assessment)) {
    throw new TypeError('Complete V09 diagnostic modules required');
  }
  if (!injected && require.cache[assessmentPath]) {
    throw new Error('V09 assessment diagnostic must be installed before assessment composition');
  }
  const evidence = modules?.evidence || require(evidencePath);
  const originalBuilder = evidence.buildMailHtmlInjectionCandidate;
  if (typeof originalBuilder !== 'function') throw new TypeError('V09 evidence builder required');
  const prepare = prepareJudgeInput || require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput;
  let count = 0;
  const observe = value => {
    if (count >= maximumRecords) return;
    count += 1;
    try { record(structuredClone(value)); } catch (_) { /* diagnostics cannot change assessment behavior */ }
  };
  evidence.buildMailHtmlInjectionCandidate = input => {
    const candidate = originalBuilder(input);
    if (!candidate) {
      observe(Object.freeze({ version: 1, phase: 'candidate', present: false }));
      return candidate;
    }
    try {
      const prepared = prepare({
        rubric: { ...evidence.MAIL_HTML_INJECTION_RUBRIC, mode: 'vuln' },
        ...candidate,
      });
      observe(Object.freeze({
        version: 1,
        phase: 'candidate',
        present: true,
        packetBytes: typeof prepared?.packet === 'string' ? Buffer.byteLength(prepared.packet) : null,
        evidenceDigest: SHA.test(prepared?.evidenceDigest || '') ? prepared.evidenceDigest : null,
        evidenceError: prepared?.evidenceError ? describeError(prepared.evidenceError) : [],
      }));
    } catch (error) {
      observe(Object.freeze({ version: 1, phase: 'candidate_prepare_threw', error: describeError(error) }));
    }
    return candidate;
  };

  let assessment;
  try {
    assessment = modules?.assessment || require(assessmentPath);
  } catch (error) {
    evidence.buildMailHtmlInjectionCandidate = originalBuilder;
    throw error;
  }
  const originalFactory = assessment.createMailHtmlInjectionAssessment;
  if (typeof originalFactory !== 'function') {
    evidence.buildMailHtmlInjectionCandidate = originalBuilder;
    throw new TypeError('V09 assessment factory required');
  }
  assessment.createMailHtmlInjectionAssessment = options => {
    const service = originalFactory(options);
    const originalRunAttempt = service?.runAttempt;
    if (typeof originalRunAttempt !== 'function') throw new TypeError('V09 assessment service required');
    return Object.freeze({
      ...service,
      async runAttempt(input) {
        observe(Object.freeze({ version: 1, phase: 'run_attempt_entered' }));
        try {
          const value = await originalRunAttempt(input);
          observe(Object.freeze({ version: 1, phase: 'run_attempt_returned', result: resultShape(value) }));
          return value;
        } catch (error) {
          observe(Object.freeze({ version: 1, phase: 'run_attempt_threw', error: describeError(error) }));
          throw error;
        }
      },
    });
  };

  let restored = false;
  return () => {
    if (restored) return;
    restored = true;
    assessment.createMailHtmlInjectionAssessment = originalFactory;
    evidence.buildMailHtmlInjectionCandidate = originalBuilder;
    if (!injected && require.cache[assessmentPath]?.exports === assessment) delete require.cache[assessmentPath];
  };
}

module.exports = { describeError, installV09AssessmentDiagnostic };
