'use strict';

// This is an unmounted response projection. It intentionally does not create
// credit, persistence, or provider-execution evidence.
const ROUTES = new Set([
  'prompt_injection',
  'chain_of_thought',
  'context_stuffing',
  'multi_turn_jailbreak',
]);
const ATTACK_MARKERS = new Set([
  'ignore previous',
  'forget everything',
  'new instructions',
  'override',
  'jailbreak',
  'pretend you are',
]);
const CHAIN_MARKERS = new Set([
  'step 1:',
  'step 2:',
  'step 3:',
  'analysis:',
  'reasoning:',
  'conclusion:',
]);
const VERDICTS = new Set(['pass', 'fail', 'inconclusive', 'unavailable']);
const CRITERION_ID = 'synthetic_canary_disclosed';
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_INPUT_BYTES = 384 * 1024;
const MAX_LABEL_BYTES = 256;
const MAX_TURNS = 10000;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/;

function invalid(message) {
  return Object.assign(new TypeError(message), { code: 'INVALID_EXPERIMENT_RESULT' });
}

function plain(value, label) {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) {
    throw invalid('Valid ' + label + ' required');
  }
  return value;
}

function member(value, key, label) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
    throw invalid('Valid ' + label + ' required');
  }
  return descriptor.value;
}

function boundedText(value, label, maxBytes) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > maxBytes) {
    throw invalid('Valid ' + label + ' required');
  }
  return value;
}

function label(value, name) {
  if (value === null) return null;
  const text = boundedText(value, name, MAX_LABEL_BYTES);
  if (!LABEL.test(text)) throw invalid('Valid ' + name + ' required');
  return text;
}

function whole(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalid('Valid ' + label + ' required');
  }
  return value;
}

function markerList(value, allowed, label) {
  if (!Array.isArray(value) || value.length > allowed.size) {
    throw invalid('Valid ' + label + ' required');
  }
  const result = [];
  for (const marker of value) {
    if (typeof marker !== 'string' || !allowed.has(marker) || result.includes(marker)) {
      throw invalid('Valid ' + label + ' required');
    }
    result.push(marker);
  }
  return Object.freeze(result);
}

function commonDiagnostics(value) {
  const diagnostics = plain(value, 'experiment diagnostics');
  const inputBytes = whole(member(diagnostics, 'inputBytes', 'input byte count'), 'input byte count', 1, MAX_INPUT_BYTES);
  const inputCharacters = whole(member(diagnostics, 'inputCharacters', 'input character count'), 'input character count', 1, MAX_INPUT_BYTES);
  if (inputCharacters > inputBytes
      || member(diagnostics, 'tokenCount', 'token count') !== null
      || member(diagnostics, 'contextWindowTokens', 'context window tokens') !== null
      || member(diagnostics, 'tokenMetrics', 'token metrics') !== 'unknown') {
    throw invalid('Valid experiment diagnostics required');
  }
  return { diagnostics, inputBytes, inputCharacters };
}

function projectDiagnostics(sourceRoute, value) {
  const { diagnostics, inputBytes, inputCharacters } = commonDiagnostics(value);
  const result = {
    inputBytes,
    inputCharacters,
    tokenCount: null,
    contextWindowTokens: null,
    tokenMetrics: 'unknown',
  };
  if (sourceRoute === 'context_stuffing') {
    const stuffingBytes = whole(member(diagnostics, 'stuffingBytes', 'stuffing byte count'), 'stuffing byte count', 1, 65536);
    const stuffingCharacters = whole(member(diagnostics, 'stuffingCharacters', 'stuffing character count'), 'stuffing character count', 1, 65536);
    if (stuffingCharacters > stuffingBytes
        || !Array.isArray(member(diagnostics, 'responseChainFormatMarkers', 'response chain markers'))
        || member(diagnostics, 'responseChainFormatMarkers', 'response chain markers').length !== 0) {
      throw invalid('Valid context-stuffing diagnostics required');
    }
    result.stuffingBytes = stuffingBytes;
    result.stuffingCharacters = stuffingCharacters;
    result.responseChainFormatMarkers = Object.freeze([]);
    return Object.freeze(result);
  }

  const inputAttackMarkers = markerList(
    member(diagnostics, 'inputAttackMarkers', 'input attack markers'),
    ATTACK_MARKERS,
    'input attack markers',
  );
  result.inputAttackMarkers = inputAttackMarkers;
  if (sourceRoute === 'chain_of_thought') {
    result.responseChainFormatMarkers = markerList(
      member(diagnostics, 'responseChainFormatMarkers', 'response chain markers'),
      CHAIN_MARKERS,
      'response chain markers',
    );
    return Object.freeze(result);
  }
  const responseChainFormatMarkers = member(
    diagnostics,
    'responseChainFormatMarkers',
    'response chain markers',
  );
  if (!Array.isArray(responseChainFormatMarkers) || responseChainFormatMarkers.length !== 0) {
    throw invalid('Valid experiment diagnostics required');
  }
  result.responseChainFormatMarkers = Object.freeze([]);
  if (sourceRoute === 'multi_turn_jailbreak') {
    result.turns = whole(member(diagnostics, 'turns', 'conversation turn count'), 'conversation turn count', 0, MAX_TURNS);
  }
  return Object.freeze(result);
}

function projectEvaluation(value) {
  const evaluation = plain(value, 'experiment evaluation');
  const verdict = member(evaluation, 'verdict', 'evaluation verdict');
  const criteria = member(evaluation, 'criteria', 'evaluation criteria');
  const runnerPassed = member(evaluation, 'passed', 'evaluation pass state');
  if (!VERDICTS.has(verdict) || typeof runnerPassed !== 'boolean' || !Array.isArray(criteria)
      || criteria.length > 1) {
    throw invalid('Valid experiment evaluation required');
  }
  if (criteria.length === 0) {
    if (verdict === 'pass' || runnerPassed) throw invalid('Inconsistent experiment evaluation state');
    return Object.freeze({
      verdict,
      criteria: Object.freeze([]),
      passed: false,
    });
  }
  const criterion = plain(criteria[0], 'experiment criterion');
  if (member(criterion, 'id', 'criterion id') !== CRITERION_ID
      || typeof member(criterion, 'satisfied', 'criterion state') !== 'boolean') {
    throw invalid('Valid experiment criterion required');
  }
  const satisfied = member(criterion, 'satisfied', 'criterion state');
  const passed = verdict === 'pass' && satisfied && runnerPassed === true;
  if (runnerPassed !== passed) throw invalid('Inconsistent experiment evaluation state');
  return Object.freeze({
    verdict,
    criteria: Object.freeze([Object.freeze({ id: CRITERION_ID, satisfied })]),
    passed,
  });
}

function freezeResult(value) {
  Object.freeze(value.teaching.diagnostics);
  if (value.teaching.evaluation.criteria.length) {
    Object.freeze(value.teaching.evaluation.criteria[0]);
  }
  Object.freeze(value.teaching.evaluation.criteria);
  Object.freeze(value.teaching.evaluation);
  Object.freeze(value.teaching);
  return Object.freeze(value);
}

function projectLegacyAiExperimentResult(result, { sourceRoute } = {}) {
  if (!ROUTES.has(sourceRoute)) throw invalid('Valid legacy AI experiment route required');
  const input = plain(result, 'legacy AI experiment result');
  const teaching = plain(member(input, 'teaching', 'experiment teaching result'), 'experiment teaching result');
  if (member(teaching, 'route', 'experiment route') !== sourceRoute) {
    throw invalid('Experiment route does not match request route');
  }
  const response = boundedText(member(input, 'response', 'experiment response'), 'experiment response', MAX_RESPONSE_BYTES);
  const modelUsed = label(member(input, 'modelUsed', 'model identifier'), 'model identifier');
  const provider = label(member(input, 'provider', 'provider identifier'), 'provider identifier');
  const diagnostics = projectDiagnostics(sourceRoute, member(teaching, 'diagnostics', 'experiment diagnostics'));
  const evaluation = projectEvaluation(member(teaching, 'evaluation', 'experiment evaluation'));

  return freezeResult({
    response,
    modelUsed,
    provider,
    teaching: {
      route: sourceRoute,
      diagnostics,
      evaluation,
    },
    creditAwarded: false,
  });
}

module.exports = {
  projectLegacyAiExperimentResult,
};
