const MESSAGES = Object.freeze({
  INVALID_JUDGE_OUTPUT: 'The Judge response failed validation. No completion was awarded. Retry saved evidence only when available; otherwise ask the workshop administrator to check the Judge diagnostics.',
  SEMANTIC_COVERAGE_UNAVAILABLE: 'The Judge could not establish complete evidence coverage. No completion was awarded; retrying the same assessment is not available.',
  SEMANTIC_EFFECT_UNAVAILABLE: 'The required action needs verified effect evidence that this assessment does not contain. Response text alone cannot establish completion.',
  JUDGE_QUEUE_FULL: 'The evaluation queue is full. Retry when capacity is available.',
  JUDGE_TIMEOUT: 'Evaluation timed out. You can retry the saved evidence when retry is available.',
  JUDGE_TRANSPORT: 'The Judge provider connection failed. Check the provider, then retry when available.',
  JUDGE_STORAGE_SCHEMA: 'Evaluation storage needs updating. Check the application database migrations.',
  JUDGE_STORAGE_CONSTRAINT: 'Evaluation storage rejected a record. Ask the workshop administrator to check the application logs.',
  JUDGE_STORAGE_PERMISSION: 'Evaluation storage permissions need attention. Check the application database configuration.',
});
export function judgeFailureMessage(code) {
  return typeof code === 'string' && Object.hasOwn(MESSAGES, code) ? MESSAGES[code] : null;
}

const VALIDATION_MESSAGES = Object.freeze({
  JSON_SYNTAX: 'Judge response was not valid JSON',
  SCHEMA_SHAPE_OR_TYPE: 'Judge response did not match the required format',
  EXACT_FACT_CONTRADICTION: 'Judge criterion contradicted verified evidence',
  CRITERION_EVIDENCE_INVALID: 'Judge criteria or evidence references were invalid',
  CITATION_NOT_GROUNDED: 'Judge citation did not match the source evidence',
  CITATION_REQUIRED: 'Judge omitted a required supporting citation',
  OBSERVABLE_SOURCE_REQUIRED: 'Judge cited an unsupported evidence source',
  VERDICT_INCONSISTENT: 'Judge verdict conflicted with its criteria',
  REQUIRED_FACT_CONTRADICTION: 'Judge pass lacked required verified evidence',
  VALIDATION_REJECTED: 'Judge response failed validation',
});
export function judgeValidationMessage(code) {
  return typeof code === 'string' && Object.hasOwn(VALIDATION_MESSAGES, code) ? VALIDATION_MESSAGES[code] : null;
}

export function judgeStageLabel(version, stage) {
  if (['dpi-answer-comparison-v15', 'dpi-answer-comparison-v16', 'dpi-answer-comparison-v17', 'dpi-answer-comparison-v18', 'dpi-answer-comparison-v19', 'dpi-answer-comparison-v20', 'dpi-answer-comparison-v21', 'dpi-answer-comparison-v22'].includes(version)) {
    return stage === 'selected' ? 'Task and response assessment' : 'Unknown stage';
  }
  if (version === 'dpi-answer-comparison-v14') {
    return ({ source: 'Requested tasks', verify: 'Response assessment' })[stage] || 'Unknown stage';
  }
  if (version === 'pricing-semantic-decomposition-v6') {
    return ({ source: 'Source inventory', effect: 'Source coverage and fulfillment class', relation: 'Task relation', support: 'Response assessment' })[stage] || 'Unknown stage';
  }
  if (version === 'pricing-semantic-decomposition-v5') {
    return ({ source: 'Source inventory', effect: 'Source coverage', support: 'Task relation and response assessment' })[stage] || 'Unknown stage';
  }
  const semantic = ['pricing-semantic-decomposition-v4', 'rag-semantic-decomposition-v3', 'rag-semantic-decomposition-v4'].includes(version);
  return (semantic
    ? { source: 'Source inventory', effect: 'Source coverage and task relation', support: 'Response assessment' }
    : { source: 'Source classification', effect: 'Response effect', support: 'Independent support' })[stage] || 'Unknown stage';
}
