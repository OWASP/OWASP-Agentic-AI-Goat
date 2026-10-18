import { judgeFailureMessage } from './judgeFailureMessage.mjs';
const NON_PASS = new Set(['fail', 'inconclusive', 'unavailable']);

export function isGradingUnqualified(payload = {}) {
  return [payload.judgment, ...(Array.isArray(payload.judgments) ? payload.judgments : [])]
    .some(value => value?.gradingStatus === 'pending' && value?.gradingDisposition === 'grading_unqualified');
}

export function getJudgeFeedback(payload = {}) {
  const input = [
    ...(Array.isArray(payload.judgments) ? payload.judgments : []),
    ...(payload.judgment ? [payload.judgment] : []),
  ];
  const seen = new Set();
  return input.flatMap((judgment) => {
    const pending = judgment?.gradingDisposition === 'grading_unqualified' && judgment?.gradingStatus === 'pending';
    const verdict = pending ? 'pending' : String(judgment?.verdict || '').toLowerCase();
    if (!pending && !NON_PASS.has(verdict)) return [];
    const suppliedExplanation = typeof judgment.explanation === 'string' ? judgment.explanation.trim() : '';
    // Preserve the specific failed validation stage; replace only the old generic retry promise.
    const preserveValidationDetail = judgment.errorCode === 'INVALID_JUDGE_OUTPUT' && suppliedExplanation
      && suppliedExplanation !== 'The judge returned invalid results; please retry.';
    const diagnostic = verdict === 'unavailable' && !preserveValidationDetail ? judgeFailureMessage(judgment.errorCode) : null;
    const explanation = (pending ? 'Objective grading is not qualified for reliable credit. Your response and raw evaluation are retained; no completion was awarded.' : null) || diagnostic || (typeof judgment.explanation === 'string' && judgment.explanation.trim()
      ? judgment.explanation.trim()
      : 'No completion was awarded for this attempt.');
    const objectiveId = typeof judgment.objectiveId === 'string' ? judgment.objectiveId : null;
    const key = `${objectiveId || ''}\0${verdict}\0${explanation}`;
    if (seen.has(key)) return [];
    seen.add(key);
    const evaluationId = typeof judgment.evaluationId === 'string' && judgment.evaluationId
      ? judgment.evaluationId
      : null;
    return [{ verdict, objectiveId, evaluationId,
      canRetry: verdict === 'unavailable' && judgment.canRetry === true && Boolean(evaluationId),
      content: `Judge ${verdict}: ${explanation}` }];
  });
}
