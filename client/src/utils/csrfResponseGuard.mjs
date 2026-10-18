export function createCsrfResponseGuard(identity) {
  let generation = 0;
  return {
    invalidate() { generation += 1; },
    capture() {
      const captured = generation;
      const owner = identity();
      return () => captured === generation && owner === identity();
    },
  };
}

export function csrfJudgeFeedback(judgments = []) {
  const messages = {
    fail: 'Judge: the observed result did not meet this objective. Review the outcome and try again.',
    inconclusive: 'Judge: the available evidence was insufficient. No new completion was awarded.',
    unavailable: 'Judge unavailable. Your action may have succeeded, but no new completion was awarded. Retry grading when the model is available.',
  };
  return [...new Set(judgments.map(item => messages[item?.verdict]).filter(Boolean))];
}
