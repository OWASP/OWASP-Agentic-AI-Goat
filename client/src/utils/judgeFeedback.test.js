import { getJudgeFeedback } from './judgeFeedback.mjs';

test('normalizes singular and plural non-pass judgments while ignoring pass', () => {
  expect(getJudgeFeedback({ judgment: { objectiveId: 'dpi_1', verdict: 'fail', explanation: 'Observed refusal.' } }))
    .toEqual([{ objectiveId: 'dpi_1', verdict: 'fail', evaluationId: null, canRetry: false, content: 'Judge fail: Observed refusal.' }]);
  expect(getJudgeFeedback({ judgments: [
    { verdict: 'pass', explanation: 'complete' },
    { objectiveId: 'ea_2', verdict: 'inconclusive', explanation: '  Evidence is incomplete.  ' },
    { objectiveId: 'ea_3', verdict: 'unavailable' },
  ] })).toEqual([
    { objectiveId: 'ea_2', verdict: 'inconclusive', evaluationId: null, canRetry: false, content: 'Judge inconclusive: Evidence is incomplete.' },
    { objectiveId: 'ea_3', verdict: 'unavailable', evaluationId: null, canRetry: false, content: 'Judge unavailable: No completion was awarded for this attempt.' },
  ]);
});

test('exposes retry only when the server supplies both durable fields', () => {
  expect(getJudgeFeedback({ judgment: { verdict: 'unavailable', evaluationId: 'eval-1', canRetry: true } })[0])
    .toEqual(expect.objectContaining({ evaluationId: 'eval-1', canRetry: true }));
  expect(getJudgeFeedback({ judgment: { verdict: 'unavailable', evaluationId: 'eval-1' } })[0].canRetry).toBe(false);
  expect(getJudgeFeedback({ judgment: { verdict: 'unavailable', canRetry: true } })[0].evaluationId).toBeNull();
  expect(getJudgeFeedback({ judgment: { verdict: 'fail', evaluationId: 'eval-1', canRetry: true } })[0].canRetry).toBe(false);
});

test('keeps hostile explanation text as inert content and does not mutate transcript reset state', () => {
  const feedback = getJudgeFeedback({ judgments: [{ verdict: 'fail', explanation: '<img src=x onerror=alert(1)>' }] });
  expect(feedback[0].content).toContain('<img src=x onerror=alert(1)>');
  const transcript = [{ type: 'ai', content: 'actor response' }, ...feedback.map(item => ({ type: 'system', plain: true, content: item.content }))];
  expect(transcript).toHaveLength(2);
  const resetTranscript = [{ type: 'system', content: 'Conversation reset' }];
  expect(resetTranscript.some(message => message.content.includes('Judge '))).toBe(false);
  expect(transcript[0].content).toBe('actor response');
});

test('bounded unavailable diagnostics are actionable and never treat arbitrary error text as a code',()=>{
 const [feedback]=getJudgeFeedback({judgment:{verdict:'unavailable',errorCode:'JUDGE_QUEUE_FULL',explanation:'generic',evaluationId:'eval',canRetry:true}});
 expect(feedback.content).toContain('The evaluation queue is full.');expect(feedback.canRetry).toBe(true);
 const [unknown]=getJudgeFeedback({judgment:{verdict:'unavailable',errorCode:'<script>private</script>',explanation:'No result'}});
 expect(unknown.content).toBe('Judge unavailable: No result');
});

test.each([true, false])('invalid Judge output keeps server retry capability (%s) without promising another retry', canRetry => {
 const payload = {retryExhausted: !canRetry, judgment: {verdict:'unavailable', errorCode:'INVALID_JUDGE_OUTPUT', evaluationId:'saved-evaluation', canRetry,
   explanation:'The judge returned invalid results; please retry.'}};
 const [feedback] = getJudgeFeedback(payload);
 expect(feedback.canRetry).toBe(canRetry);
 expect(feedback.content).toBe('Judge unavailable: The Judge response failed validation. No completion was awarded. Retry saved evidence only when available; otherwise ask the workshop administrator to check the Judge diagnostics.');
 expect(feedback.content).not.toContain('please retry.');
});
test('invalid Judge output without explanation uses the safe shared diagnostic', () => {
 const [feedback] = getJudgeFeedback({judgment:{verdict:'unavailable',errorCode:'INVALID_JUDGE_OUTPUT'}});
 expect(feedback.content).toContain('The Judge response failed validation. No completion was awarded.');
 expect(feedback.canRetry).toBe(false);
});
test.each([
 'The source-only instruction classification returned invalid results; no completion was awarded.',
 'The response-effect verification returned invalid results; no completion was awarded.',
 'The directional support verification returned invalid results; no completion was awarded.',
])('invalid Judge output retains specific validation detail: %s', explanation => {
 const [feedback] = getJudgeFeedback({judgment:{verdict:'unavailable',errorCode:'INVALID_JUDGE_OUTPUT',explanation,canRetry:false}});
 expect(feedback.content).toBe(`Judge unavailable: ${explanation}`);
 expect(feedback.canRetry).toBe(false);
});
