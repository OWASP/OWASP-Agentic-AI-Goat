'use strict';

// Test orchestration only: the injected agent, execution.check and authenticated
// reset perform all real work. No model output, tool effect or reset is invented.
async function qualifySqlNoSqlResetBeforeJudge({ agent, owner, message, reset, grade,
  mode = 'vuln', deadlineMs = 5000, onStart } = {}) {
  if (typeof agent?.invoke !== 'function' || typeof reset !== 'function' || typeof grade !== 'function'
      || (onStart !== undefined && typeof onStart !== 'function') || typeof message !== 'string' || !Number.isSafeInteger(deadlineMs) || deadlineMs <= 0 || deadlineMs > 600000) {
    throw new TypeError('Explicit agent, message, reset, grade and bounded deadline required');
  }
  const controller = new AbortController();
  let resolveReached, rejectReached;
  const reached = new Promise((resolve, reject) => { resolveReached = resolve; rejectReached = reject; });
  // A pre-callback actor rejection must not leave an unhandled latch rejection.
  reached.catch(() => {});
  let execution, dto, invocation, observed = false, gradeCalls = 0;
  let removeAbortListener = () => {};
  let rejectAbortWait = () => {};
  let timer;
  let stopping = false;
  const failure = (code, cause) => Object.assign(new Error(code, cause ? { cause } : undefined), { code });
  const hooks = {
    signal: controller.signal,
    includeRunMetadata: true,
    async onStart(actualExecution) { execution = actualExecution; await onStart?.(actualExecution); },
    async onResult(actualDto, check, actualExecution, actualInvocation) {
      if (observed) throw failure('RESET_QUALIFICATION_DUPLICATE_OBSERVATION');
      observed = true; dto = actualDto; invocation = actualInvocation;
      execution = actualExecution || execution;
      if (typeof execution?.signal?.addEventListener !== 'function' || typeof check !== 'function') {
        throw failure('RESET_QUALIFICATION_EXECUTION_REQUIRED');
      }
      const aborted = new Promise((resolve, reject) => {
        rejectAbortWait = reject;
        const onAbort = () => resolve();
        execution.signal.addEventListener('abort', onAbort, { once: true });
        removeAbortListener = () => execution.signal.removeEventListener('abort', onAbort);
        if (execution.signal.aborted) resolve();
      });
      resolveReached();
      await aborted;
      removeAbortListener();
      if (stopping) throw failure('RESET_QUALIFICATION_STOPPED');
      // Only the actual runtime check can fence grading. If it incorrectly
      // returns, invoke the supplied grader and report that invocation honestly.
      await check();
      if (stopping) throw failure('RESET_QUALIFICATION_STOPPED');
      gradeCalls++;
      return grade({ dto, invocation, execution });
    },
  };
  const actorOutcome = Promise.resolve().then(() => agent.invoke(String(owner), message, mode, hooks)).then(
    value => { if (!observed) rejectReached(failure('RESET_QUALIFICATION_NO_OBSERVATION')); return { value, error: null }; },
    error => { if (!observed) rejectReached(failure('RESET_QUALIFICATION_ACTOR_FAILED', error)); return { value: undefined, error }; },
  );
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(failure('RESET_QUALIFICATION_TIMEOUT')), deadlineMs);
  });
  try {
    const work = (async () => {
      // Actor may fail inside onResult before resolving reached; detect it too.
      await Promise.race([reached, actorOutcome.then(outcome => {
        throw failure('RESET_QUALIFICATION_ACTOR_ENDED_BEFORE_RESET', outcome.error);
      })]);
      let resetOutcome;
      const resetPromise = Promise.resolve().then(() => reset({ signal: controller.signal, dto, invocation, execution })).then(
        result => { resetOutcome = result; return result; },
        error => { throw failure('RESET_QUALIFICATION_RESET_FAILED', error); },
      );
      // Neither side waits on the other before it starts. Real reset can wait
      // for the actor to finish after aborting its execution boundary.
      const [actor] = await Promise.all([actorOutcome, resetPromise]);
      return { dto, invocation, execution, runId: execution?.runId ?? null,
        resetResult: resetOutcome, gradeCalls, actorResult: actor.value, actorError: actor.error,
        cancelled: execution.signal.aborted && actor.error?.name === 'AbortError' && gradeCalls === 0 };
    })();
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
    stopping = true;
    controller.abort();
    rejectAbortWait(failure('RESET_QUALIFICATION_STOPPED'));
    removeAbortListener();
  }
}
module.exports = { qualifySqlNoSqlResetBeforeJudge };
