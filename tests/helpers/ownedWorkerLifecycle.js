'use strict';

function failure(code) {
  return Object.assign(new Error(code), { code });
}

function superviseOwnedWorker(child) {
  if (!child || typeof child.on !== 'function' || typeof child.kill !== 'function') {
    throw new TypeError('Owned child process required');
  }
  let readySettled = false;
  let resultSettled = false;
  let exitSettled = false;
  let resolveReady;
  let rejectReady;
  let resolveResult;
  let rejectResult;
  let resolveExit;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const result = new Promise((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
  const exit = new Promise(resolve => { resolveExit = resolve; });
  // A process can fail while its caller is still awaiting the earlier phase.
  // Attach observation immediately; callers still receive the original rejecting promises.
  ready.catch(() => {});
  result.catch(() => {});
  const rejectPending = code => {
    const error = failure(code);
    if (!readySettled) { readySettled = true; rejectReady(error); }
    if (!resultSettled) { resultSettled = true; rejectResult(error); }
  };
  child.on('message', message => {
    if (message === 'ready' && !readySettled) {
      readySettled = true;
      resolveReady();
    } else if (message && message !== 'ready' && !resultSettled) {
      resultSettled = true;
      resolveResult(message);
    }
  });
  child.once('error', () => rejectPending('OWNED_WORKER_PROCESS_ERROR'));
  child.once('exit', code => {
    exitSettled = true;
    rejectPending(readySettled ? 'OWNED_WORKER_RESULT_MISSING' : 'OWNED_WORKER_READY_MISSING');
    resolveExit(code);
  });
  return Object.freeze({ child, ready, result, exit,
    send(value) { if (exitSettled || !child.connected) throw failure('OWNED_WORKER_NOT_RUNNING'); child.send(value); },
    async stop() {
      if (!exitSettled) child.kill('SIGTERM');
      await exit;
    } });
}

async function bounded(promise, timeoutMs, code = 'OWNED_WORKER_TIMEOUT') {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(failure(code)), timeoutMs);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

async function stopOwnedWorkers(workers) {
  await Promise.allSettled(workers.map(worker => worker.stop()));
}

module.exports = { bounded, stopOwnedWorkers, superviseOwnedWorker };
