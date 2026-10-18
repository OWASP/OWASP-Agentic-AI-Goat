import { runAfterTrackedLoad } from './serializedReconciliation';

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

test('delayed initial writes settle before a newer canonical reconciliation commits', async () => {
  const delayedInitial = deferred();
  let renderedState = 'empty';
  const trackedLoadRef = {
    current: Promise.allSettled([
      delayedInitial.promise.then(() => {
        renderedState = 'old initial state';
      }),
    ]),
  };

  const reconciliation = runAfterTrackedLoad(trackedLoadRef, async () => {
    renderedState = 'new canonical state';
  });
  expect(renderedState).toBe('empty');

  delayedInitial.resolve();
  await reconciliation;
  expect(renderedState).toBe('new canonical state');
});
