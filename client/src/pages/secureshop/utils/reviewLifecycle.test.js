import { createReviewLifecycle } from './reviewLifecycle.mjs';

test('same-key effect replay preserves admitted work and true unmount fences it', () => {
  const deferred = []; let admitted = null; let invalidations = 0;
  const lifecycle = createReviewLifecycle({ scope: {}, defer: callback => deferred.push(callback),
    invalidate() { invalidations += 1; admitted?.abort(); } });
  const firstCleanup = lifecycle.enter('7:41:customer');
  admitted = new AbortController();
  firstCleanup();
  const replayCleanup = lifecycle.enter('7:41:customer');
  deferred.splice(0).forEach(callback => callback());
  expect(admitted.signal.aborted).toBe(false);
  expect(invalidations).toBe(1);
  replayCleanup();
  deferred.splice(0).forEach(callback => callback());
  expect(admitted.signal.aborted).toBe(true);
  expect(invalidations).toBe(2);
});

test.each([
  ['product', '8:41:customer'],
  ['owner', '7:42:customer'],
  ['role', '7:41:merchant'],
])('%s transition fences admitted work synchronously without later resurrection', (_kind, nextKey) => {
  const deferred = []; const first = new AbortController(); let admitted = null;
  const lifecycle = createReviewLifecycle({ scope: {}, defer: callback => deferred.push(callback),
    invalidate() { admitted?.abort(); } });
  const cleanup = lifecycle.enter('7:41:customer');
  admitted = first;
  cleanup();
  lifecycle.enter(nextKey);
  expect(first.signal.aborted).toBe(true);
  admitted = new AbortController();
  deferred.splice(0).forEach(callback => callback());
  expect(admitted.signal.aborted).toBe(false);
});

test('fresh-instance same-key replay supersedes old cleanup in one bridge scope', () => {
  const deferred = [];
  const scope = {};
  let firstWork = null;
  let secondWork = null;
  let firstInvalidations = 0;
  let secondInvalidations = 0;
  const first = createReviewLifecycle({
    scope,
    defer: callback => deferred.push(callback),
    invalidate() { firstInvalidations += 1; firstWork?.abort(); },
  });
  const firstCleanup = first.enter('7:41:customer');
  firstWork = new AbortController();
  firstCleanup();

  const second = createReviewLifecycle({
    scope,
    defer: callback => deferred.push(callback),
    invalidate() { secondInvalidations += 1; secondWork?.abort(); },
  });
  const secondCleanup = second.enter('7:41:customer');
  deferred.splice(0).forEach(callback => callback());
  expect(firstWork.signal.aborted).toBe(false);

  secondWork = new AbortController();
  secondCleanup();
  deferred.splice(0).forEach(callback => callback());
  expect(firstWork.signal.aborted).toBe(true);
  expect(secondWork.signal.aborted).toBe(true);
  expect({ firstInvalidations, secondInvalidations }).toEqual({
    firstInvalidations: 2, secondInvalidations: 2,
  });

  const third = createReviewLifecycle({ scope, defer: callback => deferred.push(callback),
    invalidate() {} });
  const thirdCleanup = third.enter('7:41:customer');
  thirdCleanup();
  deferred.splice(0).forEach(callback => callback());
  expect({ firstInvalidations, secondInvalidations }).toEqual({
    firstInvalidations: 2, secondInvalidations: 2,
  });
});

test('fresh-instance different-key entry fences every predecessor synchronously', () => {
  const deferred = [];
  const scope = {};
  let firstWork = null;
  let secondWork = null;
  const first = createReviewLifecycle({ scope, defer: callback => deferred.push(callback),
    invalidate() { firstWork?.abort(); } });
  const firstCleanup = first.enter('7:41:customer');
  firstWork = new AbortController();
  const replacement = createReviewLifecycle({ scope, defer: callback => deferred.push(callback),
    invalidate() { secondWork?.abort(); } });
  firstCleanup();
  replacement.enter('8:41:customer');
  expect(firstWork.signal.aborted).toBe(true);
  secondWork = new AbortController();
  deferred.splice(0).forEach(callback => callback());
  expect(secondWork.signal.aborted).toBe(false);
});

test('edit cancellation fences inherited same-key work and retains current unmount ownership', () => {
  const deferred = [];
  const scope = {};
  let predecessorWork = null;
  let currentWork = null;
  let predecessorInvalidations = 0;
  const predecessor = createReviewLifecycle({ scope, defer: callback => deferred.push(callback),
    invalidate() { predecessorInvalidations += 1; predecessorWork?.abort(); } });
  const predecessorCleanup = predecessor.enter('7:41:customer');
  predecessorWork = new AbortController();
  predecessorCleanup();

  const current = createReviewLifecycle({ scope, defer: callback => deferred.push(callback),
    invalidate() { currentWork?.abort(); } });
  const currentCleanup = current.enter('7:41:customer');
  deferred.splice(0).forEach(callback => callback());
  currentWork = new AbortController();
  current.cancel();
  expect(predecessorWork.signal.aborted).toBe(true);
  expect(currentWork.signal.aborted).toBe(true);

  currentWork = new AbortController();
  currentCleanup();
  deferred.splice(0).forEach(callback => callback());
  expect(currentWork.signal.aborted).toBe(true);
  expect(predecessorInvalidations).toBe(2,
    'edit cancellation releases the predecessor instead of retaining it until later lifecycles');
});
