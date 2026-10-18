const activeByScope = new WeakMap();

function retire(scope, group) {
  if (activeByScope.get(scope) !== group) return;
  activeByScope.delete(scope);
  const invalidators = [...group.invalidators];
  group.invalidators.clear();
  for (const invalidate of invalidators) invalidate();
}

export function createReviewLifecycle({ invalidate, scope, defer = queueMicrotask } = {}) {
  if (typeof invalidate !== 'function' || (typeof scope !== 'object' && typeof scope !== 'function')
      || scope === null || typeof defer !== 'function') {
    throw new TypeError('Review lifecycle dependencies required');
  }
  let current = null;
  return Object.freeze({
    cancel() {
      const group = activeByScope.get(scope);
      if (!current || group?.latest !== current.marker || !group.invalidators.has(invalidate)) {
        invalidate();
        return;
      }
      const invalidators = [...group.invalidators];
      group.invalidators.clear();
      // An edit cancels every request inherited from a replay handoff. Keep
      // only this mounted instance so its later work is fenced on unmount.
      group.invalidators.add(invalidate);
      for (const cancel of invalidators) cancel();
    },
    enter(key) {
      if (typeof key !== 'string' || !key) throw new TypeError('Review lifecycle key required');
      const marker = {};
      const previous = current;
      let group = activeByScope.get(scope);
      const invalidatorWasActive = group?.invalidators.has(invalidate) === true;
      if (group && group.key !== key) {
        retire(scope, group);
        group = null;
      }
      if (!group) {
        group = { key, latest: marker, invalidators: new Set() };
        activeByScope.set(scope, group);
      }
      group.latest = marker;
      group.invalidators.add(invalidate);
      current = { key, marker };
      // StrictMode repeats setup with the same key. A real product/persona
      // transition has a different key and must fence the old request now.
      if ((!previous || previous.key !== key) && !invalidatorWasActive) invalidate();
      return () => defer(() => {
        if (current?.marker === marker) current = null;
        if (activeByScope.get(scope) !== group || group.latest !== marker) return;
        // The final instance owns retirement for the logical scope/key. It
        // cancels every admitted predecessor and releases their closures.
        retire(scope, group);
      });
    },
  });
}
