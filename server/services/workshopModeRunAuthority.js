'use strict';

function createWorkshopModeRunAuthority({ workshopKey, readScope } = {}) {
  if (typeof workshopKey !== 'string' || typeof readScope !== 'function') {
    throw new TypeError('A workshop key and canonical evaluation-scope reader are required');
  }
  return Object.freeze({
    async capture(userId, execution) {
      await execution?.check?.();
      const scope = await readScope(userId, workshopKey);
      if (!scope || !['vuln', 'fixed', null].includes(scope.mode)
          || typeof scope.modeStamp !== 'string' || scope.modeStamp.length === 0
          || !Number.isSafeInteger(scope.generation) || scope.generation < 0) {
        throw Object.assign(new Error('Canonical workshop mode scope is unavailable'),
          { code: 'WORKSHOP_MODE_SCOPE_UNAVAILABLE', statusCode: 503 });
      }
      const mode = scope.mode === 'fixed' ? 'fixed' : 'vuln';
      const check = async () => {
        await execution?.check?.();
        const current = await readScope(userId, workshopKey);
        if (current?.mode !== scope.mode || current?.modeStamp !== scope.modeStamp
            || current?.generation !== scope.generation) {
          throw Object.assign(new Error('Workshop mode or generation changed during this run'),
            { code: 'WORKSHOP_MODE_CHANGED', statusCode: 409 });
        }
        await execution?.check?.();
      };
      await check();
      return Object.freeze({ mode, scope: Object.freeze({ ...scope }), check });
    },
  });
}

module.exports = { createWorkshopModeRunAuthority };
