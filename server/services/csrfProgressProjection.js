'use strict';
const WORKSHOP_KEY = 'csrf_workshop';
function createCsrfProgressProjection({ readCanonical, markLocal, syncLegacy, finishWorkshop, check, pending, report }) {
  const rows = async userId => (await readCanonical(userId)).filter(row =>
    row.workshop_key === WORKSHOP_KEY && (row.completed === true || row.completed === 1));
  return {
    rows,
    async record({ userKey, objectiveId, userId, durable }) {
      await check();
      if (!durable) {
        await syncLegacy(userId, objectiveId);
        await check();
        if (!(await rows(userId)).some(row => row.objective_id === objectiveId)) {
          throw Object.assign(new Error('Canonical objective completion was not accepted'), { code: 'CANONICAL_COMPLETION_UNAVAILABLE' });
        }
        await check();
      }
      // Both paths now have accepted canonical credit. Secondary writes cannot
      // undo that result, but owner cancellation must still prevent publication.
      try {
        await markLocal(userKey, objectiveId);
        await finishWorkshop(userId);
      } catch (error) {
        await check();
        if (error?.name === 'AbortError') throw error;
        pending(objectiveId);
        report(objectiveId, userId);
      }
      await check();
    },
  };
}
module.exports = { createCsrfProgressProjection };
