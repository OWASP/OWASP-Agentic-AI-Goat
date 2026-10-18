function createWorkshopTimeHandlers({ timeService, now = Date.now } = {}) {
  if (!timeService || typeof timeService.recordHeartbeat !== 'function') {
    throw new TypeError('timeService.recordHeartbeat is required');
  }

  return {
    async recordHeartbeat(req, res) {
      const userId = Number(req.user?.id);
      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      const workshopKey = req.body?.workshopKey;
      try {
        const result = await timeService.recordHeartbeat({ userId, workshopKey, now: now() });
        return res.json({ success: true, ...result });
      } catch (error) {
        const mappedStatus = new Map(Object.entries({
          BAD_REQUEST: 400,
          AUTH_REQUIRED: 401,
          NOT_FOUND: 404,
          STALE_GENERATION: 409,
          INSTANCE_SCOPE_REQUIRED: 409,
          GRADE_STORE_NOT_READY: 503,
        })).get(error?.code);
        const statusCode = Number.isInteger(error?.statusCode) && error.statusCode >= 400 && error.statusCode <= 599
          ? error.statusCode : mappedStatus || 500;
        return res.status(statusCode).json({
          error: statusCode < 500 ? error.message : 'Failed to record workshop time',
          ...(typeof error?.field === 'string' ? { field: error.field } : {}),
          ...(typeof error?.code === 'string' ? { code: error.code } : {}),
        });
      }
    },
  };
}

module.exports = { createWorkshopTimeHandlers };
