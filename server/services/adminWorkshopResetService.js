'use strict';

function getProductionStudentWorkshopResetService() {
  return require('./postgresWorkshopResetService').getPostgresWorkshopResetService();
}

function createAdminWorkshopResetHandlers({ service, recordChange, logger = console } = {}) {
  if (!service || typeof recordChange !== 'function') {
    throw new TypeError('Admin workshop reset handlers require a service and revision recorder');
  }
  const fail = (res, error, fallback) => {
    logger.error?.(fallback, error);
    return res.status(error.statusCode || 500).json({
      success: false,
      error: error.message || fallback,
      ...(error.code ? { code: error.code } : {}),
      ...(error.committed ? { committed: true } : {}),
    });
  };
  return {
    async resetStudent(req, res) {
      const userId = Number(req.params.studentId);
      const workshopKey = req.params.workshopKey;
      try {
        await service.resetStudent({ userId, workshopKey });
        await recordChange({ type: 'progressReset', targetUserId: userId, workshopKey });
        await recordChange({ type: 'progressReset', workshopKey });
        return res.json({ success: true, message: `Progress reset for workshop "${workshopKey}" for student ${userId}` });
      } catch (error) {
        return fail(res, error, 'Failed to reset workshop progress');
      }
    },
    async resetWorkshop(req, res) {
      const workshopKey = req.params.workshopKey;
      try {
        await service.resetWorkshop({ workshopKey });
        await recordChange({ type: 'progressReset', workshopKey });
        return res.json({ success: true, message: `All student progress reset for workshop "${workshopKey}"` });
      } catch (error) {
        return fail(res, error, 'Bulk reset failed');
      }
    },
    async resetAll(req, res) {
      if (req.body?.confirmText !== 'RESET_ALL_PROGRESS') {
        return res.status(400).json({ success: false, error: 'Confirmation required. Send confirmText: "RESET_ALL_PROGRESS"' });
      }
      try {
        await service.resetAll();
        await recordChange({ type: 'progressReset' });
        return res.json({ success: true, message: 'All student progress reset across all workshops' });
      } catch (error) {
        return fail(res, error, 'Reset failed');
      }
    },
  };
}

module.exports = {
  createAdminWorkshopResetHandlers,
  getProductionStudentWorkshopResetService,
};
