'use strict';

const { toWorkshopKey } = require('../config/workshopCatalog');

const DPI_WORKSHOP_KEY = 'direct_prompt_injection';

function isDirectPromptInjectionKey(key) {
  return toWorkshopKey(key) === DPI_WORKSHOP_KEY;
}

function isAdmin(user) {
  return user?.isAdmin === true
    || user?.role === 'admin'
    || user?.role === 'super_admin'
    || Number(user?.adminLevel ?? user?.admin_level ?? 0) > 0;
}

function sendDpiRetired(res) {
  return res.status(410).json({
    error: 'Direct Prompt Injection progress is graded by /chat',
    code: 'DPI_SERVER_GRADED',
  });
}

function createGenericProgressMutationHandlers({
  db,
  syncObjectiveComplete,
  resolveObjectiveLabel = (_workshopKey, objectiveId) => (
    objectiveId.replace(/_/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase())
  ),
}) {
  if (!db || typeof db.run !== 'function') throw new TypeError('A database connection is required');

  return {
    updateProgress(req, res) {
      const authenticatedUserId = Number(req.user?.id);
      if (!Number.isInteger(authenticatedUserId) || authenticatedUserId <= 0) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const targetUserId = Number(req.params?.userId);
      if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
        return res.status(400).json({ error: 'Invalid user ID' });
      }
      if (targetUserId !== authenticatedUserId && !isAdmin(req.user)) {
        return res.status(403).json({ error: 'Cannot update another user\'s progress' });
      }

      const challengeId = req.params?.challengeId;
      if (isDirectPromptInjectionKey(challengeId)) return sendDpiRetired(res);

      const { status } = req.body || {};
      if (status === 'completed') return res.status(409).json({ error: 'Exercise completion is derived from judged objectives.', code: 'JUDGED_ATTEMPT_REQUIRED' });
      const completedAt = status === 'completed' ? new Date().toISOString() : null;
      return db.run(
        `INSERT OR REPLACE INTO workshop_progress
         (user_id, challenge_id, status, completed_at)
         VALUES (?, ?, ?, ?)`,
        [targetUserId, challengeId, status, completedAt],
        (error) => {
          if (error) return res.status(500).json({ error: error.message });
          return res.json({ success: true, message: 'Progress updated successfully' });
        }
      );
    },

    completeObjective(req, res) {
      const userId = Number(req.user?.id);
      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      const { challengeId, objectiveId } = req.body || {};
      if (!challengeId || !objectiveId) {
        return res.status(400).json({ error: 'Challenge ID and Objective ID are required' });
      }
      if (isDirectPromptInjectionKey(challengeId)) return sendDpiRetired(res);

      return res.status(409).json({
        error: 'Objective completion requires a server-observed, judged attempt in the exercise.',
        code: 'JUDGED_ATTEMPT_REQUIRED',
      });
    },
  };
}

function createDpiResetHandlers({ progressService, logger = console }) {
  if (!progressService) throw new TypeError('A Direct Prompt Injection progress service is required');

  const fail = (res, error, message) => {
    logger.error?.(message, error);
    return res.status(500).json({ error: message });
  };

  return {
    async resetStudent(req, res, next) {
      const userId = Number(req.user?.id);
      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      if (!isDirectPromptInjectionKey(req.params?.workshopKey)) return next();
      try {
        await progressService.resetProgress({ userId, userKey: String(userId) });
        return res.json({ success: true });
      } catch (error) {
        return fail(res, error, 'Failed to reset progress');
      }
    },

    async resetAdminStudent(req, res, next) {
      if (!isDirectPromptInjectionKey(req.params?.workshopKey)) return next();
      const userId = Number(req.params?.studentId);
      if (!Number.isInteger(userId) || userId <= 0) {
        return res.status(400).json({ error: 'Invalid student ID' });
      }
      try {
        await progressService.resetProgress({ userId, userKey: String(userId) });
        return res.json({
          success: true,
          message: `Progress reset for workshop "${req.params.workshopKey}" for student ${req.params.studentId}`,
        });
      } catch (error) {
        return fail(res, error, 'Failed to reset workshop progress');
      }
    },

    async resetAdminBulk(req, res, next) {
      if (!isDirectPromptInjectionKey(req.params?.workshopKey)) return next();
      try {
        await progressService.resetAllProgress();
        return res.json({
          success: true,
          message: `All student progress reset for workshop "${req.params.workshopKey}"`,
        });
      } catch (error) {
        return fail(res, error, 'Bulk reset failed');
      }
    },
  };
}

function createStudentWorkshopResetHandler({ service, logger = console } = {}) {
  if (!service || typeof service.resetStudent !== 'function') {
    throw new TypeError('Student workshop reset requires an authoritative reset service');
  }

  return async function resetStudentWorkshop(req, res) {
    const userId = Number(req.user?.id);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    try {
      await service.resetStudent({ userId, workshopKey: req.params?.workshopKey });
      return res.json({ success: true });
    } catch (error) {
      const manualResetRequired = error.code === 'TARGETED_RESET_UNSUPPORTED';
      if (!manualResetRequired) logger.error?.('Failed to reset workshop progress', error);
      return res.status(error.statusCode || 500).json({
        success: false,
        error: manualResetRequired
          ? 'This exercise stores progress in the browser. Open the exercise and use its Reset Progress control.'
          : error.message || 'Failed to reset progress',
        ...(error.code ? { code: error.code } : {}),
        ...(error.committed ? { committed: true } : {}),
        ...(manualResetRequired ? { manualResetRequired: true } : {}),
      });
    }
  };
}

function retireArbitraryProgressMutation(_req, res) {
  return res.status(410).json({
    error: 'Path-scoped progress mutation is retired; use owner-scoped workshop APIs.',
    code: 'ARBITRARY_PROGRESS_MUTATION_RETIRED',
  });
}

module.exports = {
  createDpiResetHandlers,
  createGenericProgressMutationHandlers,
  createStudentWorkshopResetHandler,
  isDirectPromptInjectionKey,
  retireArbitraryProgressMutation,
};
