const express = require('express');
const {
  createWorkshopConfigMutationService,
} = require('../services/workshopConfigMutationService');
const { createAdminChangeRecorder } = require('../services/adminChangeRevision');

let recordCommittedContent;
function recordContentChange(change) {
  recordCommittedContent ||= createAdminChangeRecorder(require('../services/changeRevisionService'));
  return recordCommittedContent.record(change);
}

function statusFor(error) {
  if (Number.isInteger(error?.statusCode) && error.statusCode >= 400 && error.statusCode <= 499) {
    return error.statusCode;
  }
  if (error.code === 'NOT_FOUND') return 404;
  if (error.code === 'BAD_REQUEST') return 400;
  return 500;
}

function errorResponse(error) {
  const status = statusFor(error);
  const body = { error: status === 500 ? 'Exercise configuration operation failed' : error.message };
  if (status !== 500 && error.field) body.field = error.field;
  return { status, body };
}

function createAdminExercisesRouter({
  service = createWorkshopConfigMutationService(),
  auth = require('../middleware/adminAuth'),
  onCommitted = () => {},
  onContentCommitted = recordContentChange,
} = {}) {
  const router = express.Router();
  const { authenticateToken, requireAdminLevel, requirePermission } = auth;
  router.use(authenticateToken);
  router.use(requireAdminLevel(1));

  const mutate = (operation, contentChange = null) => async (req, res) => {
    try {
      const result = await operation(req);
      if (result.changed) onCommitted(result.revision);
      if (result.changed && contentChange) await onContentCommitted(contentChange(req));
      res.json({ success: true, ...result });
    } catch (error) {
      const response = errorResponse(error);
      res.status(response.status).json(response.body);
    }
  };

  router.get('/:challengeKey/objectives/:objectiveId/hint', async (req, res) => {
    try {
      const hint = await service.getHintContent(
        req.params.challengeKey, req.params.objectiveId);
      res.json({ success: true, hint });
    } catch (error) {
      const response = errorResponse(error);
      res.status(response.status).json(response.body);
    }
  });

  router.get('/:challengeKey/objectives/:objectiveId/solution', async (req, res) => {
    try {
      const solution = await service.getSolutionContent(req.params.challengeKey, req.params.objectiveId);
      res.json({ success: true, solution });
    } catch (error) {
      const response = errorResponse(error);
      res.status(response.status).json(response.body);
    }
  });

  router.get('/:challengeKey/objectives/:objectiveId', async (req, res) => {
    try {
      const objective = await service.getObjectiveMetadata(req.params.challengeKey, req.params.objectiveId);
      res.json({ success: true, objective });
    } catch (error) {
      const response = errorResponse(error);
      res.status(response.status).json(response.body);
    }
  });

  router.use(requirePermission('challenge_management'));

  router.post('/reflected_xss_llm/group-controls', mutate((req) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).length !== 2 || !Object.hasOwn(body, 'dimension') || !Object.hasOwn(body, 'enabled')
      || !['active', 'hints', 'solutions', 'objectives'].includes(body.dimension) || typeof body.enabled !== 'boolean') {
      throw Object.assign(new Error('Invalid XSS group controls'), { code: 'BAD_REQUEST' });
    }
    return service.setXssGroupControls(body.dimension, body.enabled, req.user.id);
  }, req => ({ type: 'xssGroupControls', dimension: req.body.dimension, bulk: true })));

  router.patch('/content-visibility', mutate((req) =>
    service.setAllHintAndSolutionVisibility(req.body?.enabled, req.user.id),
    () => ({ type: 'hintAndSolutionVisibility', bulk: true })));

  router.patch('/:challengeKey', mutate((req) =>
    service.setExerciseVisibility(
      req.params.challengeKey, req.body?.enabled, req.user.id),
    (req) => ({ type: 'challengeVisibility', challengeKey: req.params.challengeKey })));

  router.patch('/:challengeKey/objectives/:objectiveId', mutate((req) =>
    service.setObjectiveVisibility(
      req.params.challengeKey, req.params.objectiveId, req.body?.enabled, req.user.id),
    (req) => ({
      type: 'objectiveVisibility',
      workshopKey: req.params.challengeKey,
      objectiveId: req.params.objectiveId,
    })));

  router.put('/:challengeKey/objectives/:objectiveId', mutate((req) =>
    service.updateObjectiveMetadata(req.params.challengeKey, req.params.objectiveId, req.body || null, req.user.id),
    (req) => ({ type: 'objectiveMetadata', workshopKey: req.params.challengeKey, objectiveId: req.params.objectiveId })));

  router.patch('/:challengeKey/hints', mutate((req) =>
    service.setMasterHintVisibility(
      req.params.challengeKey, req.body?.enabled, req.user.id),
    (req) => ({ type: 'hintVisibility', workshopKey: req.params.challengeKey, bulk: true })));

  router.patch('/:challengeKey/objectives/:objectiveId/hint', mutate((req) =>
    service.setObjectiveHintVisibility(
      req.params.challengeKey, req.params.objectiveId, req.body?.enabled, req.user.id),
    (req) => ({
      type: 'hintVisibility',
      workshopKey: req.params.challengeKey,
      objectiveId: req.params.objectiveId,
    })));

  router.patch('/:challengeKey/solutions', mutate((req) =>
    service.setMasterSolutionVisibility(
      req.params.challengeKey, req.body?.enabled, req.user.id),
    (req) => ({ type: 'solutionVisibility', workshopKey: req.params.challengeKey, bulk: true })));

  router.patch('/:challengeKey/objectives/:objectiveId/solution', mutate((req) =>
    service.setObjectiveSolutionVisibility(
      req.params.challengeKey, req.params.objectiveId, req.body?.enabled, req.user.id),
    (req) => ({
      type: 'solutionVisibility',
      workshopKey: req.params.challengeKey,
      objectiveId: req.params.objectiveId,
    })));

  router.put('/:challengeKey/objectives/:objectiveId/hint', mutate((req) =>
    service.updateHintContent(
      req.params.challengeKey, req.params.objectiveId, req.body || null, req.user.id),
    (req) => ({ type: 'hintContent', workshopKey: req.params.challengeKey, objectiveId: req.params.objectiveId })));

  router.put('/:challengeKey/objectives/:objectiveId/solution', mutate((req) =>
    service.updateSolutionContent(
      req.params.challengeKey, req.params.objectiveId, req.body || null, req.user.id),
    (req) => ({ type: 'solutionContent', workshopKey: req.params.challengeKey, objectiveId: req.params.objectiveId })));

  return router;
}

module.exports = { createAdminExercisesRouter };
