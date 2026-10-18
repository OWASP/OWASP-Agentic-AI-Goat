'use strict';
const express = require('express');
const paths = require('../config/workshopSolutionPaths');
function stores() { return require('../services/postgresPlatformStores').getPostgresPlatformStores().config; }
function failure(res, error) {
  const status = { FORBIDDEN: 403, NOT_FOUND: 404, BAD_REQUEST: 400 }[error.code] || 500;
  return res.status(status).json({ success: false, error: status === 500 ? 'Unable to load workshop content' : error.message });
}
function createPostgresHintsRouter(config = stores()) {
  const router = express.Router();
  router.get('/:workshopKey/status', async (req, res) => {
    try { res.json({ success: true, objectives: await config.getHintVisibilityMap(req.params.workshopKey) }); }
    catch (error) { failure(res, error); }
  });
  router.get('/:workshopKey/:objectiveId', async (req, res) => {
    try { res.json({ success: true, hint: await config.getStudentContent(req.params.workshopKey, req.params.objectiveId, 'hint') }); }
    catch (error) { failure(res, error); }
  });
  return router;
}
function createPostgresSolutionsRouter(config = stores()) {
  const router = express.Router();
  for (const [key, path] of Object.entries(paths)) {
    router.get(`/${path.statusPrefix}/status`, async (req, res) => {
      try {
        if (key === 'csrf_workshop') {
          const exercise = (await config.getSnapshot()).exercises[key];
          const master = { hints: !!exercise?.showHints, solutions: !!exercise?.showSolutions };
          const objectives = Object.fromEntries(Object.entries(exercise?.objectives || {}).map(([id, objective]) => [id, { hint: objective.hintVisible, solution: objective.solutionVisible, enabled: objective.solutionVisible }]));
          return res.json({ success: true, master, objectives });
        }
        res.json({ success: true, objectives: await config.getSolutionVisibilityMap(key) });
      } catch (error) { failure(res, error); }
    });
    router.get(`/${path.statusPrefix}/${path.contentSubpath}:objectiveId`, async (req, res) => {
      try { res.json({ success: true, solution: await config.getStudentContent(key, req.params.objectiveId, 'solution') }); }
      catch (error) { failure(res, error); }
    });
  }
  return router;
}
module.exports = { createPostgresHintsRouter, createPostgresSolutionsRouter };
