'use strict';

const express = require('express');
const { createAdminEmailConfiguration } = require('../services/adminEmailConfiguration');

function responseFor(error) {
  const status = error?.statusCode >= 400 && error.statusCode < 500 ? error.statusCode : 500;
  const body = { error: status === 500 ? 'Email configuration operation failed' : error.message };
  if (status !== 500 && error.field) body.field = error.field;
  return { status, body };
}

function createAdminEmailConfigurationRouter({
  service = createAdminEmailConfiguration(),
  auth = require('../middleware/adminAuth'),
} = {}) {
  const router = express.Router();
  router.use(auth.authenticateToken);
  router.use(auth.requireAdminLevel(2));
  router.use(auth.requirePermission('challenge_management'));

  router.get('/', async (_req, res) => {
    try { res.json({ success: true, configuration: await service.status() }); }
    catch (error) { const response = responseFor(error); res.status(response.status).json(response.body); }
  });
  router.put('/', async (req, res) => {
    try { res.json({ success: true, configuration: await service.save(req.body) }); }
    catch (error) { const response = responseFor(error); res.status(response.status).json(response.body); }
  });
  return router;
}

module.exports = { createAdminEmailConfigurationRouter };
