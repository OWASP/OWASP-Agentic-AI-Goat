/**
 * SecureShop v2 — email REST router.
 *
 * Mounted alongside customer/merchant/admin/uploads routers. Exposes the
 * email task-agent tools directly over HTTP so students can drive email
 * vulns without going through the supervisor loop.
 */

const express = require('express');

const emailTools = require('../../../agent-host/agents/email/tools/index.js');

module.exports = function buildEmailRouter() {
  const router = express.Router();

  router.post('/email/send', async (req, res) => {
    try {
      const r = await emailTools.send(req.body || {});
      res.json(r);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.get('/email/inbox/:userId', async (req, res) => {
    try {
      const r = await emailTools.read_inbox({ user_id: Number(req.params.userId) });
      res.json(r);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.get('/email/thread/:threadId', async (req, res) => {
    try {
      const r = await emailTools.summarize_thread({ thread_id: Number(req.params.threadId) });
      res.json(r);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  router.post('/email/auto-reply/:threadId', async (req, res) => {
    try {
      const r = await emailTools.auto_reply({ thread_id: Number(req.params.threadId), from: req.body?.from });
      res.json(r);
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  });

  return router;
};
