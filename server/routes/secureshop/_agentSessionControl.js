'use strict';

const sessionStore = require('../../services/secureshop/sessionStore.js');

function agentSessionControl(role, store = sessionStore) {
  async function create(req, res, next) {
    try {
      const { id } = await store.createSession({ userId: req.ssUser.id, role });
      res.json({ sessionId: id });
    } catch (error) {
      next(error);
    }
  }

  async function requireOwned(req, res, next) {
    const sessionId = req.params?.sessionId || req.body?.sessionId;
    if (!sessionId) return res.status(400).json({ error: 'sessionId required' });
    try {
      const session = await store.getSession(sessionId);
      const ownsSession = session
        && String(session.userId) === String(req.ssUser.id)
        && session.role === role
        && req.ssUser.role === role;
      if (!ownsSession) return res.status(404).json({ error: 'agent session not found' });
      req.agentSession = session;
      next();
    } catch (error) {
      next(error);
    }
  }

  function runExclusive(sessionId, operation) {
    return store.runSessionExclusive(sessionId, operation);
  }

  async function getLatestOwned(req, limit, readOwned) {
    if (req.ssUser.role !== role) return [];
    return readOwned({ userId: req.ssUser.id, role, limit });
  }

  async function filterOwnedTraceRows(req, rows) {
    if (req.ssUser.role !== role) return [];
    const ids = [...new Set((rows || []).map((row) => row.session_id).filter(Boolean))];
    const sessions = await Promise.all(ids.map((id) => store.getSession(id)));
    const allowed = new Set(sessions.filter((session) => session
      && String(session.userId) === String(req.ssUser.id)
      && session.role === role).map((session) => session.id));
    return (rows || []).filter((row) => allowed.has(row.session_id));
  }

  return { create, requireOwned, runExclusive, getLatestOwned, filterOwnedTraceRows };
}

module.exports = { agentSessionControl };
