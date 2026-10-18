'use strict';

const crypto = require('node:crypto');
const { hasAdminLevel } = require('./postgresAdminAuth');
const { readBearerAuthorization } = require('./bearerToken');
function createPostgresSessionManager(adapter) {
  const repo = adapter.repository;
  let cleanupInterval;
  const manager = {
    JWT_SECRET: adapter.jwtSecret,
    serverInstanceId: crypto.randomBytes(16).toString('hex'),
    serverStartTime: new Date().toISOString(),
    async initializeSessionManagement() {
      manager.startCleanupTask();
    },
    getSessionDuration(role, level = 0) {
      return (level >= 2 || role === 'student' ? 4 : 2) * 3600000;
    },
    getSessionType(role, level = 0) {
      const identity = { role, admin_level: level };
      return hasAdminLevel(identity, 2) ? 'super_admin' : hasAdminLevel(identity) ? 'admin' : role === 'student' ? 'student' : 'user';
    },
    detectPlatform(agent = '') {
      return /Android/.test(agent) ? 'Android' : /iOS|iPhone|iPad/.test(agent) ? 'iOS' : /Windows/.test(agent) ? 'Windows' : /Mac/.test(agent) ? 'macOS' : /Linux/.test(agent) ? 'Linux' : 'Unknown';
    },
    getLocationFromIP: async ip => ['127.0.0.1', '::1'].includes(ip) ? 'Localhost' : 'Unknown Location',
    async createSession(user, req) {
      const duration = manager.getSessionDuration(user.role, user.admin_level);
      const result = await adapter.createSession(user, req, {
        durationMs: duration
      });
      return {
        ...result,
        sessionInfo: {
          deviceInfo: {
            userAgent: req.get?.('User-Agent'),
            acceptLanguage: req.get?.('Accept-Language'),
            platform: manager.detectPlatform(req.get?.('User-Agent'))
          },
          ipAddress: req.ip,
          duration,
          type: manager.getSessionType(user.role, user.admin_level)
        }
      };
    },
    async validateSession(token, req) {
      try {
        const found = await adapter.validateSession(token);
        if (!found) return null;
        await repo.touchSession(token, found.user.id);
        const s = found.session;
        return {
          user: adapter.userDto(found.user),
          session: {
            id: s.id,
            expiresAt: s.expires_at,
            lastActivity: s.last_activity,
            ipAddress: s.ip_address,
            deviceInfo: s.device_info || {},
            needsRefresh: manager.shouldRefreshSession(s)
          },
          decoded: found.decoded
        };
      } catch (error) {
        if (['JsonWebTokenError', 'TokenExpiredError', 'NotBeforeError', 'AccountLocked'].includes(error.name)) return null;
        throw error;
      }
    },
    invalidateAllSessionsOnStartup: () => repo.revokeAllActiveSessions('server_restart'),
    invalidateAllActiveSessions: () => repo.revokeAllActiveSessions('server_shutdown'),
    cleanupUserSessions: id => repo.pruneUserSessions(id),
    invalidateSession: token => adapter.logout(token),
    invalidateAllUserSessions: id => repo.revokeAllUserSessions(id),
    async getUserSessions(id) {
      return (await repo.listActiveSessions(id)).map(s => ({
        id: s.id,
        deviceInfo: s.device_info,
        ipAddress: s.ip_address,
        location: s.location,
        createdAt: s.created_at,
        lastActivity: s.last_activity,
        expiresAt: s.expires_at,
        isCurrent: false
      }));
    },
    shouldRefreshSession: s => new Date(s.expires_at).getTime() - Date.now() < 3600000,
    cleanupExpiredSessions: () => repo.cleanupExpiredSessions(),
    startCleanupTask() {
      if (!cleanupInterval) {
        cleanupInterval = setInterval(() => repo.cleanupExpiredSessions().catch(() => {}), 3600000);
        cleanupInterval.unref();
      }
    },
    stopCleanupTask() {
      if (cleanupInterval) clearInterval(cleanupInterval);
      cleanupInterval = null;
    },
    middleware() {
      return async (req, res, next) => {
        // This middleware only enriches requests with an already-valid platform
        // session. Route authorization remains authoritative, and a teaching
        // cookie or a token under another authentication scheme cannot promote
        // the request to platform authority.
        const { token } = readBearerAuthorization(req);
        if (!token) return next();
        try {
          const found = await manager.validateSession(token, req);
          if (found) {
            req.user = found.user;
            req.sessionManager = manager;
          }
          next();
        } catch {
          res.status(503).json({
            error: 'Session store unavailable'
          });
        }
      };
    }
  };
  manager.startCleanupTask();
  return manager;
}
module.exports = {
  createPostgresSessionManager
};
