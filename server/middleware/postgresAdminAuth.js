'use strict';
const { readBearerAuthorization } = require('./bearerToken');

const {
  auditMetadata
} = require('./auditMetadata');
function hasAdminLevel(user, level = 1) {
  return Boolean(user && ['admin', 'super_admin'].includes(user.role) && user.admin_level >= level);
}
function createPostgresAdminAuth(adapter) {
  const repo = adapter.repository;
  const authenticateToken = async (req, res, next) => {
    const token = readBearerAuthorization(req).token;
    if (!token) return res.status(401).json({
      error: 'Authentication required',
      message: 'Access token is missing'
    });
    try {
      const found = await adapter.validateSession(token);
      if (!found) return res.status(401).json({
        error: 'Session expired',
        message: 'Please login again'
      });
      req.user = {
        id: found.user.id,
        username: found.user.username,
        email: found.user.email,
        role: found.user.role,
        admin_level: found.user.admin_level || 0,
        full_name: found.user.full_name,
        email_verified: found.user.email_verified,
        last_login: found.user.last_login
      };
      req.identitySession = found.session;
      try {
        require('../utils/requestContext').syncUserToContext(req);
      } catch {}
      next();
    } catch (error) {
      if (error.name === 'AccountLocked') return res.status(423).json({
        error: 'Account locked',
        lockedUntil: error.lockedUntil
      });
      if (['JsonWebTokenError', 'TokenExpiredError', 'NotBeforeError'].includes(error.name)) return res.status(401).json({
        error: 'Invalid token',
        message: 'Token verification failed'
      });
      return res.status(503).json({
        error: 'Authentication error',
        message: 'Session store unavailable'
      });
    }
  };
  const authenticated = (req, res) => {
    if (req.user) return true;
    res.status(401).json({
      error: 'Authentication required'
    });
    return false;
  };
  return {
    authenticateToken,
    JWT_SECRET: adapter.jwtSecret,
    requireRole: (roles = []) => (req, res, next) => {
      if (!authenticated(req, res)) return;
      if (!roles.includes(req.user.role)) return res.status(403).json({
        error: 'Access denied',
        userRole: req.user.role
      });
      next();
    },
    requireAdminLevel: (level = 1) => (req, res, next) => {
      if (!authenticated(req, res)) return;
      if (!hasAdminLevel(req.user, level)) return res.status(403).json({
        error: 'Insufficient privileges',
        userLevel: req.user.admin_level
      });
      next();
    },
    requirePermission: permission => async (req, res, next) => {
      if (!authenticated(req, res)) return;
      try {
        if (!(await repo.hasPermission(req.user.id, permission))) return res.status(403).json({
          error: 'Permission denied',
          requiredPermission: permission
        });
        req.permission = {
          admin_id: req.user.id,
          permission_name: permission
        };
        next();
      } catch {
        return res.status(503).json({
          error: 'Permission check failed'
        });
      }
    },
    requireEmailVerification: (req, res, next) => {
      if (!authenticated(req, res)) return;
      if (!req.user.email_verified) return res.status(403).json({
        error: 'Email verification required',
        emailVerified: false
      });
      next();
    },
    checkAccountLockout: async (req, res, next) => {
      if (!req.user) return next();
      try {
        const lock = await repo.checkAccountLockout(req.user.id);
        if (lock.locked) return res.status(423).json({
          error: 'Account locked',
          lockedUntil: lock.lockedUntil
        });
        next();
      } catch {
        return res.status(503).json({
          error: 'Account state unavailable'
        });
      }
    },
    logActivity: actionType => async (req, res, next) => {
      try {
        await repo.recordAudit({
          userId: req.user?.id,
          actionType,
          details: auditMetadata(req),
          ipAddress: req.ip,
          userAgent: req.get?.('User-Agent')
        });
        next();
      } catch {
        return res.status(503).json({
          error: 'Audit store unavailable'
        });
      }
    },
    getUserPermissions: userId => repo.getUserPermissions(userId),
    hasPermission: (userId, permission) => repo.hasPermission(userId, permission)
  };
}
module.exports = {
  createPostgresAdminAuth, hasAdminLevel
};
