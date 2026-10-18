'use strict';
const { readBearerAuthorization } = require('./bearerToken');

// A teaching cookie is never platform authority. Optional authentication admits
// only genuinely anonymous requests; a presented invalid credential fails closed.
function createWorkshopPlatformAuthority({ authenticateToken, optional = false }) {
  if (typeof authenticateToken !== 'function') throw new TypeError('Canonical authentication required');
  return (req, res, next) => {
    if (optional && !readBearerAuthorization(req).present) {
      delete req.user;
      delete req.identitySession;
      return next();
    }
    return authenticateToken(req, res, next);
  };
}
module.exports = { createWorkshopPlatformAuthority };
