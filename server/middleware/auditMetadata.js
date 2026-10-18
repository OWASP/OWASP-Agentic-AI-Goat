'use strict';

// Platform audit logs describe actions, not submitted credentials or lab payloads.
function auditMetadata(req) {
  const route = req.route?.path;
  return {
    method: req.method,
    url: typeof route === 'string' ? `${req.baseUrl || ''}${route}` : String(req.url || '').split('?')[0],
    timestamp: new Date().toISOString(),
  };
}

module.exports = { auditMetadata };
