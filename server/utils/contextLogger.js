'use strict';

const logger = require('./logger');
const { getRequestContext } = require('./requestContext');

/**
 * Thin wrapper around the Winston logger that automatically merges
 * userId / username / ip from the AsyncLocalStorage request context
 * into every log call's metadata object.
 *
 * Usage:  const logger = require('../utils/contextLogger');
 *         logger.info('chat_request', { workshop: 'sensitive_info', ... });
 *         // => meta will include userId, username, ip from the current request
 */
function withContext(meta) {
  const ctx = getRequestContext();
  return {
    ...meta,
    userId:   meta.userId   ?? ctx.userId   ?? null,
    username: meta.username ?? ctx.username ?? null,
    ip:       meta.ip       ?? ctx.ip       ?? null
  };
}

module.exports = {
  info:  (msg, meta = {}) => logger.info(msg, withContext(meta)),
  warn:  (msg, meta = {}) => logger.warn(msg, withContext(meta)),
  error: (msg, meta = {}) => logger.error(msg, withContext(meta)),
  debug: (msg, meta = {}) => logger.debug(msg, withContext(meta))
};
