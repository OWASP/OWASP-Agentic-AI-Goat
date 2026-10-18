'use strict';

const fail = (code, message) => { const error = new Error(message); error.code = code; throw error; };
const positive = value => Number.isSafeInteger(value) && value > 0;

function bearer(request) {
  const value = request?.headers?.authorization;
  if (typeof value !== 'string' || !/^Bearer [^\s]+$/.test(value)) fail('MCP_PLATFORM_SESSION_REQUIRED', 'A current platform bearer session is required');
  return value.slice(7);
}

// Unwired adapter. validateSession must verify JWT signature/claims and read the
// current durable identity.user_sessions row; Express session fields are only
// compared after that authoritative lookup and never become the source.
function createMcpPlatformSessionResolver({ validateSession } = {}) {
  if (typeof validateSession !== 'function') throw new TypeError('validateSession is required');
  return Object.freeze({
    async resolveRequest(request) {
      const token = bearer(request);
      const found = await validateSession(token, request);
      const ownerId = found?.user?.id;
      const platformSessionId = found?.session?.id;
      if (!positive(ownerId) || !positive(platformSessionId)) fail('MCP_PLATFORM_SESSION_REQUIRED', 'The durable platform session is unavailable');
      if (request?.user && request.user.id !== ownerId) fail('MCP_PLATFORM_OWNER_MISMATCH', 'Authenticated platform owner changed');
      const copied = request?.session?.sessionData?.id;
      if (copied != null && copied !== platformSessionId) fail('MCP_PLATFORM_SESSION_MISMATCH', 'Copied session state does not match the durable session');
      const identity = { platformOwnerId: ownerId, platformSessionId };
      // Private revalidation capability. It is deliberately non-enumerable so
      // spreading the public scope into SQL/HTTP payloads cannot expose it.
      Object.defineProperty(identity, 'assertCurrent', { enumerable: false, value: async () => {
        const current = await validateSession(token, request);
        if (current?.user?.id !== ownerId || current?.session?.id !== platformSessionId) {
          fail('MCP_PLATFORM_SESSION_REQUIRED', 'The bound platform session is no longer current');
        }
        return true;
      } });
      return Object.freeze(identity);
    },
  });
}

module.exports = { createMcpPlatformSessionResolver, _internals: { bearer } };
