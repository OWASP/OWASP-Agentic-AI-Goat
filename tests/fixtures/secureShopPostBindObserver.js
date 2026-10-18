'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { URL } = require('node:url');

function fail(code) { throw Object.assign(new Error(code), { code }); }
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
const SCOPE_KEYS = ['generation', 'launchId', 'platformOwnerId', 'platformSessionId', 'scenarioId', 'targetId'];

// Test-only wrapper around the genuine owned target factory. The endpoint is
// observed only from that instance's issue() result; callers cannot submit a
// URL or nonce to this seam.
function createObservedTargetFactory({ createTarget, root, registry, grant, scope } = {}) {
  if (typeof createTarget !== 'function' || typeof root !== 'string' || !path.isAbsolute(root)
      || typeof registry?.apply !== 'function' || !exact(grant, ['capability', 'scope', 'version'])
      || grant.version !== 1 || !exact(scope, SCOPE_KEYS) || !exact(grant.scope, SCOPE_KEYS)
      || !SCOPE_KEYS.every(key => grant.scope[key] === scope[key])) fail('POST_BIND_CONFIGURATION');
  const canonicalRoot = path.resolve(root);
  if (canonicalRoot !== root) fail('POST_BIND_ROOT_INVALID');
  let sequence = 0, registered = false, created = false, retired = false, registeredEndpoint = null;
  return async function observedCreateTarget(args = {}) {
    if (created) fail('POST_BIND_FACTORY_REBOUND');
    if (!exact(args, ['root', 'targetId']) || args.targetId !== scope.targetId || args.root !== canonicalRoot) fail('POST_BIND_FACTORY_SCOPE');
    created = true;
    const ownedRoot = await fs.realpath(canonicalRoot).catch(() => null);
    const stat = await fs.lstat(ownedRoot || '').catch(() => null);
    if (ownedRoot !== canonicalRoot || !stat?.isDirectory() || stat.isSymbolicLink()) fail('POST_BIND_ROOT_INVALID');
    const target = await createTarget({ root: ownedRoot, targetId: args.targetId });
    if (!target || typeof target.issue !== 'function') fail('POST_BIND_TARGET_INVALID');
    const issue = target.issue.bind(target);
    const observedIssue = input => {
      if (retired) fail('POST_BIND_TARGET_RETIRED');
      const issued = issue(input);
      if (!issued || typeof issued !== 'object' || issued.targetId !== scope.targetId || typeof issued.url !== 'string') fail('POST_BIND_RESULT_INVALID');
      let url; try { url = new URL(issued.url); } catch { fail('POST_BIND_ENDPOINT_INVALID'); }
      if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || url.search || url.hash
          || !/^[1-9][0-9]*$/.test(url.port) || Number(url.port) > 65535) fail('POST_BIND_ENDPOINT_INVALID');
      if (!registered) {
        const endpoint = Object.freeze({ host: url.hostname, port: Number(url.port) });
        const result = registry.apply({ version: 1, capability: grant.capability, scope, sequence: ++sequence,
          operation: 'register', endpoint });
        if (result.state !== 'active') fail('POST_BIND_REGISTRATION');
        registered = true; registeredEndpoint = endpoint;
      } else {
        if (url.protocol !== 'http:' || url.hostname !== registeredEndpoint.host || Number(url.port) !== registeredEndpoint.port) fail('POST_BIND_ENDPOINT_REBOUND');
      }
      return issued;
    };
    const cleanup = typeof target.cleanup === 'function' ? target.cleanup.bind(target) : null;
    const disconnect = typeof target.disconnect === 'function' ? target.disconnect.bind(target) : null;
    const revoke = () => {
      retired = true;
      if (!registered) return;
      registered = false;
      registry.apply({ version: 1, capability: grant.capability, scope, sequence: ++sequence, operation: 'revoke', endpoint: null });
    };
    const closeTarget = async (close, args) => {
      const failures = []; let result;
      try { revoke(); } catch (error) { failures.push(error); }
      try { result = await close(...args); } catch (error) { failures.push(error); }
      if (failures.length) throw new AggregateError(failures, 'Post-bind target cleanup failed');
      return result;
    };
    return Object.freeze({ ...target, issue: observedIssue,
      ...(cleanup ? { cleanup: (...args) => closeTarget(cleanup, args) } : {}),
      ...(disconnect ? { disconnect: (...args) => closeTarget(disconnect, args) } : {}) });
  };
}

function createEndpointSocketPolicy({ permits, trackSocket } = {}) {
  if (typeof permits !== 'function' || typeof trackSocket !== 'function') fail('SOCKET_POLICY_CONFIGURATION');
  return Object.freeze({
    assert(host, port) {
      if (host !== '127.0.0.1' || !['number', 'string'].includes(typeof port) || !/^[1-9][0-9]*$/.test(String(port))
          || !Number.isSafeInteger(Number(port)) || !permits(host, Number(port))) fail('QUALIFICATION_ENDPOINT_BLOCKED');
      return true;
    },
    track(host, port, socket) {
      this.assert(host, port);
      return trackSocket(host, Number(port), socket);
    },
  });
}
module.exports = { createObservedTargetFactory, createEndpointSocketPolicy };
