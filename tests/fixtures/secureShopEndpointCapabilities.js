'use strict';
const crypto = require('node:crypto');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SCOPE = ['targetId','launchId','scenarioId','generation','platformOwnerId','platformSessionId'];
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function fail() { throw Error('Owned endpoint capability rejected'); }
function scopeOf(value) {
  if (!exact(value, SCOPE) || !['targetId','launchId','scenarioId'].every(key => UUID.test(value[key]))
      || !Number.isSafeInteger(value.generation) || value.generation < 0
      || !['platformOwnerId','platformSessionId'].every(key => Number.isSafeInteger(value[key]) && value[key] > 0)) fail();
  return Object.freeze(Object.fromEntries(SCOPE.map(key => [key,value[key]])));
}
// Pure controller primitive. Only the trusted target-creation seam may receive
// grant(). The IPC transport must authenticate its peer before calling apply().
// This protocol does not prove that a listener exists or that a process owns it.
function createSecureShopEndpointCapabilities({ reservedPorts = [], maxTargets = 8 } = {}) {
  if (!Array.isArray(reservedPorts) || reservedPorts.some(port => !Number.isInteger(port) || port < 1 || port > 65535)
      || !Number.isInteger(maxTargets) || maxTargets < 1 || maxTargets > 32) fail();
  const reserved = new Set([5432,8081,8082,11434,...reservedPorts]);
  const entries = new Map(), ports = new Map();let closed = false;
  function grant(scope) {
    if (closed || entries.size >= maxTargets) fail();const bound = scopeOf(scope);
    if ([...entries.values()].some(entry => entry.scope.targetId === bound.targetId)) fail();
    const token = crypto.randomBytes(32).toString('hex');
    entries.set(token,{ scope: bound, sequence: 0, state: 'issued', endpoint: null, sockets: new Set() });
    return Object.freeze({ version: 1, capability: token, scope: bound });
  }
  function retire(entry) {
    entry.state = 'revoked';
    if (entry.endpoint) ports.delete(entry.endpoint.port);
    const failures=[];
    for (const socket of entry.sockets) { try { socket.destroy(); } catch (error) { failures.push(error); } }
    entry.sockets.clear();
    if (failures.length) throw new AggregateError(failures,'Owned endpoint socket cleanup failed');
  }
  function apply(message) {
    if (closed || !exact(message,['version','capability','scope','sequence','operation','endpoint']) || message.version !== 1) fail();
    const entry=entries.get(message.capability);
    if (!entry || entry.state === 'revoked' || JSON.stringify(scopeOf(message.scope)) !== JSON.stringify(entry.scope)
        || message.sequence !== entry.sequence + 1) fail();
    if (message.operation === 'register') {
      const value=message.endpoint;
      if (entry.state !== 'issued' || !exact(value,['host','port']) || value.host !== '127.0.0.1'
          || !Number.isInteger(value.port) || value.port < 1 || value.port > 65535 || reserved.has(value.port) || ports.has(value.port)) fail();
      entry.endpoint=Object.freeze({host:value.host,port:value.port});entry.state='active';ports.set(value.port,entry);
    } else if (message.operation === 'revoke' && message.endpoint === null) {
      entry.sequence=message.sequence;retire(entry);
    } else fail();
    entry.sequence=message.sequence;
    return Object.freeze({version:1,targetId:entry.scope.targetId,sequence:entry.sequence,state:entry.state});
  }
  function permits(host,port) { return !closed && host === '127.0.0.1' && Number.isInteger(port) && ports.get(port)?.state === 'active'; }
  function trackSocket(host,port,socket) {
    if (!permits(host,port) || typeof socket?.destroy !== 'function') fail();
    const entry=ports.get(port);entry.sockets.add(socket);
    return () => entry.sockets.delete(socket);
  }
  function close() {
    closed=true;const failures=[];
    for (const entry of entries.values()) { try { retire(entry); } catch(error) { failures.push(error); } }
    if (failures.length) throw new AggregateError(failures,'Owned endpoint registry cleanup failed');
  }
  return Object.freeze({grant,apply,permits,trackSocket,close});
}
module.exports={createSecureShopEndpointCapabilities};
