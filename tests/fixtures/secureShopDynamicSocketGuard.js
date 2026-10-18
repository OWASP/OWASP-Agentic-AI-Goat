'use strict';
const net = require('node:net');
function fail(code) { throw Object.assign(new Error(code), { code }); }
function normalizeConnectArgs(args) {
  const values = args.length === 1 && Array.isArray(args[0]) ? args[0] : args;
  const first = values[0];
  if (first && typeof first === 'object') {
    if (first.path !== undefined && first.path !== null || first.lookup !== undefined
      || first.host === undefined && first.hostname === undefined || first.port === undefined) fail('QUALIFICATION_SOCKET_FORM');
    const host = first.host ?? first.hostname;
    if (typeof host !== 'string' || !host.length) fail('QUALIFICATION_SOCKET_FORM');
    const port = first.port;
    if (!((typeof port === 'number' && Number.isInteger(port)) || (typeof port === 'string' && /^[1-9][0-9]*$/.test(port)))) fail('QUALIFICATION_SOCKET_FORM');
    const numericPort = Number(port);
    if (numericPort < 1 || numericPort > 65535) fail('QUALIFICATION_SOCKET_FORM');
    return { host, port: numericPort };
  }
  if (!((typeof first === 'number' && Number.isSafeInteger(first)) || (typeof first === 'string' && /^[1-9][0-9]*$/.test(first))) || typeof values[1] !== 'string') fail('QUALIFICATION_SOCKET_FORM');
  const port = Number(first);
  if (port < 1 || port > 65535) fail('QUALIFICATION_SOCKET_FORM');
  return { host: values[1], port };
}
function createDynamicSocketGuard({ permits, trackSocket, connect } = {}) {
  if (typeof permits !== 'function' || typeof trackSocket !== 'function' || typeof connect !== 'function') fail('QUALIFICATION_SOCKET_CONFIG');
  return function guarded(...args) {
    const endpoint = normalizeConnectArgs(args);
    if (endpoint.host !== '127.0.0.1' || !permits(endpoint.host, endpoint.port)) fail('QUALIFICATION_ENDPOINT_BLOCKED');
    let socket;
    try {
      socket = connect.apply(this, args);
      trackSocket(endpoint.host, endpoint.port, socket);
    } catch (error) {
      try { socket?.destroy?.(); } catch {}
      throw error;
    }
    return socket;
  };
}
function installDynamicSocketGuard({ permits, trackSocket, connect = net.Socket.prototype.connect } = {}) {
  const original = net.Socket.prototype.connect;
  const guarded = createDynamicSocketGuard({ permits, trackSocket, connect });
  net.Socket.prototype.connect = guarded;
  return Object.freeze({ restore() { if (net.Socket.prototype.connect === guarded) net.Socket.prototype.connect = original; }, guarded });
}
module.exports = { createDynamicSocketGuard, installDynamicSocketGuard, normalizeConnectArgs };
