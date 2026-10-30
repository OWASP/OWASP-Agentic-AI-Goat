'use strict';

const http = require('node:http');

function configuredPort(value) {
  if (!/^\d+$/.test(String(value)) || Number(value) < 1 || Number(value) > 65535) return null;
  return Number(value);
}

function installBackendReadinessIpc({ Server = http.Server, environment = process.env,
  send = typeof process.send === 'function' ? process.send.bind(process) : null,
  pid = process.pid } = {}) {
  const expectedPort = configuredPort(environment.PORT || 8081);
  const token = environment.OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN;
  if (!expectedPort || !/^[A-Za-z0-9_-]{43}$/.test(String(token || '')) || typeof send !== 'function') {
    throw Object.assign(new Error('Supported launcher readiness channel is invalid'), { code: 'INVALID_LAUNCH_READINESS' });
  }
  const originalEmit = Server.prototype.emit;
  let reported = false;
  Server.prototype.emit = function readinessEmit(event, ...args) {
    const result = originalEmit.call(this, event, ...args);
    if (!reported && event === 'listening') {
      const address = this.address?.();
      if (address && typeof address === 'object' && address.port === expectedPort) {
        reported = true;
        Server.prototype.emit = originalEmit;
        send({ type: 'owasp-ai-goat-backend-ready', token, pid, port: expectedPort });
      }
    }
    return result;
  };
  return () => { Server.prototype.emit = originalEmit; };
}

if (process.env.OWASP_AI_GOAT_LAUNCH_READINESS_TOKEN) installBackendReadinessIpc();

module.exports = { configuredPort, installBackendReadinessIpc };
