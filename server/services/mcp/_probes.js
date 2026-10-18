'use strict';

/**
 * Shared HTTP liveness prober for the MCP lab. Used by the sidecar supervisor
 * (to decide whether the docker-compose sidecars are already up) and by the
 * /infra endpoint (to report live status). Resolves true if the URL answers
 * with any status code before the timeout, false otherwise — never rejects.
 */
const http = require('node:http');
const https = require('node:https');

function httpProbe(url, timeoutMs = 1500) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (up) => { if (!done) { done = true; resolve(up); } };
    try {
      const lib = url.startsWith('https') ? https : http;
      const req = lib.get(url, (r) => { r.resume(); finish(r.statusCode > 0); });
      req.on('error', () => finish(false));
      req.setTimeout(timeoutMs, () => { req.destroy(); finish(false); });
    } catch { finish(false); }
  });
}

module.exports = { http: httpProbe };
