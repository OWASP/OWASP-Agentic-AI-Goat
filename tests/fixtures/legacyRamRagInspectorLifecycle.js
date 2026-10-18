'use strict';

const http = require('node:http');
const net = require('node:net');
const { exportLegacyRamRag, evaluateInspector } = require('./legacyRamRagExport');

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

function bounded(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new TypeError(`${name} invalid`);
  return value;
}

function tcpOpen(port) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port });
    const finish = value => { socket.destroy(); resolve(value); };
    socket.setTimeout(250, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

function targets(port) {
  return new Promise((resolve, reject) => {
    const request = http.get({ host: '127.0.0.1', port, path: '/json/list', timeout: 500 }, response => {
      const chunks = []; let bytes = 0;
      response.once('error', reject);
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 4096) response.destroy(Object.assign(new Error('Inspector discovery response too large'), { code: 'INSPECTOR_DISCOVERY_OVERSIZE' }));
        else chunks.push(chunk);
      });
      response.once('end', () => {
        try {
          if (response.statusCode !== 200) throw new Error('Inspector discovery rejected');
          const rows = JSON.parse(Buffer.concat(chunks));
          if (!Array.isArray(rows) || rows.length > 4) throw new Error('Inspector target list invalid');
          resolve(rows);
        } catch (error) { reject(error); }
      });
    });
    request.once('timeout', () => request.destroy(new Error('Inspector discovery timed out')));
    request.once('error', reject);
  });
}

async function discover(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs; let latest;
  while (Date.now() < deadline) {
    try {
      const rows = await targets(port);
      const urls = rows.map(row => row.webSocketDebuggerUrl).filter(value => typeof value === 'string');
      if (urls.length === 1 && urls[0].startsWith(`ws://127.0.0.1:${port}/`)) return urls[0];
      if (urls.length > 1) throw new Error('Inspector target discovery ambiguous');
    } catch (error) {
      latest = error;
    }
    await delay(25);
  }
  throw Object.assign(new Error('Owned inspector did not become ready'), { cause: latest });
}

async function evaluatedPid(url) {
  const value = await evaluateInspector({ url, expression: '({pid:process.pid})', timeoutMs: 3000 });
  return value?.pid;
}

async function closeMatching(url, expectedPid) {
  if (await evaluatedPid(url) !== expectedPid) throw new Error('Inspector PID mismatch; refusing cleanup');
  const receipt = await evaluateInspector({ url, expression: `(()=>{if(process.pid!==${expectedPid})throw Error('PID mismatch');setTimeout(()=>{try{process.getBuiltinModule('inspector').close();}catch{}},50);return{pid:process.pid,closeScheduled:true};})()`, timeoutMs: 3000 });
  if (receipt?.pid !== expectedPid || receipt.closeScheduled !== true) throw new Error('Inspector close receipt invalid');
}

async function identifyMatching(port, expectedPid, timeoutMs) {
  const deadline = Date.now() + timeoutMs; let latest;
  while (Date.now() < deadline) {
    try {
      const url = await discover(port, Math.min(500, Math.max(1, deadline - Date.now())));
      if (await evaluatedPid(url) !== expectedPid) throw new Error('Inspector PID mismatch');
      return url;
    } catch (error) { latest = error; await delay(25); }
  }
  throw Object.assign(new Error('Owned inspector identity unresolved'), { cause: latest });
}

async function waitAbsent(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { if (!await tcpOpen(port)) return; await delay(25); }
  throw new Error('Owned inspector listener remains open');
}

async function exportThroughOwnedInspector({ pid, port, expectedModule, output, timeoutMs = 10000, failurePoint }) {
  bounded(pid, 'pid', 2147483647); bounded(port, 'port', 65535);
  if (failurePoint !== undefined && failurePoint !== 'after-signal') throw new TypeError('Unknown lifecycle failure point');
  if (await tcpOpen(port)) throw new Error('Inspector port was not free before activation');
  try { process.kill(pid, 0); } catch { throw new Error('Owned target PID absent'); }
  let activated = false, matchedUrl = null, result, primaryError = null, cleanupError = null;
  try {
    process.kill(pid, 'SIGUSR1'); activated = true;
    if (failurePoint === 'after-signal') throw new Error('Injected lifecycle failure after signal');
    matchedUrl = await identifyMatching(port, pid, timeoutMs);
    result = await exportLegacyRamRag({ inspectorUrl: matchedUrl, output, expectedPid: pid, expectedModule });
  } catch (error) { primaryError = error; }
  if (activated) {
    try {
      // A transient before or during normal discovery must not skip cleanup.
      // Rediscovery still closes only an endpoint that proves the exact PID.
      const cleanupUrl = matchedUrl || await identifyMatching(port, pid, Math.min(timeoutMs, 3000));
      await closeMatching(cleanupUrl, pid);
      await waitAbsent(port, timeoutMs);
    } catch (error) {
      cleanupError = Object.assign(new Error(await tcpOpen(port)
        ? 'Owned inspector cleanup unresolved; listener remains open'
        : 'Owned inspector cleanup could not be verified'), { cause: error });
    }
  }
  if (primaryError && cleanupError) throw new AggregateError([primaryError, cleanupError], 'Inspector export and cleanup failed');
  if (primaryError) throw primaryError;
  if (cleanupError) throw cleanupError;
  return result;
}

module.exports = { exportThroughOwnedInspector, tcpOpen, identifyMatching, closeMatching, waitAbsent };
