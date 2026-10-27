'use strict';
// Test-process witness, not an OS sandbox. Install before application imports.
// Browser networking has its separate owned-origin interception policy.
const net = require('node:net');
const tls = require('node:tls');
const http = require('node:http');
const https = require('node:https');
const http2 = require('node:http2');
const dns = require('node:dns');
const dgram = require('node:dgram');
const childProcess = require('node:child_process');
const workers = require('node:worker_threads');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { syncBuiltinESMExports } = require('node:module');
const ROOT = path.resolve(__dirname, '../..');
const PASSWORD_WORKER = path.join(ROOT, 'server/agent-runtime/workers/passwordComparisonWorker.js');
const PASSWORD_WORKER_SHA256 = '5ff9e42db912875c264d87b154d560e41d754246a1db233cec0f1bf1af821fdf';
let installed = false;
function installDeletionNetworkGuard({ postgresPort, chromium } = {}) {
  if (installed) throw Error('Deletion network guard already installed');
  if (!Number.isInteger(postgresPort) || postgresPort < 1 || postgresPort > 65535 ||
      typeof chromium !== 'string' || !path.isAbsolute(chromium) ||
      fs.realpathSync(chromium) !== chromium || !fs.statSync(chromium).isFile())
    throw Error('Exact owned PostgreSQL endpoint and canonical Chromium required');
  for (const [key, value] of Object.entries(process.env)) if (value && /^(?:https?|all|no)_proxy$/i.test(key))
    throw Error('Proxy environment forbidden for deletion cohort');
  const counts = { postgresAttempts: 0, chromeSpawnAttempts: 0, chromeSpawnsAllowed: 0,
    nonPostgresAttempts: 0, blockedAttempts: 0, fetchAttempts: 0, tlsAttempts: 0,
    httpAttempts: 0, dnsAttempts: 0, literalLoopbackLookups: 0, udpAttempts: 0, subprocessAttempts: 0, workerAttempts: 0,
    passwordWorkersStarted: 0, passwordWorkersExited: 0, passwordWorkersLive: 0 };
  const patches = []; let active = true;
  function reject(kind) {
    counts.nonPostgresAttempts++; counts.blockedAttempts++;
    if (kind) counts[kind]++;
    throw Object.assign(Error('Deletion cohort forbidden outbound operation'), { code: 'DELETION_EGRESS_BLOCKED' });
  }
  function replace(object, key, value) {
    const prior = object[key]; object[key] = value; patches.push({ object, key, prior, value });
  }
  const originalConnect = net.Socket.prototype.connect;
  function connect(...args) {
    // net.createConnection uses Node's normalized argument tuple; direct callers
    // may use an options object or the numeric port/host overload.
    const supplied = Array.isArray(args[0]) ? args[0] : args;
    const first = supplied[0];
    const options = first && typeof first === 'object' ? { ...first } :
      (typeof first === 'number' ? { port: first, host: supplied[1] } : null);
    if (!options || !['number', 'string'].includes(typeof options.port) ||
        (typeof options.port === 'number' && !Number.isInteger(options.port)) ||
        options.host !== '127.0.0.1' || Number(options.port) !== postgresPort ||
        !/^[0-9]+$/.test(String(options.port)) || options.path !== undefined || options.fd !== undefined ||
        options.socket !== undefined || options.lookup !== undefined || options.localAddress !== undefined ||
        (options.family !== undefined && options.family !== 4)) return reject();
    counts.postgresAttempts++;
    // Pass the validated copy, so accessors cannot change the destination later.
    return originalConnect.call(this, options, typeof supplied[1] === 'function' ? supplied[1] : supplied[2]);
  }
  replace(net.Socket.prototype, 'connect', connect);
  replace(tls, 'connect', () => reject('tlsAttempts'));
  for (const object of [http, https]) for (const key of ['request', 'get']) replace(object, key, () => reject('httpAttempts'));
  replace(http2, 'connect', () => reject('httpAttempts'));
  if (typeof globalThis.fetch === 'function') replace(globalThis, 'fetch', async () => reject('fetchAttempts'));
  for (const object of [dns, dns.promises, dns.Resolver.prototype, dns.promises.Resolver.prototype]) {
    for (const key of Object.getOwnPropertyNames(object)) if (/^(lookup|resolve|reverse)/.test(key) && typeof object[key] === 'function')
      if (object === dns && key === 'lookup') {
        replace(object, key, (hostname, options, callback) => {
          // Node's Server.listen performs lookup even for an explicit numeric
          // bind address. Resolve only this literal locally; never call DNS.
          if (typeof options === 'function') { callback = options; options = {}; }
          if (options === undefined) options = {};
          if (typeof options === 'number') options = { family: options };
          if (hostname !== '127.0.0.1' || !options || typeof options !== 'object' ||
              typeof callback !== 'function' ||
              ![undefined, 0, 4].includes(options.family) ||
              ![undefined, false, true].includes(options.all)) return reject('dnsAttempts');
          const all = options.all === true;
          counts.literalLoopbackLookups++;
          process.nextTick(() => all ? callback(null, [{address:'127.0.0.1',family:4}]) : callback(null,'127.0.0.1',4));
        });
      } else replace(object, key, () => reject('dnsAttempts'));
  }
  for (const key of ['send', 'connect']) replace(dgram.Socket.prototype, key, () => reject('udpAttempts'));
  for (const key of ['exec', 'execFile', 'execSync', 'execFileSync', 'spawnSync', 'fork']) replace(childProcess, key, () => reject('subprocessAttempts'));
  const originalSpawn = childProcess.ChildProcess.prototype.spawn;
  replace(childProcess.ChildProcess.prototype, 'spawn', function(options) {
    counts.chromeSpawnAttempts++;
    const args = options?.args;
    const profiles = Array.isArray(args) ? args.filter(arg => typeof arg === 'string' && arg.startsWith('--user-data-dir=')) : [];
    const profile = profiles.length === 1 ? profiles[0].slice('--user-data-dir='.length) : '';
    let privateProfile = false;
    if (path.isAbsolute(profile) && profile.startsWith(path.join(ROOT, 'tasks/qualification') + path.sep)) {
      try { const stat = fs.lstatSync(profile); privateProfile = fs.realpathSync(profile) === profile && stat.isDirectory() && !stat.isSymbolicLink() &&
        (stat.mode & 0o077) === 0 && (typeof process.getuid !== 'function' || stat.uid === process.getuid()); } catch {}
    }
    if (options?.file !== chromium || !Array.isArray(args) || args[0] !== chromium ||
        counts.chromeSpawnsAllowed !== 0 || !privateProfile || !args.includes('--remote-debugging-pipe') ||
        args.some(arg => typeof arg !== 'string' || arg.startsWith('--remote-debugging-port')) ||
        options.shell || !Array.isArray(options.stdio) || options.stdio.length < 5 ||
        options.stdio[3] !== 'pipe' || options.stdio[4] !== 'pipe') return reject('subprocessAttempts');
    for (const entry of options.envPairs || []) if (/^(?:https?|all|no)_proxy=/i.test(entry)) return reject('subprocessAttempts');
    counts.chromeSpawnsAllowed++;
    return originalSpawn.call(this, options);
  });
  const OriginalWorker = workers.Worker;
  replace(workers, 'Worker', function(filename, options) {
    counts.workerAttempts++;
    const expected = {env:{},execArgv:[],resourceLimits:{maxOldGenerationSizeMb:64}};
    if (filename !== PASSWORD_WORKER || !isDeepStrictEqual(options, expected) ||
        counts.passwordWorkersStarted >= 4 || fs.realpathSync(filename) !== PASSWORD_WORKER ||
        createHash('sha256').update(fs.readFileSync(filename)).digest('hex') !== PASSWORD_WORKER_SHA256) return reject();
    // Pass fresh closed options rather than caller-owned objects. This source
    // executes only bcrypt comparison; it does not inherit the parent's guard.
    const worker = new OriginalWorker(PASSWORD_WORKER, expected);
    counts.passwordWorkersStarted++; counts.passwordWorkersLive++;
    worker.once('exit', () => { counts.passwordWorkersExited++; counts.passwordWorkersLive--; });
    return worker;
  });
  installed = true; syncBuiltinESMExports();
  function snapshot() {
    const intact = patches.every(patch => patch.object[patch.key] === patch.value);
    return Object.freeze({ version: 1, active, intact: active ? intact : null,
      ...counts, policy: 'node-owned-postgres-and-one-chrome-pipe-only',
      passwordWorkerPolicy: 'source-pinned-bcrypt-only-max-four-total',
      browserNetworkPolicySeparate: true, osSandboxClaimed: false });
  }
  function restore() {
    if (!active) return snapshot();
    if (counts.passwordWorkersLive !== 0) throw Error('Owned password workers must exit before restoring network guard');
    const intact = patches.every(patch => patch.object[patch.key] === patch.value);
    for (const patch of patches.reverse()) patch.object[patch.key] = patch.prior;
    active = false; installed = false; syncBuiltinESMExports();
    if (!intact) throw Error('Deletion network guard was modified while active');
    return snapshot();
  }
  return Object.freeze({ snapshot, restore });
}
module.exports = { installDeletionNetworkGuard };
