'use strict';
// VM-controlled filesystem, native helper, sockets and HTTP only. No real
// Windows APIs, listeners, process shutdown or application state are exercised.
const test = require('node:test'), assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm');
const { EventEmitter } = require('node:events');
const source = fs.readFileSync(path.resolve(__dirname, '../scripts/launcher-control.js'), 'utf8');
const workspace = 'C:\\workspace', home = 'C:\\Users\\learner';
const denied = () => Object.assign(Error('Windows private state operation denied.'), { code: 'WINDOWS_PRIVATE_STATE_DENIED' });
function harness() {
  const files = new Map(), directories = new Set([home]), calls = [], fsCalls = [], signals = [], servers = new Map();
  const liveOwners = new Set([4242]); let nextPort = 40000, fileCounter = 1;
  const controls = { occupied: false, beforeSnapshot: null, beforeDelete: null, beforeEnsure: null,
    beforeCreate: null, afterPort: null, cleanupDenied: false, response: null };
  const same = (a, b) => a.volumeSerial === b.volumeSerial && a.fileId === b.fileId;
  const identity = () => Object.freeze({ volumeSerial: 123, fileId: (fileCounter++).toString(16).padStart(16, '0') });
  const missing = () => { throw Object.assign(Error('missing'), { code: 'ENOENT' }); };
  function put(file, state) { files.set(file, { bytes: Buffer.isBuffer(state) ? Buffer.from(state) : Buffer.from(JSON.stringify(state) + '\n'), identity: identity() }); }
  const native = {
    ensurePrivateDirectory(directory) {
      calls.push(['ensure', directory]); controls.beforeEnsure?.(directory);
      if (!directories.has(path.win32.dirname(directory))) throw denied(); directories.add(directory);
    },
    createPrivateFile(file, bytes) {
      calls.push(['create', file]); controls.beforeCreate?.(file, bytes);
      if (files.has(file) || !directories.has(path.win32.dirname(file))) throw denied();
      files.set(file, { bytes: Buffer.from(bytes), identity: identity() });
      const saved = files.get(file); return Object.freeze({ path: file, size: bytes.length, identity: saved.identity });
    },
    readPrivateFileSnapshot(file) {
      calls.push(['snapshot', file]); controls.beforeSnapshot?.(file);
      const saved = files.get(file); if (!saved) throw denied();
      const bytes = Buffer.from(saved.bytes);
      return Object.freeze({ path: file, size: bytes.length, identity: saved.identity, get bytes() { return Buffer.from(bytes); } });
    },
    deleteMatchingPrivateFile(file, bytes, expectedIdentity) {
      calls.push(['delete', file, Buffer.from(bytes), { ...expectedIdentity }]); controls.beforeDelete?.(file);
      const saved = files.get(file);
      if (controls.cleanupDenied || !saved || !same(saved.identity, expectedIdentity) || !saved.bytes.equals(bytes)) throw denied();
      files.delete(file); return Object.freeze({ path: file, size: bytes.length, identity: saved.identity, deleted: true });
    },
  };
  const observedFs = new Proxy({
    realpathSync(value) { fsCalls.push(['realpath', value]); return value; },
    lstatSync(file) {
      fsCalls.push(['lstat', file]); if (!files.has(file)) return missing();
      // Deliberately unusable for identity/privacy admission. Windows callers
      // may use this only to observe presence; native snapshot is authoritative.
      return { dev: 999, ino: 999, size: 0, uid: 0, mode: 0o777, isFile: () => false, isSymbolicLink: () => true };
    },
  }, { get(target, name) { return name in target ? target[name] : () => assert.fail(`Raw Windows fs.${String(name)} fallback`); } });
  const http = {
    createServer(handler) {
      const server = new EventEmitter(); server.handler = handler; server.listening = false;
      server.listen = (_port, host, done) => {
        assert.equal(host, '127.0.0.1'); server.port = nextPort++; server.listening = true; servers.set(server.port, server); done();
      };
      server.address = () => ({ port: server.port });
      server.close = done => { server.listening = false; servers.delete(server.port); done(); };
      calls.push(['server']); return server;
    },
    request(options, callback) {
      calls.push(['http', options]); const request = new EventEmitter();
      request.destroy = error => request.emit('error', error);
      request.end = () => queueMicrotask(() => {
        if (controls.response) return controls.response(options, callback, request);
        const server = servers.get(options.port);
        if (!server) return request.emit('error', Object.assign(Error('refused'), { code: 'ECONNREFUSED' }));
        const response = new EventEmitter(); response.resume = () => {};
        server.handler({ headers: { authorization: options.headers.Authorization }, method: options.method, url: options.path }, {
          writeHead(code) { response.statusCode = code; },
          end(_text, done) { callback(response); queueMicrotask(() => { response.emit('end'); done?.(); }); },
        });
      });
      return request;
    },
  };
  const net = { createConnection(options) {
    calls.push(['port', options]); const socket = new EventEmitter(); socket.setTimeout = () => {}; socket.destroy = () => {};
    queueMicrotask(() => {
      controls.afterPort?.();
      if (controls.occupied) socket.emit('connect');
      else socket.emit('error', Object.assign(Error('closed'), { code: 'ECONNREFUSED' }));
    }); return socket;
  } };
  const process = { platform: 'win32', pid: 4242, kill(pid, signal) {
    signals.push([pid, signal]); assert.equal(signal, 0);
    if (!liveOwners.has(pid)) throw Object.assign(Error('absent'), { code: 'ESRCH' });
  } };
  const module = { exports: {} };
  vm.runInNewContext(source, { module, exports: module.exports, process, Buffer, setTimeout, clearTimeout,
    require(name) {
      if (name === 'node:fs') return observedFs;
      if (name === 'node:path') return path.win32;
      if (name === 'node:os') return { homedir: () => home };
      if (name === 'node:http') return http;
      if (name === 'node:net') return net;
      if (name === './lib/windows-private-state') return native;
      return require(name);
    },
  }, { filename: 'launcher-control.js' });
  const api = module.exports, stateFile = api.statePath(workspace);
  function state(overrides = {}) { return { version: 2, workspace, port: 32123, token: 'a'.repeat(64), ownerPid: 999999, ...overrides }; }
  function respond200(callback) { const response = new EventEmitter(); response.statusCode = 200; response.resume = () => {}; callback(response); queueMicrotask(() => response.emit('end')); }
  return { api, stateFile, state, files, directories, calls, fsCalls, signals, controls, servers, liveOwners, put, respond200 };
}

test('Windows controller ensures two private leaves, exclusively creates/snapshots state and authenticates native cleanup', async () => {
  const h = harness(); let stops = 0;
  const controller = await h.api.createController({ workspace, stop: async () => { stops++; } });
  assert.equal(controller.stateFile, h.stateFile);
  const directory = path.win32.dirname(h.stateFile), parent = path.win32.dirname(directory);
  assert.deepEqual(h.calls.slice(0, 2), [['ensure', parent], ['ensure', directory]]);
  assert.deepEqual(h.calls.filter(c => ['create', 'snapshot'].includes(c[0])).map(c => c[0]), ['create', 'snapshot']);
  const retained = h.files.get(h.stateFile), state = JSON.parse(retained.bytes);
  assert.equal(state.ownerPid, 4242); assert.equal(state.workspace, workspace);
  const server = h.servers.get(state.port); let status;
  server.handler({ headers: {}, method: 'POST', url: '/stop' }, { writeHead(code) { status = code; }, end() {} });
  assert.equal(status, 403); assert.equal(stops, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(await h.api.requestStop({ workspace, timeoutMs: 100 }))), { stopped: true, controllerRecovered: false });
  assert.equal(stops, 1); assert.equal(h.files.has(h.stateFile), false);
  const deletion = h.calls.find(c => c[0] === 'delete');
  assert(deletion[2].equals(retained.bytes)); assert.deepEqual(deletion[3], retained.identity);
  const http = h.calls.find(c => c[0] === 'http')[1];
  assert.equal(http.host, '127.0.0.1'); assert.equal(http.path, '/stop'); assert.equal(http.method, 'POST');
  assert.equal(http.headers.Authorization, 'Bearer ' + state.token);
  await controller.close(); assert.equal(h.calls.filter(c => c[0] === 'delete').length, 1);
});

test('Windows stale recovery preserves owner and loopback port gates before exact native removal', async () => {
  const h = harness(), state = h.state(); h.put(h.stateFile, state);
  const original = h.files.get(h.stateFile);
  assert.deepEqual(JSON.parse(JSON.stringify(await h.api.requestStop({ workspace }))), { controllerRecovered: true, childrenStopped: false });
  assert.equal(h.files.has(h.stateFile), false);
  assert.deepEqual(h.signals, [[state.ownerPid, 0], [state.ownerPid, 0], [state.ownerPid, 0]]);
  assert.deepEqual(JSON.parse(JSON.stringify(h.calls.find(c => c[0] === 'port')[1])), { host: '127.0.0.1', port: state.port });
  const deletion = h.calls.find(c => c[0] === 'delete'); assert(deletion[2].equals(original.bytes)); assert.deepEqual(deletion[3], original.identity);
});

test('Windows restart recovers only admitted stale state before publishing a new exclusive file', async () => {
  const h = harness(); h.put(h.stateFile, h.state());
  const controller = await h.api.createController({ workspace, stop: async () => {} });
  const operations = h.calls.map(c => c[0]); assert(operations.indexOf('delete') < operations.indexOf('create'));
  assert.equal(JSON.parse(h.files.get(h.stateFile).bytes).ownerPid, 4242);
  await controller.close();
});

test('Windows live/reappearing owner or occupied port retains state and never reaches deletion', async () => {
  for (const type of ['live', 'reappeared', 'occupied']) {
    const h = harness(), state = h.state(); h.put(h.stateFile, state);
    if (type === 'live') h.liveOwners.add(state.ownerPid);
    if (type === 'reappeared') h.controls.afterPort = () => h.liveOwners.add(state.ownerPid);
    if (type === 'occupied') h.controls.occupied = true;
    await assert.rejects(h.api.createController({ workspace, stop: async () => {} }), {
      code: type === 'occupied' ? 'LAUNCHER_PORT_OCCUPIED' : 'LAUNCHER_OWNER_PRESENT',
    });
    assert(h.files.has(h.stateFile)); assert(!h.calls.some(c => c[0] === 'delete' || c[0] === 'create'));
  }
});

test('Windows unsafe native reads, oversized state and legacy recovery refuse without raw reads', async () => {
  for (const type of ['denied', 'oversized', 'legacy', 'workspace']) {
    const h = harness(); h.put(h.stateFile, type === 'oversized' ? Buffer.alloc(4097) : h.state({
      version: type === 'legacy' ? 1 : 2, workspace: type === 'workspace' ? 'C:\\other' : workspace,
    }));
    if (type === 'denied') h.controls.beforeSnapshot = () => { throw denied(); };
    await assert.rejects(h.api.createController({ workspace, stop: async () => {} }), {
      code: { denied: 'WINDOWS_PRIVATE_STATE_DENIED', oversized: 'LAUNCHER_STATE_UNSAFE', legacy: 'LAUNCHER_LEGACY_STATE', workspace: 'LAUNCHER_STATE_INVALID' }[type],
    });
    assert(h.files.has(h.stateFile)); assert(!h.calls.some(c => c[0] === 'delete' || c[0] === 'create'));
    assert(h.fsCalls.every(c => ['realpath', 'lstat'].includes(c[0])));
  }
});

test('Windows parent admission and publication reobservation failures retain partial state without cleanup fallback', async () => {
  const parent = harness(); parent.controls.beforeEnsure = directory => { if (directory !== path.win32.dirname(path.win32.dirname(parent.stateFile))) throw denied(); };
  await assert.rejects(parent.api.createController({ workspace, stop: async () => {} }), { code: 'WINDOWS_PRIVATE_STATE_DENIED' });
  assert(!parent.calls.some(c => c[0] === 'server' || c[0] === 'create'));
  const h = harness(); h.controls.beforeSnapshot = file => { const saved = h.files.get(file); h.put(file, saved.bytes); };
  await assert.rejects(h.api.createController({ workspace, stop: async () => {} }), { code: 'LAUNCHER_STATE_CHANGED' });
  assert(h.files.has(h.stateFile)); assert(!h.calls.some(c => c[0] === 'delete')); assert.equal(h.servers.size, 0);
});

test('Windows matching-delete denies replaced bytes or identity and retains the replacement', async () => {
  for (const replacement of ['bytes', 'identity']) {
    const h = harness(); h.put(h.stateFile, h.state());
    h.controls.beforeDelete = file => {
      const saved = h.files.get(file);
      if (replacement === 'bytes') saved.bytes = Buffer.from(JSON.stringify(h.state({ token: 'b'.repeat(64) })) + '\n');
      else h.put(file, saved.bytes);
    };
    await assert.rejects(h.api.requestStop({ workspace }), { code: 'WINDOWS_PRIVATE_STATE_DENIED' });
    assert(h.files.has(h.stateFile)); assert.equal(h.calls.filter(c => c[0] === 'delete').length, 1);
  }
});

test('Windows cleanup failure retains state and authenticated stop reports unconfirmed release', async () => {
  const h = harness(), controller = await h.api.createController({ workspace, stop: async () => {} });
  h.controls.cleanupDenied = true;
  await assert.rejects(h.api.requestStop({ workspace, timeoutMs: 5 }), { code: 'LAUNCHER_STATE_RETAINED' });
  assert(h.files.has(h.stateFile)); assert.equal(h.calls.filter(c => c[0] === 'delete').length, 1);
  await assert.rejects(controller.close(), { code: 'WINDOWS_PRIVATE_STATE_DENIED' });
});

test('Windows release accepts disappearance between existence and native read only after fresh ENOENT', async () => {
  const h = harness(); h.put(h.stateFile, h.state({ ownerPid: 4242 })); let snapshots = 0;
  h.controls.beforeSnapshot = file => { if (++snapshots === 2) h.files.delete(file); };
  h.controls.response = (_options, callback) => h.respond200(callback);
  assert.deepEqual(JSON.parse(JSON.stringify(await h.api.requestStop({ workspace }))), { stopped: true, controllerRecovered: false });
  assert.equal(snapshots, 2); assert.equal(h.files.has(h.stateFile), false);
  assert(!h.calls.some(c => c[0] === 'delete'));
});

test('Windows native read denial with still-present state remains a failure after authenticated response', async () => {
  const h = harness(); h.put(h.stateFile, h.state({ ownerPid: 4242 })); let snapshots = 0;
  h.controls.beforeSnapshot = () => { if (++snapshots === 2) throw denied(); };
  h.controls.response = (_options, callback) => h.respond200(callback);
  await assert.rejects(h.api.requestStop({ workspace }), { code: 'WINDOWS_PRIVATE_STATE_DENIED' });
  assert(h.files.has(h.stateFile)); assert(!h.calls.some(c => c[0] === 'delete'));
});
