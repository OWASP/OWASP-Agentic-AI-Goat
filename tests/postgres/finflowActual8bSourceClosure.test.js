'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const sourceRoot = path.resolve(__dirname, '..', '..');
const entries = [
  'tests/postgres/finflowReconActual8b.integration.test.js',
  'server/routes/sensitiveInfoWorkshop.js',
];
const localRequire = /\brequire\s*\(\s*(['"])(\.[^'"]+)\1\s*\)/g;

function resolveLocal(fromFile, request) {
  const unresolved = path.resolve(path.dirname(fromFile), request);
  const candidates = [
    unresolved,
    `${unresolved}.js`,
    `${unresolved}.json`,
    path.join(unresolved, 'index.js'),
    path.join(unresolved, 'index.json'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
  }
  return null;
}

function literalLocalClosure() {
  const pending = entries.map(entry => path.join(sourceRoot, entry));
  const visited = new Set();
  const unresolved = [];
  while (pending.length) {
    const file = pending.pop();
    const relative = path.relative(sourceRoot, file).split(path.sep).join('/');
    assert.ok(relative && !relative.startsWith('../'), `local dependency escaped source root: ${file}`);
    if (visited.has(relative)) continue;
    const stat = fs.lstatSync(file);
    assert.equal(stat.isSymbolicLink(), false, `local dependency must not be a symlink: ${relative}`);
    assert.equal(stat.isFile(), true, `local dependency must be a regular file: ${relative}`);
    visited.add(relative);
    if (!/\.(?:c?js|mjs)$/.test(file)) continue;
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(localRequire)) {
      const resolved = resolveLocal(file, match[2]);
      if (!resolved) unresolved.push(`${relative} -> ${match[2]}`);
      else pending.push(resolved);
    }
  }
  return { visited, unresolved };
}

test('mounted FinFlow route has a complete literal local dependency closure', () => {
  const { visited, unresolved } = literalLocalClosure();
  assert.deepEqual(unresolved, []);
  assert.ok(visited.has('server/database/postgres/workshopProgressTimePredicate.js'));
  assert.ok(visited.has('server/routes/sensitiveInfoWorkshop.js'));
  assert.ok(visited.size >= 200, `unexpectedly narrow mounted closure: ${visited.size}`);
});

test('production FinFlow router mounts without database, model, or network execution', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-finflow-closure-'));
  const appData = path.join(tempRoot, 'app-data');
  const logs = path.join(appData, 'logs');
  fs.mkdirSync(logs, { recursive: true, mode: 0o700 });
  const probe = String.raw`
    const blocked = name => function blockedOfflineOperation() {
      throw new Error('offline closure preflight attempted ' + name);
    };
    globalThis.fetch = blocked('fetch');
    const net = require('node:net');
    net.Socket.prototype.connect = blocked('net.connect');
    const http = require('node:http');
    const https = require('node:https');
    http.request = blocked('http.request'); http.get = blocked('http.get');
    https.request = blocked('https.request'); https.get = blocked('https.get');
    const pg = require('pg');
    pg.Pool.prototype.connect = blocked('pg.connect');
    pg.Pool.prototype.query = blocked('pg.query');
    const express = require('express');
    const router = require('./server/routes/sensitiveInfoWorkshop');
    const app = express();
    app.use('/api/workshop/sensitive-info', router);
    if (typeof app.handle !== 'function' || typeof router.handle !== 'function') {
      throw new Error('mounted FinFlow route contract unavailable');
    }
    process.stdout.write('FINFLOW_SOURCE_CLOSURE_MOUNTED\n');
  `;
  try {
    const env = {
      PATH: process.env.PATH || '',
      HOME: process.env.HOME || tempRoot,
      TMPDIR: process.env.TMPDIR || os.tmpdir(),
      NODE_ENV: 'test',
      PLATFORM_DATABASE_ENGINE: 'postgres',
      WORKSHOP_DATABASE_ENGINE: 'postgres',
      JWT_SECRET: 'offline-source-closure-only-32-bytes',
      IDENTITY_DATABASE_URL: 'postgresql://offline:offline@127.0.0.1:1/offline',
      FINFLOW_WORKSHOP_DATABASE_URL: 'postgresql://offline:offline@127.0.0.1:1/offline',
      DVAIA_APP_DATA_ROOT: appData,
      LOGS_DIR: logs,
    };
    const result = spawnSync(process.execPath, ['-e', probe], {
      cwd: sourceRoot,
      env,
      encoding: 'utf8',
      timeout: 20_000,
    });
    assert.equal(result.error, undefined, result.error?.stack);
    assert.equal(result.signal, null, `source closure probe signal: ${result.signal}`);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /FINFLOW_SOURCE_CLOSURE_MOUNTED/);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
