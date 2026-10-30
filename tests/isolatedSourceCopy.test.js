'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const { CONTROLLED_FINFLOW_LOGS, createCopyFilter, copyIsolatedSource } = require('../scripts/lib/isolated-source-copy');

const ROOT = path.resolve(__dirname, '..');
const GIT = process.platform === 'darwin' && fs.existsSync('/Library/Developer/CommandLineTools/usr/bin/git')
  ? '/Library/Developer/CommandLineTools/usr/bin/git' : 'git';
const REVIEWED_FINFLOW_LOG_SHA256 = Object.freeze({
  'server/sensitive_files/logs/access.log': '44f13d63c97178c9d0434049d1e3c5694a23a28362a2422e5e2953349bad4992',
  'server/sensitive_files/logs/error.log': 'd06ca3d984446ec4592688eca9bc503d7e0d0f549b2b9df1e237fa3481a846ed',
  'server/sensitive_files/logs/audit.log': '3d99a2ffed2e3c3ab07819a446f51c189bd2b9154787baeab2ab8d79b80bb85d',
  'server/sensitive_files/logs/llm_requests.log': 'e3ea56185d1abd80ac16e977b562b22eb618abdffa943c44515b0e601c191c69',
});
const sha256 = filename => createHash('sha256').update(fs.readFileSync(filename)).digest('hex');

test('isolated source copy admits exactly the approved FinFlow log fixtures', () => {
  const include = createCopyFilter(ROOT);
  for (const relative of CONTROLLED_FINFLOW_LOGS) {
    assert.equal(include(path.join(ROOT, relative)), true, relative);
    assert.equal(sha256(path.join(ROOT, relative)), REVIEWED_FINFLOW_LOG_SHA256[relative], relative);
  }
  assert.equal(include(path.join(ROOT, 'server/sensitive_files/logs/unapproved.log')), false);
  assert.equal(include(path.join(ROOT, 'server/sensitive_files/logs/debug.log')), false);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-source-copy-'));
  const source = path.join(directory, 'synthetic-donor');
  const destination = path.join(directory, 'copy');
  const included = [...CONTROLLED_FINFLOW_LOGS, 'example.js', '.env.example'];
  const excluded = ['server/sensitive_files/logs/unapproved.log', 'server/sensitive_files/logs/debug.log',
    '.env', '.env.local', 'state.db', 'state.db-wal', 'state.sqlite', 'state.sqlite3-journal',
    '.git/config', 'node_modules/pkg/index.js', '.cache/data', 'coverage/report',
    'server/logs/runtime.log', 'server/uploads/file.txt', 'client/build/index.html',
    'server/database/vector-indexes/index.hnsw', 'server/config/secrets.env',
    'server/platform_secrets.json'];
  try {
    for (const relative of [...included, ...excluded]) {
      const filename = path.join(source, relative);
      fs.mkdirSync(path.dirname(filename), { recursive: true });
      fs.writeFileSync(filename, CONTROLLED_FINFLOW_LOGS.has(relative)
        ? fs.readFileSync(path.join(ROOT, relative))
        : `synthetic donor: ${relative}\n`);
    }
    copyIsolatedSource(source, destination);
    for (const relative of included) {
      if (CONTROLLED_FINFLOW_LOGS.has(relative)) {
        assert.equal(sha256(path.join(destination, relative)), REVIEWED_FINFLOW_LOG_SHA256[relative], relative);
      } else {
        assert.equal(fs.readFileSync(path.join(destination, relative), 'utf8'), `synthetic donor: ${relative}\n`, relative);
      }
    }
    for (const relative of excluded) assert.equal(fs.existsSync(path.join(destination, relative)), false, relative);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Git ignores every non-inventoried log while allowing the four controlled fixtures', () => {
  const repository = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-log-ignore-'));
  const fixtures = [...CONTROLLED_FINFLOW_LOGS];
  const excluded = [
    'server/sensitive_files/logs/debug.log',
    'server/sensitive_files/logs/unapproved.log',
    'server/sensitive_files/logs/notes.txt',
    'server/logs/runtime.log',
    'logs/runtime.log',
  ];
  try {
    fs.copyFileSync(path.join(ROOT, '.gitignore'), path.join(repository, '.gitignore'));
    for (const relative of [...fixtures, ...excluded]) {
      const target = path.join(repository, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, 'synthetic test fixture\n');
    }
    const gitHome = path.join(repository, 'home');
    const gitConfig = path.join(repository, 'xdg');
    fs.mkdirSync(gitHome);fs.mkdirSync(gitConfig);
    const gitEnv = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', HOME: gitHome, XDG_CONFIG_HOME: gitConfig };
    execFileSync(GIT, ['init', '-q'], { cwd: repository, timeout: 5000, env: gitEnv });
    const isIgnored = relative => spawnSync(GIT, ['check-ignore', '-q', '--', relative], { cwd: repository, timeout: 5000, env: gitEnv }).status === 0;
    for (const relative of fixtures) assert.equal(isIgnored(relative), false, relative);
    for (const relative of excluded) assert.equal(isIgnored(relative), true, relative);
  } finally {
    fs.rmSync(repository, { recursive: true, force: true });
  }
});

test('only byte-pinned synthetic MCP environment is copied; private and changed environment files stay excluded', t => {
  const fixture='sidecars/sandbox-runner/labfs/opt/app/config/.env';
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-env-copy-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const source=path.join(dir,'source');const destination=path.join(dir,'copy');
  const file=path.join(source,fixture);fs.mkdirSync(path.dirname(file),{recursive:true});
  fs.copyFileSync(path.join(ROOT,fixture),file);
  fs.writeFileSync(path.join(source,'.env'),'PRIVATE_TEST_SENTINEL=not-a-real-secret');
  fs.writeFileSync(path.join(source,'.env.local'),'PRIVATE_TEST_SENTINEL=not-a-real-secret');
  copyIsolatedSource(source,destination);
  assert.equal(sha256(path.join(destination,fixture)),sha256(file));
  assert.equal(fs.existsSync(path.join(destination,'.env')),false);
  assert.equal(fs.existsSync(path.join(destination,'.env.local')),false);
  fs.writeFileSync(file,'changed fixture');
  assert.throws(()=>createCopyFilter(source)(file),/fixture changed or is unsafe/);
  fs.unlinkSync(file);fs.symlinkSync(path.join(ROOT,fixture),file);
  assert.throws(()=>createCopyFilter(source)(file),/fixture changed or is unsafe/);
});
