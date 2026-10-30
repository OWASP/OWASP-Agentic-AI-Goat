#!/usr/bin/env node
'use strict';

// Explicit focused unit runner for repository-only environments. This is not
// the historical isolated aggregate: it does not copy source or use a native
// database/browser/model. The child gets read-only source and one writable
// private directory below tasks/tmp.
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const {spawn} = require('node:child_process');
const {selectIsolatedTests, isolatedDatabaseGuard} = require('./lib/isolated-test-selection');
const {artifactEnvironment} = require('./lib/isolated-test-boundary');
const {tapCounts, writeJsonExclusive} = require('./lib/isolated-test-receipt');

const source = fs.realpathSync(path.resolve(__dirname, '..'));
const runtimeParent = path.join(source, 'tasks/tmp');
const forbidden = new Set(['api.test.js', 'ctfHintCost.smoke.test.js',
  'promptInjection.test.js', 'solutions.test.js', 'frontend.test.js',
  'secureshopUserLookupAssessmentRoute.test.js']);

function selectFiles(requested) {
  if (!requested.length) throw new Error('Explicit focused tests/*.test.js files required');
  const files = selectIsolatedTests(source, 'unit', requested);
  if (!files || files.some(file => forbidden.has(path.basename(file))))
    throw new Error('Server-required suites need a separate owned integration harness');
  return files;
}

function privateRuntime() {
  const directory = process.env.OWASP_AI_GOAT_REPO_LOCAL_UNIT_RUNTIME;
  if (typeof directory !== 'string' || !directory.startsWith(`${runtimeParent}${path.sep}`)
      || path.dirname(directory) !== runtimeParent || !/^focused-unit\.[A-Za-z0-9]+$/.test(path.basename(directory)))
    throw new Error('Focused unit runner requires the repository-only wrapper mode');
  const actual = fs.realpathSync(directory), stat = fs.lstatSync(directory);
  if (actual !== directory || !stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0)
    throw new Error('Repository test runtime must be private, canonical and owned');
  return directory;
}

function childEnvironment(directory) {
  const {HOME: _home, USERPROFILE: _userProfile, ...data} = artifactEnvironment(directory);
  return {
    ...data,
    PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
    NODE_ENV: 'test', AI_PROVIDER: 'mock', OLLAMA_MODEL: 'llama3.1:8b',
    OLLAMA_BASE_URL: 'http://127.0.0.1:1',
    PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
    SANDBOX_RUNNER_URL: 'http://127.0.0.1:1', SSRF_TARGET_URL: 'http://127.0.0.1:1',
    ROGUE_MCP_URL: 'http://127.0.0.1:1', MAILPIT_API_URL: 'http://127.0.0.1:1',
    MAILPIT_SMTP_HOST: '127.0.0.1', MAILPIT_SMTP_PORT: '1',
    OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE: source,
    OWASP_AI_GOAT_REPO_LOCAL_UNIT_RUNTIME: directory,
    AWS_EC2_METADATA_DISABLED: 'true', MCP_WORKSHOP_AUTOSTART: 'false',
    MCP_SIDECARS_AUTOSTART: 'false', SS_ENABLE: 'false', HF_HUB_OFFLINE: '1',
    PUPPETEER_CACHE_DIR: path.join(directory, 'browser-cache'),
  };
}

async function probeBoundary() {
  const protectedSource = path.join(source, 'scripts/test-repo-local-unit.js');
  let sourceWriteDenied = false;
  try {
    const handle = fs.openSync(protectedSource, 'r+');
    fs.closeSync(handle);
  } catch (error) {
    sourceWriteDenied = ['EPERM', 'EACCES'].includes(error.code);
    if (!sourceWriteDenied) throw error;
  }
  if (!sourceWriteDenied) throw new Error('Focused unit source-write boundary absent');
  const networkError = await new Promise((resolve, reject) => {
    const socket = net.createConnection({host: '127.0.0.1', port: 1});
    socket.setTimeout(1500, () => {socket.destroy(); reject(new Error('Network denial probe timed out'));});
    socket.once('error', resolve);
    socket.once('connect', () => {socket.destroy(); resolve(null);});
  });
  if (!networkError || !['EPERM', 'EACCES'].includes(networkError.code))
    throw new Error('Focused unit network boundary absent');
  return Object.freeze({sourceWriteDenied, networkDenied: true});
}

async function main(requested = process.argv.slice(2)) {
  const files = selectFiles(requested);
  const directory = privateRuntime();
  const boundaryProbe = await probeBoundary();
  const env = childEnvironment(directory);
  for (const key of ['SECURESHOP_UPLOAD_ROOT', 'LOGS_DIR', 'LEGACY_SENSITIVE_FILES_ROOT',
    'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME'])
    fs.mkdirSync(env[key], {recursive: true, mode: 0o700});
  const args = ['--require', isolatedDatabaseGuard(source), '--test',
    '--test-reporter=tap', '--test-concurrency=1', '--test-timeout=180000', ...files];
  const logPath = path.join(directory, 'tests.tap');
  const log = fs.openSync(logPath, 'wx', 0o600);
  let timedOut = false;
  let interrupted = null;
  let child;
  const stop = () => {
    if (!Number.isSafeInteger(child?.pid) || child.pid <= 1) return;
    try { process.kill(-child.pid, 'SIGKILL'); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
  };
  const onTerm = () => {interrupted = 'SIGTERM'; stop();};
  const onInt = () => {interrupted = 'SIGINT'; stop();};
  process.on('SIGTERM', onTerm);
  process.on('SIGINT', onInt);
  try {
    const result = await new Promise((resolve, reject) => {
      child = spawn(process.execPath, args,
        {cwd: source, env, detached: true, stdio: ['ignore', log, log]});
      const timer = setTimeout(() => { timedOut = true; stop(); }, 300000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', (code, signal) => { clearTimeout(timer); resolve({code, signal}); });
    });
    const output = fs.readFileSync(logPath, 'utf8');
    const counts = tapCounts(output);
    const passed = result.code === 0 && result.signal === null && !timedOut && !interrupted
      && counts.tests !== null && counts.fail === 0 && counts.skipped === 0
      && counts.pass === counts.tests;
    const receipt = {schemaVersion: 1, kind: 'repo-local-focused-unit-result',
      passed, files, counts, code: result.code, signal: result.signal, timedOut, interrupted,
      sourceReadOnlyBoundary: boundaryProbe.sourceWriteDenied,
      networkDenied: boundaryProbe.networkDenied, applicationDatabaseAccessDenied: true,
      nativeQualificationAccepted: false,
      limitation: 'Focused controlled unit result only; no source copy, native store, browser, or actual-model qualification.'};
    writeJsonExclusive(directory, 'result.json', receipt);
    process.stdout.write(`${JSON.stringify({receipt: path.join(directory, 'result.json'), ...receipt})}\n`);
    if (!passed) process.exitCode = 1;
  } finally {
    process.off('SIGTERM', onTerm);
    process.off('SIGINT', onInt);
    fs.closeSync(log);
  }
}

if (require.main === module) main().catch(error => {process.stderr.write(`${error.message}\n`); process.exitCode = 1;});
module.exports = Object.freeze({selectFiles, childEnvironment, probeBoundary});
