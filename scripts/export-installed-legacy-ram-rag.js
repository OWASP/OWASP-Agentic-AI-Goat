#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { exportThroughOwnedInspector, tcpOpen } = require('../tests/fixtures/legacyRamRagInspectorLifecycle');

const SCOPE = 'installed-legacy-ram-rag-final-snapshot-v1';
const text = value => String(value).trim();
const sha = value => crypto.createHash('sha256').update(value).digest('hex');

function privateDirectory(directory) {
  const real = fs.realpathSync(directory), stat = fs.lstatSync(real);
  if (real !== directory || !stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) throw Error('Private owned directory required');
  return real;
}

function processField(pid, field, exec = execFileSync) {
  return text(exec('/bin/ps', ['-p', String(pid), '-o', `${field}=`], { encoding: 'utf8', maxBuffer: 4096 }));
}

function lsofIdentity(pid, exec = execFileSync) {
  const rows = String(exec('/usr/sbin/lsof', ['-a', '-p', String(pid), '-d', 'cwd,txt', '-Fn'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 })).split(/\r?\n/);
  let kind = null, cwd = null, executable = null;
  for (const row of rows) {
    if (row === 'fcwd') kind = 'cwd';
    else if (row === 'ftxt') kind = 'txt';
    else if (row.startsWith('n') && kind === 'cwd' && cwd === null) cwd = row.slice(1);
    else if (row.startsWith('n') && kind === 'txt' && executable === null) executable = row.slice(1);
  }
  if (!cwd || !executable) throw Error('Process filesystem identity unavailable');
  return { cwd: fs.realpathSync(cwd), executable: fs.realpathSync(executable) };
}

function inspectProcess({ pid, expectedUid, expectedStartTime, expectedCwd, expectedExecutable }, adapters = {}) {
  if (!Number.isSafeInteger(pid) || pid < 1 || !Number.isSafeInteger(expectedUid) || expectedUid < 0
      || typeof expectedStartTime !== 'string' || !expectedStartTime.trim()
      || !path.isAbsolute(expectedCwd || '') || !path.isAbsolute(expectedExecutable || '')) throw TypeError('Explicit process identity required');
  const exec = adapters.exec || execFileSync;
  const observed = { pid, uid: Number(processField(pid, 'uid', exec)), startTime: processField(pid, 'lstart', exec), ...lsofIdentity(pid, exec) };
  const expected = { pid, uid: expectedUid, startTime: expectedStartTime.trim(), cwd: fs.realpathSync(expectedCwd), executable: fs.realpathSync(expectedExecutable) };
  if (JSON.stringify(observed) !== JSON.stringify(expected)) throw Error('Observed process identity mismatch');
  return observed;
}

function health(url, request = http.get) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || parsed.username || parsed.password || parsed.hash) throw TypeError('Exact loopback health URL required');
  return new Promise((resolve, reject) => {
    let settled = false, bytes = 0, chunks = [], handle;
    const timer = setTimeout(() => finish(Error('Health request timed out')), 3000);
    const finish = (error, value) => { if (settled) return;settled = true;clearTimeout(timer);handle?.destroy();error ? reject(error) : resolve(value); };
    handle = request(parsed, response => {
      response.on('data', chunk => { bytes += chunk.length;if (bytes > 4096)return finish(Error('Health response exceeded bound'));chunks.push(chunk); });
      response.once('error', finish);response.once('end', () => {
        try { const body = Buffer.concat(chunks);const value = JSON.parse(body);if (response.statusCode !== 200 || value?.status !== 'healthy')throw Error('Application health rejected');finish(null,{statusCode:200,bodySha256:sha(body)}); } catch (error) { finish(error); }
      });
    });
    handle.once('error', finish);
  });
}

function durablePrivateFile(filename, value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`), descriptor = fs.openSync(filename, 'wx', 0o600);
  try { fs.writeFileSync(descriptor, bytes);fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  const parent = fs.openSync(path.dirname(filename), fs.constants.O_RDONLY);try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  return { bytes: bytes.length, sha256: sha(bytes) };
}

async function run(options, adapters = {}) {
  const parent = privateDirectory(path.dirname(options.output));
  if (path.dirname(options.output) !== parent || fs.existsSync(options.output)) throw Error('New private output directory required');
  const expectedModule = fs.realpathSync(options.expectedModule), beforeIdentity = inspectProcess(options, adapters);
  const beforeHealth = await health(options.healthUrl, adapters.request);
  if (await tcpOpen(options.inspectorPort)) throw Error('Inspector port must initially be closed');
  fs.mkdirSync(options.output, { mode: 0o700 });privateDirectory(options.output);
  const archive = path.join(options.output, 'legacy-rag-origin.json');
  const capture = await (adapters.exporter || exportThroughOwnedInspector)({ pid: options.pid, port: options.inspectorPort,
    expectedModule, output: archive, timeoutMs: options.timeoutMs || 10000 });
  const afterIdentity = inspectProcess(options, adapters), afterHealth = await health(options.healthUrl, adapters.request);
  if (await tcpOpen(options.inspectorPort)) throw Error('Inspector listener remained open');
  const receipt = { version: 1, scope: SCOPE, status: 'passed', process: beforeIdentity, sameProcessAfter: JSON.stringify(beforeIdentity) === JSON.stringify(afterIdentity),
    expectedModule, inspectorPort: options.inspectorPort, inspectorClosed: true, health: { before: beforeHealth, after: afterHealth }, archive: { file: 'legacy-rag-origin.json', ...capture } };
  if (!receipt.sameProcessAfter) throw Error('Process identity changed after export');
  const receiptDigest = durablePrivateFile(path.join(options.output, 'receipt.json'), receipt);
  return { scope: SCOPE, status: 'passed', output: options.output, receipt: receiptDigest };
}

function parse(argv) {
  const values = {};for (let index = 0; index < argv.length; index += 2) { const key = argv[index], value = argv[index + 1];if (!key?.startsWith('--') || value === undefined || Object.hasOwn(values, key)) throw TypeError('Explicit unique CLI arguments required');values[key] = value; }
  const required = ['--pid','--uid','--start-time','--cwd','--executable','--module','--inspector-port','--health-url','--output'];if (required.some(key => !Object.hasOwn(values, key)) || Object.keys(values).some(key => !required.includes(key))) throw TypeError(`Required: ${required.join(' ')}`);
  const pid = Number(values['--pid']), expectedUid = Number(values['--uid']), inspectorPort = Number(values['--inspector-port']);
  if (![pid,expectedUid,inspectorPort].every(Number.isSafeInteger) || pid < 1 || expectedUid < 0 || inspectorPort < 1 || inspectorPort > 65535) throw TypeError('Numeric identity arguments invalid');
  for (const key of ['--cwd','--executable','--module','--output'])if (!path.isAbsolute(values[key]) || path.normalize(values[key]) !== values[key]) throw TypeError('Absolute normalized path required');
  return { pid, expectedUid, expectedStartTime: values['--start-time'], expectedCwd: values['--cwd'], expectedExecutable: values['--executable'], expectedModule: values['--module'], inspectorPort, healthUrl: values['--health-url'], output: values['--output'] };
}

if (require.main === module) { let options;try { options = parse(process.argv.slice(2)); } catch (error) { console.error(JSON.stringify({ scope:SCOPE,status:'failed',code:'INVALID_ARGUMENTS' }));process.exitCode=1;options=null; }if (options)run(options).then(result=>console.log(JSON.stringify(result))).catch(error=>{console.error(JSON.stringify({scope:SCOPE,status:'failed',code:error.code||'FINAL_RAM_SNAPSHOT_FAILED'}));process.exitCode=1;}); }
module.exports = { SCOPE, parse, inspectProcess, health, run };
