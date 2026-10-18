#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { isolatedDatabaseGuard, selectIsolatedTests } = require('./lib/isolated-test-selection');
const nativeBrowserFiles = new Set(Object.values(require('./lib/native-browser-suites')).flat().map(row => row.file));
const nativeSecureShop = require('./lib/native-secureshop-suites');
const { artifactEnvironment, discoverSecrets, buildBoundary } = require('./lib/isolated-test-boundary');
const { discoveryReceipt, resultReceipt, writeJsonExclusive } = require('./lib/isolated-test-receipt');

const source = path.resolve(__dirname, '..');
const mode = process.argv[2] || 'unit';
if (mode === 'native-operator') {
  if (process.platform !== 'darwin') throw new Error('Native operator qualification is supported only on Darwin');
  if (process.argv.length !== 3) throw new Error('Native operator qualification accepts no extra arguments');
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-native-operator-')));
  fs.chmodSync(directory, 0o700);
  const env = {PATH:path.dirname(process.execPath), HOME:directory, TMPDIR:directory, LOGS_DIR:directory,
    NODE_ENV:'test', AI_PROVIDER:'mock', AWS_EC2_METADATA_DISABLED:'true'};
  const logPath = path.join(directory, 'tests.tap'), log = fs.openSync(logPath, 'wx', 0o600);
  const child = spawn(process.execPath, ['--test','--test-reporter=tap','--test-concurrency=1',
    '--test-timeout=60000','tests/legacyRamRagMaintenanceOperator.test.js','tests/legacyRamRagOperator.test.js','tests/setupLocalProcessIdentity.test.js'],
    {cwd:source,env,detached:true,stdio:['ignore',log,log]});
  let timedOut = false, finalized = false, interrupted = null;
  const retire = () => { if(Number.isSafeInteger(child.pid)&&child.pid>1)try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;} };
  const timer = setTimeout(() => {timedOut=true;retire();},480000);
  const finish = async (code,signal,error) => {
    if(finalized)return;finalized=true;clearTimeout(timer);
    try {
      retire(); fs.closeSync(log);
      let groupAbsent = !(Number.isSafeInteger(child.pid)&&child.pid>1);
      const deadline = Date.now() + 5000;
      while (!groupAbsent && Date.now() < deadline) {
        try { process.kill(-child.pid,0); }
        catch (failure) { if(failure.code==='ESRCH')groupAbsent=true;else throw failure; }
        if(!groupAbsent)await new Promise(resolve=>setTimeout(resolve,50));
      }
      const output=fs.readFileSync(logPath,'utf8');
      const count = label => Number(output.match(new RegExp('^# '+label+' (\\d+)$','m'))?.[1] ?? NaN);
      const expectedNames=["CLI requires the complete explicit identity and normalized private output arguments", "Linux hidden proc entries require ESRCH; live, EPERM, unknown and unavailable procfs deny", "Linux proc start ticks parse losslessly and PID reuse still refuses before absence", "a lost enter response after mutation conditionally rolls back from the durable record", "a partial password write restores an arbitrary disabled original environment", "an injected post-cleanup uncertainty after gate application invokes conditional rollback", "closed identities reject malformed foreign host boot operation and parent binding", "failed stable drain rolls back the exact prior gate and records rollback", "historical auth refuses a cached factory hash mismatch before mutation", "historical auth uses its exact cached factory contract and a stable tracked HTTP drain", "live reused identity is refused without birth comparison or signaling", "operator binds exact process identity, captures once, closes inspector and writes private receipt", "permission and malformed process probe responses are unknown, never absent", "read-only preflight verifies cached gate semantics, then enter persists restoration authority and explicit restore reopens prior state", "real cooperative child v2 retains live test parent in complete chain after child exit", "real owned parent and child refuse while alive then establish only recorded absence after cooperative exit", "symlink workspace cannot bind a process proof", "unsafe integer process table values fail closed on macOS", "v2 captures complete bounded chain and rejects every live ancestor or reused PID", "v2 records foreign UID boundary without treating it as owned or authorizing recovery", "v2 refuses reparenting, cycles, truncation and malformed boundary"];
      const actualNames=[...output.matchAll(/^# Subtest: (.+)$/gm)].map(match=>match[1]).sort();
      const exactNames=JSON.stringify(actualNames)===JSON.stringify(expectedNames);
      const passed=exactNames&&groupAbsent&&!error&&!timedOut&&!interrupted&&code===0&&count('tests')===21&&count('pass')===21&&count('fail')===0&&count('skipped')===0;
      const receipt={scope:'Owned synthetic process native operator qualification only',passed,code,signal,timedOut,interrupted,groupAbsent,exactNames,
        tests:count('tests'),pass:count('pass'),fail:count('fail'),skipped:count('skipped'),logPath,
        limitation:'Does not qualify an installed application or replace the unit sandbox gate'};
      fs.writeFileSync(path.join(directory,'result.json'),JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
      console.log(JSON.stringify(receipt));process.exitCode=passed?0:1;
    } catch(failure){console.error(failure.message);process.exitCode=1;}
    finally {process.off('SIGTERM',onTerm);process.off('SIGINT',onInt);}
  };
  const onSignal = signal => {
    interrupted ||= signal;
    try {retire();} catch(error) {void finish(null,signal,error);return;}
    void finish(null,signal,new Error('Native operator interrupted'));
  };
  const onTerm=()=>onSignal('SIGTERM'),onInt=()=>onSignal('SIGINT');
  process.on('SIGTERM',onTerm);process.on('SIGINT',onInt);
  child.once('error',error=>finish(null,null,error));child.once('exit',(code,signal)=>finish(code,signal));
} else {
if (!['unit', 'secureshop', 'postgres'].includes(mode)) throw new Error('Expected unit, secureshop or postgres');
if (mode === 'postgres') throw new Error('PostgreSQL tests require their separately reviewed owned native launcher; main-source aggregate does not dispatch it');
const focusedFiles = selectIsolatedTests(source, mode, process.argv.slice(3));
// Historical qualification suites require explicitly retained local artifacts, never default unit discovery.
const {retainedEvidenceSuites, isDefaultUnitSuite} = require('./lib/retained-evidence-suites');
const serverRequired = new Set(['api.test.js', 'ctfHintCost.smoke.test.js', 'promptInjection.test.js', 'solutions.test.js', 'frontend.test.js']);
if (focusedFiles?.some(filename => serverRequired.has(path.basename(filename)))) {
  throw new Error('Server-required tests need their separate owned integration harness');
}
const destination = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dvaia-regression-')));
fs.chmodSync(destination, 0o700);

const env = Object.fromEntries(['PATH', 'HOME', 'USERPROFILE', 'SYSTEMROOT', 'COMSPEC', 'TEMP', 'TMP', 'TMPDIR', 'PUPPETEER_EXECUTABLE_PATH', 'PUPPETEER_CACHE_DIR'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
// Shell-spawned Node commands must use the same runtime as this verifier.
env.PATH = require('./lib/isolated-runtime-path').isolatedRuntimePath(destination, env.PATH);
Object.assign(env, { NODE_ENV: 'test', AI_PROVIDER: 'mock', OLLAMA_MODEL: 'llama3.1:8b', OLLAMA_BASE_URL: 'http://127.0.0.1:1',
  PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
  // Disposable data does not isolate live sidecar state.
  // Broad regressions must never rotate workshop keys or clear the learner's
  // shared mail sink. Real effects have explicit owned-sidecar qualifications.
  SANDBOX_RUNNER_URL: 'http://127.0.0.1:1', SSRF_TARGET_URL: 'http://127.0.0.1:1',
  ROGUE_MCP_URL: 'http://127.0.0.1:1', MAILPIT_API_URL: 'http://127.0.0.1:1',
  MAILPIT_SMTP_HOST: '127.0.0.1', MAILPIT_SMTP_PORT: '1',
  DVAIA_ISOLATED_TEST_WORKSPACE: source,
  AWS_EC2_METADATA_DISABLED: 'true', MCP_WORKSHOP_AUTOSTART: 'false', MCP_SIDECARS_AUTOSTART: 'false', SS_ENABLE: 'false', HF_HUB_OFFLINE: '1' });

Object.assign(env, artifactEnvironment(destination));
for (const key of ['SECURESHOP_UPLOAD_ROOT','LOGS_DIR','LEGACY_SENSITIVE_FILES_ROOT','HOME','TMPDIR','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME']) fs.mkdirSync(env[key],{recursive:true,mode:0o700});
const maskRoot=path.join(destination,'boundary-masks');fs.mkdirSync(maskRoot,{mode:0o700});fs.mkdirSync(path.join(maskRoot,'empty-dir'),{mode:0o500});fs.writeFileSync(path.join(maskRoot,'empty-file'),'',{mode:0o400});
const secrets = discoverSecrets(fs.realpathSync(source), os.homedir());
// Construct and validate before any initializer/test child; no unsandboxed fallback.
const boundary = (executable,args) => buildBoundary({source,directory:destination,secrets,executable,args});
boundary(process.execPath,[]);

async function run(args, logName, timeoutMs = 300000, executable = process.execPath) {
  const log = fs.openSync(path.join(destination, logName), 'wx', 0o600);
  try {
    return await new Promise((resolve, reject) => {
      const fenced = boundary(executable,args);
      const child = spawn(fenced.command, fenced.args, { cwd: fenced.cwd, env, detached: process.platform !== 'win32', stdio: ['ignore', log, log] });
      let timedOut = false;
      const stop = () => {
        if (!Number.isSafeInteger(child.pid) || child.pid <= 1) return;
        if (process.platform === 'win32') spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore' });
        else { try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
      };
      const timer = setTimeout(() => { timedOut = true; stop(); }, timeoutMs);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', (code, signal) => { clearTimeout(timer); resolve({ code, signal, timedOut }); });
    });
  } finally { fs.closeSync(log); }
}

(async () => {
  console.log(`Isolated ${mode} regression workspace: ${destination}`);
  console.log(`Regression runtime: Node ${process.version}`);
  for (const directory of ['node_modules', path.join('client','node_modules')]) {
    if (!fs.existsSync(path.join(source,directory))) throw new Error(`Install dependencies first: ${directory}`);
  }
  const logs = env.LOGS_DIR;
  for (const name of ['access', 'error', 'audit', 'llm_requests']) fs.writeFileSync(path.join(logs, `${name}.log`), 'Synthetic regression fixture\n');
  if (mode === 'secureshop') nativeSecureShop.validateRegistry(source);
  const discoveredFiles = focusedFiles || (mode === 'unit'
    ? fs.readdirSync(path.join(source, 'tests')).filter(name => !nativeBrowserFiles.has(`tests/${name}`) && !['legacyRamRagMaintenanceOperator.test.js','legacyRamRagOperator.test.js','setupLocalProcessIdentity.test.js','transformers43QualificationRunner.test.js'].includes(name) && isDefaultUnitSuite(name, serverRequired)).sort().map(name => `tests/${name}`)
    : fs.readdirSync(path.join(source,'tests/secureshop'),{recursive:true,withFileTypes:true}).filter(entry=>entry.isFile()&&entry.name.endsWith('.test.js')).map(entry=>path.relative(source,path.join(entry.parentPath,entry.name)).split(path.sep).join('/')).sort());
  const partition = mode === 'secureshop'
    ? nativeSecureShop.partitionSecureShopTests(discoveredFiles)
    : { files: discoveredFiles, deferred: [] };
  const files = partition.files.filter(file => !nativeBrowserFiles.has(file));
  if (partition.deferred.length) console.log(`Deferred native PostgreSQL/browser qualification (${partition.deferred.length} files): ${nativeSecureShop.command}; not included in controlled pass`);
  if(mode==='secureshop')console.log('Deferred native SecureShop E2E: node scripts/test-native-browser.js --secureshop-e2e; fixed four browser flows excluded from this aggregate');
  if (focusedFiles) console.log(`Focused isolated tests: ${focusedFiles.join(', ')}`);
  if (mode === 'unit') console.log(`Retained-evidence qualification suites require explicit opt-in and local artifacts: ${retainedEvidenceSuites.join(', ')}`);
  if (mode === 'unit') console.log(`Deferred native browser qualification: ${[...nativeBrowserFiles].join(', ')}; run npm run test:native-browser or npm run test:admin-bundle for the admin bundle, or node scripts/test-native-browser.js --secureshop / --xss for the corresponding suites (not included in unit pass)`);
  if (mode === 'unit') console.log('Deferred native operator qualification: legacyRamRagMaintenanceOperator.test.js, legacyRamRagOperator.test.js, setupLocalProcessIdentity.test.js; run npm run test:native-operator (not included in unit pass)');
  if (mode === 'unit') console.log('Deferred native verifier process qualification: node --test --test-timeout=15000 tests/transformers43QualificationRunner.test.js (not included in unit pass)');
  if (mode === 'unit') console.log(`Server-required suites are separate: ${[...serverRequired].join(', ')}`);
  const discovery = discoveryReceipt({ mode, focused: focusedFiles !== null, files, deferredNative: partition.deferred,
    boundaryKind: process.platform === 'darwin' ? 'sandbox-exec' : 'bubblewrap' });
  const discoveryArtifact = writeJsonExclusive(destination, 'discovery.json', discovery);
  const childArgs = ['--require', isolatedDatabaseGuard(source),
    '--test', '--test-concurrency=1', '--test-timeout=180000', ...files];
  const result = await run(childArgs, 'tests.log', 900000);
  const output = fs.readFileSync(path.join(destination, 'tests.log'), 'utf8');
  const completed = resultReceipt({ discovery, discoverySha256: discoveryArtifact.sha256,
    argv: childArgs, result, testsLog: path.join(destination, 'tests.log') });
  writeJsonExclusive(destination, 'result.json', completed);
  console.log(output.split('\n').filter(line => /^(?:ℹ|# (?:tests|pass|fail|skip)|✖)/.test(line)).slice(-40).join('\n'));
  if (!completed.passed) throw new Error(`Regression failed (${result.signal || result.code || 'invalid receipt'}); logs retained at ${destination}`);
  console.log(`Regression passed; logs: ${path.join(destination, 'tests.log')}`);
})().catch(error => { console.error(error.message); process.exitCode = 1; });

}
