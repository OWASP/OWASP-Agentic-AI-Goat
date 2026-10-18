'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const { VERSION, ISOLATION, hash, normalizeRequest, requestDigest } = require('./contract');
const INIT = '/usr/local/libexec/dvaia-system-config-init';
const SUPERVISOR = '/usr/local/libexec/dvaia-system-config-supervisor';
const CLEAN_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const ATTESTATION = Buffer.from('system-config-init-v1 uid=10001 gid=10001 caps=zero bounding=zero ambient=zero nnp=1\n');
const ASSET_HASHES = Object.freeze({
  'worker.js': '8c16b4644aa9a33f0930fd7ba9f3f63194ffa0f27d3d143481ffd615f872155c',
  'config-reader.js': '017f8351f4677ea4e2f23d8677de5a7336ff15ddcebd2bf43747e742f0736b73',
  'contract.js': 'f197254bc1c683989737ba819ac1c2e79f0262b57dc963439013c3cfb14923e9',
});
const FIXTURES = Object.freeze({
  '/app/config/application.json': '{"application":"SecureShop owned System fixture","environment":"synthetic-only"}\n',
  '/app/.env': 'SECURESHOP_SYSTEM_FIXTURE=true\nSYSTEM_SECRET=TRAINING-OWNED-SYSTEM-CONFIG-ONLY\n',
  '/app/platform_secrets.json': '{"synthetic":true,"api_key":"TRAINING-OWNED-SYSTEM-API-KEY-ONLY","session_token":"TRAINING-OWNED-SYSTEM-SESSION-TOKEN-ONLY"}\n',
});
// JSON escaping can expand text sixfold, followed by base64 expansion. The
// reader's512KiB upper bound plus path metadata remains below this hard cap.
const MAX_CAPTURE_BYTES = 5 * 1024 * 1024;
const MAX_STDERR_BYTES = 16 * 1024;
const NAMESPACE = Object.freeze(['--cap-drop', 'ALL', '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_SETPCAP',
  '--unshare-user', '--unshare-net', '--unshare-pid', '--unshare-uts', '--unshare-ipc']);
function error(code, message) { return Object.assign(new Error(message), { code }); }
function loadAssets(read = fs.readFileSync) {
  const assets = {};
  for (const [name, expected] of Object.entries(ASSET_HASHES)) {
    const bytes = read(path.join(__dirname, name));
    if (hash(bytes) !== expected) throw error('SYSTEM_CONFIG_ASSET_INVALID', 'System config asset checksum mismatch');
    assets[name] = Buffer.from(bytes);
  }
  return assets;
}
function namespaceArgv(runtimeMounts) {
  return [...NAMESPACE, '--die-with-parent', '--new-session', '--clearenv',
    ...runtimeMounts.flatMap(entry => ['--ro-bind', entry, entry]),
    '--tmpfs', '/usr/local/libexec', '--ro-bind', INIT, INIT,
    '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--tmpfs', '/work', '--chdir', '/work',
    '--setenv', 'PATH', CLEAN_PATH];
}
function buildReadArgv(raw, marker, runtimeMounts = ['/usr', '/bin', '/lib', '/lib64']) {
  const request = normalizeRequest(raw);
  if (!/^__SYSTEM_CONFIG_[0-9a-f]{64}__$/.test(marker)) throw new TypeError('Invalid System marker');
  const argv = [...namespaceArgv(runtimeMounts), '--dir', '/opt', '--dir', '/opt/system-config', '--tmpfs', '/app', '--dir', '/app/config'];
  for (const [index, name] of Object.keys(ASSET_HASHES).entries()) argv.push('--ro-bind-data', String(index + 4), `/opt/system-config/${name}`);
  for (const [index, name] of Object.keys(FIXTURES).entries()) argv.push('--file', String(index + 7), name);
  return [...argv, '--remount-ro', '/app', '--hostname', `system-${hash(request.operationId).slice(0,20)}`, INIT, '--read', Buffer.from(JSON.stringify(request)).toString('base64'), marker];
}
function decodeRead(stdout, marker, request) {
  if (!stdout.subarray(0, ATTESTATION.length).equals(ATTESTATION)) throw error('SYSTEM_CONFIG_RESULT_INVALID', 'System worker attestation missing');
  const encoded = stdout.subarray(ATTESTATION.length).toString('utf8');
  if (!encoded.startsWith(marker)) throw error('SYSTEM_CONFIG_RESULT_INVALID', 'System worker result missing');
  const text = encoded.slice(marker.length);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || Buffer.from(text,'base64').toString('base64') !== text) throw error('SYSTEM_CONFIG_RESULT_INVALID', 'System worker encoding invalid');
  const receipt = JSON.parse(Buffer.from(text,'base64').toString('utf8'));
  if (Object.keys(receipt).sort().join(',') !== 'isolation,operationId,readResult,requestSha256,version'
      || receipt.version !== VERSION || receipt.isolation !== ISOLATION || receipt.operationId !== request.operationId
      || receipt.requestSha256 !== requestDigest(request)) throw error('SYSTEM_CONFIG_RESULT_INVALID', 'System receipt identity mismatch');
  const read = receipt.readResult;
  const sanitized = request.path.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
  const resolved = path.posix.resolve('/app/config', sanitized);
  const absolute = request.path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(request.path) || request.path.startsWith('\\\\');
  const contained = resolved === '/app' || resolved.startsWith('/app/');
  const expected = !absolute && contained ? FIXTURES[resolved] : undefined;
  if (expected !== undefined) {
    if (!read || Object.keys(read).sort().join(',') !== 'content,contentSha256,input,ok,sanitized,size,targetPath'
        || read.ok !== true || read.input !== request.path || read.sanitized !== sanitized || read.targetPath !== resolved
        || read.content !== expected || read.size !== Buffer.byteLength(expected) || read.contentSha256 !== hash(expected)) throw error('SYSTEM_CONFIG_RESULT_INVALID', 'System file correspondence invalid');
  } else {
    const expectedError = absolute ? 'absolute paths not allowed' : !contained ? 'path outside synthetic target'
      : ['/app','/app/config'].includes(resolved) ? 'regular fixture file required'
      : Object.keys(FIXTURES).some(file => resolved.startsWith(file + '/')) ? 'config read unavailable' : 'config not found';
    if (!read || Object.keys(read).sort().join(',') !== 'error,ok' || read.ok !== false || read.error !== expectedError) throw error('SYSTEM_CONFIG_RESULT_INVALID', 'System negative observation invalid');
  }
  return Object.freeze({ ...receipt, readResult: Object.freeze({ ...read }) });
}
function createSystemConfigExecutor({ spawnImpl = spawn, spawnSyncImpl = spawnSync, readFileSync = fs.readFileSync,
  existsSync = fs.existsSync, timeoutMs = 1500, drainGraceMs = 1000 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000 || !Number.isInteger(drainGraceMs) || drainGraceMs < 100 || drainGraceMs > 5000) throw new TypeError('Bounded System execution deadlines required');
  const assets = loadAssets(readFileSync);
  const mounts = ['/usr', '/bin', '/lib', '/lib64'].filter(name => existsSync(name));
  let ready = false;
  function assertReady() {
    if (!ready) {
      if (!existsSync(INIT) || !existsSync(SUPERVISOR)
          || spawnSyncImpl('bwrap', [...namespaceArgv(mounts), INIT, '--probe'], { timeout: 5000, maxBuffer: MAX_STDERR_BYTES, env: { PATH: CLEAN_PATH } })?.status !== 0) throw error('SYSTEM_CONFIG_ISOLATION_UNAVAILABLE', 'Strict System config namespace unavailable');
      ready = true;
    }
  }
  return Object.freeze({ isolation: ISOLATION, assertReady,
    read(raw, { signal } = {}) {
      const request = normalizeRequest(raw); signal?.throwIfAborted(); assertReady();
      const marker = `__SYSTEM_CONFIG_${crypto.randomBytes(32).toString('hex')}__`;
      return new Promise((resolve, reject) => {
        let child;
        try { child = spawnImpl(SUPERVISOR, buildReadArgv(request, marker, mounts), { detached: false, env: { PATH: CLEAN_PATH },
          stdio: ['ignore', ...Array(3 + Object.keys(assets).length + Object.keys(FIXTURES).length).fill('pipe')] }); }
        catch { reject(error('SYSTEM_CONFIG_SUPERVISOR_FAILED', 'System supervisor spawn failed')); return; }
        for (const [fd, bytes] of [[3,Buffer.alloc(0)], ...Object.values(assets).map((bytes,index)=>[index+4,bytes]), ...Object.values(FIXTURES).map((bytes,index)=>[index+7,bytes])]) {
          child.stdio[fd].on('error',()=>{}); child.stdio[fd].end(bytes);
        }
        let stdout=Buffer.alloc(0), stderr=Buffer.alloc(0), truncated=false, timedOut=false, forced=false, spawnFailed=false, stopping=false, drainTimer;
        const stop=()=>{ if(stopping)return; stopping=true; try{child.kill('SIGTERM');}catch{} drainTimer=setTimeout(()=>{forced=true;try{child.kill('SIGKILL');}catch{}},drainGraceMs); };
        const append=(old,chunk,max)=>{const data=Buffer.from(chunk);if(old.length+data.length>max){truncated=true;stop();}return Buffer.concat([old,data.subarray(0,Math.max(0,max-old.length))]);};
        child.stdout.on('data',chunk=>{stdout=append(stdout,chunk,MAX_CAPTURE_BYTES);});
        child.stderr.on('data',chunk=>{stderr=append(stderr,chunk,MAX_STDERR_BYTES);});
        child.once('error',()=>{spawnFailed=true;});
        const abort=()=>stop();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
        const timer=setTimeout(()=>{timedOut=true;stop();},timeoutMs);
        child.once('close',code=>{
          clearTimeout(timer);clearTimeout(drainTimer);signal?.removeEventListener('abort',abort);
          if(signal?.aborted)return reject(signal.reason instanceof Error?signal.reason:new DOMException('Aborted','AbortError'));
          const drained=!forced&&!spawnFailed;
          if(code!==0||timedOut||truncated||!drained) return resolve(Object.freeze({version:VERSION,isolation:ISOLATION,operationId:request.operationId,requestSha256:requestDigest(request),status:'unavailable',exitCode:Number.isInteger(code)?code:null,timedOut,truncated,drained}));
          try { resolve(Object.freeze({...decodeRead(stdout,marker,request),status:'completed',exitCode:0,timedOut:false,truncated:false,drained:true})); }
          catch { reject(error('SYSTEM_CONFIG_RESULT_INVALID','System config observation could not be verified')); }
        });
      });
    },
  });
}
module.exports={createSystemConfigExecutor,loadAssets,buildReadArgv,decodeRead,ASSET_HASHES,FIXTURES,ATTESTATION,INIT,SUPERVISOR,MAX_CAPTURE_BYTES};
