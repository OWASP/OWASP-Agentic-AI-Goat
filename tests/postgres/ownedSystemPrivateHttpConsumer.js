'use strict';

// Prospective original System runtime. This is deliberately NOT a public live
// launcher. A past image/metadata receipt cannot authorize effects. The owning
// build driver's branded capability + fixed operation transport remain required.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { isDeepStrictEqual: same } = require('node:util');
const adapter = require('./ownedSystemConfigBuildAdapter');
const { createSecureShopSystemConfigClient } = require('../../server/services/secureshopSystemConfigClient');
const ROOT = path.resolve(__dirname, '../..');
const PYTHON = path.join(__dirname, 'owned_system_private_http_channel.py');
const PROFILE = path.join(ROOT, 'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in');
const PROFILE_SHA = 'dbd654c9ec9c10de04c77b76fc55c57ef5750a8cbe19870e132fc145f86a89d2';
// Informational native-admission status, not a second capability mint or an
// independently configurable gate. The sole public build gate is the producer.
const LIVE_ENABLED = false;
const fail = code => Object.assign(new Error(code), { code });
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && same(Object.keys(value).sort(), [...keys].sort());

function validateBinding(value) {
  if (!exact(value, ['version','target','runId','imageId','inputSha256','daemonId','physical'])
    || value.version !== 1 || !['original-v24-system','original-v24-policy','original-v03-diagnostic'].includes(value.target)
    || !/^[a-f0-9]{32}$/.test(value.runId) || !/^sha256:[a-f0-9]{64}$/.test(value.imageId)
    || !/^[a-f0-9]{64}$/.test(value.inputSha256) || !/^[A-Za-z0-9:-]{20,128}$/.test(value.daemonId)) throw fail('SYSTEM_BINDING');
  const p = value.physical, root = '/var/tmp/dvaia-v23-build-' + value.runId + '/fs';
  if (!exact(p, ['privateDockerHost','namespaceInode','filesystemIdentity','daemonProcess','namespaceHolder'])
    || p.privateDockerHost !== 'unix://' + root + '/docker.sock' || !/^net:\[[1-9][0-9]*\]$/.test(p.namespaceInode)
    || !exact(p.filesystemIdentity, ['device','inode']) || !Number.isSafeInteger(p.filesystemIdentity.device)
    || p.filesystemIdentity.device < 0 || !Number.isSafeInteger(p.filesystemIdentity.inode) || p.filesystemIdentity.inode < 1)
    throw fail('SYSTEM_BINDING');
  for (const [key, exe] of [['daemonProcess','/usr/bin/dockerd'],['namespaceHolder','/usr/bin/sleep']]) {
    const item = p[key];
    if (!exact(item, ['pid','startTicks','exe']) || !Number.isSafeInteger(item.pid) || item.pid < 2
      || item.exe !== exe || typeof item.startTicks !== 'string' || !/^[1-9][0-9]*$/.test(item.startTicks)) throw fail('SYSTEM_BINDING');
  }
  if (p.daemonProcess.pid === p.namespaceHolder.pid) throw fail('SYSTEM_BINDING');
  return JSON.parse(JSON.stringify(value));
}

function boundedSource(file, maximum) {
  if (fs.realpathSync(file) !== file) throw fail('SYSTEM_SOURCE_PATH');
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.size < 1 || before.size > maximum) throw fail('SYSTEM_SOURCE_FILE');
    const raw = Buffer.alloc(before.size + 1), count = fs.readSync(fd, raw, 0, raw.length, 0);
    const after = fs.fstatSync(fd), current = fs.lstatSync(file);
    if (count !== before.size || !['dev','ino','size','mtimeMs','ctimeMs'].every(key => before[key] === after[key] && before[key] === current[key]))
      throw fail('SYSTEM_SOURCE_CHANGED');
    return raw.subarray(0, count);
  } finally { fs.closeSync(fd); }
}

// Preparation is not execution authority. Literal operations only; runtime
// secrets are read from bounded private stdin, never Python/SSH argv or receipts.
function operationProgram(binding, operation, channelIds = []) {
  binding = validateBinding(binding);
  if (!['start','inspect','stop','claim-cohort'].includes(operation)
    || operation === 'claim-cohort' && binding.target !== 'original-v03-diagnostic' || !Array.isArray(channelIds)
    || channelIds.length > 64 || new Set(channelIds).size !== channelIds.length
    || channelIds.some(id => typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id))
    || (operation !== 'stop' && channelIds.length)) throw fail('SYSTEM_OPERATION');
  const bytes = boundedSource(PYTHON, 65536), profile = boundedSource(PROFILE, 32768);
  if (sha(profile) !== PROFILE_SHA) throw fail('SYSTEM_PROFILE_SOURCE');
  const source = bytes.toString('utf8').split("\nif __name__ == '__main__':")[0];
  const suffix = `
import base64, signal
stopping = [False]
def interrupted(*_): stopping[0] = True
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
B = json.loads(${JSON.stringify(JSON.stringify(binding))})
OPERATION = ${JSON.stringify(operation)}
CHANNELS = json.loads(${JSON.stringify(JSON.stringify(channelIds))})
# Actual owning driver supplies guest-monotonic deadline once, no epoch/host clock.
ready, _, _ = select.select([0], [], [], 5)
require(bool(ready), 'SYSTEM_PRIVATE_INPUT_TIMEOUT')
raw = os.read(0, 4097)
require(len(raw) <= 4096, 'SYSTEM_PRIVATE_INPUT_BYTES')
settings = json.loads(raw)
require(type(settings) is dict and set(settings) == (({'deadline','runtimeDeadline'} if B['target']=='original-v24-policy' else {'deadline','runtimeDeadline','token'}) if OPERATION == 'start' else {'deadline','cohort'} if OPERATION == 'claim-cohort' else {'deadline'}), 'SYSTEM_PRIVATE_INPUT')
runtime = GuestRuntime(B, settings['deadline'], stopped=lambda: stopping[0])
if OPERATION == 'start':
    result = runtime.start(settings.get('token'), base64.b64decode(${JSON.stringify(profile.toString('base64'))}, validate=True), settings['runtimeDeadline'])
elif OPERATION == 'inspect':
    result = runtime.inspect(True)
elif OPERATION == 'claim-cohort':
    result = runtime.claim_diagnostic_cohort(settings['cohort'])
else:
    result = runtime.stop(CHANNELS)
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
`;
  return Object.freeze({ source: source + suffix, sourceSha256: sha(source + suffix),
    helperSha256: sha(bytes), profileSha256: PROFILE_SHA, operation });
}

// Fixed host bridge template. The producer owns the controller PID/group,
// inherited private journal FD3, stdin stop pipe and bounded stdout framing.
// authority is its actual existing-mux capture, re-admitted by the Python helper
// before listen and before each SSH channel. This prepares code, never runs it.
function bridgeProgram(binding, authority) {
  binding = validateBinding(binding);
  if (!authority || typeof authority !== 'object' || Array.isArray(authority)
    || Buffer.byteLength(JSON.stringify(authority)) > 8192) throw fail('SYSTEM_MUX_CAPTURE');
  const bytes = boundedSource(PYTHON, 65536);
  const source = bytes.toString('utf8').split("\nif __name__ == '__main__':")[0];
  const suffix = `
import sys
sys.path.insert(0, ${JSON.stringify(path.dirname(PYTHON))})
__file__ = ${JSON.stringify(PYTHON)}
require(digest(Path(__file__).read_bytes()) == ${JSON.stringify(sha(bytes))}, 'SYSTEM_CHANNEL_SOURCE')
B = json.loads(${JSON.stringify(JSON.stringify(binding))})
A = json.loads(${JSON.stringify(JSON.stringify(authority))})
if isinstance(A.get('masterBirth'), list): A['masterBirth'] = tuple(A['masterBirth'])
# Deadline is an inherited host-monotonic absolute value, not an epoch time.
require(len(sys.argv)==2, 'SYSTEM_BRIDGE_DEADLINE_ARG')
bridge_controller(${JSON.stringify(ROOT)}, A, B, float(sys.argv[1]), 3)
`;
  return Object.freeze({source:source+suffix,sourceSha256:sha(source+suffix),helperSha256:sha(bytes)});
}

function validateRetirement(binding, local, remote) {
  validateBinding(binding);
  const tagged=binding.target!=='original-v24-system', extra=tagged?['target']:[];
  if (tagged&&(local?.target!==binding.target||remote?.target!==binding.target))throw fail('SYSTEM_RETIREMENT_UNPROVEN');
  if (!exact(local, ['version','runId','channelIds','localRetired','retirementUnproven','remoteRetired','builderReleaseAllowed','failures',...extra])
    || local.version !== 1 || local.runId !== binding.runId || local.localRetired !== true
    || local.retirementUnproven !== false || local.remoteRetired !== false || local.builderReleaseAllowed !== false
    || !Array.isArray(local.channelIds) || local.channelIds.length > 64
    || new Set(local.channelIds).size !== local.channelIds.length
    || local.channelIds.some(id => !/^[a-f0-9]{32}$/.test(id))
    || !Array.isArray(local.failures) || local.failures.some(code => typeof code !== 'string' || code.length > 100)
    || !exact(remote, ['version','runId','containerAbsent','profileAbsent','remoteChannelsAbsent','channelFailures','builderReleaseAllowed',...extra])
    || remote.version !== 1 || remote.runId !== binding.runId || remote.containerAbsent !== true
    || remote.profileAbsent !== true || remote.remoteChannelsAbsent !== true || remote.builderReleaseAllowed !== false
    || !Array.isArray(remote.channelFailures) || new Set(remote.channelFailures).size !== remote.channelFailures.length
    || remote.channelFailures.some(id => !local.channelIds.includes(id)))
    throw fail('SYSTEM_RETIREMENT_UNPROVEN');
  // This structured result is a replayable observation, NOT authority to release
  // the driver's disk/daemon. Only its in-memory owner closure may confirm that.
  return Object.freeze({ retirementObserved: true, transportSucceeded: local.failures.length === 0 && remote.channelFailures.length === 0,
    builderReleaseAllowed: false, failures: Object.freeze([...local.failures]) });
}

async function originalReadiness({ port, token, signal, deadline }, fetchImpl = globalThis.fetch) {
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || !(signal instanceof AbortSignal)
    || !Number.isFinite(deadline) || deadline - performance.now() < 100
    || deadline - performance.now() > 120000) throw fail('SYSTEM_READINESS_LIFECYCLE');
  signal.throwIfAborted();
  const client = createSecureShopSystemConfigClient({ baseURL: `http://127.0.0.1:${port}`, token,
    timeoutMs: Math.min(2000, Math.floor(deadline - performance.now())), fetchImpl });
  // The unchanged actual protocol probes executor readiness. No traversal read,
  // model, substitute fixture response or policy-instruction grading occurs.
  await client.assertReady({ signal });
  signal.throwIfAborted();
  if (performance.now() >= deadline) throw fail('SYSTEM_READINESS_DEADLINE');
  return client;
}

async function waitForOriginalReadiness(options, fetchImpl = globalThis.fetch) {
  // Original executor startup polls only authenticated GET /health for <=40s.
  // No POST, config read, model call or failed tool operation is retried here.
  const end = Math.min(options.deadline, performance.now() + 40000);
  let last;
  while (end - performance.now() >= 100) {
    options.signal.throwIfAborted();
    try { return await originalReadiness({ ...options, deadline: end }, fetchImpl); }
    catch (error) {
      last = error;
      options.signal.throwIfAborted();
      if (error.code !== 'SYSTEM_CONFIG_UNAVAILABLE') throw error;
    }
    const delay = Math.min(250, Math.max(0, end - performance.now()));
    await new Promise((resolve, reject) => {
      const cleanup = () => options.signal.removeEventListener('abort', abort);
      const timer = setTimeout(() => { cleanup(); resolve(); }, delay);
      const abort = () => { clearTimeout(timer); cleanup(); reject(options.signal.reason); };
      options.signal.addEventListener('abort', abort, { once: true });
      if (options.signal.aborted) abort();
    });
  }
  throw last || fail('SYSTEM_READINESS_DEADLINE');
}

function validateRuntime(binding, row) {
  validateBinding(binding);
  const policy=binding.target==='original-v24-policy';
  const tagged=binding.target!=='original-v24-system';
  if (!exact(row, ['version','runId','containerId','imageId','running','namespaceInode',...(tagged?['target']:[])])
    || row.version !== 1 || row.runId !== binding.runId || row.imageId !== binding.imageId
    || !/^[a-f0-9]{64}$/.test(row.containerId) || row.running !== true
    || !Number.isSafeInteger(row.namespaceInode) || row.namespaceInode<1 || tagged&&row.target!==binding.target
    || (policy ? row.target!==binding.target||`net:[${row.namespaceInode}]`===binding.physical.namespaceInode
      : `net:[${row.namespaceInode}]` !== binding.physical.namespaceInode))
    throw fail('SYSTEM_RUNTIME_CHANGED');
  return row;
}

async function settleWithin(work, milliseconds) {
  let timer;
  try {
    return await Promise.race([work.then(() => true, () => true),
      new Promise(resolve => { timer = setTimeout(() => resolve(false), milliseconds); })]);
  } finally { clearTimeout(timer); }
}

// Only the public entry may obtain this owner from the adapter's private brand.
// The controlled seam below is explicitly NOT a source of live capability.
async function consumeOwned(owner, lifecycle, consumer, fetchImpl) {
  const binding = validateBinding(owner.binding);
  if (binding.target==='original-v03-diagnostic') throw fail('DIAGNOSTIC_DISTINCT_CONSUMER_REQUIRED');
  if (!(lifecycle?.signal instanceof AbortSignal) || !Number.isFinite(lifecycle.deadline)
    || lifecycle.deadline <= performance.now() || lifecycle.deadline - performance.now() > 900000
    || typeof consumer !== 'function' || ['assertActive','startRuntime','inspectRuntime','openBridge','closeBridge','stopRuntime','confirmRetired','beginRetirement']
      .some(key => typeof owner[key] !== 'function')) throw fail('SYSTEM_CONSUMER_LIFECYCLE');
  const controller = new AbortController(), token = crypto.randomBytes(32).toString('base64url');
  let primary, result, work, attempted = false, retirement;
  const pending = new Set();
  let timer, rejectInterrupted;
  const interrupted = new Promise((_, reject) => { rejectInterrupted = reject; });
  // Register before any async work and consume rejection even if setup fails.
  void interrupted.catch(() => {});
  const abort = () => {
    const reason = lifecycle.signal.reason || fail('SYSTEM_CONSUMER_DEADLINE');
    controller.abort(reason); rejectInterrupted(reason);
  };
  const current = () => {
    controller.signal.throwIfAborted(); lifecycle.signal.throwIfAborted();
    if (performance.now() >= lifecycle.deadline) throw fail('SYSTEM_CONSUMER_DEADLINE');
    owner.assertActive();
  };
  const stage = async action => {
    current();
    const item = Promise.resolve().then(() => { current(); return action(); });
    pending.add(item); void item.then(() => pending.delete(item), () => pending.delete(item));
    return Promise.race([item, interrupted]);
  };
  lifecycle.signal.addEventListener('abort', abort, { once: true });
  timer = setTimeout(abort, Math.max(0, lifecycle.deadline - performance.now()));
  try {
    current(); attempted = true;
    const policy=binding.target==='original-v24-policy';
    const started = validateRuntime(binding, await stage(() => owner.startRuntime(policy?{}:{ token })));
    current();
    if (!same(started, validateRuntime(binding, await stage(() => owner.inspectRuntime())))) throw fail('SYSTEM_RUNTIME_CHANGED');
    current();
    const bridge = await stage(() => owner.openBridge());
    if (!exact(bridge, ['port']) || !Number.isInteger(bridge.port) || bridge.port < 1024 || bridge.port > 65535)
      throw fail('SYSTEM_BRIDGE_ENDPOINT');
    current();
    const client = await (policy?policyReadiness:waitForOriginalReadiness)({ port: bridge.port, token, signal: controller.signal,
      deadline: Math.min(lifecycle.deadline, performance.now()+40000), runtimeDeadline:lifecycle.deadline }, fetchImpl);
    current();
    work = Promise.resolve().then(() => {
      current();
      return consumer(Object.freeze({ client, baseURL:`http://127.0.0.1:${bridge.port}`, ...(policy?{target:binding.target}:{token}),
        signal:controller.signal, deadline:lifecycle.deadline }));
    });
    result = await Promise.race([work, interrupted]);
    current();
  } catch (error) { primary = error instanceof Error ? error : Object.assign(fail('SYSTEM_CONSUMER_FAILED'),{cause:error}); }
  finally {
    clearTimeout(timer); lifecycle.signal.removeEventListener('abort', abort);
    controller.abort(primary || fail('SYSTEM_CONSUMER_COMPLETE'));
    let cleanupEnd;
    const retirementDeadline = () => {
      const end = owner.beginRetirement();
      const now = performance.now();
      if (!Number.isFinite(end) || end <= now || end > now+600000
        || (cleanupEnd !== undefined && end !== cleanupEnd)) throw fail('SYSTEM_RETIREMENT_DEADLINE');
      return end;
    };
    try { cleanupEnd = retirementDeadline(); }
    catch (error) {
      if (primary) primary.cleanupError = error; else primary = error;
      primary.retirementUnproven = true;
      primary.cleanupDebt = ['owner-retirement-deadline-unproven'];
    }
    // Never remove stores/container/profile beneath an unresolved cohort. The
    // Guest channel admission remains deadline-bound; this is not a container
    // watchdog or proof of retirement. Unsettled work retains the owned runtime.
    const obligations = [...pending, ...(work ? [work] : [])];
    if (obligations.length && !await settleWithin(Promise.allSettled(obligations),
      Math.min(5000,Math.max(0,(cleanupEnd ?? performance.now())-performance.now())))) {
      primary ||= fail('SYSTEM_CONSUMER_UNQUIESCED');
      primary.retirementUnproven = true;
      primary.cleanupDebt = ['consumer-or-owner-operation-unsettled'];
    } else if (attempted && cleanupEnd !== undefined) {
      let cleanupTimer, confirmed = false;
      const cleanupExpired = new Promise((_, reject) => {
        cleanupTimer = setTimeout(() => reject(fail('SYSTEM_CLEANUP_DEADLINE')),Math.max(0,cleanupEnd-performance.now()));
      });
      void cleanupExpired.catch(() => {});
      const cleanup = action => Promise.race([Promise.resolve().then(() => {
        retirementDeadline();
        return action();
      }).then(value => { retirementDeadline(); return value; }),cleanupExpired]);
      try {
        const local = await cleanup(() => owner.closeBridge());
        if (local.localRetired !== true || local.retirementUnproven !== false) throw fail('SYSTEM_LOCAL_RETIREMENT_UNPROVEN');
        const remote = await cleanup(() => owner.stopRuntime());
        retirement = validateRetirement(binding, local, remote);
        // No supplied proof enters this call. Only its still-owning closure may
        // confirm actual controller/group and namespace/runtime retirement.
        if (await cleanup(() => owner.confirmRetired()) !== true) throw fail('SYSTEM_OWNER_RETIREMENT_UNPROVEN');
        confirmed = true;
        if (!retirement.transportSucceeded) throw Object.assign(fail('SYSTEM_TRANSPORT_FAILED'), { retirement });
      } catch (error) {
        if (primary) primary.cleanupError = error;
        else primary = error;
        if (!confirmed) primary.retirementUnproven = true;
      } finally { clearTimeout(cleanupTimer); }
    }
  }
  if (primary) throw primary;
  return { value:result, retirement, qualificationAccepted:false };
}

async function withSystemPrivateHttp(capability, lifecycle, consumer) {
  const owner = adapter.assertSystemImageCapability(capability); // rejects receipt dictionaries
  // Only the actual producer can mint this live owner. No caller-supplied
  // binding, runner, environment flag or serialized receipt grants admission.
  return consumeOwned(owner, lifecycle, consumer, globalThis.fetch);
}

// One lifecycle owns BOTH endpoints. Nesting the single-target consumer would
// start retirement while its parent still considers the cohort active.
async function consumePairOwned(owner,lifecycle,callback,fetchImpl){
  if(!(lifecycle?.signal instanceof AbortSignal)||!Number.isFinite(lifecycle.deadline)
    ||lifecycle.deadline<=performance.now()||lifecycle.deadline-performance.now()>900000||typeof callback!=='function'
    ||!owner?.slots||!exact(owner.slots,['system','policy']))throw fail('SYSTEM_PAIR_CONSUMER');
  const slots=['system','policy'],bindings={};
  for(const slot of slots){
    const value=owner.slots[slot];bindings[slot]=validateBinding(value.binding);
    if(bindings[slot].target!==`original-v24-${slot}`||['assertActive','startRuntime','inspectRuntime','openBridge','closeBridge','stopRuntime','confirmRetired']
      .some(key=>typeof value[key]!=='function'))throw fail('SYSTEM_PAIR_CONSUMER');
  }
  if(bindings.system.runId!==bindings.policy.runId||bindings.system.daemonId!==bindings.policy.daemonId
    ||!same(bindings.system.physical,bindings.policy.physical)||bindings.system.imageId===bindings.policy.imageId
    ||typeof owner.beginRetirement!=='function'||typeof owner.assertActive!=='function')throw fail('SYSTEM_PAIR_CONSUMER');
  const controller=new AbortController(),pending=new Set(),attempted=new Set(),endpoints={},observed={},confirmed=new Set();
  let primary,result,work,end,retirementTimer,rejectInterrupted;
  const interrupted=new Promise((_,reject)=>{rejectInterrupted=reject;});void interrupted.catch(()=>{});
  const abort=()=>{const reason=lifecycle.signal.reason||fail('SYSTEM_CONSUMER_DEADLINE');controller.abort(reason);rejectInterrupted(reason);};
  const timer=setTimeout(abort,Math.max(0,lifecycle.deadline-performance.now()));
  lifecycle.signal.addEventListener('abort',abort,{once:true});
  const current=()=>{controller.signal.throwIfAborted();lifecycle.signal.throwIfAborted();
    if(performance.now()>=lifecycle.deadline)throw fail('SYSTEM_CONSUMER_DEADLINE');owner.assertActive();};
  const track=action=>{
    const value=Promise.resolve().then(()=>{current();return action();});pending.add(value);
    void value.then(()=>pending.delete(value),()=>pending.delete(value));return Promise.race([value,interrupted]);
  };
  try{
    current();
    for(const slot of slots){
      const target=owner.slots[slot],binding=bindings[slot],token=slot==='system'?crypto.randomBytes(32).toString('base64url'):undefined;
      const started=validateRuntime(binding,await track(()=>{attempted.add(slot);return target.startRuntime(slot==='system'?{token}:{});}));
      if(!same(started,validateRuntime(binding,await track(()=>target.inspectRuntime()))))throw fail('SYSTEM_RUNTIME_CHANGED');
      observed[slot]=started;
      if(slot==='policy'&&started.namespaceInode===observed.system.namespaceInode)throw fail('SYSTEM_PAIR_NAMESPACE_ALIAS');
      const bridge=await track(()=>target.openBridge());
      if(!exact(bridge,['port'])||!Number.isInteger(bridge.port)||bridge.port<1024||bridge.port>65535
        ||slot==='policy'&&bridge.port===endpoints.system.port)throw fail('SYSTEM_BRIDGE_ENDPOINT');
      const options={port:bridge.port,token,signal:controller.signal,deadline:Math.min(lifecycle.deadline,performance.now()+40000),runtimeDeadline:lifecycle.deadline};
      // The original clients keep their wire contracts. Their actual transport
      // also inherits this pair's lifetime, including callers omitting signal.
      const boundFetch=(url,request)=>{
        current();const left=Math.floor(lifecycle.deadline-performance.now());
        if(left<=0)throw fail('SYSTEM_CONSUMER_DEADLINE');
        return fetchImpl(url,{...request,signal:AbortSignal.any([controller.signal,
          ...(request.signal?[request.signal]:[]),AbortSignal.timeout(left)])});
      };
      const client=await track(()=>(slot==='system'?waitForOriginalReadiness:policyReadiness)(options,boundFetch));
      endpoints[slot]=Object.freeze({client,port:bridge.port,baseURL:`http://127.0.0.1:${bridge.port}`,...(slot==='system'?{token}:{})});
    }
    current();
    work=Promise.resolve().then(()=>{current();return callback(Object.freeze({system:endpoints.system,policy:endpoints.policy,
      signal:controller.signal,deadline:lifecycle.deadline}));});void work.catch(()=>{});
    result=await Promise.race([work,interrupted]);current();
  }catch(error){primary=error instanceof Error?error:Object.assign(fail('SYSTEM_CONSUMER_FAILED'),{cause:error});}
  finally{
    clearTimeout(timer);lifecycle.signal.removeEventListener('abort',abort);controller.abort(primary||fail('SYSTEM_CONSUMER_COMPLETE'));
    const retirement=()=>{
      const value=owner.beginRetirement(),now=performance.now();
      if(!Number.isFinite(value)||value<=now||end===undefined&&value>now+600000||end!==undefined&&value!==end)throw fail('SYSTEM_RETIREMENT_DEADLINE');
      end=value;return value;
    };
    let cleanupFailure;
    try{
      retirement();
      if(!await settleWithin(Promise.allSettled([...pending,...(work?[work]:[])]),Math.min(5000,Math.max(0,end-performance.now()))))
        throw fail('SYSTEM_CONSUMER_UNQUIESCED');
      const expired=new Promise((_,reject)=>{retirementTimer=setTimeout(()=>reject(fail('SYSTEM_CLEANUP_DEADLINE')),Math.max(0,end-performance.now()));});
      void expired.catch(()=>{});
      const cleanup=action=>Promise.race([Promise.resolve().then(()=>{retirement();return action();}).then(value=>{retirement();return value;}),expired]);
      const locals={},remotes={};
      // All local channels join before ANY remote container/profile deletion.
      for(const slot of attempted){locals[slot]=await cleanup(()=>owner.slots[slot].closeBridge());
        if(locals[slot].localRetired!==true||locals[slot].retirementUnproven!==false)throw fail('SYSTEM_LOCAL_RETIREMENT_UNPROVEN');}
      for(const slot of attempted){remotes[slot]=await cleanup(()=>owner.slots[slot].stopRuntime());
        validateRetirement(bindings[slot],locals[slot],remotes[slot]);}
      for(const slot of attempted){if(await cleanup(()=>owner.slots[slot].confirmRetired())!==true)throw fail('SYSTEM_OWNER_RETIREMENT_UNPROVEN');confirmed.add(slot);}
      if([...attempted].some(slot=>!validateRetirement(bindings[slot],locals[slot],remotes[slot]).transportSucceeded))throw fail('SYSTEM_TRANSPORT_FAILED');
    }catch(error){cleanupFailure=error;}
    finally{clearTimeout(retirementTimer);}
    if(cleanupFailure){if(primary)primary.cleanupError=cleanupFailure;else primary=cleanupFailure;
      if(confirmed.size!==attempted.size||cleanupFailure.code==='SYSTEM_CONSUMER_UNQUIESCED'||end===undefined)primary.retirementUnproven=true;}
  }
  if(primary)throw primary;
  return Object.freeze({value:result,retirementObserved:true,qualificationAccepted:false});
}
async function withSystemAndPolicyPrivateHttp(capability,lifecycle,callback){
  const owner=require('./ownedSystemImageProducer').assertPairedRuntimeCapability(capability);
  return consumePairOwned(owner,lifecycle,callback,globalThis.fetch);
}

// Additive protocol preparation only: the future paired producer must supply a
// genuine owner. No renderer receipt or serialized endpoint mints that owner.
async function policyReadiness({port,signal,deadline,runtimeDeadline=deadline},fetchImpl=globalThis.fetch){
  if(!Number.isInteger(port)||port<1024||port>65535||!(signal instanceof AbortSignal)
    ||!Number.isFinite(deadline)||deadline-performance.now()<100||deadline-performance.now()>120000
    ||!Number.isFinite(runtimeDeadline)||runtimeDeadline<deadline||runtimeDeadline-performance.now()>900000)
    throw fail('SYSTEM_READINESS_LIFECYCLE');
  const baseUrl=`http://127.0.0.1:${port}`;
  let ready=false;
  const runtime=require('../../server/services/secureshopPolicySandboxRuntime').createSecureShopPolicySandboxRuntime({
    baseUrl,timeoutMs:Math.min(10000,Math.floor(deadline-performance.now())),fetchImpl:async(url,request)=>{
      const end=ready?runtimeDeadline:deadline;
      signal.throwIfAborted();if(performance.now()>=end)throw fail('SYSTEM_READINESS_DEADLINE');
      const parsed=new URL(url);
      if(parsed.origin!==baseUrl||!((request.method===undefined&&parsed.pathname==='/health')
        ||(request.method==='POST'&&parsed.pathname==='/secureshop/policy-render')))throw fail('POLICY_ENDPOINT');
      const remaining=Math.floor(end-performance.now());if(remaining<=0)throw fail('SYSTEM_READINESS_DEADLINE');
      return fetchImpl(url,{...request,redirect:'error',signal:AbortSignal.any([signal,request.signal,AbortSignal.timeout(remaining)])});
    }});
  await runtime.checkReadiness();signal.throwIfAborted();
  if(performance.now()>=deadline)throw fail('SYSTEM_READINESS_DEADLINE');
  ready=true;
  return runtime;
}

module.exports = { LIVE_ENABLED, withSystemPrivateHttp,withSystemAndPolicyPrivateHttp,
  _internals: { validateBinding, validateRuntime, operationProgram, bridgeProgram, validateRetirement, originalReadiness,
    waitForOriginalReadiness, policyReadiness, PROFILE_SHA,async runControlledPairConsumer(owner,lifecycle,callback,fetchImpl){
      return {...await consumePairOwned(owner,lifecycle,callback,fetchImpl),controlled:true};
    }, async runControlledConsumer(owner, lifecycle, consumer, fetchImpl) {
      const result = await consumeOwned(owner, lifecycle, consumer, fetchImpl);
      return { ...result, controlled:true, qualificationAccepted:false };
    } } };
