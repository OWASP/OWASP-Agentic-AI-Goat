'use strict';
// Unintegrated shared guest APT authentication; no operation runs on import.
const fs=require('node:fs/promises'),nativeFs=require('node:fs'),crypto=require('node:crypto');
const {spawn}=require('node:child_process'),{Readable}=require('node:stream');
const metadata=require('./ownedPolicySystemMetadata'),replay=require('./ownedMcpArtifactReplay');
const targets=require('./ownedPolicySystemBuild');
const admitted=new WeakMap();
const hash=data=>crypto.createHash('sha256').update(data).digest('hex');
const error=code=>Object.assign(new Error(code),{code});
const now=()=>Number(process.hrtime.bigint())/1000000;
  async function read(file, maximum, mode = 0o444) {
    if (await fs.realpath(file) !== file) throw error('ORIGINAL_BUILD_RETAINED_PATH');
    const fd = await fs.open(file, nativeFs.constants.O_RDONLY | nativeFs.constants.O_NOFOLLOW);
    try { const before = await fd.stat();
      if (!before.isFile() || before.nlink !== 1 || before.uid !== 0 || (before.mode & 0o777) !== mode || before.size < 1 || before.size > maximum) throw error('ORIGINAL_BUILD_RETAINED_FILE');
      const bytes = await fd.readFile(), after = await fd.stat();
      if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw error('ORIGINAL_BUILD_RETAINED_CHANGED');
      return bytes;
    } finally { await fd.close(); }
  }

async function admitRetained(binding){
 if(!binding||!['v03-diagnostic','v23-registry','v24-system','v33-pricing','v24-policy'].includes(binding.target))throw error('ORIGINAL_BUILD_TARGET');
 const spec=targets.targetSpecification(binding.target),retention=targets.metadataRetentionSpecification(binding.target);
 if(binding.base!==spec.base||!retention)throw error('ORIGINAL_BUILD_TARGET');
 binding=Object.freeze(structuredClone(binding));
  const raw = await read('/metadata-retained/result.json', 1024 ** 2);
  const envelope = metadata.validateResultEnvelope(raw.toString(), binding);
  const candidate = envelope.candidate, retained = metadata.validateRetainedMetadata(candidate, binding);
  const retainedBytes = await read('/metadata-retained/manifest.json', 1024 ** 2);
  if (JSON.stringify(JSON.parse(retainedBytes)) !== JSON.stringify(retained)) throw error('ORIGINAL_BUILD_RETAINED_MANIFEST');
  const byUrl = new Map();
  for (const row of retained.objects) {
    const bytes = await read('/metadata-retained/' + row.file, 32 * 1024 ** 2);
    if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('ORIGINAL_BUILD_RETAINED_INTEGRITY');
    if (row.kind === 'upstream') byUrl.set(row.url, row);
  }
  const metadataRead = async url => {
    const row = byUrl.get(url); if (!row) throw error('ORIGINAL_BUILD_UNLISTED_METADATA');
    const bytes = await read('/metadata-retained/' + row.file, 32 * 1024 ** 2);
    if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('ORIGINAL_BUILD_RETAINED_INTEGRITY');
    return { bytes: bytes.length, sha256: row.sha256, stream: Readable.from([bytes]) };
  };
  if (hash(await fs.readFile(candidate.keyringPath)) !== candidate.keyringSha256
    || hash(await fs.readFile('/var/lib/dpkg/status')) !== candidate.installedStatusSha256) throw error('ORIGINAL_BUILD_BASE_WITNESS');
  for (const entry of envelope.sourceSnapshot.files) {
    const bytes = await fs.readFile(entry.path);
    if (hash(bytes) !== entry.sha256 || bytes.length !== entry.bytes) throw error('ORIGINAL_BUILD_BASE_SOURCES');
  }

 if(retained.kind!==retention.kind||JSON.stringify(retained.stages.map(({name,packages})=>({name,packages})))!==JSON.stringify(retention.stages))throw error('ORIGINAL_BUILD_TARGET_STAGES');
 const capability=Object.freeze({kind:'owned-apt-retained-admission',target:binding.target});
 admitted.set(capability,{binding,spec,candidate,retained,retainedBytes,envelope,metadataRead});return capability;
}
async function authenticate(capability,lifecycle){
 const state=admitted.get(capability);if(!state)throw error('ORIGINAL_BUILD_ADMISSION');
 if(!lifecycle||Object.keys(lifecycle).sort().join(',')!=='deadline,signal'||!(lifecycle.signal instanceof AbortSignal)
  ||!Number.isFinite(lifecycle.deadline)||lifecycle.deadline<=now()||lifecycle.deadline-now()>300000)throw error('ORIGINAL_BUILD_GUEST_AUTHORITY');
 admitted.delete(capability);
 const {binding,spec,candidate,retained,retainedBytes,envelope,metadataRead}=state;
 const deadline=lifecycle.deadline,controller=new AbortController(),children=new Set();
 let commandBytes=0,expandedBytes=0;const cleanupDebt=[];
 const current=()=>{controller.signal.throwIfAborted();if(now()>=deadline)throw error('ORIGINAL_BUILD_DEADLINE');};
 const abort=()=>controller.abort(lifecycle.signal.reason);
 if(lifecycle.signal.aborted)abort();else lifecycle.signal.addEventListener('abort',abort,{once:true});
 const timer=setTimeout(()=>controller.abort(error('ORIGINAL_BUILD_DEADLINE')),Math.max(0,deadline-now()));
 try{
 controller.signal.throwIfAborted();
  for (const name of ['/metadata/sources', '/metadata/lists/partial', '/metadata/cache/archives/partial']) await fs.mkdir(name, { recursive: true });
  for (const entry of envelope.sourceSnapshot.files) {
    const name = entry.path === '/etc/apt/sources.list' ? 'main.list' : entry.path.split('/').pop();
    await fs.writeFile('/metadata/sources/' + name, metadata.canonicalSources(name, entry.text, targets.metadataSourcePolicy(binding.target,true)), { flag: 'wx', mode: 0o600 });
  }
  async function command(file, args, { expanded = false } = {}) {
    if (controller.signal.aborted || now() >= deadline) throw error('ORIGINAL_BUILD_DEADLINE');
    if (!['/usr/bin/apt-get', '/usr/bin/apt-cache', '/usr/lib/apt/apt-helper'].includes(file)) throw error('ORIGINAL_BUILD_COMMAND');
    return new Promise((resolve, reject) => {
      const child = spawn(file, args, { detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: '/usr/bin:/bin', LC_ALL: 'C', DEBIAN_FRONTEND: 'noninteractive' } });
      children.add(child); let failure, chunks = [], size = 0,settled=false,joinTimer;
      const debt=code=>cleanupDebt.push({code,pid:child.pid||null});
      const finish=(cause,value)=>{if(settled)return;settled=true;clearTimeout(joinTimer);controller.signal.removeEventListener('abort',abort);cause?reject(cause):resolve(value);};
      const kill = cause => { failure ||= cause;
        if(!joinTimer)joinTimer=setTimeout(()=>{debt('ORIGINAL_BUILD_CHILD_JOIN_UNPROVEN');finish(failure);},5000);
        if (child.pid) try { process.kill(-child.pid, 'SIGKILL'); } catch (e) { if (e.code !== 'ESRCH') debt('ORIGINAL_BUILD_CHILD_KILL_FAILED'); }
      };
      const abort = () => kill(error('ORIGINAL_BUILD_DEADLINE')); controller.signal.addEventListener('abort', abort, { once: true });
      child.on('error', kill);
      child.stdout.on('data', chunk => {
        if (expanded) { expandedBytes += chunk.length; if (expandedBytes > 512 * 1024 ** 2) kill(error('ORIGINAL_BUILD_EXPANSION')); }
        else { size += chunk.length; commandBytes += chunk.length; if (size > 1024 ** 2 || commandBytes > 2 * 1024 ** 2) kill(error('ORIGINAL_BUILD_OUTPUT')); else chunks.push(chunk); }
      });
      child.stderr.on('data', chunk => { commandBytes += chunk.length; if (commandBytes > 2 * 1024 ** 2) kill(error('ORIGINAL_BUILD_OUTPUT')); });
      child.once('close', (code, signal) => {
        let absent=true;
        if (child.pid) try { process.kill(-child.pid, 0); absent=false;failure ||= error('ORIGINAL_BUILD_DESCENDANTS'); } catch (e) { if (e.code !== 'ESRCH'){absent=false;failure ||= e;} }
        if(absent)children.delete(child);else debt('ORIGINAL_BUILD_DESCENDANTS_UNRETIRED');
        // Never signal a reaped leader's group: unresolved descendants require outer owned-process recovery.
        finish(failure || (code !== 0 || signal ? error('ORIGINAL_BUILD_APT_FAILED'):null),Buffer.concat(chunks).toString());
      });
      if(controller.signal.aborted)abort();
    });
  }

  const certificate = replay.replayCertificate(), replayBudget = replay.createReplayBudget();
  const offline = replay.createReplay({ ...certificate, read: metadataRead, budget: replayBudget });
  let authenticated, authenticationError;
  try {
    const authority = await offline.listen(), options = metadata.metadataAptOptions(authority.port);
    await command('/usr/bin/apt-get', [...options, 'update', '--error-on=any']);
    for (const row of candidate.indices) {
      const bytes = await fs.readFile('/metadata/lists/' + row.name);
      if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('ORIGINAL_BUILD_AUTHENTICATED_INDEX_CHANGED');
      await command('/usr/lib/apt/apt-helper', ['cat-file', '/metadata/lists/' + row.name], { expanded: true });
    }
    for (const row of candidate.releaseFreshness || []) {
      const bytes = await fs.readFile('/metadata/lists/' + row.name);
      metadata.authenticatedReleaseFreshness(row.name, bytes.toString(), Date.now());
    }
    const uriLines = value => value.split('\n').filter(line => line.startsWith("'")).sort();
    for (const stage of retained.stages) {
      const selection = await command('/usr/bin/apt-get', [...options, '--print-uris', '--download-only', '--yes', '--no-install-recommends', 'install', ...stage.packages]);
      if (JSON.stringify(uriLines(selection)) !== JSON.stringify(uriLines(stage.selection))) throw error('ORIGINAL_BUILD_APT_SELECTION_CHANGED');
      const simulation = await command('/usr/bin/apt-get', [...options, '--simulate', '--no-install-recommends', 'install', ...stage.packages]);
      const installed = value => value.split('\n').filter(line => line.startsWith('Inst '));
      if (JSON.stringify(installed(simulation)) !== JSON.stringify(installed(stage.simulation))) throw error('ORIGINAL_BUILD_APT_SIMULATION_CHANGED');
      for (const row of stage.selected) {
        const text = await command('/usr/bin/apt-cache', [...options, 'show', `${row.name}=${row.version}`]);
        const records = text.trim().split(/\n\n+/).map(block => Object.fromEntries(block.split('\n').filter(line => /^[A-Za-z][A-Za-z0-9-]*: /.test(line)).map(line => { const split = line.indexOf(': '); return [line.slice(0, split), line.slice(split + 2)]; })));
        if (!records.some(record => record.Package === row.name && record.Version === row.version && record.Architecture === row.architecture
          && record.Filename === row.filename && record.SHA256 === row.sha256 && Number(record.Size) === row.bytes)) throw error('ORIGINAL_BUILD_APT_PACKAGE_CHANGED');
      }
    }
    if (hash(await fs.readFile('/var/lib/dpkg/status')) !== candidate.installedStatusSha256) throw error('ORIGINAL_BUILD_APT_BASE_CHANGED');
    authenticated = { version: 1, method: 'original-base-apt-closed-replay', retainedManifestSha256: hash(retainedBytes),
      keyringSha256: candidate.keyringSha256, installedStatusSha256: candidate.installedStatusSha256,
      stages: retained.stages.map(stage => ({ name: stage.name, selectionSha256: hash(stage.selection) })), expandedBytes };
  } catch (cause) { authenticationError = cause; throw cause; }
  finally {
    try {
      let closeTimer;const result=await Promise.race([offline.close(),new Promise((_,reject)=>{closeTimer=setTimeout(()=>reject(error('ORIGINAL_BUILD_APT_REPLAY_JOIN_UNPROVEN')),5000);})]).finally(()=>clearTimeout(closeTimer));
      if (result.failure || !result.absenceVerified) throw error('ORIGINAL_BUILD_APT_REPLAY_RETIREMENT');
    } catch (cause) {
      if (authenticationError) authenticationError.replayCleanupError = cause.code || 'ORIGINAL_BUILD_APT_REPLAY_RETIREMENT';
      else throw cause;
    }
  }

 current();
 if(cleanupDebt.length||children.size)throw error('ORIGINAL_BUILD_CHILD_RETIREMENT');
 return Object.freeze({binding,...authenticated});
 }catch(cause){
  cause.cleanupDebt=cleanupDebt.slice();
  for(const child of children)if(!cause.cleanupDebt.some(row=>row.pid===(child.pid||null)))cause.cleanupDebt.push({code:'ORIGINAL_BUILD_CHILD_RETIREMENT_UNPROVEN',pid:child.pid||null});
  throw cause;
 }finally{clearTimeout(timer);lifecycle.signal.removeEventListener('abort',abort);}
}
module.exports={admitRetained,authenticate};

