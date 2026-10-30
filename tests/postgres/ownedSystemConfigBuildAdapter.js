'use strict';
// Prospective System build pipeline; public execution remains closed pending the
// target-specific private HTTP consumer and its owned retirement channel.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { Readable } = require('node:stream');
const { isDeepStrictEqual: equal } = require('node:util');
const bounded = require('./ownedMcpBoundedBuild');
const inputs = require('./ownedSystemConfigPrivateBuild');
const metadata = require('./ownedPolicySystemMetadata');
const closure = require('./ownedMcpDependencyClosure');
const systemBounded = require('./ownedSystemBoundedDerivation');
const rendererInputs = require('./ownedPolicyRendererBuildInputs');
const fail = code => Object.assign(new Error(code), { code });
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const TARGET = 'original-v24-system';
const LIMITS = Object.freeze({ disk: 6 * 1024 ** 3, acquisitionMs: 300000,
  buildMs: 300000, deb: 128 * 1024 ** 2, context: 16 * 1024 ** 2 });
const GUEST_MODULES = Object.freeze(['ownedAptAuthentication', 'ownedPolicySystemBuild',
  'ownedPolicySystemMetadata', 'ownedMcpArtifactReplay', 'ownedMcpDependencyClosure']);
function freeze(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function systemArtifacts(stages, target = 'v24-system') {
  const error = code => Object.assign(new Error(code), { code });
  if (target === 'v24-policy') {
    const expected = [['build',['gcc','libc6-dev']],['runtime',['bubblewrap']]];
    if (!Array.isArray(stages) || stages.length !== 2) throw error('SYSTEM_APT_STAGES');
    const rows = new Map(),urls=new Map();
    for (let i=0;i<2;i++) {
      const stage=stages[i];
      if (stage?.name!==expected[i][0] || JSON.stringify(stage.packages)!==JSON.stringify(expected[i][1])) throw error('SYSTEM_APT_STAGES');
      // The shared parser below validates every actual selected URI/package.
      // Only its single-stage envelope is reused; resulting stage identities
      // remain the original renderer's build/runtime identities.
      for (const row of systemArtifacts([{...stage,name:'system',packages:['gcc','libc6-dev','bubblewrap']}])) {
        if(urls.has(row.urls[0])&&urls.get(row.urls[0])!==row.digest)throw error('SYSTEM_APT_PACKAGE');
        urls.set(row.urls[0],row.digest);const prior=rows.get(row.digest);
        if(prior&&prior.bytes!==row.bytes)throw error('SYSTEM_APT_PACKAGE');
        if(prior){if(!prior.stages.includes(stage.name))prior.stages.push(stage.name);if(!prior.urls.includes(row.urls[0]))prior.urls.push(row.urls[0]);prior.urls.sort();}
        else rows.set(row.digest,{...row,stages:[stage.name]});
      }
    }
    const result=[...rows.values()].sort((a,b)=>a.urls[0].localeCompare(b.urls[0]));
    if(result.reduce((n,row)=>n+row.bytes,0)>128*1024**2)throw error('SYSTEM_APT_BYTES');
    return result;
  }
  if(!['v24-system','v03-diagnostic'].includes(target))throw error('SYSTEM_APT_TARGET');
  const stageName=target==='v03-diagnostic'?'diagnostic':'system';
  const stage = stages?.[0];
  if (!Array.isArray(stages) || stages.length !== 1 || stage.name !== stageName
    || JSON.stringify(stage.packages) !== JSON.stringify(['gcc','libc6-dev','bubblewrap'])
    || typeof stage.selection !== 'string' || Buffer.byteLength(stage.selection) > 1048576
    || !Array.isArray(stage.selected) || !stage.selected.length || stage.selected.length > 128) throw error('SYSTEM_APT_STAGES');
  const choices = new Map(), names = new Set(), digests = new Set();
  for (const line of stage.selection.split('\n')) {
    if (!line.startsWith("'")) continue;
    const match = /^'([^']+)' \S+ ([0-9]+)(?: (?:SHA256:[a-f0-9]{64}|MD5Sum:[a-f0-9]{32}))?$/.exec(line.trim());
    if (!match) throw error('SYSTEM_APT_SELECTION');
    const url = new URL(match[1]);
    if (!['http:','https:'].includes(url.protocol) || url.hostname !== 'deb.debian.org' || url.username || url.password || url.port || url.search || url.hash) throw error('SYSTEM_APT_URL');
    const filename = decodeURIComponent(url.pathname).replace(/^\/(?:debian|debian-security)\//,'');
    if (!/^pool\/[A-Za-z0-9_./+~:-]+\.deb$/.test(filename) || filename.includes('..') || choices.has(filename)) throw error('SYSTEM_APT_SELECTION');
    choices.set(filename,{url:url.href,bytes:Number(match[2])});
  }
  if (choices.size !== stage.selected.length) throw error('SYSTEM_APT_SELECTION');
  let total = 0;
  const rows = stage.selected.map(row => {
    const choice = choices.get(row?.filename);
    if (!row || !/^[a-z0-9][a-z0-9+.-]*$/.test(row.name) || names.has(row.name)
      || !/^[A-Za-z0-9.+:~_-]+$/.test(row.version) || !['arm64','all'].includes(row.architecture)
      || !/^[a-f0-9]{64}$/.test(row.sha256) || digests.has(row.sha256)
      || !Number.isSafeInteger(row.bytes) || row.bytes <= 0 || row.bytes > 64*1024**2
      || !choice || choice.bytes !== row.bytes) throw error('SYSTEM_APT_PACKAGE');
    names.add(row.name);digests.add(row.sha256);total += row.bytes;
    return {kind:'deb',algorithm:'sha256',digest:row.sha256,bytes:row.bytes,urls:[choice.url],stages:[stageName]};
  });
  if(total>128*1024**2)throw error('SYSTEM_APT_BYTES');
  return rows.sort((a,b)=>a.urls[0].localeCompare(b.urls[0]));
}

// Serialized guest executes in the exact original base. No host apt, npm,
// upstream fallback, source rewrite, or registry admission exception.
async function guestMain(load, binding, deriveArtifacts, mode = 'legacy') {
  const fs = require('node:fs/promises'), native = require('node:fs');
  const crypto = require('node:crypto'), { Readable } = require('node:stream');
  const apt = load('ownedAptAuthentication'), metadata = load('ownedPolicySystemMetadata');
  const closure = load('ownedMcpDependencyClosure'), replay = load('ownedMcpArtifactReplay');
  const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  const error = code => Object.assign(new Error(code), { code });
  if (!['legacy','acquire','replay'].includes(mode) || !['v24-system','v24-policy','v03-diagnostic'].includes(binding.target)
    || mode==='legacy'&&!['v24-system','v03-diagnostic'].includes(binding.target)) throw error('SYSTEM_GUEST_MODE');
  const controller = new AbortController();
  // The shared builder records Linux time.monotonic(), in this same guest
  // kernel. Node hrtime shares that clock; never compare with host or epoch time.
  const monotonic = () => Number(process.hrtime.bigint()) / 1e6;
  const deadline = Number(process.env.OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS) * 1000;
  const remaining = deadline - monotonic();
  const port = Number(process.env.OWASP_AI_GOAT_ARTIFACT_PROXY_PORT);
  if (mode!=='replay' && (!(remaining > 0 && remaining <= 300000) || !Number.isInteger(port) || port < 1 || port > 65535))
    throw error('SYSTEM_GUEST_ADMISSION');
  const current = () => { controller.signal.throwIfAborted(); if (monotonic() >= deadline) throw error('SYSTEM_ACQUISITION_DEADLINE'); };
  const publish = async (name, value) => {
    const bytes = Buffer.from(JSON.stringify(value));
    if (!/^[a-z-]+\.json$/.test(name) || bytes.length > 1024 ** 2) throw error('SYSTEM_PUBLICATION_BOUND');
    const file = '/system-closure/' + name, temporary = file + '.partial';
    const fd = await fs.open(temporary, native.constants.O_WRONLY | native.constants.O_CREAT | native.constants.O_EXCL | native.constants.O_NOFOLLOW, 0o400);
    try { await fd.writeFile(bytes); await fd.sync(); } finally { await fd.close(); }
    await fs.link(temporary, file); await fs.unlink(temporary);
    const dir = await fs.open('/system-closure', native.constants.O_RDONLY);
    try { await dir.sync(); } finally { await dir.close(); }
  };
  let service, finishing, primary, timer, readyPublished = false;
  let terminalResolve;
  const terminal = new Promise(resolve => { terminalResolve = resolve; });
  const finish = () => finishing ||= (async () => {
    controller.abort(); const errors = [];
    const first = service?.failureRecord();
    if (first) try { await publish('replay-failure.json', { binding, ...first }); }
    catch { errors.push('SYSTEM_FAILURE_PUBLICATION'); }
    let result = null, joinTimer;
    if (service) try {
      result = await Promise.race([service.close(), new Promise((_, reject) => {
        joinTimer = setTimeout(() => reject(error('SYSTEM_REPLAY_JOIN')), 5000);
      })]);
      if (result.absenceVerified !== true) errors.push('SYSTEM_REPLAY_ABSENCE');
    } catch { errors.push('SYSTEM_REPLAY_JOIN'); } finally { clearTimeout(joinTimer); }
    if (primary?.cleanupDebt?.length || primary?.replayCleanupError) errors.push('SYSTEM_APT_CLEANUP_DEBT');
    try { await publish(mode==='acquire'?'acquisition-terminal.json':'terminal.json', { version: 1, binding, result,
      failure: primary ? primary.code || 'SYSTEM_GUEST_FAILED' : first?.cause || null, cleanupErrors: errors,
      ...((binding.target==='v03-diagnostic' || mode==='acquire' && ['v24-system','v24-policy'].includes(binding.target)) && primary ? { failureDiagnostic: closure.failureDiagnostic(primary),
        ...(mode==='acquire' && ['v24-system','v24-policy'].includes(binding.target) && primary.closureAttempts ? { attemptProof: primary.closureAttempts } : {}) } : {}) }); }
    catch { errors.push('SYSTEM_TERMINAL_PUBLICATION'); }
    process.exitCode = errors.length ? 2 : primary || result?.failure ? 1 : 0;
    clearTimeout(timer); terminalResolve();
    return { result, errors };
  })();
  const interrupt = () => { if (!readyPublished) primary ||= error('SYSTEM_GUEST_INTERRUPTED'); controller.abort(); if (service) void finish(); };
  process.on('SIGTERM', interrupt); process.on('SIGINT', interrupt);
  if(mode!=='replay')timer = setTimeout(interrupt, remaining);
  try {
    let authentication,acquired,record;
    if(mode!=='replay'){
      current();
      const capability = await apt.admitRetained(binding);
      authentication = await apt.authenticate(capability, { signal: controller.signal, deadline });
      current();
    }
    const raw = await fs.readFile('/metadata-retained/result.json', 'utf8');
    const envelope = metadata.validateResultEnvelope(raw, binding);
    const retained = metadata.validateRetainedMetadata(envelope.candidate, binding);
    const artifacts = deriveArtifacts(retained.stages,binding.target);
    closure._internals.validateArtifacts(artifacts);
    if(binding.target==='v03-diagnostic' && (!artifacts.length || artifacts.length>35 || artifacts.some(row=>row.kind!=='deb'))) throw error('DIAGNOSTIC_ARTIFACT_CONNECTION_BOUND');
    if(mode!=='replay'){
    acquired = await closure.acquireArtifacts({ artifacts, directory: '/system-closure/artifacts',
      authority: { host: '127.0.0.1', port }, signal: controller.signal,
      now: monotonic, deadline, attemptProof: mode==='acquire' && ['v24-system','v24-policy'].includes(binding.target) });
    current();
    if (acquired.bytes.npm !== 0 || acquired.artifacts.some(row => row.kind !== 'deb')) throw error('SYSTEM_NON_APT_ARTIFACT');
    record = { version: 1, binding, authentication, acquired };
    await publish('closure.json', record);
    if(mode==='acquire'){await finish();return;}
    }else{
      const fd=await fs.open('/system-closure/closure.json',native.constants.O_RDONLY|native.constants.O_NOFOLLOW);
      try{
        const stat=await fd.stat();if(!stat.isFile()||stat.nlink!==1||stat.uid!==0||(stat.mode&0o777)!==0o400||stat.size<=0||stat.size>1048576)throw error('SYSTEM_CLOSURE_FILE');
        record=JSON.parse(await fd.readFile());
      }finally{await fd.close();}
      if(JSON.stringify(record.binding)!==JSON.stringify(binding)||record.acquired?.artifactBytesVerified!==true
        ||record.acquired.bytes?.npm!==0||record.authentication?.method!=='original-base-apt-closed-replay'
        ||JSON.stringify(record.authentication.binding)!==JSON.stringify(binding))throw error('SYSTEM_CLOSURE_EVIDENCE');
      acquired=record.acquired;
      const expected=artifacts.map(row=>({...row,actualBytes:row.bytes,file:'objects/'+closure._internals.objectName(row)}));
      if(JSON.stringify(acquired.artifacts)!==JSON.stringify(expected))throw error('SYSTEM_CLOSURE_EVIDENCE');
    }
    const packageRead = closure.artifactReader('/system-closure/artifacts', acquired);
    const upstream = new Map(retained.objects.filter(row => row.kind === 'upstream').map(row => [row.url, row]));
    const read = async url => {
      const row = upstream.get(url); if (!row) return packageRead(url);
      const fd = await fs.open('/metadata-retained/' + row.file, native.constants.O_RDONLY | native.constants.O_NOFOLLOW);
      let bytes;
      try { const stat = await fd.stat(); if (!stat.isFile() || stat.nlink !== 1 || stat.size !== row.bytes || stat.size > 32 * 1024 ** 2) throw error('SYSTEM_METADATA_FILE'); bytes = await fd.readFile(); }
      finally { await fd.close(); }
      if (bytes.length !== row.bytes || hash(bytes) !== row.sha256) throw error('SYSTEM_METADATA_HASH');
      return { bytes: bytes.length, sha256: row.sha256, stream: Readable.from([bytes]) };
    };
    service = replay.createReplay({ ...replay.replayCertificate(), read });
    // Register before listen; finalize outside the failing request's promise.
    service.firstFailure.then(() => { void finish(); }).catch(() => { process.exitCode = 2; });
    await publish('replay-intent.json', { version: 1, binding, policy: 'strict-default' });
    const authority = await service.listen();
    if(mode!=='replay')current();else controller.signal.throwIfAborted();
    clearTimeout(timer); timer = null; // replay retains its own bounded lease
    await publish('ready.json', { version: 1, binding, port: authority.port,
      closureSha256: hash(JSON.stringify(record)), metadataAuthenticated: true,
      artifactBytesVerified: true });
    readyPublished = true;
    await terminal;
  } catch (cause) { primary = cause; await finish(); }
  finally { clearTimeout(timer); process.off('SIGTERM', interrupt); process.off('SIGINT', interrupt); }
}

async function guestSource(root, binding, mode='legacy') {
  const modules = {}, hashes = {};
  for (const name of GUEST_MODULES) {
    const relative = 'tests/postgres/' + name + '.js';
    const bytes = await fs.readFile(path.join(root, relative));
    if (bytes.length > 1024 ** 2) throw fail('SYSTEM_MODULE_BOUND');
    modules[name] = bytes.toString(); hashes[relative] = sha(bytes);
  }
  const loader = 'const modules='+JSON.stringify(modules)+',cache=new Map();function load(name){if(!Object.hasOwn(modules,name))throw Error("SYSTEM_MODULE");if(cache.has(name))return cache.get(name).exports;const m={exports:{}};cache.set(name,m);new Function("require","module","exports",modules[name])(id=>id.startsWith("node:")?require(id):load(id.replace(/^\\.\\//,"")),m,m.exports);return m.exports;}';
  const text = "'use strict';"+loader+'\n('+guestMain.toString()+')(load,'+JSON.stringify(binding)+','+systemArtifacts.toString()+','+JSON.stringify(mode)+').catch(()=>{process.exitCode=2;});\n';
  if (Buffer.byteLength(text) > 1024 ** 2) throw fail('SYSTEM_GUEST_BOUND');
  return { text, sha256: sha(text), hashes };
}

// Deterministic USTAR: only the original 55 members. Recipe is installed outside
// that context, preserving the original COPY . image contents exactly.
function tarFile(name, bytes, mode) {
  if (Buffer.byteLength(name) > 100 || !/^[A-Za-z0-9_./-]+$/.test(name) || name.includes('..')) throw fail('SYSTEM_TAR_NAME');
  const header = Buffer.alloc(512);
  header.write(name, 0, 100);
  for (const [offset,width,value] of [[100,8,mode],[108,8,0],[116,8,0],[124,12,bytes.length],[136,12,0]])
    header.write(value.toString(8).padStart(width-1,'0')+'\0',offset,width);
  header.fill(32,148,156);header[156]=48;header.write('ustar\0',257,6);header.write('00',263,2);
  header.write(header.reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148,8);
  return Buffer.concat([header,bytes,Buffer.alloc((512-bytes.length%512)%512)]);
}
async function contextBytes(root,captured) {
  const diagnostic=captured?.recipe?.target==='original-v03-diagnostic';
  const verify=diagnostic?require('./ownedSystemDiagnosticBuildInputs').verifyDiagnosticBuildInputs:inputs.verifySystemBuildInputs;
  await verify(root,captured);
  const chunks=[];
  for(const row of captured.context.files){
    if(!Number.isSafeInteger(row.bytes)||row.bytes<0||row.bytes>1048576)throw fail('SYSTEM_CONTEXT_BOUND');
    const fd=await fs.open(path.join(root,captured.context.sourceRoot,row.name),require('node:fs').constants.O_RDONLY|require('node:fs').constants.O_NOFOLLOW|require('node:fs').constants.O_NONBLOCK);
    const bytes=Buffer.alloc(row.bytes);let offset=0;
    try{
      const before=await fd.stat();
      if(!before.isFile()||before.nlink!==1||before.size!==row.bytes)throw fail('SYSTEM_CONTEXT_CHANGED');
      while(offset<bytes.length){const {bytesRead}=await fd.read(bytes,offset,bytes.length-offset,offset);if(!bytesRead)throw fail('SYSTEM_CONTEXT_CHANGED');offset+=bytesRead;}
      const extra=Buffer.alloc(1);if((await fd.read(extra,0,1,offset)).bytesRead)throw fail('SYSTEM_CONTEXT_CHANGED');
      const after=await fd.stat();
      if(after.size!==before.size||after.mtimeMs!==before.mtimeMs||after.ctimeMs!==before.ctimeMs)throw fail('SYSTEM_CONTEXT_CHANGED');
    }finally{await fd.close();}
    if(sha(bytes)!==row.sha256)throw fail('SYSTEM_CONTEXT_CHANGED');
    chunks.push(tarFile((diagnostic?'owned-system/':'')+row.name,bytes,row.mode));
  }
  if(diagnostic)chunks.push(tarFile(captured.recipe.generatedEntry.name,Buffer.from(captured.recipe.generatedEntry.source),0o644));
  chunks.push(Buffer.alloc(1024));
  await verify(root,captured);
  const bytes=Buffer.concat(chunks);if(bytes.length>LIMITS.context+131072)throw fail('SYSTEM_CONTEXT_BOUND');return bytes;
}

function commandsFor(meta, spec, captured, guest) {
  const diagnostic=captured?.recipe?.target==='original-v03-diagnostic';
  if(diagnostic){
    require('./ownedSystemDiagnosticBuildInputs').validateRecipe(captured.recipe);
    if(meta.binding.target!=='v03-diagnostic'||meta.binding.base!==captured.recipe.base)throw fail('DIAGNOSTIC_BUILD_BINDING');
  }
  const quote = value => "'" + value.replace(/'/g, "'\\''") + "'";
  const suffix = '\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" info --format \'{{json .}}\'\n';
  if (!meta.commands.inspect.endsWith(suffix)) throw fail('SYSTEM_GUARD_SHAPE');
  const guard = meta.commands.inspect.slice(0,-suffix.length);
  const identity = String.raw`
system_identity() {
 [ -f "$root/fs/system.cid" ] && [ ! -L "$root/fs/system.cid" ]
 cid=$(cat "$root/fs/system.cid")
 [ "$(printf '%s' "$cid" | wc -c | tr -d ' ')" = 64 ]; case "$cid" in *[!a-f0-9]*) return 97;; esac
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$cid")" = "$cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "owasp-ai-goat.system.closure"}}' "$cid")" = "$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$cid")" = "$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' 'node@BASE')" ]
}
`.replace('node@BASE','node@'+captured.recipe.base);
const start = guard+identity+(diagnostic?'\nrelay_control v03_credit >&2\n':'')+String.raw`
check_mount; check_runtime
[ ! -e "$root/fs/system-closure" ] && [ ! -L "$root/fs/system-closure" ]
mkdir -m 0700 "$root/fs/system-closure"
/usr/bin/python3 -I -S -B -c 'import sys,os,hashlib; b=sys.stdin.buffer.read(1048577); assert 0<len(b)<=1048576 and hashlib.sha256(b).hexdigest()==sys.argv[2]; f=os.fdopen(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400),"wb"); f.write(b); f.flush(); os.fsync(f.fileno()); f.close()' "$root/fs/system-guest.js" GUEST_SHA
proxy_port=$(relay_control authority); deadline=$(cat "$root/acquisition.deadline")
printf '%s' "$nonce" > "$root/fs/system.intent"
docker --host "unix://$root/fs/docker.sock" create --cidfile "$root/fs/system.cid" --name "owasp-ai-goat-system-closure-$nonce" --label "owasp-ai-goat.system.closure=$nonce" --pull never --network host --read-only --memory 768m --cpus 1 --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges --log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false --mount "type=bind,source=$root/fs/metadata-retained,target=/metadata-retained,readonly" --mount "type=bind,source=$root/fs/system-closure,target=/system-closure" --mount "type=bind,source=$root/fs/system-guest.js,target=/system-guest.js,readonly" --tmpfs /metadata:rw,nosuid,nodev,noexec,size=512m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --env "OWASP_AI_GOAT_ARTIFACT_DEADLINE_SECONDS=$deadline" --env "OWASP_AI_GOAT_ARTIFACT_PROXY_PORT=$proxy_port" --entrypoint /usr/local/bin/node 'node@BASE' /system-guest.js >/dev/null
system_identity; docker --host "unix://$root/fs/docker.sock" start "$cid" >/dev/null
attempt=0
until [ -f "$root/fs/system-closure/ready.json" ]; do
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = true ]
 attempt=$((attempt+1)); [ "$attempt" -lt 1500 ]; sleep .2
done
system_identity; cat "$root/fs/system-closure/ready.json"
`.replace('GUEST_SHA',quote(guest.sha256)).replace('node@BASE','node@'+captured.recipe.base);
  // Explicit unpacker accepts only exact names, regular files, sizes, modes and
  // hashes. Never tar-extract a caller-supplied member/link/path.
  const unpack = String.raw`
import sys,os,tarfile,hashlib,json
root=sys.argv[1]; rows=json.loads(sys.argv[2]); recipe=json.loads(sys.argv[3]);directories=json.loads(sys.argv[4])
context=root+'/fs/system-context';os.mkdir(context,0o700)
seen=set(); total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
 for member in archive:
  assert member.name in rows and member.name not in seen and member.isfile()
  row=rows[member.name];assert member.size==row['bytes'] and member.mode==row['mode']
  assert member.uid==0 and member.gid==0 and member.size<=1048576
  data=archive.extractfile(member).read(1048577);total+=len(data);assert total<=16777216
  assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
  name=context+'/'+member.name;os.makedirs(os.path.dirname(name),mode=0o700,exist_ok=True)
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,row['mode'])
  with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fchmod(f.fileno(),row['mode']);os.fsync(f.fileno())
  seen.add(member.name)
assert seen==set(rows)
for row in directories:os.chmod(context if row['name']=='.' else context+'/'+row['name'],row['mode'])
with os.fdopen(os.open(root+'/fs/system.Dockerfile',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400),'wb') as f:
 data=recipe['dockerfile'].encode();assert hashlib.sha256(data).hexdigest()==recipe['dockerfileSha256']
 f.write(data);f.flush();os.fsync(f.fileno())
`;
  const rows=Object.fromEntries(captured.context.files.map(({name,...row})=>[(diagnostic?'owned-system/':'')+name,row]));
  const directories=diagnostic?[{name:'.',mode:0o700},...captured.context.directories.map(row=>({...row,name:row.name==='.'?'owned-system':'owned-system/'+row.name}))]:captured.context.directories;
  if(diagnostic){const entry=captured.recipe.generatedEntry;rows[entry.name]={bytes:entry.bytes,sha256:entry.sha256,mode:0o644};}
  const build = guard+identity+'\ncheck_mount; check_runtime; system_identity\n'
    +'[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format \'{{.State.Running}}\' "$cid")" = true ]\n'
    +'/usr/bin/python3 -I -S -B -c '+quote(unpack)+' "$root" '+quote(JSON.stringify(rows))+' '+quote(JSON.stringify(captured.recipe))+' '+quote(JSON.stringify(directories))+'\n'
    + 'port=$(/usr/bin/python3 -I -S -B -c '+quote("import sys,json,os; f=os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)); assert os.fstat(f.fileno()).st_size<=1048576; r=json.load(f); assert r['binding']==json.loads(sys.argv[2]) and r['metadataAuthenticated'] is True and r['artifactBytesVerified'] is True; assert type(r['port']) is int and 0<r['port']<65536; print(r['port'])")+' "$root/fs/system-closure/ready.json" '+quote(JSON.stringify(meta.binding))+')\n'
    +'stop_private_relay\nproxy="http://127.0.0.1:$port"\n'
    +'timeout --signal=TERM --kill-after=10 300 docker --host "unix://$root/fs/docker.sock" build --pull=false --network=host --platform linux/arm64 --build-arg "HTTP_PROXY=$proxy" --build-arg "HTTPS_PROXY=$proxy" --build-arg "http_proxy=$proxy" --build-arg "https_proxy=$proxy" --build-arg NO_PROXY= --build-arg no_proxy= --label '+quote('owasp-ai-goat.system.inputs='+captured.inputSha256)+' --label "owasp-ai-goat.build-run=$nonce" -f "$root/fs/system.Dockerfile" -t "owasp-ai-goat-system-build:$nonce" "$root/fs/system-context"\nsystem_identity\n';
  const terminalCheck=String.raw`
import sys,json,os,stat
f=os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW));s=os.fstat(f.fileno())
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=1048576
r=json.load(f);assert r['version']==1 and r['binding']==json.loads(sys.argv[3]) and r['cleanupErrors']==[]
assert sys.argv[2] in ('0','1')
if r['result'] is not None: assert r['result']['closed'] is True and r['result']['absenceVerified'] is True and r['result']['active']==0
assert int(sys.argv[2])==(1 if r['failure'] or (r['result'] and r['result']['failure']) else 0)
`;
  const retire=guard+identity+String.raw`
if [ ! -e "$root/fs/system.intent" ] && [ ! -L "$root/fs/system.intent" ]; then printf 'absent\n'; exit 0; fi
check_mount; check_runtime; system_identity
docker --host "unix://$root/fs/docker.sock" stop --time 10 "$cid" >/dev/null
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = false ]
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.OOMKilled}}' "$cid")" = false ]
code=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$cid")
`
    +'/usr/bin/python3 -I -S -B -c '+quote(terminalCheck)+' "$root/fs/system-closure/terminal.json" "$code" '+quote(JSON.stringify(meta.binding))+'\n'
    +String.raw`
docker --host "unix://$root/fs/docker.sock" rm "$cid" >/dev/null
remaining=$(docker --host "unix://$root/fs/docker.sock" ps --all --quiet --no-trunc)
for id in $remaining; do
 [ "$(printf '%s' "$id" | wc -c | tr -d ' ')" = 64 ]; case "$id" in *[!a-f0-9]*) exit 97;; esac
 [ "$id" != "$cid" ]
done
printf 'absent\n'
`;
  const evidence=guard+String.raw`
check_mount
/usr/bin/python3 -I -S -B - "$root/fs/system-closure" <<'SYSTEM_EVIDENCE'
import sys,os,json,stat
result={}
for name in ('closure.json','ready.json','replay-intent.json','replay-failure.json','terminal.json'):
 p=sys.argv[1]+'/'+name
 if not os.path.lexists(p):result[name]=None;continue
 f=os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW));s=os.fstat(f.fileno())
 assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o400 and 0<s.st_size<=1048576
 with f:result[name]=f.read(1048577)
encoded=json.dumps(result);assert len(encoded.encode())<=2097152;print(encoded)
SYSTEM_EVIDENCE
`;

  const handoff=guard+String.raw`
check_mount; check_runtime; check_network
/usr/bin/python3 -I -S -B - "$root" "$nonce" <<'SYSTEM_HANDOFF'
import os,sys,json
root,run=sys.argv[1:]
def text(name):
 f=os.fdopen(os.open(root+'/fs/'+name,os.O_RDONLY|os.O_NOFOLLOW))
 with f:
  s=os.fstat(f.fileno());assert s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=4096
  return f.read(4097).strip()
namespace=text('namespace.inode')
assert namespace!=text('shared.inode') and namespace!=os.readlink('/proc/1/ns/net')
def process(name,exe):
 pid=int(text(name+'.pid'));start=text(name+'.start');assert pid>1
 with open('/proc/'+str(pid)+'/stat') as f: fields=f.read().rsplit(')',1)[1].split()
 assert fields[19]==start and os.readlink('/proc/'+str(pid)+'/exe')==exe
 assert os.readlink('/proc/'+str(pid)+'/ns/net')==namespace
 return {'pid':pid,'startTicks':start,'exe':exe}
s=os.stat(root+'/fs')
print(json.dumps({'version':1,'target':'original-v24-system','runId':run,'privateDockerHost':'unix://'+root+'/fs/docker.sock',
 'namespaceInode':namespace,'filesystemIdentity':{'device':s.st_dev,'inode':s.st_ino},
 'daemonProcess':process('daemon','/usr/bin/dockerd'),'namespaceHolder':process('namespace','/usr/bin/sleep')}))
SYSTEM_HANDOFF
`;

  const commands={inventory:meta.commands.inventory,...Object.fromEntries(Object.entries(meta.phases).filter(([key])=>key!=='version')),
    inspect:meta.commands.inspect,startArtifacts:start,build,retireArtifacts:retire,closureEvidence:evidence,handoff,
    image:guard+'\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" image inspect "owasp-ai-goat-system-build:$nonce"\n'};
  if(diagnostic){
    commands.handoff=commands.handoff.replace("'target':'original-v24-system'","'target':'original-v03-diagnostic'");
    for(const key of ['build','image'])commands[key]=commands[key].replaceAll('owasp-ai-goat-system-build:','owasp-ai-goat-diagnostic-build:').replaceAll('owasp-ai-goat.system.inputs=','owasp-ai-goat.diagnostic.inputs=');
  }
  return commands;
}

const PAIR_BUILD=Symbol('paired build inputs');
async function systemBuildPlan(root,runId,recipe,mode) {
  if(mode!==undefined&&mode!==PAIR_BUILD)throw fail('SYSTEM_PLAN_MODE');
  if(!/^[a-f0-9]{32}$/.test(runId||''))throw fail('SYSTEM_RUN_ID');
  const captured=await inputs.captureSystemBuildInputs(root,recipe);
  const derived=await systemBounded.loadSystemBounded(mode===PAIR_BUILD);
  const meta=await derived.bounded._internals.systemMetadataQualificationPlan(root,runId);
  const spec=derived.bounded.specification(root,runId),guest=await guestSource(root,meta.binding);
  const metadataGuestSource=metadata.guestMetadataSource(meta.binding,{retention:meta.metadataRetention.mode});
  if(sha(metadataGuestSource)!==meta.guestSourceSha256)throw fail('SYSTEM_METADATA_SOURCE_CHANGED');
  const hashes={...guest.hashes};
  for(const name of ['ownedSystemConfigBuildAdapter','ownedSystemConfigPrivateBuild','ownedMcpBoundedBuild','ownedSystemBoundedDerivation','ownedSystemRuntimeLease']){
    const relative='tests/postgres/'+name+'.js';hashes[relative]=sha(await fs.readFile(path.join(root,relative)));
  }
  for(const relative of ['tests/postgres/ownedSystemRuntimeTransport.js','tests/postgres/ownedSystemPrivateHttpConsumer.js','tests/postgres/owned_system_private_http_channel.py']){
    hashes[relative]=sha(await fs.readFile(path.join(root,relative)));
  }
  return freeze({version:1,target:TARGET,runId,binding:meta.binding,spec,captured,metadata:meta,
    holderLease:{sourceSha256:derived.sourceSha256,derivedSha256:derived.derivedSha256,target:derived.leaseTarget,totalMs:derived.totalMs},
    guestSource:guest.text,metadataGuestSource,helperHashes:hashes,commands:commandsFor(meta,spec,captured,guest),limits:LIMITS,
    executionApproved:false,runtimeAvailable:false,pending:['private-system-http-consumer','outer-owned-channel-admission']});
}
const PAIR_TARGET='original-v24-system-and-policy';
const PAIR_PHASES=Object.freeze(['inventory','preflight','prepare','namespace','relayStart','daemonStart','inspect',
  'systemMetadata','systemMetadataRetire','systemReserve','systemAcquire','systemAcquireRetire','systemEvidence','policyOverhead',
  'policyMetadata','policyMetadataRetire','policyReserve','policyAcquire','policyAcquireRetire','policyEvidence','acquisitionSeal','acquisitionRetire','inspect',
  'systemReplay','systemBuild','systemImage','systemReplayRetire','systemEvidence',
  'policyReplay','policyBuild','policyImage','policyReplayRetire','policyEvidence','inspect','handoff']);
const PAIR_CLEANUP=Object.freeze(['systemMetadataRetire','policyMetadataRetire','systemAcquireRetire','policyAcquireRetire','systemReplayRetire','policyReplayRetire',
  'systemEvidence','policyEvidence','stop','evidence','systemExport','policyExport','systemFailureExport','policyFailureExport','cleanup','inventory']);
// A failed acquisition is evidence, never an authenticated metadata receipt.
// Preserve only this slot's actual bounded raw files, including incomplete
// publications. The unchanged successful exporter below remains strict.
const FAILED_SLOT_ARCHIVE=String.raw`
import os,sys,stat,json,hashlib,tarfile,io,re
def failed_slot_archive(root,proof,output):
 cap=144*1024**2
 assert os.path.realpath(root)==root
 def identity(s):return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_mode,s.st_nlink)
 def directory(p):
  s=os.lstat(p);assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
  return identity(s),sorted(os.listdir(p))
 directories={root:directory(root)};files=[];total=0
 assert set(directories[root][1])<= {'manifest.json','result.json','objects','partial'}
 for name in directories[root][1]:
  if name in ('objects','partial'):
   p=root+'/'+name;directories[p]=directory(p);assert len(directories[p][1])<=64
   for leaf in directories[p][1]:
    assert re.fullmatch('[a-f0-9]{64}' if name=='objects' else '[0-9]{4}',leaf)
    files.append(name+'/'+leaf)
  else:files.append(name)
 assert len(files)<=66 and len([n for n in files if '/' in n])<=64
 def opened(name):
  p=root+'/'+name;fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   s=os.fstat(fd)
   assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode) in (0o444,0o600)
   assert s.st_size<=(32*1048576 if '/' in name else 1048576) and identity(os.lstat(p))==identity(s)
   return os.fdopen(fd,'rb'),s
  except BaseException:os.close(fd);raise
 rows=[]
 for name in files:
  with opened(name)[0] as f:
   s=os.fstat(f.fileno());total+=s.st_size;assert total<=cap
   digest=hashlib.file_digest(f,'sha256').hexdigest()
   assert identity(os.fstat(f.fileno()))==identity(s)==identity(os.lstat(root+'/'+name))
   rows.append(dict(file=name,bytes=s.st_size,sha256=digest,identity=list(identity(s))))
 provenance=dict(version=1,kind='failed-slot-raw-metadata',authenticated=False,qualificationComplete=False,
  **proof,empty=not files,directories=[os.path.relpath(p,root) for p in directories],objects=rows,bytes=total)
 encoded=json.dumps(provenance,separators=(',',':')).encode();assert len(encoded)<=65536
 class Bounded:
  def __init__(self):self.count=0
  def write(self,data):
   self.count+=len(data);assert self.count<=145*1048576
   return output.write(data)
 with tarfile.open(fileobj=Bounded(),mode='w|',format=tarfile.USTAR_FORMAT) as archive:
  def add(name,source,size):
   info=tarfile.TarInfo(name);info.size=size;info.mode=0o600;info.uid=0;info.gid=0;info.mtime=0;archive.addfile(info,source)
  add('failure-provenance.json',io.BytesIO(encoded),len(encoded))
  for row in rows:
   with opened(row['file'])[0] as f:
    assert list(identity(os.fstat(f.fileno())))==row['identity']
    add('raw/'+row['file'],f,row['bytes']);f.seek(0)
    assert hashlib.file_digest(f,'sha256').hexdigest()==row['sha256']
    assert list(identity(os.fstat(f.fileno())))==row['identity']==list(identity(os.lstat(root+'/'+row['file'])))
  for p,observed in directories.items():assert directory(p)==observed
 output.flush()
`;
function replaceRequired(text,from,to){
  if(!text.includes(from))throw fail('SYSTEM_PAIR_COMMAND_SHAPE');return text.split(from).join(to);
}
// Closed target slots: only host paths, owner labels and exact image tags are
// namespaced. The guest's /metadata-retained and /system-closure interfaces and
// both original Dockerfiles remain byte-for-byte unchanged.
function slotCommands(meta,spec,captured,acquisition,replay,slot){
  if(!['system','policy'].includes(slot))throw fail('SYSTEM_PAIR_SLOT');
  const adapted={...captured,context:{...captured.context,
    files:captured.context.files.map(({base64,...row})=>row),
    directories:captured.context.directories||[{name:'.',mode:0o755},{name:'policy-render',mode:0o755},{name:'policy-render/assets',mode:0o755}]}};
  const original=commandsFor(meta,spec,adapted,replay),acq=commandsFor(meta,spec,adapted,acquisition);
  const host=text=>text.replaceAll('$root/fs/system',`$root/fs/${slot}`)
    .replaceAll('/fs/system-context',`/fs/${slot}-context`).replaceAll('/fs/system.Dockerfile',`/fs/${slot}.Dockerfile`)
    .replaceAll('owasp-ai-goat-system-',`owasp-ai-goat-${slot}-`).replaceAll('owasp-ai-goat.system.',`owasp-ai-goat.${slot}.`)
    .replaceAll('$root/fs/metadata-retained',`$root/fs/${slot}-metadata-retained`);
  const acquisitionIdentity=text=>text.replaceAll('$root/fs/'+slot+'.cid','$root/fs/'+slot+'-acquire.cid')
    .replaceAll('$root/fs/'+slot+'.intent','$root/fs/'+slot+'-acquire.intent')
    .replaceAll('$root/fs/'+slot+'-guest.js','$root/fs/'+slot+'-acquire-guest.js')
    .replaceAll(`owasp-ai-goat-${slot}-closure-`,`owasp-ai-goat-${slot}-acquire-`)
    .replaceAll(`owasp-ai-goat.${slot}.closure`,`owasp-ai-goat.${slot}.acquire`);
  let acquire=acquisitionIdentity(host(acq.startArtifacts));
  acquire=replaceRequired(acquire,`$root/fs/${slot}-closure/ready.json`,`$root/fs/${slot}-closure/acquisition-terminal.json`);
  // Publication alone is not process/descriptor retirement. Wait for the real
  // exited state before handing off to removal, including the publish/exit race.
  const loopAt=acquire.indexOf('\nattempt=0\n');if(loopAt<0)throw fail('SYSTEM_PAIR_COMMAND_SHAPE');
  acquire=acquire.slice(0,loopAt)+String.raw`
attempt=0
while :; do
 state=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")
 case "$state" in
  false) [ -f "$root/fs/SLOT-closure/acquisition-terminal.json" ]; break;;
  true) attempt=$((attempt+1)); [ "$attempt" -lt 1500 ]; sleep .2;;
  *) exit 97;;
 esac
done
system_identity
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.OOMKilled}}' "$cid")" = false ]
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$cid")" = 0 ]
cat "$root/fs/SLOT-closure/acquisition-terminal.json"
`.replaceAll('SLOT',slot);
  const acquireRetire=replaceRequired(acquisitionIdentity(host(acq.retireArtifacts)),
    `$root/fs/${slot}-closure/terminal.json`,`$root/fs/${slot}-closure/acquisition-terminal.json`);
  let replayStart=host(original.startArtifacts);
  replayStart=replaceRequired(replayStart,`[ ! -e "$root/fs/${slot}-closure" ] && [ ! -L "$root/fs/${slot}-closure" ]\nmkdir -m 0700 "$root/fs/${slot}-closure"`,
    `[ -d "$root/fs/${slot}-closure" ] && [ ! -L "$root/fs/${slot}-closure" ]\n[ -f "$root/fs/${slot}-closure/acquisition-terminal.json" ]`);
  replayStart=replaceRequired(replayStart,'proxy_port=$(relay_control authority); deadline=$(cat "$root/acquisition.deadline")','proxy_port=0; deadline=0');
  let build=replaceRequired(host(original.build),'stop_private_relay\n','');
  if(slot==='policy')build=replaceRequired(build,'-f "$root/fs/policy.Dockerfile"','-f "$root/fs/policy-context/policy-render/Dockerfile"');
  let fetch=meta.phases.metadataFetch.replaceAll('$root/fs/metadata-retained',`$root/fs/${slot}-metadata-retained`)
    .replaceAll('$root/fs/metadata.cid',`$root/fs/${slot}-metadata.cid`).replaceAll('owasp-ai-goat-metadata-',`owasp-ai-goat-${slot}-metadata-`)
    .replaceAll('owasp-ai-goat.metadata.owner',`owasp-ai-goat.${slot}.metadata.owner`);
  const evidence=replaceRequired(host(original.closureEvidence),"'closure.json','ready.json'","'closure.json','acquisition-terminal.json','ready.json'");
  const exported=meta.phases.retainedExport.replaceAll('$root/fs/metadata-retained',`$root/fs/${slot}-metadata-retained`);
  const archiveAnchor=`/usr/bin/python3 -I -S -B - "$root/fs/${slot}-metadata-retained" "$nonce" <<'OWASP_AI_GOAT_METADATA_ARCHIVE'\n`;
  const archiveAt=exported.indexOf(archiveAnchor);
  if(archiveAt<0||exported.indexOf(archiveAnchor,archiveAt+1)!==-1)throw fail('SYSTEM_GUARD_SHAPE');
  // Reuse exact owner/mount and stopped-daemon guards, not success-manifest
  // assertions. No missing or malformed report is manufactured or repaired.
  const failureExport=exported.slice(0,archiveAt)+`/usr/bin/python3 -I -S -B - "$root/fs/${slot}-metadata-retained" "$nonce" <<'OWASP_AI_GOAT_FAILED_SLOT_ARCHIVE'\n`+
    FAILED_SLOT_ARCHIVE+`\nproof=json.loads(${JSON.stringify(JSON.stringify({slot,binding:meta.binding,metadataSourceSha256:meta.guestSourceSha256}))})\n`+
    "assert proof['binding']['runId']==sys.argv[2]\nfailed_slot_archive(sys.argv[1],proof,sys.stdout.buffer)\nOWASP_AI_GOAT_FAILED_SLOT_ARCHIVE\n";
  const suffix='\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" info --format \'{{json .}}\'\n';
  if(!meta.commands.inspect.endsWith(suffix))throw fail('SYSTEM_GUARD_SHAPE');
  const metadataRetire=meta.commands.inspect.slice(0,-suffix.length)+String.raw`
check_mount; check_runtime
name="owasp-ai-goat-SLOT-metadata-$nonce"
listing=$(docker --host "unix://$root/fs/docker.sock" ps --all --quiet --no-trunc --filter "name=^/$name$")
if [ -n "$listing" ]; then
 [ -f "$root/fs/SLOT-metadata.cid" ] && [ ! -L "$root/fs/SLOT-metadata.cid" ]
 cid=$(cat "$root/fs/SLOT-metadata.cid")
 [ "$(printf '%s' "$cid" | wc -c | tr -d ' ')" = 64 ]; case "$cid" in *[!a-f0-9]*) exit 97;; esac
 [ "$listing" = "$cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$cid")" = "$cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "owasp-ai-goat.SLOT.metadata.owner"}}' "$cid")" = "$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$cid")" = "$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' 'node@BASE')" ]
 docker --host "unix://$root/fs/docker.sock" rm -f "$cid" >/dev/null
fi
listing=$(docker --host "unix://$root/fs/docker.sock" ps --all --quiet --no-trunc --filter "name=^/$name$")
[ -z "$listing" ]
if [ -e "$root/fs/SLOT-metadata.cid" ] || [ -L "$root/fs/SLOT-metadata.cid" ]; then
 [ -f "$root/fs/SLOT-metadata.cid" ] && [ ! -L "$root/fs/SLOT-metadata.cid" ]
 cid=$(cat "$root/fs/SLOT-metadata.cid")
 [ "$(printf '%s' "$cid" | wc -c | tr -d ' ')" = 64 ]; case "$cid" in *[!a-f0-9]*) exit 97;; esac
 all=$(docker --host "unix://$root/fs/docker.sock" ps --all --quiet --no-trunc)
 for id in $all; do
  [ "$(printf '%s' "$id" | wc -c | tr -d ' ')" = 64 ]; case "$id" in *[!a-f0-9]*) exit 97;; esac
  [ "$id" != "$cid" ]
 done
fi
printf 'absent\n'
`.replaceAll('SLOT',slot).replace('node@BASE','node@'+captured.recipe.base);
  return {metadata:fetch,metadataRetire,acquire,acquireRetire,replay:replayStart,replayRetire:host(original.retireArtifacts),
    build,image:host(original.image),evidence,export:exported,failureExport};
}
async function rendererContextBytes(root,captured){
  await rendererInputs.verifyPolicyRendererBuildInputs(root,captured);
  const chunks=captured.context.files.map(row=>{
    const bytes=Buffer.from(row.base64,'base64');
    if(bytes.length!==row.bytes||sha(bytes)!==row.sha256)throw fail('SYSTEM_CONTEXT_CHANGED');
    return tarFile(row.name,bytes,row.mode);
  });
  chunks.push(Buffer.alloc(1024));const result=Buffer.concat(chunks);
  if(result.length>LIMITS.context+131072)throw fail('SYSTEM_CONTEXT_BOUND');return result;
}
async function systemPolicyBuildPlan(root,runId,recipe){
  const system=await systemBuildPlan(root,runId,recipe,PAIR_BUILD),derived=await systemBounded.loadSystemBounded(true);
  const policy=await derived.bounded._internals.policyRendererMetadataQualificationPlan(root,runId);
  const renderer=policy.rendererInputs;
  await rendererInputs.verifyPolicyRendererBuildInputs(root,renderer);
  if(system.captured.context.bytes+renderer.context.bytes>LIMITS.context)throw fail('SYSTEM_PAIR_CONTEXT_BOUND');
  const slots={},commands={...system.commands},helperHashes={...system.helperHashes};
  for(const [slot,meta,captured]of [['system',system.metadata,system.captured],['policy',policy,renderer]]){
    const acquisition=await guestSource(root,meta.binding,'acquire'),replay=await guestSource(root,meta.binding,'replay');
    const produced=slotCommands(meta,system.spec,captured,acquisition,replay,slot);
    slots[slot]={binding:meta.binding,metadata:meta,captured,acquisitionSource:acquisition.text,replaySource:replay.text,
      metadataSource:metadata.guestMetadataSource(meta.binding,{retention:meta.metadataRetention.mode}),
      storage:{metadata:system.spec.mount+'/'+slot+'-metadata-retained',closure:system.spec.mount+'/'+slot+'-closure',
        context:system.spec.mount+'/'+slot+'-context',acquisitionCid:system.spec.mount+'/'+slot+'-acquire.cid',
        replayCid:system.spec.mount+'/'+slot+'.cid',image:'owasp-ai-goat-'+slot+'-build:'+runId}};
    if(sha(slots[slot].metadataSource)!==meta.guestSourceSha256)throw fail('SYSTEM_METADATA_SOURCE_CHANGED');
    for(const [suffix,key]of [['Metadata','metadata'],['MetadataRetire','metadataRetire'],['Acquire','acquire'],['AcquireRetire','acquireRetire'],
      ['Replay','replay'],['ReplayRetire','replayRetire'],['Build','build'],['Image','image'],['Evidence','evidence'],['Export','export'],['FailureExport','failureExport']])commands[slot+suffix]=produced[key];
  }
  commands.prepare=replaceRequired(system.commands.prepare,'mkdir -m 0700 "$root/fs/metadata-retained"',
    'mkdir -m 0700 "$root/fs/system-metadata-retained" "$root/fs/policy-metadata-retained"');
  const suffix='\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" info --format \'{{json .}}\'\n';
  if(!system.commands.inspect.endsWith(suffix))throw fail('SYSTEM_GUARD_SHAPE');
  commands.acquisitionRetire=system.commands.inspect.slice(0,-suffix.length)+'\ncheck_mount; check_runtime\nstop_private_relay\n';
  for(const [name,operation]of Object.entries({systemReserve:'pair_system_reserve',policyOverhead:'pair_policy_overhead',policyReserve:'pair_policy_reserve',acquisitionSeal:'pair_seal'})){
    commands[name]=system.commands.inspect.slice(0,-suffix.length)+'\ncheck_mount; check_runtime\nrelay_control '+operation+'\n';
  }
  for(const name of ['metadataFetch','startArtifacts','build','image','retireArtifacts','closureEvidence','retainedExport'])delete commands[name];
  for(const name of ['ownedPolicyRendererBuildInputs','ownedSystemConfigPhaseDriver','ownedSystemImageProducer']){
    const relative='tests/postgres/'+name+'.js';helperHashes[relative]=sha(await fs.readFile(path.join(root,relative)));
  }
  for(const relative of ['server/services/secureshopSystemConfigClient.js','server/services/secureshopPolicySandboxRuntime.js',
    'server/services/secureshopPromptPolicyContract.js'])helperHashes[relative]=sha(await fs.readFile(path.join(root,relative)));
  return freeze({...system,target:PAIR_TARGET,version:2,slots,commands,helperHashes,connectionPolicy:systemBounded.PAIR_POLICY,wirePolicy:systemBounded.PAIR_WIRE_POLICY,
    phases:PAIR_PHASES,cleanupPhases:PAIR_CLEANUP,executionApproved:false,runtimeAvailable:false,
    pending:['paired-runtime-composition-review','original-browser-owner-and-main-admission']});
}
const planDigest=plan=>sha(JSON.stringify(plan));
async function verifyPlan(plan){
  if(plan?.target==='original-v03-diagnostic')return require('./ownedSystemDiagnosticBuildAdapter').verifyDiagnosticBuildPlan(plan);
  if(plan.target===PAIR_TARGET&&!equal(plan.wirePolicy,systemBounded.PAIR_WIRE_POLICY))throw fail('SYSTEM_PAIR_WIRE_POLICY');
  await inputs.verifySystemBuildInputs(plan.spec.root,plan.captured);
  for(const [name,digest]of Object.entries(plan.helperHashes))if(sha(await fs.readFile(path.join(plan.spec.root,name)))!==digest)throw fail('SYSTEM_HELPER_CHANGED');
  for(const [name,digest]of Object.entries(plan.metadata.buildSources))if(sha(await fs.readFile(path.join(plan.spec.root,name)))!==digest)throw fail('SYSTEM_INFRASTRUCTURE_CHANGED');
  if(plan.target===PAIR_TARGET){
    await rendererInputs.verifyPolicyRendererBuildInputs(plan.spec.root,plan.slots.policy.captured);
    for(const [name,digest]of Object.entries(plan.slots.policy.metadata.buildSources))if(sha(await fs.readFile(path.join(plan.spec.root,name)))!==digest)throw fail('SYSTEM_INFRASTRUCTURE_CHANGED');
  }
}

// No Boolean, JSON receipt, arbitrary callback or injected phase runner creates
// a live capability. Future channel support must be owned by this producer.
function validatePhysicalHandoff(value,plan){
  const target=plan.target==='original-v03-diagnostic'?'original-v03-diagnostic':TARGET;
  const keys=['version','target','runId','privateDockerHost','namespaceInode','filesystemIdentity','daemonProcess','namespaceHolder'];
  if(!value||Object.keys(value).sort().join(',')!==keys.sort().join(',')||value.version!==1||value.target!==target
    ||value.runId!==plan.runId||value.privateDockerHost!=='unix://'+plan.spec.socket
    ||!/^net:\[[1-9][0-9]*\]$/.test(value.namespaceInode))throw fail('SYSTEM_PHYSICAL_HANDOFF');
  for(const [name,exe]of [['daemonProcess','/usr/bin/dockerd'],['namespaceHolder','/usr/bin/sleep']]){
    const row=value[name];
    if(!row||Object.keys(row).sort().join(',')!=='exe,pid,startTicks'||row.exe!==exe
      ||!Number.isSafeInteger(row.pid)||row.pid<=1||!/^[1-9][0-9]*$/.test(row.startTicks))throw fail('SYSTEM_PROCESS_HANDOFF');
  }
  if(value.daemonProcess.pid===value.namespaceHolder.pid||!value.filesystemIdentity
    ||Object.keys(value.filesystemIdentity).sort().join(',')!=='device,inode'
    ||!Number.isSafeInteger(value.filesystemIdentity.device)||value.filesystemIdentity.device<0
    ||!Number.isSafeInteger(value.filesystemIdentity.inode)||value.filesystemIdentity.inode<=0)throw fail('SYSTEM_FILESYSTEM_HANDOFF');
  return freeze(structuredClone(value));
}
// Resolve only at invocation: producer and its fixed driver import this adapter
// while initializing. The producer's private WeakMap is the sole authority;
// this layer neither reconstructs capabilities nor admits native execution.
function assertSystemImageCapability(capability){
 return require('./ownedSystemImageProducer').assertSystemImageCapability(capability);
}
async function withPrivateSystemImage(options,callback){
 return require('./ownedSystemImageProducer').withPrivateSystemImage(options,callback);
}

// Controlled executable orchestration: includes actual guest/build commands,
// but cannot expose a runtime or live image capability. Native gate above stays
// closed until its default bounded driver and HTTP consumer are reviewed.
const STOP_AT_IMAGE=Symbol('private-system-observation-replay');
async function runControlledPipeline(plan,options={}){
  const diagnostic=plan?.target==='original-v03-diagnostic',target=diagnostic?'original-v03-diagnostic':TARGET;
  const {expectedPlanSha256,phase,record,verify=verifyPlan,context=contextBytes,signal}=options;
  if(expectedPlanSha256!==planDigest(plan)||typeof phase!=='function'||typeof record!=='function')throw fail('SYSTEM_PLAN_ADMISSION');
  signal?.throwIfAborted();await verify(plan);
  let intended=false,artifacts=false,retired=false,image,primary,before;const debt=[];
  const step=async(name,input,cleanup=false)=>{
    if(!cleanup){signal?.throwIfAborted();await verify(plan);signal?.throwIfAborted();}
    await record(name+'-intent',{planSha256:expectedPlanSha256});
    const value=await phase(name,{command:plan.commands[name],input,signal:cleanup?undefined:signal});
    await record(name+'-result',value);return value;
  };
  try{
    before=bounded._internals.checkInventory(await step('inventory'));
    await step('preflight');intended=true;
    for(const name of ['prepare','namespace','relayStart','daemonStart'])await step(name);
    const daemon=bounded._internals.checkDaemon(JSON.parse(await step('inspect')),plan.spec);
    const envelope=metadata.validateResultEnvelope(await step('metadataFetch',Readable.from([plan.metadataGuestSource])),plan.binding);
    if(envelope.ok!==true||envelope.version!==3)throw fail('SYSTEM_METADATA_NOT_READY');
    artifacts=true;const ready=JSON.parse(await step('startArtifacts',Readable.from([plan.guestSource])));
    if(!equal(ready.binding,plan.binding)||ready.metadataAuthenticated!==true||ready.artifactBytesVerified!==true||!(/^[a-f0-9]{64}$/).test(ready.closureSha256))throw fail('SYSTEM_CLOSURE_NOT_READY');
    const packet=JSON.parse(await step('closureEvidence'));
    const saved=JSON.parse(packet['closure.json']);
    if(sha(packet['closure.json'])!==ready.closureSha256||!equal(saved.binding,plan.binding)
      ||!equal(saved.authentication.binding,plan.binding)||saved.authentication.method!=='original-base-apt-closed-replay'
      ||saved.acquired.artifactBytesVerified!==true||saved.acquired.bytes.npm!==0)throw fail('SYSTEM_CLOSURE_EVIDENCE');
    const retained=metadata.validateRetainedMetadata(envelope.candidate,plan.binding);
    const expected=systemArtifacts(retained.stages,diagnostic?'v03-diagnostic':'v24-system');
    const expectedAuthentication={binding:plan.binding,version:1,method:'original-base-apt-closed-replay',
      retainedManifestSha256:sha(JSON.stringify(retained)),keyringSha256:envelope.candidate.keyringSha256,
      installedStatusSha256:envelope.candidate.installedStatusSha256,
      stages:retained.stages.map(stage=>({name:stage.name,selectionSha256:sha(stage.selection)})),
      expandedBytes:envelope.candidate.expandedBytes};
    const total=expected.reduce((n,row)=>n+row.bytes,0);
    const expectedAcquired={version:1,artifactBytesVerified:true,metadataAuthenticated:false,buildApproved:false,
      qualificationComplete:false,bytes:{deb:total,npm:0,total},
      artifacts:expected.map(row=>({...row,actualBytes:row.bytes,file:'objects/'+closure._internals.objectName(row)}))};
    if(!equal(saved.authentication,expectedAuthentication)||!equal(saved.acquired,expectedAcquired))throw fail('SYSTEM_CLOSURE_EVIDENCE');
    if(bounded._internals.checkDaemon(JSON.parse(await step('inspect')),plan.spec)!==daemon)throw fail('SYSTEM_DAEMON_CHANGED');
    await step('build',Readable.from([await context(plan.spec.root,plan.captured)]));
    const rows=JSON.parse(await step('image'));image=rows?.[0];
    if(rows.length!==1||!/^sha256:[a-f0-9]{64}$/.test(image?.Id)||image.Architecture!=='arm64'||image.Os!=='linux'
      ||image.Config?.Labels?.[diagnostic?'owasp-ai-goat.diagnostic.inputs':'owasp-ai-goat.system.inputs']!==plan.captured.inputSha256||image.Config?.Labels?.['owasp-ai-goat.build-run']!==plan.runId
      ||image.Config?.User!=='10001:10001'||!equal(image.Config?.Entrypoint,plan.captured.recipe.entrypoint))throw fail('SYSTEM_IMAGE_IDENTITY');
    retired=(await step('retireArtifacts')).trim()==='absent';if(!retired)throw fail('SYSTEM_ARTIFACT_RETIREMENT');
    const terminal=JSON.parse(JSON.parse(await step('closureEvidence'))['terminal.json']);
    if(terminal.failure!==null||terminal.result?.failure!==null||terminal.cleanupErrors?.length)throw fail('SYSTEM_REPLAY_FAILED');
    if(bounded._internals.checkDaemon(JSON.parse(await step('inspect')),plan.spec)!==daemon)throw fail('SYSTEM_DAEMON_CHANGED');
    const physical=validatePhysicalHandoff(JSON.parse(await step('handoff')),plan);
    await record('controlled-image',{version:1,target,physical,daemonId:daemon,imageId:image.Id,
      inputSha256:plan.captured.inputSha256,controlled:true,runtimeAvailable:false});
    await verify(plan);
    if(options[STOP_AT_IMAGE]===true){
      const {version,target,runId,...coordinates}=physical;
      return freeze({version:1,target,runId:plan.runId,imageId:image.Id,
        inputSha256:plan.captured.inputSha256,daemonId:daemon,physical:coordinates});
    }
  }catch(error){primary=error;}
  if(artifacts&&!retired)try{retired=(await step('retireArtifacts',undefined,true)).trim()==='absent';if(!retired)throw fail('SYSTEM_ARTIFACT_RETIREMENT');}catch(error){debt.push(error);}
  if(intended&&(!artifacts||retired)){
    // Evidence must survive before disk cleanup; publication failure retains disk.
    for(const name of ['closureEvidence','stop','evidence','retainedExport','cleanup','inventory']){
      if(name==='closureEvidence'&&!artifacts)continue;
      if(name==='cleanup'&&debt.length)continue;
      try{
        const value=await step(name,undefined,true);
        if(name==='cleanup'&&value.trim()!=='absent')throw fail('SYSTEM_CLEANUP_UNPROVEN');
        if(name==='inventory'&&!equal(before,bounded._internals.checkInventory(value)))throw fail('SYSTEM_SHARED_STATE_CHANGED');
      }catch(error){debt.push(error);}
    }
  }
  const result={version:1,target,controlled:true,buildCompleted:!!image&&!primary,
    cleanupVerified:debt.length===0,runtimeAvailable:false,qualificationComplete:false,
    failure:primary?.code||primary?.name||null,cleanupErrors:debt.map(e=>e.code||e.name)};
  await record('result',result);
  if(primary||debt.length)throw Object.assign(new AggregateError([primary,...debt].filter(Boolean),'System build failed'),{result});
  return result;
}
// Pure replay of the fixed driver's OWN captured outputs, not a public
// capability constructor. A JSON result cannot admit the public runtime.
async function validateDriverObservations(plan,observations){
  if(!Array.isArray(observations))throw fail('SYSTEM_DRIVER_OBSERVATIONS');
  let index=0;
  const binding=await runControlledPipeline(plan,{expectedPlanSha256:planDigest(plan),
    [STOP_AT_IMAGE]:true,record:async()=>{},context:async()=>Buffer.alloc(0),
    phase:async name=>{const row=observations[index++];
      if(!row||Object.keys(row).sort().join(',')!=='name,value'||row.name!==name||typeof row.value!=='string')throw fail('SYSTEM_DRIVER_OBSERVATIONS');
      return row.value;}});
  if(index!==observations.length)throw fail('SYSTEM_DRIVER_OBSERVATIONS');
  return binding;
}
function pairEnvelope(plan,observations,slot){
  const row=observations.find(row=>row.name===slot+'Metadata');
  if(!row)throw fail('SYSTEM_PAIR_METADATA');
  const envelope=metadata.validateResultEnvelope(row.value,plan.slots[slot].binding);
  if(envelope.ok!==true||envelope.version!==3)throw fail('SYSTEM_PAIR_METADATA');
  return {envelope,retained:metadata.validateRetainedMetadata(envelope.candidate,plan.slots[slot].binding)};
}
function pairMetadataComplete(plan,observations,slot){
  try{pairEnvelope(plan,observations,slot);return true;}catch{return false;}
}
const PAIR_CREDIT_PHASES=Object.freeze(['systemReserve','policyOverhead','policyReserve','acquisitionSeal']);
function pairCensus(plan,observations,slot){
  const {retained}=pairEnvelope(plan,observations,slot);
  const artifacts=systemArtifacts(retained.stages,plan.slots[slot].binding.target);
  if(!artifacts.length||artifacts.length>128)throw fail('SYSTEM_PAIR_CENSUS');
  return artifacts;
}
function pairAttemptProof(artifacts,proof){
  const bad=()=>{throw fail('SYSTEM_PAIR_ATTEMPTS');};
  if(!proof||!equal(Object.keys(proof).sort(),['attempts','version'])||proof.version!==1||!Array.isArray(proof.attempts)
    ||proof.attempts.length<artifacts.length||proof.attempts.length>2*artifacts.length)bad();
  let pos=0,retries=0;
  for(const [index,artifact] of artifacts.entries()){
    let verified=false;
    for(let ordinal=1;ordinal<=2;ordinal++){
      const row=proof.attempts[pos++];
      if(!row||!equal(Object.keys(row).sort(),['digest','index','kind','ordinal','outcome'])
        ||row.index!==index||row.kind!==artifact.kind||row.digest!==artifact.digest||row.ordinal!==ordinal)bad();
      if(row.outcome==='verified'){verified=true;break;}
      if(ordinal!==1||row.outcome!=='retired-pre-response-reset')bad();retries++;
    }
    if(!verified)bad();
  }
  if(pos!==proof.attempts.length)bad();return {count:pos,retries,attempts:proof.attempts};
}
function pairObservedAttempts(plan,observations,slot){
  const evidence=observations.find(row=>row.name===slot+'Evidence');if(!evidence)throw fail('SYSTEM_PAIR_ATTEMPTS');
  const saved=JSON.parse(JSON.parse(evidence.value)['closure.json']);
  return pairAttemptProof(pairCensus(plan,observations,slot),saved.acquired.attemptProof);
}
function validatePairCredits(plan,observations,through='acquisitionSeal'){
  const bad=()=>{throw fail('SYSTEM_PAIR_CREDIT_EVIDENCE');};
  if(plan.target!==PAIR_TARGET||!equal(plan.connectionPolicy,systemBounded.PAIR_POLICY)
    ||!equal(plan.wirePolicy,systemBounded.PAIR_WIRE_POLICY)||!PAIR_CREDIT_PHASES.includes(through))bad();
  const policy=systemBounded.PAIR_POLICY.name,phases=['system-overhead','system-artifacts','policy-overhead','policy-artifacts','sealed'];
  let old={version:1,policy,runId:plan.runId,sequence:0,phase:phases[0],allocation:32,starts:{adapter:0,connector:0},quota:32,artifactCount:0};
  let lastCounts={adapter:0,connector:0},lastSequence={adapter:0,connector:0},lastRejected={adapter:0,connector:0};
  const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
  const count=n=>Number.isSafeInteger(n)&&n>=0;
  function snapshot(packet,credit,overhead=false){
    if(!exact(packet,'version,runId,variant,rows')||packet.version!==1||packet.runId!==plan.runId||packet.variant!=='metadata-idle-barrier-v4'||!exact(packet.rows,'adapter,connector'))bad();
    const counts={};
    for(const mode of ['adapter','connector']){
      const row=packet.rows[mode],b=row?.pairBudget;
      if(!exact(row,'kind,variant,runId,mode,sequence,trigger,counts,activeWorkers,deniedAuthorities,admission,pairBudget')
        ||row.kind!=='transport-audit'||row.variant!==packet.variant||row.runId!==plan.runId||row.mode!==mode||row.trigger!=='checkpoint'
        ||!count(row.sequence)||row.sequence<=lastSequence[mode]||row.activeWorkers!==0
        ||!exact(b,'policy,lifetime,connections,credit')||b.policy!==policy||b.lifetime!==320||!equal(b.credit,credit)
        ||!count(b.connections)||b.connections<lastCounts[mode]||b.connections<credit.starts[mode]||b.connections>credit.starts[mode]+credit.quota
        ||!exact(row.admission,'workerLimitRejected,connectionLimitRejected,saturated')
        ||!count(row.admission.workerLimitRejected)||row.admission.workerLimitRejected>65535
        ||row.admission.workerLimitRejected<lastRejected[mode]
        ||(!overhead&&row.admission.workerLimitRejected!==lastRejected[mode])
        ||row.admission.connectionLimitRejected!==0||row.admission.saturated!==false
        ||!equal(row.deniedAuthorities,{hosts:{},unclassified:0,overflow:0})
        ||!exact(row.counts,'dnsSubprocesses,externalConnectAttempts,unixConnectAttempts,peerChecks,peerDenied')
        ||!Object.values(row.counts).every(count)||row.counts.peerDenied!==0||Object.values(row.counts).some(n=>n>b.connections))bad();
      counts[mode]=b.connections;lastSequence[mode]=row.sequence;lastRejected[mode]=row.admission.workerLimitRejected;
    }
    if(counts.adapter!==counts.connector)bad();lastCounts=counts;return counts;
  }
  for(let i=0;i<=PAIR_CREDIT_PHASES.indexOf(through);i++){
    const rows=observations.filter(row=>row.name===PAIR_CREDIT_PHASES[i]);if(rows.length!==1)bad();
    const proof=JSON.parse(rows[0].value);
    if(!exact(proof,'version,policy,runId,before,after')||proof.version!==1||proof.policy!==policy||proof.runId!==plan.runId)bad();
    const counts=snapshot(proof.before,old,i%2===0);
    if(i%2===1&&Object.keys(counts).some(mode=>counts[mode]-old.starts[mode]!==pairObservedAttempts(plan,observations,i===1?'system':'policy').count))bad();
    const quota=i===0?pairCensus(plan,observations,'system').length:i===2?pairCensus(plan,observations,'policy').length:i===1?32:0;
    const artifactCount=i%2===0?quota:0,allocation=old.allocation+quota;
    const allowed=artifactCount?Math.min(2*artifactCount,allocation-Math.max(...Object.values(counts))):quota;
    if(allowed<artifactCount)bad();
    const next={version:1,policy,runId:plan.runId,sequence:i+1,phase:phases[i+1],allocation,starts:counts,quota:allowed,artifactCount};
    if(next.allocation>320||!equal(snapshot(proof.after,next),counts))bad();old=next;
  }
  return freeze(old);
}
function validatePairPhaseAdmission(plan,observations,next){
  if(next==='systemReserve'||next==='policyReserve'){
    pairCensus(plan,observations,next==='systemReserve'?'system':'policy');
    if(next==='policyReserve')validatePairAcquisitionBudget(plan,observations);
  }
  if(next==='policyOverhead'||next==='acquisitionSeal'){
    const slot=next==='policyOverhead'?'system':'policy';
    const {envelope,retained}=pairEnvelope(plan,observations,slot);
    const packets=observations.filter(row=>row.name===slot+'Evidence');
    if(packets.length!==1)throw fail('SYSTEM_PAIR_PRIOR_ACQUISITION');
    const packet=JSON.parse(packets[0].value);validatePairClosure(plan,slot,envelope,retained,packet);
    if(observations.find(row=>row.name===slot+'Acquire')?.value.trim()!==packet['acquisition-terminal.json']
      ||observations.find(row=>row.name===slot+'AcquireRetire')?.value.trim()!=='absent')throw fail('SYSTEM_PAIR_PRIOR_ACQUISITION');
  }
  const previous={systemAcquire:'systemReserve',policyOverhead:'systemReserve',policyMetadata:'policyOverhead',
    policyReserve:'policyOverhead',policyAcquire:'policyReserve',acquisitionSeal:'policyReserve',acquisitionRetire:'acquisitionSeal'}[next];
  if(previous)validatePairCredits(plan,observations,previous);
}
const pairRelayQualificationFailures=new WeakSet();
const isPairRelayQualificationFailure=error=>pairRelayQualificationFailures.has(error);
function validatePairRelayTerminal(plan,observations,text){
  // A failed acquisition retains its ordinary failed-run evidence/cleanup.
  // A completed paired acquisition additionally requires the exact sealed
  // admission ledger to survive both relay processes' real termination.
  if(!observations.some(row=>row.name==='acquisitionSeal'))return;
  const credit=validatePairCredits(plan,observations),packet=JSON.parse(text);
  const bad=()=>{throw fail('SYSTEM_PAIR_RELAY_TERMINAL');};
  let artifactDenied=false;
  if(packet.runId!==plan.runId||!packet.files||Object.values(packet.files).some(row=>row!==null&&typeof row!=='string')
    ||Object.values(packet.files).reduce((n,row)=>n+(row===null?0:Buffer.byteLength(row)),0)>262144)bad();
  for(const mode of ['adapter','connector']){
    const lines=packet.files['relay.'+mode+'.log'];if(typeof lines!=='string'||Buffer.byteLength(lines)>262144)bad();
    const rows=lines.trim().split('\n').map(JSON.parse),terminals=rows.filter(row=>row.kind==='relay-terminal');
    const audits=rows.filter(row=>row.kind==='transport-audit'&&row.trigger==='terminal');
    if(terminals.length!==1||audits.length!==1)bad();
    const terminal=terminals[0],audit=audits[0],n=credit.starts[mode];
    const finalAudit=JSON.parse(observations.find(row=>row.name==='acquisitionSeal').value).after.rows[mode];
    if(terminal.connections!==n||!Array.isArray(terminal.records)||terminal.records.length!==n||n>320
      ||terminal.unjoinedWorkers!==0||terminal.unresolvedResolverCleanup!==0||terminal.cleanupVerified!==true
      ||!Number.isSafeInteger(terminal.bytes)||terminal.bytes<0||terminal.bytes>systemBounded.PAIR_WIRE_POLICY.totalBytes
      ||!equal(audit.pairBudget,{policy:credit.policy,lifetime:320,connections:n,credit})
      ||audit.runId!==plan.runId||audit.mode!==mode||audit.activeWorkers!==0
      ||!equal(audit.admission,finalAudit.admission)
      ||!equal(audit.deniedAuthorities,{hosts:{},unclassified:0,overflow:0})
      ||audit.counts?.peerDenied!==0)bad();
    const wire=systemBounded.PAIR_WIRE_POLICY;
    const caps={'registry-1.docker.io':wire.registryBytes,'auth.docker.io':wire.authBytes,'deb.debian.org':wire.aptBytes,'production.cloudfront.docker.com':wire.cloudfrontBytes};
    if(!equal(Object.keys(terminal.hostBytes||{}).sort(),Object.keys(caps).sort())
      ||Object.entries(terminal.hostBytes).some(([host,n])=>!Number.isSafeInteger(n)||n<0||n>caps[host])
      ||Object.values(terminal.hostBytes).reduce((a,b)=>a+b,0)!==terminal.bytes)bad();
    // Records append on completion. Each proven zero-worker barrier fixes a
    // complete prefix; do not attribute an overhead denial's unknown cause.
    // Completion order is not admission order. Every paired worker retains
    // its accept-thread connection ordinal, including denied transports.
    const ordered=terminal.records.slice().sort((a,b)=>a.connection-b.connection);
    if(ordered.some((row,index)=>!equal(Object.keys(row).sort(),['connection','host','status'])||row.connection!==index+1))bad();
    let start=0;
    for(const [i,name] of PAIR_CREDIT_PHASES.entries()){
      const end=JSON.parse(observations.find(row=>row.name===name).value).before.rows[mode].pairBudget.connections;
      const proof=i%2!==0?pairObservedAttempts(plan,observations,i===1?'system':'policy'):null;
      for(const [offset,row] of ordered.slice(start,end).entries()){
        if(!row||!Object.hasOwn(caps,row.host)||!['closed','denied'].includes(row.status))bad();
        if(proof){
          if(row.host!=='deb.debian.org'||!proof.attempts[offset])bad();
          if(row.status==='denied'&&proof.attempts[offset].outcome!=='retired-pre-response-reset')artifactDenied=true;
        }
      }
      if(i%2!==0){const attempts=pairObservedAttempts(plan,observations,i===1?'system':'policy');
        if(end-start!==attempts.count)artifactDenied=true;}
      start=end;
    }
    if(start!==n)bad();
  }
  // Qualification still fails. Brand only after BOTH terminal processes and
  // every safety/authority/accounting join pass; a mixed unsafe record never
  // inherits authority to retire resources from an earlier denied artifact.
  if(artifactDenied){const error=fail('SYSTEM_PAIR_RELAY_TERMINAL');pairRelayQualificationFailures.add(error);throw error;}
}
function validatePairAcquisitionBudget(plan,observations){
  if(plan.target!==PAIR_TARGET)throw fail('SYSTEM_PAIR_PLAN');
  let total=0;
  for(const slot of ['system','policy']){
    const {retained}=pairEnvelope(plan,observations,slot);
    total+=systemArtifacts(retained.stages,plan.slots[slot].binding.target).reduce((n,row)=>n+row.bytes,0);
  }
  if(total>LIMITS.deb)throw fail('SYSTEM_PAIR_ARTIFACT_BOUND');return total;
}
function validatePairClosure(plan,slot,envelope,retained,packet){
  const binding=plan.slots[slot].binding,saved=JSON.parse(packet['closure.json']);
  const artifacts=systemArtifacts(retained.stages,binding.target),total=artifacts.reduce((n,row)=>n+row.bytes,0);
  const authentication={binding,version:1,method:'original-base-apt-closed-replay',
    retainedManifestSha256:sha(JSON.stringify(retained)),keyringSha256:envelope.candidate.keyringSha256,
    installedStatusSha256:envelope.candidate.installedStatusSha256,
    stages:retained.stages.map(stage=>({name:stage.name,selectionSha256:sha(stage.selection)})),expandedBytes:envelope.candidate.expandedBytes};
  const acquired={version:1,artifactBytesVerified:true,metadataAuthenticated:false,buildApproved:false,qualificationComplete:false,
    bytes:{deb:total,npm:0,total},artifacts:artifacts.map(row=>({...row,actualBytes:row.bytes,file:'objects/'+closure._internals.objectName(row)}))};
  pairAttemptProof(artifacts,saved.acquired?.attemptProof);acquired.attemptProof=saved.acquired.attemptProof;
  if(!equal(saved,{version:1,binding,authentication,acquired}))throw fail('SYSTEM_PAIR_CLOSURE');
  const terminal=JSON.parse(packet['acquisition-terminal.json']);
  if(!equal(terminal,{version:1,binding,result:null,failure:null,cleanupErrors:[]}))throw fail('SYSTEM_PAIR_ACQUISITION');
  return sha(packet['closure.json']);
}
async function validatePairDriverObservations(plan,observations){
  if(plan.target!==PAIR_TARGET||!Array.isArray(observations)||observations.length!==PAIR_PHASES.length)throw fail('SYSTEM_PAIR_OBSERVATIONS');
  for(let i=0;i<PAIR_PHASES.length;i++)if(!equal(Object.keys(observations[i]).sort(),['name','value'])||observations[i].name!==PAIR_PHASES[i]||typeof observations[i].value!=='string')throw fail('SYSTEM_PAIR_OBSERVATIONS');
  await verifyPlan(plan);validatePairAcquisitionBudget(plan,observations);validatePairCredits(plan,observations);
  const values=name=>observations.filter(row=>row.name===name).map(row=>row.value);
  bounded._internals.checkInventory(values('inventory')[0]);
  const daemonIds=values('inspect').map(value=>bounded._internals.checkDaemon(JSON.parse(value),plan.spec));
  if(new Set(daemonIds).size!==1)throw fail('SYSTEM_DAEMON_CHANGED');
  const images={};
  for(const slot of ['system','policy']){
    const {envelope,retained}=pairEnvelope(plan,observations,slot),packets=values(slot+'Evidence').map(JSON.parse);
    const digest=validatePairClosure(plan,slot,envelope,retained,packets[0]);
    if(validatePairClosure(plan,slot,envelope,retained,packets[1])!==digest)throw fail('SYSTEM_PAIR_CLOSURE_CHANGED');
    const binding=plan.slots[slot].binding,ready=JSON.parse(values(slot+'Replay')[0]),terminal=JSON.parse(packets[1]['terminal.json']);
    if(!equal(ready.binding,binding)||ready.closureSha256!==digest||ready.version!==1||ready.metadataAuthenticated!==true||ready.artifactBytesVerified!==true
      ||!Number.isInteger(ready.port)||ready.port<1||ready.port>65535||packets[1]['ready.json']!==values(slot+'Replay')[0].trim())throw fail('SYSTEM_PAIR_READY');
    if(!equal(terminal.binding,binding)||terminal.version!==1||terminal.failure!==null||terminal.cleanupErrors?.length!==0
      ||terminal.result?.closed!==true||terminal.result.absenceVerified!==true||terminal.result.active!==0||terminal.result.failure!==null)throw fail('SYSTEM_PAIR_REPLAY');
    if(values(slot+'Acquire')[0].trim()!==packets[0]['acquisition-terminal.json'])throw fail('SYSTEM_PAIR_ACQUISITION');
    for(const suffix of ['MetadataRetire','AcquireRetire','ReplayRetire'])if(values(slot+suffix)[0].trim()!=='absent')throw fail('SYSTEM_PAIR_RETIREMENT');
    const image=JSON.parse(values(slot+'Image')[0]),captured=plan.slots[slot].captured;
    if(!Array.isArray(image)||image.length!==1||!/^sha256:[a-f0-9]{64}$/.test(image[0]?.Id)||image[0].Architecture!=='arm64'||image[0].Os!=='linux'
      ||image[0].Config?.Labels?.[`owasp-ai-goat.${slot}.inputs`]!==captured.inputSha256||image[0].Config?.Labels?.['owasp-ai-goat.build-run']!==plan.runId
      ||image[0].Config?.User!==captured.recipe.user||!equal(image[0].Config?.Entrypoint,captured.recipe.entrypoint))throw fail('SYSTEM_PAIR_IMAGE');
    images[slot]={imageId:image[0].Id,inputSha256:captured.inputSha256,base:captured.recipe.base,closureSha256:digest};
  }
  if(images.system.imageId===images.policy.imageId)throw fail('SYSTEM_PAIR_IMAGE_ALIAS');
  const physical=validatePhysicalHandoff(JSON.parse(values('handoff')[0]),plan);
  // Validate the complete run/target envelope first, then expose the same
  // five-coordinate consumer DTO as the existing single-image path.
  const {version,target,runId,...coordinates}=physical;
  return freeze({version:1,target:PAIR_TARGET,runId:plan.runId,daemonId:daemonIds[0],physical:coordinates,images,runtimeAvailable:false});
}
module.exports={systemBuildPlan,systemPolicyBuildPlan,planDigest,verifyPlan,assertSystemImageCapability,withPrivateSystemImage,
  _internals:{TARGET,PAIR_TARGET,PAIR_PHASES,PAIR_CLEANUP,FAILED_SLOT_ARCHIVE,pairMetadataComplete,LIMITS,GUEST_MODULES,guestMain,guestSource,systemArtifacts,contextBytes,rendererContextBytes,
    tarFile,commandsFor,slotCommands,runControlledPipeline,validatePhysicalHandoff,validateDriverObservations,validatePairAcquisitionBudget,validatePairDriverObservations,validatePairClosure,
    PAIR_CREDIT_PHASES,pairCensus,validatePairCredits,validatePairPhaseAdmission,validatePairRelayTerminal,isPairRelayQualificationFailure}};


