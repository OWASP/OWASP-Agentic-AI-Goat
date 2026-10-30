'use strict';
// Explicit import/probe only. No build, extraction, activation, or import on load.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {constants}=require('node:fs'),{spawn}=require('node:child_process');
const {Transform,Readable}=require('node:stream'),{pipeline}=require('node:stream/promises');
const tar=require('tar-stream');
const {isDeepStrictEqual}=require('node:util');
const {PINS,LIMITS}=require('./ownedMcpBoundedBuild');
const {IMAGE_PROBE}=require('../../scripts/install/secureshop-owned-mcp-registry')._internals;
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
const EXPORT=Object.freeze({runId:'f7314e2a960b4d88a9c32700ecb615f2',
  imageId:'sha256:cf3a39ae05223946b3a7c8e2087ca4dd9c285e65d7fe45b59cd5c8f6ad7fd44d',
  archiveSha256:'c0c9404e2e69cb52c8159c59538eb35d103111ece109ff6c400dd1f0fcb66bfa',archiveBytes:438994944,
  packageDigest:'c20c2de942f9fa8f631ee39e3152414c69fca169e1b729d027a3dbb4d3e142a7'});
const DOCKER_SHA='8a55fc0cf28b70ebfb3d90f660fbd3a856640e657436ae6887ef53f533276025';
// Docker 29's save also emits legacy per-layer JSON compatibility records.
// These are not additional OCI images. Admit only the exact observed records
// of the pinned export, never arbitrary unreferenced archive content.
const LEGACY_METADATA=new Set([
  '0574f501f084a3cf3ec7f240a14367a1d6117bbab127c4b8d5a90bb307c44a24',
  '0c2d52b74e4a9ce2f7a634b0502bf4815857380e73a25edc45e8e21f304322cd',
  '4cb9672260a689c71f9a8e8764292def2348f6cf9b5255207415b9a0065f14a0',
  '501415792ca76dfea13a50e154583b0c94930dab046243604bb3efcbb1b5b843',
  '513ff4eb64c3d36cb4c5020edde6893d1c55e3fcc68b34f707e1d1e63a7bab13',
  '780506a406d68076f48978f475b96ac48e823d8180469d1407534d5770a0408a',
  '786968319db279e54658a6109e54f9c38807ef6eb1fb05ddb7cef114e7f792eb',
  '7f413cf5e7717fb035e036d746438d4072992d1039df6a2c56e41e8b965651a5',
  '83435da5a7342cbd148643bfda4c4e1cce6b25f03e756ae6f9496ba2221f3f37',
  '9c9112f8182e25f811288f7bbf93fce0993118eec67b1301d34959ad15acb046',
  'a358f4079d42b905ace01a7e39bdc66e2cedc821ee4462bd074667396836404e',
  'a9e3df5261f1fe81182a90718aeb1965995f9a589d9ab86a1ac1230a55bf9c15',
  'c8888b1fe8c877a945b40368b62cd705ee69cf80808bc0f38f26332791acd579',
  'd704be7fc44c963ccbd62d200445b23363c30522915f42f52cd10d555171b146',
  'e5892b5d9ce030352c71b70d133822ebea55c78f2639ab391160fbee83662634',
  'e7760040dd20bdeba7e28423017961aa55dbf5bbdfbd6080f80b68408f4398e8',
  'eeb6621bbc410224a4eedb7e009e5a64c023e71c595fabff92a2281131a31ca7',
]);
function specification(root,expected=EXPORT){
  if(typeof root!=='string'||!path.isAbsolute(root)||root==='/'||path.resolve(root)!==root||
    !/^[a-f0-9]{32}$/.test(expected.runId)||!/^sha256:[a-f0-9]{64}$/.test(expected.imageId)||
    !/^[a-f0-9]{64}$/.test(expected.archiveSha256)||!/^[a-f0-9]{64}$/.test(expected.packageDigest)||
    !Number.isSafeInteger(expected.archiveBytes)||expected.archiveBytes<=0||expected.archiveBytes>LIMITS.export)throw fail('ADMISSION_SPEC_INVALID');
  const directory=path.join(root,'tasks/tmp/v23-build-'+expected.runId);
  return Object.freeze({root,directory,archive:path.join(directory,'image.tar'),expected:Object.freeze({...expected}),
    docker:path.join(root,'tasks/runtime/container/bin/docker'),host:'unix://'+path.join(root,'.qualification/goat-q/docker.sock')});
}
const metadata=s=>['dev','ino','size','mtimeMs','ctimeMs','nlink','uid','mode'].map(k=>s[k]).join(':');
async function unchanged(fd,before){if(metadata(await fd.stat())!==metadata(before))throw fail('ADMISSION_ARCHIVE_CHANGED');}
function fileStream(fd){
  // Streams never own/close the handle: validation and loading share exactly
  // this open descriptor, including when pipeline destroys its input stream.
  return Readable.from((async function*(){let offset=0;for(;;){const bytes=Buffer.alloc(65536);const read=await fd.read(bytes,0,bytes.length,offset);if(!read.bytesRead)return;offset+=read.bytesRead;yield bytes.subarray(0,read.bytesRead);}})());
}
function validateConfig(value,expected){
  if(value.architecture!=='arm64'||value.os!=='linux'||value.config?.User!=='10001:10001'||
    JSON.stringify(value.config.Entrypoint)!==JSON.stringify(['node','sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'])||
    Object.keys(value.config.Volumes||{}).length||value.config.Labels?.['owasp-ai-goat.registry.package']!==expected.packageDigest||
    value.config.Labels?.['owasp-ai-goat.build-run']!==expected.runId)throw fail('ADMISSION_CONFIG_MISMATCH');
}
async function validateArchive(fd,expected){
  const before=await fd.stat();
  if(!before.isFile()||before.nlink!==1||before.uid!==process.getuid()||(before.mode&0o077)||before.size!==expected.archiveBytes)throw fail('ADMISSION_ARCHIVE_METADATA');
  const extract=tar.extract(),entries=new Map(),small=new Map(),hash=crypto.createHash('sha256');
  let bytes=0,retained=0;
  const meter=new Transform({transform(chunk,encoding,next){bytes+=chunk.length;if(bytes>LIMITS.export)return next(fail('ADMISSION_ARCHIVE_LIMIT'));hash.update(chunk);next(null,chunk);}});
  extract.on('entry',(header,stream,next)=>{
    (async()=>{
      const name=header.name.replace(/\/$/,'');
      if(entries.size>=128||entries.has(name)||!Number.isSafeInteger(header.size)||header.size<0||header.size>LIMITS.export)throw fail('ADMISSION_TAR_INVALID');
      if(header.type==='directory'){
        if(!['blobs','blobs/sha256'].includes(name)||header.size!==0)throw fail('ADMISSION_TAR_DIRECTORY');
      }else if(header.type!=='file'||!(['manifest.json','index.json','oci-layout'].includes(name)||/^blobs\/sha256\/[a-f0-9]{64}$/.test(name)))throw fail('ADMISSION_TAR_ENTRY');
      const h=crypto.createHash('sha256'),chunks=[];
      const keep=header.size<=65536||name==='blobs/sha256/'+expected.imageId.slice(7);
      if(keep&&(retained+=header.size)>2*1024**2)throw fail('ADMISSION_METADATA_LIMIT');
      let count=0;for await(const chunk of stream){count+=chunk.length;h.update(chunk);if(keep)chunks.push(chunk);}
      if(count!==header.size)throw fail('ADMISSION_TAR_TRUNCATED');
      const digest=h.digest('hex');
      if(name.startsWith('blobs/sha256/')&&name.slice(13)!==digest)throw fail('ADMISSION_BLOB_DIGEST');
      entries.set(name,{size:count,digest,type:header.type});if(keep)small.set(name,Buffer.concat(chunks));next();
    })().catch(error=>extract.destroy(error));
  });
  await pipeline(fileStream(fd),meter,extract);
  await unchanged(fd,before);
  if(bytes!==expected.archiveBytes||hash.digest('hex')!==expected.archiveSha256)throw fail('ADMISSION_ARCHIVE_HASH');
  const json=name=>{if(!small.has(name))throw fail('ADMISSION_METADATA_MISSING');return JSON.parse(small.get(name));};
  const manifest=json('manifest.json'),index=json('index.json');
  if(!Array.isArray(manifest)||manifest.length!==1||manifest[0].Config!=='blobs/sha256/'+expected.imageId.slice(7)||
    !(manifest[0].RepoTags===null||Array.isArray(manifest[0].RepoTags)&&manifest[0].RepoTags.length===0)||
    !Array.isArray(manifest[0].Layers)||manifest[0].Layers.length===0||
    index.schemaVersion!==2||index.manifests?.length!==1||json('oci-layout').imageLayoutVersion!=='1.0.0')throw fail('ADMISSION_MANIFEST_MISMATCH');
  const descriptor=index.manifests[0];
  if(!/^sha256:[a-f0-9]{64}$/.test(descriptor.digest)||descriptor.annotations)throw fail('ADMISSION_INDEX_MISMATCH');
  const oci=json('blobs/sha256/'+descriptor.digest.slice(7));
  if(oci.schemaVersion!==2||oci.config?.digest!==expected.imageId||!Array.isArray(oci.layers)||
    JSON.stringify(oci.layers.map(x=>'blobs/sha256/'+x.digest?.slice(7)))!==JSON.stringify(manifest[0].Layers))throw fail('ADMISSION_OCI_MISMATCH');
  for(const item of [descriptor,oci.config,...oci.layers]){
    if(!/^sha256:[a-f0-9]{64}$/.test(item.digest)||entries.get('blobs/sha256/'+item.digest.slice(7))?.size!==item.size)throw fail('ADMISSION_DESCRIPTOR_MISMATCH');
  }
  const allowed=new Set(['manifest.json','index.json','oci-layout','blobs','blobs/sha256',manifest[0].Config,'blobs/sha256/'+descriptor.digest.slice(7),...manifest[0].Layers]);
  for(const name of entries.keys())if(!allowed.has(name)&&!(expected.archiveSha256===EXPORT.archiveSha256&&LEGACY_METADATA.has(name.slice(13))&&entries.get(name).size<=16384&&json(name).os==='linux'))throw fail('ADMISSION_EXTRA_IMAGE_CONTENT');
  const config=json(manifest[0].Config);validateConfig(config,expected);
  before.archiveIdentity={configImageId:expected.imageId,runtimeImageId:descriptor.digest,descriptor,config};
  return before;
}
async function command(spec,args,{input,timeoutMs=180000}={}){
  return new Promise((resolve,reject)=>{
    const child=spawn(spec.docker,['--host',spec.host,...args],{cwd:spec.root,env:{PATH:process.env.PATH,TMPDIR:path.join(spec.root,'tasks/tmp')},detached:true,stdio:['pipe','pipe','pipe']});
    let error,signalError,bytes=0,chunks=[],stderr=Buffer.alloc(0);
    const stop=e=>{error ||= e;input?.destroy();if(child.pid)try{process.kill(-child.pid,'SIGKILL');}catch(cause){if(cause.code!=='ESRCH')signalError=cause.code;}};
    const timer=setTimeout(()=>stop(fail('ADMISSION_COMMAND_TIMEOUT')),timeoutMs);
    child.on('error',stop);child.stdin.on('error',stop);
    for(const stream of [child.stdout,child.stderr])stream.on('data',chunk=>{bytes+=chunk.length;if(stream===child.stderr)stderr=Buffer.concat([stderr,chunk]).subarray(-16384);if(bytes>2*1024**2)stop(fail('ADMISSION_OUTPUT_LIMIT'));else if(stream===child.stdout)chunks.push(chunk);});
    child.on('close',(code,signal)=>{clearTimeout(timer);input?.destroy();if(error||code!==0){const failure=error||fail('ADMISSION_DOCKER_FAILED');failure.diagnostic={exitCode:code,signal,signalError:signalError||null,stderr:stderr.toString('utf8'),stderrTailBytes:stderr.length,outputBytes:bytes};reject(failure);}else resolve(Buffer.concat(chunks).toString('utf8'));});
    if(input){input.on('error',stop);input.pipe(child.stdin);}else child.stdin.end();
  });
}
async function inventory(spec,run){
  const daemon=JSON.parse(await run(spec,['info','--format','{{json .ID}}']));
  if(daemon!==PINS.daemon)throw fail('ADMISSION_DAEMON_MISMATCH');
  const lines=s=>s.trim().split('\n').filter(Boolean).sort();
  const images=lines(await run(spec,['image','ls','--all','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}']));
  if(!images.includes(PINS.postgres+' postgres:18'))throw fail('ADMISSION_POSTGRES_MISSING');
  return{daemon,images,containers:lines(await run(spec,['ps','-a','--no-trunc','--quiet'])),volumes:lines(await run(spec,['volume','ls','--quiet']))};
}
function preserved(before,after,expected,requireCandidate=false){
  if(requireCandidate&&!after.images.includes(expected.imageId+' <none>:<none>'))throw fail('ADMISSION_IMAGE_DISAPPEARED');
  const withoutCandidate=after.images.filter(x=>x===expected.imageId+' <none>:<none>'?false:true);
  if(JSON.stringify({...after,images:withoutCandidate})!==JSON.stringify(before))throw fail('ADMISSION_SHARED_STATE_CHANGED');
}
async function probeJournal(spec,name,value){
  const handle=await fs.open(path.join(spec.directory,name),constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await handle.writeFile(JSON.stringify(value));await handle.sync();}finally{await handle.close();}
  const directory=await fs.open(spec.directory,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{await directory.sync();}finally{await directory.close();}
}
async function probe(spec,run){
  const name='owasp-ai-goat-v23-assets-'+spec.expected.runId,token=crypto.randomBytes(16).toString('hex');let id,primary,digest;
  const args=['create','--name',name,'--label','owasp-ai-goat.admission='+token,'--network','none','--read-only','--cap-drop','ALL','--memory','512m','--cpus','1','--pids-limit','32','--log-driver','none','--security-opt','no-new-privileges','--user','10001:10001','--entrypoint','node',spec.expected.imageId,'-e',IMAGE_PROBE];
  const intent={version:1,name,token,imageId:spec.expected.imageId,daemon:PINS.daemon,host:spec.host,executable:spec.docker,argv:['--host',spec.host,...args],automaticRetry:false};
  // Commit authority before dispatch. An existing/partial journal is never
  // overwritten, and a lost create reply never authorizes removal by name.
  await probeJournal(spec,'probe-intent.json',intent);
  const intentSha256=sha(JSON.stringify(intent));
  const inspect=async()=>{const rows=JSON.parse(await run(spec,['container','inspect',id]));const row=rows[0];if(rows.length!==1||row.Id!==id||row.Name!=='/'+name||row.Image!==spec.expected.imageId||row.Config?.Labels?.['owasp-ai-goat.admission']!==token)throw fail('ADMISSION_PROBE_IDENTITY');return row;};
  try{
    id=(await run(spec,args)).trim();
    if(!/^[a-f0-9]{64}$/.test(id))throw fail('ADMISSION_PROBE_CREATE_UNCERTAIN');
    await probeJournal(spec,'probe-created.json',{version:1,intentSha256,id});
    const row=await inspect();
    if(row.HostConfig?.NetworkMode!=='none'||row.HostConfig.ReadonlyRootfs!==true||row.Config.User!=='10001:10001'||!Array.isArray(row.Mounts)||row.Mounts.length||row.HostConfig.Privileged!==false||
      JSON.stringify(row.HostConfig.CapDrop)!=='["ALL"]'||(row.HostConfig.CapAdd||[]).length||row.HostConfig.Memory!==536870912||row.HostConfig.NanoCpus!==1000000000||row.HostConfig.PidsLimit!==32||
      row.HostConfig.LogConfig?.Type!=='none'||JSON.stringify(row.HostConfig.SecurityOpt)!=='["no-new-privileges"]'||JSON.stringify(row.Config.Entrypoint)!=='["node"]'||
      JSON.stringify(row.Config.Cmd)!==JSON.stringify(['-e',IMAGE_PROBE]))throw fail('ADMISSION_PROBE_BOUNDARY');
    digest=(await run(spec,['start','--attach',id])).trim();
    const ended=await inspect();if(ended.State?.Running||ended.State?.ExitCode!==0||!/^[a-f0-9]{64}$/.test(digest))throw fail('ADMISSION_PROBE_FAILED');
  }catch(error){primary=error;}
  let cleanupError;
  try{
    if(!id||!/^[a-f0-9]{64}$/.test(id))throw fail('ADMISSION_PROBE_CLEANUP_UNCERTAIN');
    const row=await inspect();if(row.State?.Running)await run(spec,['stop','--time','5',id]);
    if((await inspect()).State?.Running)throw fail('ADMISSION_PROBE_NOT_JOINED');await run(spec,['rm',id]);
    const ids=(await run(spec,['ps','-a','--no-trunc','--quiet'])).trim().split('\n');if(ids.includes(id))throw fail('ADMISSION_PROBE_REMAINS');
  }catch(error){cleanupError=error;}
  try{await probeJournal(spec,'probe-cleanup.json',{version:1,intentSha256,id:/^[a-f0-9]{64}$/.test(id||'')?id:null,status:cleanupError?'uncertain':'removed',absenceVerified:!cleanupError,error:cleanupError?.code||cleanupError?.message||null,automaticRetry:false});}
  catch(error){cleanupError=new AggregateError([cleanupError,error].filter(Boolean),'Probe cleanup journal failed');}
  if(cleanupError)throw new AggregateError([primary,cleanupError].filter(Boolean),'Image probe cleanup failed');
  if(primary)throw primary;return digest;
}
async function admitImage({root,expected=EXPORT,run=command,verifyDocker=true,attempt=1,target}={}){
  require('./ownedMcpBoundedBuild').validateClosedBuildTarget(target);
  if(![1,2].includes(attempt))throw fail('ADMISSION_ATTEMPT_INVALID');
  const original=specification(root,expected);
  const spec=attempt===1?original:Object.freeze({...original,directory:path.join(original.directory,'admission-attempt-2')});
  if(await fs.realpath(spec.root)!==spec.root||await fs.realpath(spec.archive)!==spec.archive)throw fail('ADMISSION_PATH_ALIAS');
  if(verifyDocker&&(await fs.realpath(spec.docker)!==spec.docker||sha(await fs.readFile(spec.docker))!==DOCKER_SHA))throw fail('ADMISSION_DOCKER_PIN');
  const fd=await fs.open(spec.archive,constants.O_RDONLY|constants.O_NOFOLLOW);
  let before,primary,result,intended=false;
  try{
    const state=await validateArchive(fd,expected);
    before=await inventory(spec,run);
    if(before.images.some(x=>x.startsWith(expected.imageId+' ')))throw fail('ADMISSION_IMAGE_ALREADY_PRESENT');
    if(attempt===2){
      const read=async name=>{const handle=await fs.open(path.join(original.directory,name),constants.O_RDONLY|constants.O_NOFOLLOW);try{const stat=await handle.stat();if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.size>65536)throw fail('ADMISSION_PRIOR_RECEIPT_INVALID');return JSON.parse(await handle.readFile('utf8'));}finally{await handle.close();}};
      const prior=await read('admission-result.json'),intent=await read('admission-intent.json');
      if(prior.result!==null||prior.error!=='ADMISSION_DOCKER_FAILED'||prior.preservationError!==null||prior.automaticRetry!==false||
        JSON.stringify(intent.expected)!==JSON.stringify(expected)||JSON.stringify(intent.before)!==JSON.stringify(before))throw fail('ADMISSION_PRIOR_ATTEMPT_UNSAFE');
      try{await fs.lstat(path.join(original.directory,'probe-intent.json'));throw fail('ADMISSION_PRIOR_PROBE_EXISTS');}catch(error){if(error.code!=='ENOENT')throw error;}
      await fs.mkdir(spec.directory,{mode:0o700});
    }
    await fs.writeFile(path.join(spec.directory,'admission-intent.json'),JSON.stringify({version:1,expected,before}),{flag:'wx',mode:0o600});intended=true;
    await unchanged(fd,state);
    const hash=crypto.createHash('sha256');let bytes=0;
    const meter=new Transform({transform(chunk,encoding,next){bytes+=chunk.length;if(bytes>expected.archiveBytes)return next(fail('ADMISSION_LOAD_LIMIT'));hash.update(chunk);next(null,chunk);}});
    const input=fileStream(fd);input.on('error',error=>meter.destroy(error));input.pipe(meter);
    try{await run(spec,['image','load'],{input:meter});}catch(error){error.diagnostic={...error.diagnostic,archiveBytesRead:bytes,archiveSha256Read:hash.copy().digest('hex')};throw error;}finally{input.destroy();meter.destroy();}
    if(bytes!==expected.archiveBytes||hash.digest('hex')!==expected.archiveSha256)throw fail('ADMISSION_LOADED_BYTES_CHANGED');
    await unchanged(fd,state);
    const rows=JSON.parse(await run(spec,['image','inspect',expected.imageId]));
    if(rows.length!==1||rows[0].Id!==expected.imageId)throw fail('ADMISSION_IMAGE_ID');
    validateConfig({architecture:rows[0].Architecture,os:rows[0].Os,config:rows[0].Config},expected);
    preserved(before,await inventory(spec,run),expected,true);
    const runtimeDigest=await probe(spec,run);
    preserved(before,await inventory(spec,run),expected,true);
    result={version:1,...expected,runtimeDigest,archivePreserved:true,qualificationComplete:false};
  }catch(error){primary=error;}
  finally{await fd.close();}
  let preservationError;
  if(before&&intended)try{preserved(before,await inventory(spec,run),expected,!primary);}catch(error){preservationError=error;}
  if(intended)await fs.writeFile(path.join(spec.directory,'admission-result.json'),JSON.stringify({result:primary||preservationError?null:result,error:primary?.code||primary?.message||null,diagnostic:primary?.diagnostic||null,preservationError:preservationError?.code||null,automaticRetry:false}),{flag:'wx',mode:0o600});
  if(primary||preservationError)throw new AggregateError([primary,preservationError].filter(Boolean),'Image admission failed; retained image/archive require inspection, no automatic retry');
  return result;
}
async function privateJson(directory,name){
  if(await fs.realpath(directory)!==directory)throw fail('ADMISSION_RECEIPT_PATH_ALIAS');
  const fd=await fs.open(path.join(directory,name),constants.O_RDONLY|constants.O_NOFOLLOW);
  try{const stat=await fd.stat();if(!stat.isFile()||stat.nlink!==1||stat.uid!==process.getuid()||(stat.mode&0o077)||stat.size>65536)throw fail('ADMISSION_PRIOR_RECEIPT_INVALID');return JSON.parse(await fd.readFile('utf8'));}finally{await fd.close();}
}
function verifyImported(row,identity){
  const {config,descriptor,runtimeImageId}=identity;
  if(row?.Id!==runtimeImageId||!isDeepStrictEqual(row.Descriptor,descriptor)||
    row.Architecture!==config.architecture||row.Os!==config.os||!isDeepStrictEqual(row.Config,config.config)||
    config.rootfs?.type!=='layers'||!Array.isArray(config.rootfs.diff_ids)||
    !isDeepStrictEqual(row.RootFS,{Type:config.rootfs.type,Layers:config.rootfs.diff_ids})||
    (row.RepoTags||[]).length||(row.RepoDigests||[]).length)throw fail('ADMISSION_IMPORTED_IDENTITY_MISMATCH');
}
// Explicit recovery of the two recorded inspect failures. This path cannot
// load, tag, rebuild, or delete an image. Older inventory receipts omitted
// hidden images and are retained as incomplete evidence, never rewritten.
async function recoverImportedImage({root,expected=EXPORT,run=command,verifyDocker=true,target}={}){
  require('./ownedMcpBoundedBuild').validateClosedBuildTarget(target);
  const original=specification(root,expected);
  if(await fs.realpath(root)!==root||await fs.realpath(original.archive)!==original.archive)throw fail('ADMISSION_PATH_ALIAS');
  if(verifyDocker&&(await fs.realpath(original.docker)!==original.docker||sha(await fs.readFile(original.docker))!==DOCKER_SHA))throw fail('ADMISSION_DOCKER_PIN');
  const fd=await fs.open(original.archive,constants.O_RDONLY|constants.O_NOFOLLOW);let identity,state;
  try{state=await validateArchive(fd,expected);identity=state.archiveIdentity;await unchanged(fd,state);}finally{await fd.close();}
  const spec=Object.freeze({...original,directory:path.join(original.directory,'admission-recovery-1'),expected:Object.freeze({...expected,imageId:identity.runtimeImageId})});
  const before=await inventory(spec,run),priorReceipts=[];
  for(const directory of [original.directory,path.join(original.directory,'admission-attempt-2')]){
    const intent=await privateJson(directory,'admission-intent.json'),result=await privateJson(directory,'admission-result.json');
    if(!isDeepStrictEqual(intent.expected,expected)||result.result!==null||result.error!=='ADMISSION_DOCKER_FAILED'||result.preservationError!==null||result.automaticRetry!==false)throw fail('ADMISSION_RECOVERY_PRIOR_INVALID');
    try{await fs.lstat(path.join(directory,'probe-intent.json'));throw fail('ADMISSION_PRIOR_PROBE_EXISTS');}catch(error){if(error.code!=='ENOENT')throw error;}
    preserved(intent.before,before,spec.expected,true);
    priorReceipts.push({directory,intentSha256:sha(JSON.stringify(intent)),resultSha256:sha(JSON.stringify(result)),inventoryComplete:false});
  }
  const rows=JSON.parse(await run(spec,['image','inspect',identity.runtimeImageId]));
  if(rows.length!==1)throw fail('ADMISSION_IMPORTED_IDENTITY_MISMATCH');verifyImported(rows[0],identity);
  await fs.mkdir(spec.directory,{mode:0o700});
  await probeJournal(spec,'recovery-intent.json',{version:1,expected,configImageId:identity.configImageId,runtimeImageId:identity.runtimeImageId,descriptor:identity.descriptor,before,priorReceipts,automaticRetry:false});
  let result,primary,preservationError;
  try{const runtimeDigest=await probe(spec,run);result={version:1,...expected,configImageId:identity.configImageId,runtimeImageId:identity.runtimeImageId,runtimeDigest,archivePreserved:true,qualificationComplete:false};}catch(error){primary=error;}
  try{if(!isDeepStrictEqual(await inventory(spec,run),before))throw fail('ADMISSION_SHARED_STATE_CHANGED');}catch(error){preservationError=error;}
  await probeJournal(spec,'recovery-result.json',{result:primary||preservationError?null:result,error:primary?.code||primary?.message||null,diagnostic:primary?.diagnostic||null,preservationError:preservationError?.code||null,priorInventoryComplete:false,automaticRetry:false});
  if(primary||preservationError)throw new AggregateError([primary,preservationError].filter(Boolean),'Imported image recovery failed; no automatic retry');
  return result;
}
module.exports={admitImage,recoverImportedImage,EXPORT,_internals:{specification,validateArchive,validateConfig,inventory,preserved,probe,command,verifyImported}};
