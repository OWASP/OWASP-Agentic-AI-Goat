'use strict';
// Pricing-specific integrity boundary. These pure/source-reading operations do
// not mint a live image capability. Native phase transport is admitted separately.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const producer=require('./ownedPricingOriginalBuild');
const metadata=require('./ownedPolicySystemMetadata');
const targets=require('./ownedPolicySystemBuild');
const closure=require('./ownedMcpDependencyClosure');
const bounded=require('./ownedMcpBoundedBuild');
const derivation=require('./ownedPricingBoundedDerivation');
const lease=require('./ownedPricingRuntimeLease');
const transport=require('./ownedPricingPhaseTransport');
const egress=require('./ownedPricingEgressPolicy');
const ROOT=path.resolve(__dirname,'../..'),TARGET='original-v33-pricing';
const MODULES=Object.freeze(['ownedAptAuthentication','ownedPolicySystemBuild','ownedPolicySystemMetadata','ownedMcpArtifactReplay','ownedMcpDependencyClosure','ownedPricingEgressPolicy']);
const LIMITS=Object.freeze({contextBytes:16*1024**2,diskBytes:6*1024**3,buildMs:300000,acquisitionMs:300000});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const digest=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const daemonId=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9:-]{0,127}$/.test(v);
const keys=(v,names)=>v&&typeof v==='object'&&!Array.isArray(v)&&equal(Object.keys(v).sort(),names.split(',').sort());
function freeze(v){if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
function sourceFile(root,name){
 const file=path.join(root,name);if(fs.realpathSync(file)!==file)throw fail('PRICING_SOURCE_PATH');
 const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const a=fs.fstatSync(fd);if(!a.isFile()||a.nlink!==1||a.size<1||a.size>1024**2)throw fail('PRICING_SOURCE_FILE');
  const b=Buffer.alloc(a.size+1);let n=0,k;while(n<b.length&&(k=fs.readSync(fd,b,n,b.length-n,n)))n+=k;
  const z=fs.fstatSync(fd),last=fs.lstatSync(file);
  if(n!==a.size||['dev','ino','size','mtimeMs','ctimeMs'].some(key=>a[key]!==z[key]||a[key]!==last[key]))throw fail('PRICING_SOURCE_CHANGED');
  return b.subarray(0,n);
 }finally{fs.closeSync(fd);}
}
function pricingBuildInputs(root,runId,profile='v33'){
 lease.profile(profile);
 if(root!==ROOT||!(/^[a-f0-9]{32}$/).test(runId))throw fail('PRICING_BUILD_IDENTITY');
 const captured=producer.capturePricingTarget(root),spec=targets.targetSpecification('v33-pricing');
 if(spec.base!==captured.baseImageDigest||!equal(targets.metadataRetentionSpecification('v33-pricing').stages,captured.aptStages))throw fail('PRICING_TARGET_CHANGED');
 const sources={};for(const name of MODULES.map(n=>'tests/postgres/'+n+'.js').concat(['tests/postgres/ownedPricingOriginalBuild.js','tests/postgres/ownedPricingBuildAdapter.js','tests/postgres/ownedPricingPhaseTransport.js','tests/postgres/ownedPricingPrivateHandoff.js','tests/postgres/pricing_owned_provisioning.py','tests/postgres/pricing_private_cohort.py','tests/postgres/run-secureshop-customer-pricing-current-host.py','tests/postgres/secureshopCustomerPricingActual.integration.test.js','tests/postgres/ownedPricingRuntimeLease.js','tests/postgres/ownedPricingBoundedDerivation.js','tests/postgres/ownedMcpBoundedBuild.js','server/services/secureshopPricingPackage.js']))sources[name]=sha(sourceFile(root,name));
 const files=captured.files.map(row=>({name:row.name,bytes:row.bytes.length,sha256:sha(row.bytes),mode:0o444}));
 for(const name of ['tests/postgres/ownedPricingCoordinatorWorker.js','tests/postgres/run_pricing_private_original.py'])sources[name]=sha(sourceFile(root,name));
 if(profile==='v25-manual')for(const name of [
  'tests/postgres/secureshopPricingJournal.integration.test.js','tests/fixtures/secureshopPricingV25OwnerPreload.mjs',
  'tests/postgres/ownedPricingManualConsumer.js','tests/fixtures/pricingOwnedOutput.js','tests/fixtures/inheritedFifoGrant.js',
  'tests/fixtures/secureshopPricingActual.js','tests/fixtures/secureshopPricingAssembled.js',
  'tests/fixtures/secureshopPricingJudgmentPersistence.js','tests/postgres/pricing_runtime_pins.py',
  'tests/postgres/darwin_process_inventory.py','tests/postgres/sql_nosql_process_ownership.py'])sources[name]=sha(sourceFile(root,name));
 if(files.reduce((n,row)=>n+row.bytes,0)>LIMITS.contextBytes)throw fail('PRICING_CONTEXT_LIMIT');
 return freeze({version:1,target:TARGET,root,runId,...(profile==='v33'?{}:{consumerProfile:profile}),binding:{runId,target:'v33-pricing',base:producer.BASE},
  packageDigest:captured.packageDigest,dockerfile:producer.DOCKERFILE,dockerfileSha256:producer.DOCKERFILE_SHA256,
  files,sources,entrypoint:[...captured.entrypoint],user:captured.user,limits:{...LIMITS},
  metadataPolicy:spec.metadataSourcePolicy,retention:targets.metadataRetentionSpecification('v33-pricing'),
  buildApproved:false,qualificationComplete:false});
}
function verifyPricingBuildInputs(plan){
 if(!plan||!equal(plan,pricingBuildInputs(plan.root,plan.runId,plan.consumerProfile)))throw fail('PRICING_PLAN_CHANGED');return true;
}
function tarMember(name,bytes){
 if(Buffer.byteLength(name)>100||!(/^[A-Za-z0-9_./-]+$/).test(name)||name.split('/').some(x=>!x||x==='.'||x==='..'))throw fail('PRICING_TAR_MEMBER');
 const h=Buffer.alloc(512);h.write(name,0,100);
 for(const [offset,width,value]of [[100,8,0o444],[108,8,0],[116,8,0],[124,12,bytes.length],[136,12,0]])h.write(value.toString(8).padStart(width-1,'0')+'\0',offset,width);
 h.fill(32,148,156);h[156]=48;h.write('ustar\0',257,6);h.write('00',263,2);h.write(h.reduce((a,b)=>a+b,0).toString(8).padStart(6,'0')+'\0 ',148,8);
 return Buffer.concat([h,bytes,Buffer.alloc((512-bytes.length%512)%512)]);
}
function pricingContext(plan){
 verifyPricingBuildInputs(plan);const parts=[];
 for(const row of plan.files){const bytes=sourceFile(plan.root,row.name);if(bytes.length!==row.bytes||sha(bytes)!==row.sha256)throw fail('PRICING_CONTEXT_CHANGED');parts.push(tarMember(row.name,bytes));}
 parts.push(Buffer.alloc(1024));verifyPricingBuildInputs(plan);return Buffer.concat(parts);
}
// Runs only when explicitly launched in the original base by the future fixed
// phase driver. No target-specific source, lockfile or npm substitute is used.
async function pricingGuest(load,binding){
 const fs=require('node:fs/promises'),native=require('node:fs'),crypto=require('node:crypto'),{Readable}=require('node:stream');
 const apt=load('ownedAptAuthentication'),metadata=load('ownedPolicySystemMetadata'),closure=load('ownedMcpDependencyClosure'),replay=load('ownedMcpArtifactReplay'),egress=load('ownedPricingEgressPolicy');
 const fail=code=>Object.assign(new Error(code),{code}),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
 const now=()=>Number(process.hrtime.bigint())/1e6,deadline=Number(process.env.DVAIA_ARTIFACT_DEADLINE_SECONDS)*1000,port=Number(process.env.DVAIA_ARTIFACT_PROXY_PORT);
 if(binding.target!=='v33-pricing'||binding.base!==closure.BASE||!Number.isFinite(deadline)||deadline<=0||deadline<=now()||deadline-now()>300000||!Number.isInteger(port)||port<1||port>65535)throw fail('PRICING_GUEST_ADMISSION');
 const controller=new AbortController();let service,primary,closing,ready=false,timer,phase='admit';
 let complete;const terminal=new Promise(resolve=>{complete=resolve;});
 const current=()=>{controller.signal.throwIfAborted();if(now()>=deadline)throw fail('PRICING_ACQUISITION_DEADLINE');};
 const publish=async(name,value)=>{
  if(!/^[a-z-]+\.json$/.test(name))throw fail('PRICING_PUBLICATION');const bytes=Buffer.from(JSON.stringify(value));if(bytes.length>1024**2)throw fail('PRICING_PUBLICATION');
  const temp='/pricing-closure/'+name+'.partial',final='/pricing-closure/'+name;
  const fd=await fs.open(temp,native.constants.O_CREAT|native.constants.O_EXCL|native.constants.O_WRONLY|native.constants.O_NOFOLLOW,0o400);
  try{await fd.writeFile(bytes);await fd.sync();}finally{await fd.close();}
  await fs.link(temp,final);await fs.unlink(temp);const dir=await fs.open('/pricing-closure',native.constants.O_RDONLY);try{await dir.sync();}finally{await dir.close();}
 };
 const finish=()=>closing||=(async()=>{
  controller.abort();const debt=[];let result=null,join;
  try{if(service){result=await Promise.race([service.close(),new Promise((_,reject)=>{join=setTimeout(()=>reject(fail('PRICING_REPLAY_JOIN')),5000);})]);if(result.absenceVerified!==true)debt.push('PRICING_REPLAY_ABSENCE');}}
  catch{debt.push('PRICING_REPLAY_JOIN');}finally{clearTimeout(join);}
  if(primary?.cleanupDebt?.length||primary?.replayCleanupError)debt.push('PRICING_AUTHENTICATION_RETIREMENT');
  const failure=primary?.code|| (primary?'PRICING_GUEST_FAILED':result?.failure||null);
  const diagnostic={phase,...closure.failureDiagnostic(primary)};
  try{await publish('terminal.json',{version:1,binding,failure,result,cleanupErrors:debt,diagnostic});}catch{debt.push('PRICING_TERMINAL_PUBLICATION');}
  process.exitCode=debt.length?2:failure?1:0;clearTimeout(timer);complete();return {result,debt};
 })();
 const interrupt=()=>{if(!ready)primary||=fail('PRICING_GUEST_INTERRUPTED');controller.abort();if(service)void finish();};
 process.on('SIGTERM',interrupt);process.on('SIGINT',interrupt);timer=setTimeout(interrupt,Math.max(0,deadline-now()));
 try{
  current();const checkpointFd=await fs.open('/pricing-overhead.json',native.constants.O_RDONLY|native.constants.O_NOFOLLOW);let overhead;
  try{const s=await checkpointFd.stat();if(!s.isFile()||s.nlink!==1||s.uid!==0||(s.mode&0o777)!==0o600||s.size<1||s.size>65536)throw fail('PRICING_CHECKPOINT_FILE');overhead=JSON.parse(await checkpointFd.readFile('utf8'));}finally{await checkpointFd.close();}
  egress.validateOverheadCheckpoint(overhead,{runId:binding.runId});
  const cap=await apt.admitRetained(binding);phase='authenticate';const authentication=await apt.authenticate(cap,{signal:controller.signal,deadline});current();
  const envelope=metadata.validateResultEnvelope(await fs.readFile('/metadata-retained/result.json','utf8'),binding);
  const retained=metadata.validateRetainedMetadata(envelope.candidate,binding),artifacts=closure._internals.debArtifacts(retained.stages);
  closure._internals.validateArtifacts(artifacts);
  egress.validatePricingArtifactCensus(artifacts);
  phase='acquire';const acquired=await closure.acquireArtifacts({artifacts,directory:'/pricing-closure/artifacts',authority:{host:'127.0.0.1',port},signal:controller.signal,deadline,now});current();
  if(acquired.bytes.npm!==0||acquired.artifacts.some(a=>a.kind!=='deb'))throw fail('PRICING_ARTIFACT_KIND');
  const record={version:1,binding,authentication,acquired,overhead};await publish('closure.json',record);
  const packageRead=closure.artifactReader('/pricing-closure/artifacts',acquired),objects=new Map(retained.objects.filter(r=>r.kind==='upstream').map(r=>[r.url,r]));
  const read=async url=>{
   const row=objects.get(url);if(!row)return packageRead(url);
   const fd=await fs.open('/metadata-retained/'+row.file,native.constants.O_RDONLY|native.constants.O_NOFOLLOW);let bytes;
   try{const s=await fd.stat();if(!s.isFile()||s.nlink!==1||s.uid!==0||(s.mode&0o777)!==0o444||s.size!==row.bytes||s.size>32*1024**2)throw fail('PRICING_METADATA_FILE');bytes=await fd.readFile();}finally{await fd.close();}
   if(bytes.length!==row.bytes||sha(bytes)!==row.sha256)throw fail('PRICING_METADATA_INTEGRITY');return {bytes:bytes.length,sha256:row.sha256,stream:Readable.from([bytes])};
  };
  phase='replay';service=replay.createReplay({...replay.replayCertificate(),read});
  service.firstFailure.then(()=>{void finish();}).catch(()=>{process.exitCode=2;});
  await publish('replay-intent.json',{version:1,binding,policy:'strict-default'});
  const authority=await service.listen();current();
  await publish('ready.json',{version:1,binding,port:authority.port,closureSha256:sha(JSON.stringify(record)),metadataAuthenticated:true,artifactBytesVerified:true});ready=true;
  clearTimeout(timer);timer=null;await terminal;
 }catch(e){primary=e;await finish();}finally{clearTimeout(timer);process.off('SIGTERM',interrupt);process.off('SIGINT',interrupt);}
}
function pricingGuestSource(plan){
 verifyPricingBuildInputs(plan);const modules={};
 for(const name of MODULES){const file='tests/postgres/'+name+'.js',bytes=sourceFile(plan.root,file);if(sha(bytes)!==plan.sources[file])throw fail('PRICING_SOURCE_CHANGED');modules[name]=bytes.toString();}
 const loader='const modules='+JSON.stringify(modules)+',cache=new Map();function load(n){if(!Object.hasOwn(modules,n))throw Error("PRICING_MODULE");if(cache.has(n))return cache.get(n).exports;const m={exports:{}};cache.set(n,m);new Function("require","module","exports",modules[n])(id=>id.startsWith("node:")?require(id):load(id.replace(/^\\.\\//,"")),m,m.exports);return m.exports;}';
 const text="'use strict';"+loader+'\n('+pricingGuest.toString()+')(load,'+JSON.stringify(plan.binding)+').catch(()=>{process.exitCode=2;});\n';
 if(Buffer.byteLength(text)>1024**2)throw fail('PRICING_GUEST_SOURCE_LIMIT');return {text,sha256:sha(text)};
}
// Validate actual guest reports against independently captured metadata. A
// dictionary passing this predicate is still not a process/image capability.
function validatePricingClosure(plan,envelopeRaw,record){
 verifyPricingBuildInputs(plan);const envelope=metadata.validateResultEnvelope(envelopeRaw,plan.binding);
 if(!envelope.ok||envelope.version!==3)throw fail('PRICING_METADATA_FAILED');
 const c=envelope.candidate,r=metadata.validateRetainedMetadata(c,plan.binding);
 const artifacts=producer.pricingArtifactPlan({stages:r.stages}).artifacts;
 egress.validatePricingArtifactCensus(artifacts);egress.validateOverheadCheckpoint(record.overhead,{runId:plan.runId});
 const total=artifacts.reduce((n,a)=>n+a.bytes,0);
 const authentication={binding:plan.binding,version:1,method:'original-base-apt-closed-replay',retainedManifestSha256:sha(JSON.stringify(r)),
  keyringSha256:c.keyringSha256,installedStatusSha256:c.installedStatusSha256,
  stages:r.stages.map(s=>({name:s.name,selectionSha256:sha(s.selection)})),expandedBytes:c.expandedBytes};
 const acquired={version:1,artifactBytesVerified:true,metadataAuthenticated:false,buildApproved:false,qualificationComplete:false,
  bytes:{deb:total,npm:0,total},artifacts:artifacts.map(a=>({...a,actualBytes:a.bytes,file:'objects/'+closure._internals.objectName(a)}))};
 if(!equal(record,{version:1,binding:plan.binding,authentication,acquired,overhead:record.overhead}))throw fail('PRICING_AUTHENTICATION_JOIN');
 return freeze({closureSha256:sha(JSON.stringify(record)),artifactCount:artifacts.length,bytes:total});
}
function validatePricingImage(plan,rows){
 verifyPricingBuildInputs(plan);const row=rows?.[0];
 if(!Array.isArray(rows)||rows.length!==1||!/^sha256:[a-f0-9]{64}$/.test(row?.Id)||row.Architecture!=='arm64'||row.Os!=='linux'
  ||row.Config?.User!==plan.user||!equal(row.Config?.Entrypoint,plan.entrypoint)
  ||row.Config?.Labels?.['dvaia.pricing.package']!==plan.packageDigest||row.Config?.Labels?.['dvaia.build-run']!==plan.runId)throw fail('PRICING_IMAGE_IDENTITY');
 return row.Id;
}
function validatePricingHandoff(plan,value){
 verifyPricingBuildInputs(plan);
 if(!keys(value,'version,target,runId,packageDigest,imageId,daemonId,sharedDaemonId,namespaceInode,sharedNamespaceInode,filesystemIdentity,daemonProcess,namespaceHolder,relayRetired')
  ||value.version!==1||value.target!==TARGET||value.runId!==plan.runId||value.packageDigest!==plan.packageDigest
  ||!/^sha256:[a-f0-9]{64}$/.test(value.imageId)||!daemonId(value.daemonId)||!daemonId(value.sharedDaemonId)||value.daemonId===value.sharedDaemonId
  ||!/^net:\[[1-9][0-9]*\]$/.test(value.namespaceInode)||!/^net:\[[1-9][0-9]*\]$/.test(value.sharedNamespaceInode)
  ||value.namespaceInode===value.sharedNamespaceInode||value.relayRetired!==true)throw fail('PRICING_HANDOFF');
 for(const [name,exe]of [['daemonProcess','/usr/bin/dockerd'],['namespaceHolder','/usr/bin/sleep']]){
  const p=value[name];if(!keys(p,'pid,startTicks,exe')||!Number.isSafeInteger(p.pid)||p.pid<2||!(/^[1-9][0-9]*$/).test(p.startTicks)||p.exe!==exe)throw fail('PRICING_PROCESS_IDENTITY');
 }
 const f=value.filesystemIdentity;
 if(value.daemonProcess.pid===value.namespaceHolder.pid||!keys(f,'device,inode')||!Number.isSafeInteger(f.device)||f.device<0||!Number.isSafeInteger(f.inode)||f.inode<1)throw fail('PRICING_FILESYSTEM_IDENTITY');
 return freeze(structuredClone(value));
}

const quote=x=>"'"+x.replace(/'/g,"'\\''")+"'";
function pricingCommands(meta,inputs,guest){
 const suffix='\ncheck_mount; check_runtime\ndocker --host "unix://$root/fs/docker.sock" info --format \'{{json .}}\'\n';
 if(!meta.commands.inspect.endsWith(suffix))throw fail('PRICING_GUARD_SHAPE');
 const guard=meta.commands.inspect.slice(0,-suffix.length);
 const active='/usr/bin/python3 -I -S -B -c '+quote(derivation._internals.leaseProgram(inputs.consumerProfile))+' "$root" "$nonce" active >/dev/null\n';
 const identity=String.raw`
pricing_identity() {
 [ -f "$root/fs/pricing.intent" ] && [ ! -L "$root/fs/pricing.intent" ]
 [ "$(cat "$root/fs/pricing.intent")" = "$nonce" ]
 if [ -e "$root/fs/pricing.cid" ]; then
  [ ! -L "$root/fs/pricing.cid" ]; cid=$(cat "$root/fs/pricing.cid")
 else
  cid=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "dvaia-pricing-closure-$nonce")
 fi
 [ "$(printf '%s' "$cid" | wc -c | tr -d ' ')" = 64 ]; case "$cid" in *[!a-f0-9]*) return 97;; esac
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Id}}' "$cid")" = "$cid" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{index .Config.Labels "dvaia.pricing.closure"}}' "$cid")" = "$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Name}}' "$cid")" = "/dvaia-pricing-closure-$nonce" ]
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.Image}}' "$cid")" = "$(docker --host "unix://$root/fs/docker.sock" image inspect --format '{{.Id}}' 'node@BASE')" ]
}
`.replace('node@BASE','node@'+producer.BASE);
 const prefix=guard+identity+'\ncheck_mount; check_runtime\n';
 const checkpoint=prefix+active+'relay_control checkpoint | /usr/bin/python3 -I -S -B -c '+quote("import os,sys,json; b=sys.stdin.buffer.read(65537); assert 0<len(b)<=65536; json.loads(b); p=sys.argv[1]; f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\nwith os.fdopen(f,'wb') as out: out.write(b);out.flush();os.fsync(out.fileno())\nd=os.open(os.path.dirname(p),os.O_RDONLY);os.fsync(d);os.close(d);sys.stdout.buffer.write(b)")+' "$root/fs/pricing-overhead.json"\n';
 const start=prefix+active+String.raw`
[ ! -e "$root/fs/pricing-closure" ] && [ ! -L "$root/fs/pricing-closure" ]
mkdir -m 0700 "$root/fs/pricing-closure"
/usr/bin/python3 -I -S -B -c 'import sys,os,hashlib; b=sys.stdin.buffer.read(1048577); assert 0<len(b)<=1048576 and hashlib.sha256(b).hexdigest()==sys.argv[2]; f=os.fdopen(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400),"wb"); f.write(b); f.flush(); os.fsync(f.fileno()); f.close()' "$root/fs/pricing-guest.js" GUEST_SHA
deadline=$(/usr/bin/python3 -I -S -B -c 'import time,json,sys; r=json.load(open(sys.argv[1])); now=time.monotonic(); assert now*1000+300000<r["expiresAtMs"]; print(now+300)' "$root/pricing-lease.json")
proxy_port=$(relay_control authority)
(set -C; printf '%s' "$nonce" > "$root/fs/pricing.intent")
docker --host "unix://$root/fs/docker.sock" create --cidfile "$root/fs/pricing.cid" --name "dvaia-pricing-closure-$nonce" --label "dvaia.pricing.closure=$nonce" --pull never --network host --read-only --memory 768m --cpus 1 --pids-limit 64 --cap-drop ALL --security-opt no-new-privileges --log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false --mount "type=bind,source=$root/fs/metadata-retained,target=/metadata-retained,readonly" --mount "type=bind,source=$root/fs/pricing-closure,target=/pricing-closure" --mount "type=bind,source=$root/fs/pricing-guest.js,target=/pricing-guest.js,readonly" --tmpfs /metadata:rw,nosuid,nodev,noexec,size=512m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m --env "DVAIA_ARTIFACT_DEADLINE_SECONDS=$deadline" --env "DVAIA_ARTIFACT_PROXY_PORT=$proxy_port" --entrypoint /usr/local/bin/node 'node@BASE' /pricing-guest.js >/dev/null
pricing_identity; docker --host "unix://$root/fs/docker.sock" start "$cid" >/dev/null
attempt=0
until [ -f "$root/fs/pricing-closure/ready.json" ]; do
 [ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = true ]
 attempt=$((attempt+1)); [ "$attempt" -lt 1500 ]; sleep .2
done
pricing_identity; cat "$root/fs/pricing-closure/ready.json"
`.replace('GUEST_SHA',quote(guest.sha256)).replace('node@BASE','node@'+producer.BASE);
 const unpack=String.raw`import os,sys,json,tarfile,hashlib,stat
root=sys.argv[1];rows=json.loads(sys.argv[2]);context=root+'/fs/pricing-context';os.mkdir(context,0o700);seen=set();total=0
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
 for member in archive:
  assert member.name in rows and member.name not in seen and member.isfile() and member.uid==0 and member.gid==0
  row=rows[member.name];assert member.size==row['bytes'] and member.mode==row['mode'] and member.size<=1048576
  data=archive.extractfile(member).read(1048577);total+=len(data);assert total<=16777216 and len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
  filename=context+'/'+member.name;os.makedirs(os.path.dirname(filename),mode=0o700,exist_ok=True)
  with os.fdopen(os.open(filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444),'wb') as f:
   f.write(data);f.flush();os.fchmod(f.fileno(),0o444)
   s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o444 and s.st_size==len(data)
   os.fsync(f.fileno())
  seen.add(member.name)
assert seen==set(rows)
`;
 const rows=Object.fromEntries(inputs.files.map(({name,...r})=>[name,r]));
 const build=prefix+active+'pricing_identity\n'+
 '/usr/bin/python3 -I -S -B -c '+quote(unpack)+' "$root" '+quote(JSON.stringify(rows))+'\n'+
 'port=$(/usr/bin/python3 -I -S -B -c '+quote("import os,json,sys,stat; f=os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)); s=os.fstat(f.fileno()); assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=1048576; r=json.load(f); assert r['binding']==json.loads(sys.argv[2]) and r['metadataAuthenticated'] is True and r['artifactBytesVerified'] is True; assert type(r['port']) is int and 0<r['port']<65536; print(r['port'])")+' "$root/fs/pricing-closure/ready.json" '+quote(JSON.stringify(inputs.binding))+')\n'+
 'stop_private_relay\nproxy="http://127.0.0.1:$port"\n'+
 'timeout --signal=TERM --kill-after=10 300 docker --host "unix://$root/fs/docker.sock" build --pull=false --network=host --platform linux/arm64 --build-arg "HTTP_PROXY=$proxy" --build-arg "HTTPS_PROXY=$proxy" --build-arg "http_proxy=$proxy" --build-arg "https_proxy=$proxy" --build-arg NO_PROXY= --build-arg no_proxy= --label '+quote('dvaia.pricing.package='+inputs.packageDigest)+' --label "dvaia.build-run=$nonce" -f "$root/fs/pricing-context/'+producer.DOCKERFILE+'" -t "dvaia-pricing-build:$nonce" "$root/fs/pricing-context"\npricing_identity\n';
 const retire=guard+identity+String.raw`
if [ ! -e "$root/fs/pricing.intent" ] && [ ! -L "$root/fs/pricing.intent" ]; then printf 'absent\n'; exit 0; fi
check_mount; check_runtime; pricing_identity
docker --host "unix://$root/fs/docker.sock" stop --time 10 "$cid" >/dev/null
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.Running}}' "$cid")" = false ]
[ "$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.OOMKilled}}' "$cid")" = false ]
code=$(docker --host "unix://$root/fs/docker.sock" inspect --format '{{.State.ExitCode}}' "$cid")
`+'/usr/bin/python3 -I -S -B -c '+quote("import os,sys,json,stat; f=os.fdopen(os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)); s=os.fstat(f.fileno()); assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=1048576; r=json.load(f); assert r['binding']==json.loads(sys.argv[3]) and r['cleanupErrors']==[]; v=r['result']; assert v is None or (v['closed'] is True and v['absenceVerified'] is True and v['active']==0); assert sys.argv[2] in ('0','1') and int(sys.argv[2])==(1 if r['failure'] or (v and v['failure']) else 0)")+' "$root/fs/pricing-closure/terminal.json" "$code" '+quote(JSON.stringify(inputs.binding))+'\n'+
 'docker --host "unix://$root/fs/docker.sock" rm "$cid" >/dev/null\nids=$(docker --host "unix://$root/fs/docker.sock" ps -aq --no-trunc)\nfor id in $ids; do [ "$id" != "$cid" ]; done\nprintf \'absent\\n\'\n';
 const evidence=guard+'\ncheck_mount\n/usr/bin/python3 -I -S -B -c '+quote("import os,sys,stat,json; result={}\nfor name in ('closure.json','ready.json','replay-intent.json','terminal.json'):\n p=sys.argv[1]+'/'+name\n if not os.path.lexists(p):result[name]=None;continue\n f=os.fdopen(os.open(p,os.O_RDONLY|os.O_NOFOLLOW));s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and 0<s.st_size<=1048576\n with f:result[name]=f.read(1048577)\ntext=json.dumps(result);assert len(text.encode())<=2097152;print(text)")+' "$root/fs/pricing-closure"\n';
 const handoff=prefix+active+'stop_private_relay\ncheck_network\n'+
 '/usr/bin/python3 -I -S -B -c '+quote("import os,sys,json,subprocess\nr,run,package=sys.argv[1:]\ndef read(n):\n with open(r+'/fs/'+n) as f:return f.read(4097).strip()\ndef docker(socket,args):return subprocess.check_output(['/usr/bin/docker','--host','unix://'+socket]+args,timeout=10,text=True).strip()\ndef proc(n,exe):\n pid=int(read(n+'.pid'));start=read(n+'.start');assert pid>1 and os.readlink('/proc/'+str(pid)+'/exe')==exe and os.readlink('/proc/'+str(pid)+'/ns/net')==read('namespace.inode')\n with open('/proc/'+str(pid)+'/stat') as f:assert f.read().rsplit(')',1)[1].split()[19]==start\n return dict(pid=pid,startTicks=start,exe=exe)\ns=os.stat(r+'/fs');print(json.dumps(dict(version=1,target='original-v33-pricing',runId=run,packageDigest=package,imageId=docker(r+'/fs/docker.sock',['image','inspect','--format','{{.Id}}','dvaia-pricing-build:'+run]),daemonId=docker(r+'/fs/docker.sock',['info','--format','{{.ID}}']),sharedDaemonId=docker('/run/docker.sock',['info','--format','{{.ID}}']),namespaceInode=read('namespace.inode'),sharedNamespaceInode=read('shared.inode'),filesystemIdentity=dict(device=s.st_dev,inode=s.st_ino),daemonProcess=proc('daemon','/usr/bin/dockerd'),namespaceHolder=proc('namespace','/usr/bin/sleep'),relayRetired=True)))")+' "$root" "$nonce" '+quote(inputs.packageDigest)+'\n';
 return {inventory:meta.commands.inventory,...Object.fromEntries(Object.entries(meta.phases).filter(([n])=>n!=='version')),inspect:meta.commands.inspect,relayCheckpoint:checkpoint,startArtifacts:start.replace('--tmpfs /metadata:', '--mount "type=bind,source=$root/fs/pricing-overhead.json,target=/pricing-overhead.json,readonly" --tmpfs /metadata:'),build,retireArtifacts:retire,closureEvidence:evidence,handoff,
 image:prefix+active+'docker --host "unix://$root/fs/docker.sock" image inspect "dvaia-pricing-build:$nonce"\n'};
}
async function pricingBuildPlan(root,runId,profile='v33'){
 const inputs=pricingBuildInputs(root,runId,profile),derived=derivation.loadPricingBounded(profile),meta=await derived.pricingMetadataQualificationPlan(root,runId),guest=pricingGuestSource(inputs);
 if(!equal(meta.binding,inputs.binding)||meta.executionApproved!==false)throw fail('PRICING_METADATA_PLAN');
 return freeze({version:1,target:TARGET,runId,inputs,binding:inputs.binding,spec:bounded.specification(root,runId),metadata:meta,guest,
 derivedSha256:derived.derivedSha256,metadataGuestSource:metadata.guestMetadataSource(inputs.binding,{retention:inputs.retention.mode}),commands:pricingCommands(meta,inputs,guest),buildApproved:false,qualificationComplete:false});
}


const shaPlan=plan=>sha(JSON.stringify(plan));
async function verifyPlan(plan){
 if(!plan||!equal(plan,await pricingBuildPlan(plan.inputs.root,plan.runId,plan.inputs.consumerProfile)))throw fail('PRICING_PLAN_CHANGED');
}
function createFixedTransport(plan,record,controlled={}){
 const lifetime=lease.profile(plan.inputs.consumerProfile);
 const execute=controlled.execute||transport.createExecutor();
 if(typeof record!=='function')throw fail('PRICING_JOURNAL_REQUIRED');
 const normal=['inventory','preflight','prepare','namespace','relayStart','daemonStart','inspect','metadataFetch','relayCheckpoint','startArtifacts','closureEvidence','inspect','build','image','retireArtifacts','closureEvidence','inspect','handoff','publishHandoff'];
 const cleanup=['retireArtifacts','closureEvidence','stop','evidence','retainedExport','cleanup','inventory'];
 const now=controlled.now||(()=>Number(process.hrtime.bigint())/1e6),start=now();let at=0,busy=false,retiring=false,cleanupUntil=null,cleanupAt=0,failed=false,closed=false;
 let workUntil=start+180000,window='setup',last=start,retirementDebt=false;
 const check=clean=>{const time=now();if(time<last)throw fail('PRICING_CLOCK_REGRESSION');last=time;
  if(clean){if(time>=cleanupUntil)throw fail('PRICING_RETIREMENT_EXPIRED');}
  else if(time>=workUntil||time>=start+1080000)throw fail('PRICING_WORK_EXPIRED');};
 return Object.freeze({
  beginRetirement(remainingMs,anchoredAt=now()){
   if(closed||busy||retiring||!Number.isFinite(remainingMs)||remainingMs<=0||remainingMs>600000)throw fail('PRICING_RETIREMENT_ADMISSION');
   if(!Number.isFinite(anchoredAt)||anchoredAt<start||anchoredAt>now())throw fail('PRICING_RETIREMENT_ADMISSION');
   cleanupUntil=Math.min(anchoredAt+Math.floor(remainingMs),start+lifetime.totalMs);retiring=true;check(true);
   return {remainingMs:Math.max(0,Math.floor(cleanupUntil-now())),absenceProven:false};
  },
  async phase(name,{input,sink,signal,publication,cleanup:clean=false}={}){
   if(closed||busy||retirementDebt||failed&&!clean)throw fail('PRICING_PHASE_AUTHORITY');
   if(clean){if(!retiring){retiring=true;cleanupUntil=Math.min(now()+600000,start+lifetime.totalMs);}const next=cleanup.indexOf(name,cleanupAt);if(next<0)throw fail('PRICING_RETIREMENT_AUTHORITY');cleanupAt=next+1;}
   else{if(retiring||normal[at]!==name)throw fail('PRICING_PHASE_AUTHORITY');check(false);
    const nextWindow={metadataFetch:'metadata',startArtifacts:'artifacts',build:'build'}[name];
    if(nextWindow){const order=['setup','metadata','artifacts','build'];if(order.indexOf(nextWindow)!==order.indexOf(window)+1)throw fail('PRICING_WINDOW_ORDER');window=nextWindow;workUntil=now()+300000;
     const future=(3-order.indexOf(window))*300000+lifetime.budget.cohort+6000+330000+600000;
     if(workUntil+future>start+lifetime.totalMs)throw fail('PRICING_COHORT_RESERVE');}
    at++;}
   check(clean);
   busy=true;let error,diagnosticBytes=0;const diagnostics=[];
   try{
    await verifyPlan(plan);if(!clean)signal?.throwIfAborted();
    let dispatchPlan=plan;
    if(name==='publishHandoff'){
     if(clean||input||!publication||!equal(Object.keys(publication).sort(),['observed','ownerId','token'])||typeof publication.token!=='string'||!/^[A-Za-z0-9_-]{43,128}$/.test(publication.token))throw fail('PRICING_PUBLICATION_INPUT');
     const command=await pricingPublicationCommand(plan,publication.ownerId,publication.observed);
     dispatchPlan={...plan,commands:{...plan.commands,publishHandoff:command}};
     input=require('node:stream').Readable.from([Buffer.from(JSON.stringify({token:publication.token}))]);
    }else if(publication!==undefined)throw fail('PRICING_PUBLICATION_PHASE');
    await record(name+'-intent',{planSha256:shaPlan(plan),cleanup:clean});check(clean);if(!clean)signal?.throwIfAborted();
    const value=await execute(dispatchPlan,name,{input,sink,signal:clean?undefined:signal,deadline:clean?cleanupUntil:workUntil,diagnosticSink:b=>{diagnosticBytes+=b.length;if(diagnosticBytes>2*1024**2)throw fail('PRICING_DIAGNOSTIC_LIMIT');diagnostics.push(Buffer.from(b));}});
    check(clean);
    if(diagnostics.length){const text=Buffer.concat(diagnostics).toString();diagnostics.length=0;await record(name+'-diagnostic',text);}
    await record(name+'-result',{output:value,cleanup:clean});return value;
   }catch(e){error=e;failed=true;retirementDebt ||= e.retirementUnproven===true;
    throw e;
   }finally{busy=false;if(error){if(diagnostics.length)try{await record(name+'-diagnostic',Buffer.concat(diagnostics).toString());}catch(journal){error.journalError=journal.code||journal.name;}
    try{await record(name+'-failure',{code:error.code||error.name,cleanup:clean});}catch(journal){error.journalError ||= journal.code||journal.name;}}}
  },
  status(){return {pending:busy,failed,retirementDebt,retiring,cleanupUntil,normalCompleted:at===normal.length,controlled:!!controlled.execute,window,workUntil};},
  close(){if(busy)throw fail('PRICING_PHASE_PENDING');closed=true;},
 });
}
// Controlled execution of the same fixed plan. The injected transport can prove
// ordering/error behavior only; its observations never create a live capability.
async function runControlledBuild(plan,{phase,record,signal,consume,beforeRetirement,createExport=()=>transport.createExport(plan.inputs.root,plan.runId)}){
 await verifyPlan(plan);if(typeof phase!=='function'||typeof record!=='function')throw fail('PRICING_CONTROLLED_DRIVER');
 let intended=false,artifacts=false,retired=false,before,daemon,image,primary;const debt=[];
 const step=async(name,input,cleanup=false,sink)=>{
  if(!cleanup){signal?.throwIfAborted();await verifyPlan(plan);}
  await record(name+'-intent',{planSha256:shaPlan(plan),controlled:true,cleanup});
  const value=await phase(name,{input,sink,cleanup,signal:cleanup?undefined:signal});
  await record(name+'-result',value);return value;
 };
 try{
  before=bounded._internals.checkInventory(await step('inventory'));
  await step('preflight');intended=true;
  for(const n of ['prepare','namespace','relayStart','daemonStart'])await step(n);
  daemon=bounded._internals.checkDaemon(JSON.parse(await step('inspect')),plan.spec);
  const envelope=await step('metadataFetch',require('node:stream').Readable.from([plan.metadataGuestSource]));
  const parsed=metadata.validateResultEnvelope(envelope,plan.inputs.binding);if(!parsed.ok)throw fail('PRICING_METADATA_FAILED');
  const overhead=JSON.parse(await step('relayCheckpoint'));egress.validateOverheadCheckpoint(overhead,{runId:plan.runId});
  artifacts=true;const ready=JSON.parse(await step('startArtifacts',require('node:stream').Readable.from([plan.guest.text])));
  if(!equal(ready.binding,plan.inputs.binding)||ready.metadataAuthenticated!==true||ready.artifactBytesVerified!==true)throw fail('PRICING_READY');
  const packet=JSON.parse(await step('closureEvidence')),joined=validatePricingClosure(plan.inputs,envelope,JSON.parse(packet['closure.json']));
  if(!equal(JSON.parse(packet['closure.json']).overhead,overhead))throw fail('PRICING_CHECKPOINT_JOIN');
  if(ready.closureSha256!==joined.closureSha256)throw fail('PRICING_READY_DIGEST');
  if(bounded._internals.checkDaemon(JSON.parse(await step('inspect')),plan.spec)!==daemon)throw fail('PRICING_DAEMON_CHANGED');
  await step('build',require('node:stream').Readable.from([pricingContext(plan.inputs)]));
  image=validatePricingImage(plan.inputs,JSON.parse(await step('image')));
  retired=(await step('retireArtifacts')).trim()==='absent';if(!retired)throw fail('PRICING_ARTIFACT_RETIREMENT');
  const terminal=JSON.parse(JSON.parse(await step('closureEvidence'))['terminal.json']);
  if(!equal(terminal.binding,plan.inputs.binding)||terminal.failure!==null||terminal.result?.failure!==null||terminal.result?.absenceVerified!==true||!equal(terminal.cleanupErrors,[]))throw fail('PRICING_REPLAY_TERMINAL');
  if(bounded._internals.checkDaemon(JSON.parse(await step('inspect')),plan.spec)!==daemon)throw fail('PRICING_DAEMON_CHANGED');
  const handoff=validatePricingHandoff(plan.inputs,JSON.parse(await step('handoff')));
  if(handoff.imageId!==image||handoff.daemonId!==daemon)throw fail('PRICING_OBSERVED_HANDOFF');
  await record('image-observation',{handoff,controlled:true,runtimeAvailable:false});
  if(consume)await consume(handoff);
 }catch(e){primary=e;}
 if(beforeRetirement)try{await beforeRetirement();}catch(e){debt.push(e);}
 if(debt.length){
  const result={version:1,target:TARGET,controlled:true,buildCompleted:!!image&&!primary,cleanupVerified:false,qualificationComplete:false,runtimeAvailable:false,
   failure:primary?.code||primary?.name||null,cleanupErrors:debt.map(e=>e.code||e.name)};
  await record('result',result);throw Object.assign(new AggregateError([primary,...debt].filter(Boolean),'Pricing retirement not admitted'),{result});
 }
 if(artifacts&&!retired)try{retired=(await step('retireArtifacts',undefined,true)).trim()==='absent';if(!retired)throw fail('PRICING_ARTIFACT_RETIREMENT');}catch(e){debt.push(e);}
 if(intended&&(!artifacts||retired)){
  for(const name of ['closureEvidence','stop','evidence','retainedExport','cleanup']){
   if(name==='closureEvidence'&&!artifacts||name==='cleanup'&&debt.length)continue;
   try{let value;
    if(name==='retainedExport'){
     const retained=createExport();let exportError;
     try{await step(name,undefined,true,retained.sink);value=retained.finish();await record('retained-export-published',value);}
     catch(e){exportError=e;throw e;}finally{try{retained.close();}catch(e){if(exportError)exportError.closeError=e;else throw e;}}
    }else value=await step(name,undefined,true);
    if(name==='cleanup'&&value.trim()!=='absent')throw fail('PRICING_CLEANUP_UNPROVEN');
   }catch(e){debt.push(e);}
  }
 }
 if(before!==undefined)try{if(bounded._internals.checkInventory(await step('inventory',undefined,true))!==before)throw fail('PRICING_SHARED_CHANGED');}catch(e){debt.push(e);}
 const result={version:1,target:TARGET,controlled:true,buildCompleted:!!image&&!primary,cleanupVerified:debt.length===0,qualificationComplete:false,runtimeAvailable:false,
  failure:primary?.code||primary?.name||null,cleanupErrors:debt.map(e=>e.code||e.name)};
 await record('result',result);
 if(primary||debt.length)throw Object.assign(new AggregateError([primary,...debt].filter(Boolean),'Pricing build failed'),{result});
 return result;
}

function withPrivatePricingImage(){throw fail('PRICING_NATIVE_TRANSPORT_NOT_ADMITTED');}
async function pricingPublicationCommand(plan,ownerId,observed){
 await verifyPlan(plan);const witness=validatePricingHandoff(plan.inputs,observed);
 // Keep the exact plan's owner/mount/runtime/lease and relay-retirement guards.
 // Only replace its last observational Python program with fixed publication.
 const marker='/usr/bin/python3 -I -S -B -c ',at=plan.commands.handoff.lastIndexOf(marker);
 if(at<0)throw fail('PRICING_PUBLICATION_SOURCE');
 const source=require('./ownedPricingPrivateHandoff').program({runId:plan.runId,ownerId,packageSha256:plan.inputs.packageDigest,imageId:witness.imageId,sharedDaemonId:witness.sharedDaemonId},plan.inputs.consumerProfile);
 return plan.commands.handoff.slice(0,at)+marker+"'"+source.replace(/'/g,"'\\''")+"'\n";
}
module.exports={pricingBuildInputs,verifyPricingBuildInputs,pricingBuildPlan,pricingContext,pricingGuestSource,validatePricingClosure,validatePricingImage,validatePricingHandoff,withPrivatePricingImage,
 pricingPublicationCommand,
 _internals:{TARGET,LIMITS,MODULES,sourceFile,tarMember,pricingGuest,pricingCommands,verifyPlan,shaPlan,createFixedTransport,runControlledBuild}};
