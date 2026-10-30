'use strict';
// Qualified automatic package/profile preparation selected by --owned-listings.
// Package drift fails closed; application activation remains separate.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
const planner=require('./secureshop-owned-listings');
const provisioner=require('./secureshop-owned-listings-provision');
const {localProfilePlan}=require('./mcp-owned-local');
const {createRunner}=require('./secureshop-owned-system-provision')._internals;
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest,sanitizeDockerEnvironment}=require('../local-docker-authority');
const fail=code=>Object.assign(new Error('Owned Listings automatic installer candidate unavailable'),{code});
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const QUALIFICATION='tasks/secureshop-listings-package-2026-10-17.json';
const QUALIFICATION_REPORT='scripts/install/qualification/secureshop-listings-package-2026-10-17.json';
const QUALIFICATION_REPORT_SHA256='6fbd2ab59428a6507ab80394b43cdc1b4360d06b7919b53d3ad4a3fcdaf0dd03';
const V2_BUILDX_SHA256='591a852237e8ed2b8c65f6be8105ef8c2d1ec52edc77c8acf8f263c2240ef4d6';
function readSourceJson(file,expectedSha256){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>65536)throw fail('LISTINGS_PACKAGE_INVALID');const bytes=fs.readFileSync(fd);if(expectedSha256&&sha(bytes)!==expectedSha256)throw fail('LISTINGS_PACKAGE_QUALIFICATION_INVALID');return JSON.parse(bytes);}finally{fs.closeSync(fd);}}
function qualifiedReport(value,source,runtimeDigest){
 const legacy=['containerAbsent','volumeAbsent','imageAbsent','profileAbsent','remoteAbsent','buildCaAbsent','buildPgidAbsent','testPgidAbsent'];
 const result=entry=>entry?.status==='passed'&&entry.modelCalls===0&&entry.runtimeDigest===runtimeDigest;
 // The retained report predates report versioning.  Keep that historical
 // schema exactly, rather than treating a missing version as an invalid v2.
 if(value&& !Object.hasOwn(value,'version'))return value.status==='passed'&&value.frozenHashesVerified===true&&value.frozenFileCount===Object.keys(source.files).length&&result(value.result)&&result(value.restartResult)&&value.reportedCleanup?.errors?.length===0&&legacy.every(k=>value.reportedCleanup[k]===true);
 const absent=['containerAbsent','volumeAbsent','profileAbsent','imageAbsent','buildPgidAbsent','freshPgidAbsent','restartPgidAbsent'];
 const checks=['real-supplier-prototype-effect','fixed-prototype-no-effect','internal-prototype-route-denial','real-json','internal-ssrf','fixed-denial','real-file-entity','real-http-entity','external-host-denial','restart-no-refetch','timeout-child-cleanup','readonly-write-denial','authenticated-http','retirement-redaction-sibling'];
 const process=value?.ownedProcesses, validProcess=row=>row&&Number.isInteger(row.pid)&&row.pid>0&&row.pgid===row.pid;
 const hash=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
 const packageSource=value?.source?.package;
 const driverSource=value?.source?.drivers;
 const buildx=value?.source?.buildx;
 const sameFiles=(left,right)=>left&&right&&Object.keys(left).length===Object.keys(right).length&&Object.keys(left).every(key=>right[key]===left[key]);
 const exactChecks=entry=>Array.isArray(entry?.checks)&&entry.checks.length===checks.length&&entry.checks.every((check,index)=>check===checks[index]);
 const sourceValid=packageSource&&packageSource.sha256===source.sha256&&sameFiles(packageSource.files,source.files)
  &&driverSource&&Object.keys(driverSource).length>0&&Object.values(driverSource).every(hash)&&hash(value.source.node)&&hash(value.source.docker)
  &&buildx&&typeof buildx.path==='string'&&path.isAbsolute(buildx.path)&&path.basename(buildx.path)==='docker-buildx'&&buildx.sha256===V2_BUILDX_SHA256;
 return value?.version===2&&value.cohort==='listings-package'&&value.status==='passed'&&value.error===null&&value.modelCalls===0&&value.candidateOnly===true&&value.sourceCopy===false
  &&value.frozenHashesVerified===true&&value.frozenFileCount===Object.keys(source.files).length
  &&sourceValid&&value.unusedResources?.remote==='not-used'&&value.unusedResources?.buildCa==='not-used'
  &&['build','fresh','restart'].every(k=>validProcess(process?.[k]))&&result(value.result)&&result(value.restartResult)
  &&value.result.existingReceipt===false&&value.restartResult.existingReceipt===true&&exactChecks(value.result)&&exactChecks(value.restartResult)
  &&value.result.runtimeDigest===value.restartResult.runtimeDigest&&value.reportedCleanup?.errors?.length===0&&absent.every(k=>value.reportedCleanup[k]===true);
}
function qualifiedPackage({root=path.resolve(__dirname,'../..'),architecture=process.arch}={}){
 if(architecture!=='arm64')throw fail('LISTINGS_INSTALL_PLATFORM_UNQUALIFIED');
 const v=readSourceJson(path.join(root,'scripts/install/manifests/owned-listings-arm64.candidate.json')),source=planner.sourceManifest(root);
 if(Object.keys(v).sort().join(',')!=='architecture,files,qualification,runtimeDigest,sourceManifestSha256,version'||v.version!==1||v.architecture!=='arm64'||v.qualification!==QUALIFICATION||!/^[a-f0-9]{64}$/.test(v.runtimeDigest||'')||v.sourceManifestSha256!==source.sha256||JSON.stringify(v.files)!==JSON.stringify(source.files))throw fail('LISTINGS_PACKAGE_SOURCE_CHANGED');
 const qualification=readSourceJson(path.join(root,QUALIFICATION_REPORT),QUALIFICATION_REPORT_SHA256);
 if(!qualifiedReport(qualification,source,v.runtimeDigest))throw fail('LISTINGS_PACKAGE_QUALIFICATION_INVALID');
 return Object.freeze({architecture:'arm64',runtimeDigest:v.runtimeDigest,qualifiedSourceSha256:v.sourceManifestSha256});
}
// Existing installations retain their qualified executor and immutable journal.
// This finite predecessor admission is never used to build or provision a package.
const INSTALLED_PREDECESSORS=Object.freeze([Object.freeze({
 source:'cc8faa6a5afd6533eebbe5885d112324da5c4ea04a583c4a6607adf0dcf19a2f',
 runtime:'514a0b7cc6d2eadcc515ce7a96af139f7161f3c3989a271d931c068a18812e13',
 report:'scripts/install/qualification/secureshop-listings-runtime-independent-review-2026-09-26.json',
 reportSha256:'269fae83100961c1c6149a2540b10453b9dc4ac30b7fa2772960c1e537ade59c',
}),Object.freeze({
 source:'1f472adb1d26289a1c22d0a427cc63d0dad50b4ed06c930cac978d0fd185ea21',
 runtime:'73868207bb2ebbd5e345a9bb6f0062eb7dca52592e62a1988755d6e7596f0608',
 report:'scripts/install/qualification/secureshop-listings-package-2026-10-10.json',
 reportSha256:'8549e769d30ea468ad83129a6118c77a2672348db0378a97ca1448fb7bea0330',
}),Object.freeze({
 source:'a7d806b6b4a331f989ed7487c8c62352f1a16ffb6de3a35a0e82237461dd6d8b',
 runtime:'08d5f2cba9dc21d9c99899c73960a64997d8f58122e6b2d71f6ff7ea42804102',
 report:'scripts/install/qualification/secureshop-listings-package-2026-10-12.json',
 reportSha256:'2328d6bf0026b497f790cb53f485d8e5fdc1352af550fea46e87bc118c3c9937',
})]);
const installedQualifications=new WeakMap();
function qualifiedInstalledPackage({root=path.resolve(__dirname,'../..'),architecture=process.arch,configuration}={}){
 const managed=require('../../server/services/secureshopListingsManagedConfiguration');
 const value=managed.validate(configuration),current=qualifiedPackage({root,architecture});
 if(value.architecture!==architecture||value.workspaceId!==require('../application-data-root').workspaceId(root))throw fail('LISTINGS_INSTALL_CONFIGURATION_CHANGED');
 let source=planner.sourceManifest(root),qualified=current;
 if(value.sourceManifestSha256!==current.qualifiedSourceSha256||value.runtimeDigest!==current.runtimeDigest){
  const predecessor=INSTALLED_PREDECESSORS.find(entry=>value.sourceManifestSha256===entry.source&&value.runtimeDigest===entry.runtime);
  if(!predecessor)throw fail('LISTINGS_RUNTIME_PACKAGE_CHANGED');
  const report=readSourceJson(path.join(root,predecessor.report),predecessor.reportSha256);
  const files=Object.fromEntries(Object.entries(report.version===2?report.source?.package?.files||{}:report.frozenSourceHashes||{}).sort(([a],[b])=>a.localeCompare(b)));
  const historical=Object.freeze({sha256:sha(JSON.stringify(files)),files:Object.freeze(files)});
  // Only reviewed worker/denial implementations, native proof and additive
  // request actions may differ. A retained manager keeps its qualified action
  // set; an unsupported newer action therefore fails closed on that generation.
  const diagnostics=new Set(['sidecars/sandbox-runner/owned-listings/namespace-executor.js',
   'sidecars/sandbox-runner/owned-listings/namespace-worker.js','tests/fixtures/secureshopOwnedListingsPackaged.native.cjs',
   'server/services/secureshopListingRequestContract.js']);
  if(historical.sha256!==predecessor.source||Object.keys(files).length!==25
   ||Object.keys(source.files).length!==25||Object.keys(files).some(name=>!Object.hasOwn(source.files,name)||!diagnostics.has(name)&&files[name]!==source.files[name])
   ||!qualifiedReport(report,historical,predecessor.runtime))throw fail('LISTINGS_PACKAGE_QUALIFICATION_INVALID');
  source=historical;qualified=Object.freeze({architecture,runtimeDigest:predecessor.runtime,qualifiedSourceSha256:historical.sha256});
 }
 const result=Object.freeze({...qualified});
 installedQualifications.set(result,{configuration:managed.encode(value),source});
 return result;
}
function installedSourceFor(qualification,configuration){
 const retained=installedQualifications.get(qualification);
 if(!retained||retained.configuration!==require('../../server/services/secureshopListingsManagedConfiguration').encode(configuration))throw fail('LISTINGS_INSTALL_CONFIGURATION_CHANGED');
 return retained.source;
}
function profileLocation({authority,root,home,platform}){
 let location;if(platform==='linux')location=localProfilePlan({root,home,platform});
 else if(platform==='darwin'){
  const marker='/.colima/',offset=authority.host.indexOf(marker);if(!authority.host.startsWith('unix:///')||offset<8)throw fail('LISTINGS_PROFILE_AUTHORITY');
  const authorityHome=authority.host.slice(7,offset),prefix=`unix://${path.join(authorityHome,'.colima')}/`,suffix='/docker.sock';
  if(!authority.host.startsWith(prefix)||!authority.host.endsWith(suffix))throw fail('LISTINGS_PROFILE_AUTHORITY');const selected=authority.host.slice(prefix.length,-suffix.length);if(!/^[a-z0-9][a-z0-9-]{0,47}$/.test(selected))throw fail('LISTINGS_PROFILE_AUTHORITY');
  location=localProfilePlan({root,home:authorityHome,platform,colimaProfile:'colima-'+selected});
 }else throw fail('LISTINGS_INSTALL_PLATFORM_UNQUALIFIED');
 if(location.dockerHost!==authority.host)throw fail('LISTINGS_PROFILE_AUTHORITY');return location;
}
// Root helper: serialized per-profile; no overwrite of different files, no
// symlink/FIFO following, no credential inputs, no arbitrary destination.
const PROFILE_PROGRAM=String.raw`import os,sys,base64,stat,subprocess,fcntl,tempfile,hashlib
name=sys.argv[1]; data=base64.b64decode(sys.argv[2],validate=True)
assert name.startswith('owasp-ai-goat-owned-listings-') and len(name)==33 and all(c in '0123456789abcdef' for c in name[-12:])
assert len(data)<65536 and hashlib.sha256(data).hexdigest()==sys.argv[3]
assert os.geteuid()==0
root='/etc/apparmor.d'; dst=root+'/'+name; lock=root+'/.'+name+'.install-lock'
lfd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
try:
 st=os.fstat(lfd); assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600
 fcntl.flock(lfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 def read_existing():
  try: fd=os.open(dst,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  except FileNotFoundError: return False
  try:
   st=os.fstat(fd); named=os.lstat(dst); assert stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and st.st_ino==named.st_ino and st.st_dev==named.st_dev
   assert os.read(fd,65537)==data
  finally: os.close(fd)
  return True
 existing=read_existing()
 loaded=open('/sys/kernel/security/apparmor/profiles').read().splitlines()
 if not existing: assert not any(v.startswith(name+' ') or v.startswith(name+'//') for v in loaded)
 tfd,tmp=tempfile.mkstemp(prefix='.'+name+'-',dir=root)
 try:
  with os.fdopen(tfd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
  subprocess.run(['apparmor_parser','--skip-kernel-load',tmp],check=True,timeout=15)
  if not existing:
   try: os.link(tmp,dst,follow_symlinks=False)
   except FileExistsError: assert read_existing()
 finally: os.unlink(tmp)
 assert read_existing()
 dfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
 try: os.fsync(dfd)
 finally: os.close(dfd)
 subprocess.run(['apparmor_parser','-r',dst],check=True,timeout=15)
 loaded=open('/sys/kernel/security/apparmor/profiles').read().splitlines()
 assert name+' (enforce)' in loaded and name+'//bwrap (enforce)' in loaded
finally: os.close(lfd)
`;
async function provisionProfile({p,authority,root,home,platform,run}){
 const location=profileLocation({authority,root,home,platform});
 if(p.profile.name!=='owasp-ai-goat-owned-listings-'+p.workspaceId||!/^owasp-ai-goat-owned-listings-[a-f0-9]{12}$/.test(p.profile.name))throw fail('LISTINGS_PROFILE_INVALID');
 const bytes=Buffer.from(fs.readFileSync(path.join(root,'sidecars/sandbox-runner/owned-listings/profile.apparmor.in'),'utf8').replaceAll('@@SUPERVISOR_PROFILE@@',p.profile.name));if(sha(bytes)!==p.profile.sha256)throw fail('LISTINGS_PROFILE_SOURCE_CHANGED');
 const args=['python3','-c',PROFILE_PROGRAM,p.profile.name,bytes.toString('base64'),p.profile.sha256],quote=s=>"'"+s.replaceAll("'","'\"'\"'")+"'";
 const result=await run(platform==='linux'?'sudo':'ssh',platform==='linux'?['--non-interactive',...args]:['-F',location.sshConfig,location.sshHost,['sudo','--non-interactive',...args].map(quote).join(' ')],{timeoutMs:40000,maxOutputBytes:65536});
 if(result.exitCode!==0)throw fail('LISTINGS_PROFILE_PROVISION_FAILED');
 return Object.freeze({profile:p.profile.name,sha256:p.profile.sha256});
}
async function prepare(options={}){
 const root=options.root||path.resolve(__dirname,'../..'),home=options.home||os.homedir(),platform=options.platform||process.platform,environment=sanitizeDockerEnvironment(options.environment||process.env);
 const qualified=qualifiedPackage({root,architecture:options.architecture||process.arch}),run=options.run||createRunner({cwd:root,env:environment});
 const execute=async(file,args,o)=>{const result=await run(file,args,{timeoutMs:o.timeout||30000,maxOutputBytes:1048576});if(result.exitCode!==0)throw fail('LISTINGS_INSTALL_COMMAND_FAILED');return result;};
 const p=await planner.plan({...options,root,home,platform,environment,execute,...qualified});
 const authority=await readLocalDockerAuthority({directory:path.dirname(p.managedPath),workspaceId:p.workspaceId,platform});if(!authority||authorityDigest(authority)!==p.dockerAuthoritySha256)throw fail('LISTINGS_INSTALL_AUTHORITY_CHANGED');await verifyDockerAuthority({authority,execute,environment});
 await (options.provisionProfile||provisionProfile)({p,authority,root,home,platform,run});
 if(JSON.stringify(qualifiedPackage({root,architecture:qualified.architecture}))!==JSON.stringify(qualified))throw fail('LISTINGS_PACKAGE_SOURCE_CHANGED');
 return (options.provision||provisioner.provision)({...options,root,home,platform,environment,run,...qualified});
}
module.exports={qualifiedPackage,qualifiedInstalledPackage,installedSourceFor,provisionProfile,prepare,_internals:{profileLocation,PROFILE_PROGRAM,qualifiedReport}};
