#!/usr/bin/env python3
"""Four isolated stores and one owned registry executor; browser only by explicit admission."""
import argparse, urllib.request, base64, errno, hashlib, ipaddress, io, json, os, posixpath, shlex, signal, socket, stat, subprocess, tarfile, tempfile, time, uuid
from pathlib import Path
from owned_mcp_assembly_freeze import inventory,dependencies,digest,verify,record
from admin_browser_current_main_admission import inventory as browser_inventory
from sql_nosql_docker_ownership import verify_daemon,inspect_owned,cleanup_owned
SOURCE=Path(__file__).resolve().parents[2]
NODE=Path('/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA='56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
DOCKER='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker'
HOST='unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
DOCKER_SHA='95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e'
BUILDX='/Users/averma5/.docker/cli-plugins/docker-buildx'
BUILDX_REAL='/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker-buildx'
BUILDX_SHA='591a852237e8ed2b8c65f6be8105ef8c2d1ec52edc77c8acf8f263c2240ef4d6'
BUILDX_PLUGIN_DIR='/Users/averma5/.docker/cli-plugins'
DAEMON_ID='2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
PG_IMAGE='sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
SSH=['/usr/bin/ssh','-F',str(Path.home()/'.colima/_lima/colima-dvaia-pg-verify/ssh.config'),'lima-colima-dvaia-pg-verify']
STARTUP_BOUNDS={'parentSeconds':420,'buildSeconds':300,'startupSeconds':30,'childSeconds':0,'postgresBytes':0,'executorBytes':536870912,'modelCalls':0,'browserCalls':0}
BOUNDS={'parentSeconds':900,'buildSeconds':300,'childSeconds':480,'postgresBytes':1073741824,'executorBytes':536870912,'modelCalls':0,'browserCalls':0}
REGISTRY_RENDERED_FIXTURE='tests/postgres/secureshopOwnedMcpRegistryRendered.native.js'
REGISTRY_RENDERED_SCOPE='standalone-registry-rendered'
REGISTRY_RENDERED_FLAGS=('standaloneAdminRendered','ownedNamespaceRegistration','renderedToolsAndHistory','exactSavedOperationReadback','renderedRemovalHistoryRetained','siblingDenied','cleanupComplete','renderedManifestImportSaved')
REGISTRY_RENDERED_TAP='standalone admin registers, inspects, recovers, and removes an owned MCP server in the rendered UI'
REGISTRY_RENDERED_BOUNDS={**BOUNDS,'parentSeconds':960,'childSeconds':480,'browserCalls':1}
REGISTRY_PACKAGED_FIXTURE='tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs'
REGISTRY_PACKAGED_MANIFEST='scripts/install/manifests/secureshop-owned-mcp-registry-build.json'
REGISTRY_PACKAGED_MANIFEST_SHA256='04168c96e405eb2b3bee5c5b74e1cda9acae7890abf67850a705ea20f9686c40'
REGISTRY_PACKAGED_DIGEST='d9bdfa1f22d8678a455d5bebb1225b1221b9c9a1fb70d31d04c8b19f7e9cfd50'
REGISTRY_PACKAGED_SCOPE='standalone-registry-packaged'
REGISTRY_PACKAGED_CONTROL_FILES=(
 'tests/postgres/run-owned-mcp-assembly-isolated.py',
 'tests/postgres/owned_mcp_assembly_freeze.py',
 'tests/postgres/admin_browser_current_main_admission.py',
 'tests/postgres/sql_nosql_docker_ownership.py',
 'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in',
 REGISTRY_PACKAGED_MANIFEST,
)
REGISTRY_PACKAGED_CASES=(
 'actual isolated namespace readiness',
 'actual SSE tool poisoning discovery',
 'actual metadata tools/list receiving-listener and original SDK response receipt',
 'actual fixed metadata registration denied before connection with joined authenticated worker denial',
 'actual streamable HTTP fixed discovery',
 'actual fixed manifest external entity denial with joined namespace child',
 'actual bounded namespace XXE manifest import',
 'actual submitted stdio shell effect confined to namespace',
 'actual sse SDK discovery, exact schema, file-backed callTool and joined retirement',
 'actual streamable-http SDK discovery, exact schema, file-backed callTool and joined retirement',
 'actual stdio SDK discovery, exact schema, file-backed callTool and joined retirement',
 'immutable assets and all namespace descendants joined',
)
REGISTRY_PACKAGED_BOUNDS={**BOUNDS,'parentSeconds':960,'childSeconds':480,'postgresBytes':0,'modelCalls':0,'browserCalls':0}
V42_NATIVE_FIXTURE='tests/postgres/secureshopOwnedMcpAssembly.native.js'
V42_NATIVE_SHA256='eb040a1b94865c91e0c02402485b7a141d9bf13ac0558e0e9d488e0a978f8b5f'
V42_NATIVE_SCOPE='V42 actual owned discovery PostgreSQL persistence; no model/Judge/browser credit'
V42_NATIVE_LEGACY_FLAGS=('catalogPending','populatedReseed','secondSeed','canonicalReadback','ownerReplay','foreignOwnerDenied','fixedFailedWithoutPublication','resetFenced','siblingPreserved')
V42_NATIVE_FLAGS=('catalogQualified','instructorPreserved',*V42_NATIVE_LEGACY_FLAGS[1:])

def v42_native_receipt(path,qualified=False):
 path=Path(path);before=path.lstat()
 if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size>1048576:raise RuntimeError('Private V42 native receipt required')
 value=json.loads(path.read_text());after=path.lstat()
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise RuntimeError('V42 native receipt changed during read')
 v=value.get('v42')
 current=isinstance(v,dict) and set(v)=={'scope','objective','operationId','discoveryReceipt','catalogAdmission',*V42_NATIVE_FLAGS}
 legacy=isinstance(v,dict) and set(v)=={'scope','objective','operationId','discoveryReceipt',*V42_NATIVE_LEGACY_FLAGS}
 if (value.get('status')!='passed' or type(value.get('modelCalls')) is not int or value['modelCalls']!=0
     or type(value.get('browserCalls')) is not int or value['browserCalls']!=0
     or not (current or legacy) or qualified and not current
     or v.get('scope')!=V42_NATIVE_SCOPE or v.get('objective')!='ss_mcp_registry_internal_discovery'
     or any(v.get(flag) is not True for flag in (V42_NATIVE_FLAGS if current else V42_NATIVE_LEGACY_FLAGS))
     or current and (not isinstance(v.get('catalogAdmission'),dict) or any(type(v['catalogAdmission'].get(k)) is not bool for k in ('fixtureLocalCandidateAdmission','productionDefaultEnabled')))
     or current and v.get('catalogAdmission')!={'objectiveId':'ss_mcp_registry_internal_discovery','fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge','productionDefaultEnabled':False}):
  raise RuntimeError('Exact V42 native persistence receipt required')
 script="""const fs=require('node:fs'),a=require('node:assert/strict'),v=JSON.parse(fs.readFileSync(0,'utf8'));
const request={version:1,action:'register',operationId:v.operationId,expectedVersion:'0',name:'v42-native-metadata',transport:'streamable-http',url:'http://metadata.training/mcp',stdio_cmd:''};
const r=require('./server/services/secureshopMcpRegistryDiscoveryContract').validateDiscoveryReceipt(v.discoveryReceipt,{request,endpoint:request.url,tools:v.discoveryReceipt.toolsListResponse.tools});
a.equal(r.operationId,v.operationId);a.deepEqual(r.destination,{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true});"""
 checked=subprocess.run([str(NODE),'-e',script],cwd=SOURCE,input=json.dumps(v),capture_output=True,text=True,timeout=10)
 if checked.returncode:raise RuntimeError('Original V42 native discovery receipt required')
 return v

V43_FLAG='MCP_IMPERSONATION_V43_NATIVE'
V43_SCOPE='mcp-impersonation-v43-current-main-v1'
V43_NATIVE='tests/postgres/secureshopOwnedMcpRegistryRendered.native.js'
V43_NATIVE_SHA256='928ba3db6722113f96ed2aa4642c8f7d10250ea7db19a2b80970fc172c52bd7e'
V43_HELPER='tests/fixtures/secureshopMcpRegistryExploitQualification.js'
V43_HELPER_SHA256='1ef32480cd12344719a5e2e4ce4883de3cf93fc1fd38ddf8ec01bc5c5beb8c09'
V43_CONTRACT='tests/secureshopMcpRegistryExploitQualification.test.js'
V43_CONTRACT_SHA256='04e94494c564b6b9027e87175109a394e8582266812bb22653429994c0a9aa60'
V43_TRANSPORT='tests/postgres/secureshopMailActualTransport.js'
V43_FLAGS=('passed','isolatedStores','registeredAdminAuthority','distinctTenantPreflight','trustedRegistration','sameNameReplacement','originalSelectedInvocation','canonicalJudgeCredit','physicalAssessmentRead','savedReloadNoEffect','fixedNoInvocationNoCredit','siblingPreserved','sessionDenied','resetFenced','immutablePreserved','wireClosed','fixtureCleaned')
V43_RECEIPT_SCOPE='current-main registered admin MCP impersonation; original trusted registration, same-name replacement, genuine selected invocation and canonical Judge'
V43_BOUNDS={**REGISTRY_RENDERED_BOUNDS,'modelCalls':14}
V43_TAP='standalone admin replaces a trusted MCP server and genuinely invokes its impersonated tool with canonical Judge evidence'
V43_MODEL='llama3.1:8b'
V43_MODEL_SHA256='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
V43_BASE_URL='http://127.0.0.1:11434'
V66_FLAG='MCP_MANIFEST_V66_NATIVE'
V66_SCOPE='mcp-manifest-v66-current-main-v1'
V66_HELPER='tests/fixtures/secureshopMcpManifestQualification.js'
V66_HELPER_SHA256='9fbe406cd7324e2981be78933d6c42fb0d95bbbd47c1b865ca82a5b6ac13843b'
V66_TEST='tests/secureshopMcpManifestQualification.test.js'
V66_TEST_SHA256='17aab61eff04b98d710e98ee2e76ca81a629dbc7923c9be1ac27b16ec68d4bb9'
V66_RECEIPT_SCOPE='current-main admin MCP manifest import: original model preparation, physical confirmation, owned entity bytes, canonical Judge and lifecycle'
V66_PHASES=('fixedWorkerHttp','adminAssistantReady','originalTurn','physicalImport',
 'assessmentOriginalPost','assessmentSavedGet','assessment','sibling','reset')
V66_FLAGS=('isolatedStores','registeredAdminAuthority','fixedWorkerHttpDeniedNoEffect',
 'originalModelSelectedImport','physicalImportConfirmed','escapedEntityBytesVisible',
 'canonicalJudgeCredit','savedAssessmentGetNoEffect','siblingPrivate','sessionDenied',
 'resetRetiresCredit','immutablePreserved','wireClosed','fixtureCleaned','passed')
V66_TAP='standalone admin confirms model-selected owned MCP manifest import with canonical Judge evidence'
V66_BOUNDS={**REGISTRY_RENDERED_BOUNDS,'modelCalls':8}
V42_FLAG='MCP_REGISTRY_SSRF_V42_NATIVE'
V42_SCOPE='mcp-registry-ssrf-v42-current-main-v1'
V42_RECEIPT_SCOPE='current-main admin MCP internal discovery: original model preparation, physical confirmation, owned private listener receipt, canonical Judge and lifecycle'
V42_FLAGS=('isolatedStores','registeredAdminAuthority','fixedWorkerHttpDeniedNoEffect','publicBaselineNoCredit','originalModelSelectedRegistration','physicalRegistrationConfirmed','metadataDiscoveryReceived','canonicalJudgeCredit','savedAssessmentGetNoEffect','savedReloadNoEffect','publicProgress','fixedModelPrepared','fixedPhysicalDenialNoHttp','siblingPrivate','sessionDenied','resetRetiresCredit','immutablePreserved','wireClosed','fixtureCleaned','passed')
V42_TAP='standalone admin confirms model-selected owned internal MCP discovery with canonical Judge evidence and fixed isolation'
V42_BOUNDS={**REGISTRY_RENDERED_BOUNDS,'modelCalls':5}
V39_FLAG='MCP_DESCRIPTION_V39_NATIVE'
V39_SCOPE='mcp-description-v39-current-main-v1'
V39_HELPER='tests/fixtures/secureshopMcpDescriptionRenderedQualification.js'
V39_TEST='tests/secureshopMcpDescriptionRenderedQualification.test.js'
V39_RECEIPT_SCOPE='current-main registered admin MCP description adoption; distinct benign and attacker tools, complete original offered schemas, genuine selected invocation and final deviation, canonical Judge, fixed and lifecycle fences'
V39_FLAGS=('passed','isolatedStores','registeredAdminAuthority','fixtureLocalCandidateAdmission',
 'canonicalObjectiveEnabled','physicalDistinctRegistrations','completeOfferedManifest',
 'originalSelectedInvocation','originalFinalAdoption','canonicalJudgeCredit','physicalAssessment',
 'savedReadNoRepeat','fixedDeniedNoEffect','siblingDenied','sessionDenied','resetFenced',
 'immutablePreserved','wireClosed','fixtureCleaned')
V39_TAP='standalone admin adopts a registered tool description after original competing catalog and canonical Judge evidence'
V39_BOUNDS={**REGISTRY_RENDERED_BOUNDS,'modelCalls':14}
V39_NATIVE_SHA256='928ba3db6722113f96ed2aa4642c8f7d10250ea7db19a2b80970fc172c52bd7e'
V39_HELPER_SHA256='3decaeae4c194d5c6b4eb004e50468dd6085d9bff3d11314c15b8cf028916dff'
V39_TEST_SHA256='95d338d9c3f287af36766ecbbe6a2184c8d923a1e634191650869d30eadc5c66'


# Only the new nonce profile is admitted. The parent proves all containers using
# it absent before cleanup; the root helper proves the exact file before unload.
RENDERED_PROFILE_PROGRAM=r'''
import os,sys,stat,re,base64,subprocess
action,name,encoded=sys.argv[1:]
assert action in ('install','remove') and re.fullmatch(r'dvaia-owned-mcp-registry-[a-f0-9]{12}',name)
assert os.geteuid()==0
data=base64.b64decode(encoded,validate=True);assert 0<len(data)<=16384
assert ('profile "'+name+'"').encode() in data and b'@@SUPERVISOR_PROFILE@@' not in data
path='/etc/apparmor.d/'+name
def loaded():
 return [x for x in open('/sys/kernel/security/apparmor/profiles').read().splitlines() if x.startswith(name+' ') or x.startswith(name+'//')]
def syncdir():
 fd=os.open('/etc/apparmor.d',os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
if action=='install':
 assert not loaded() and not os.path.lexists(path)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb',closefd=False) as f:f.write(data);f.flush();os.fsync(fd)
 finally:os.close(fd)
 syncdir()
if not os.path.lexists(path):
 assert action=='remove' and not loaded();sys.exit(0)
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_size==len(data)
 assert os.read(fd,len(data)+1)==data
 current=os.lstat(path);assert (current.st_dev,current.st_ino)==(before.st_dev,before.st_ino)
 if action=='install':
  subprocess.run(['apparmor_parser','--skip-kernel-load',path],check=True,timeout=15)
  subprocess.run(['apparmor_parser','-r',path],check=True,timeout=15)
  assert set(loaded())=={name+' (enforce)',name+'//bwrap (enforce)'}
 else:
  rows=loaded();assert set(rows)<={name+' (enforce)',name+'//bwrap (enforce)'}
  if rows:subprocess.run(['apparmor_parser','-R',path],check=True,timeout=15)
  assert not loaded()
  current=os.lstat(path);assert (current.st_dev,current.st_ino,current.st_nlink)==(before.st_dev,before.st_ino,1)
  os.unlink(path);syncdir()
finally:os.close(fd)
'''

def rendered_layout(row,kind,network,profile):
 host=row.get('HostConfig',{})
 if row.get('Mounts')!=[] or host.get('Privileged') is not False or host.get('PidsLimit')!=128:raise RuntimeError('Rendered owned resource layout mismatch')
 if kind=='executor':
  if (row.get('Config',{}).get('User')!='10001:10001' or host.get('ReadonlyRootfs') is not True
      or host.get('Memory')!=536870912 or host.get('NanoCpus')!=1000000000
      or host.get('Tmpfs')!={'/tmp':'rw,nosuid,nodev,noexec,size=16m'} or host.get('NetworkMode')!=network
      or host.get('CapDrop')!=['ALL'] or host.get('CapAdd') not in (None,[])
      or set(host.get('SecurityOpt') or [])!={'apparmor='+profile,'seccomp=unconfined'}
      or host.get('PortBindings')!={'8094/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}
      or (row.get('State',{}).get('Running') is True and row.get('AppArmorProfile')!=profile)):raise RuntimeError('Rendered executor isolation mismatch')
 elif kind=='postgres':
  if (host.get('Memory')!=1073741824 or host.get('NanoCpus')!=2000000000
      or host.get('Tmpfs')!={'/var/lib/postgresql':'rw,size=268435456'}
      or host.get('PortBindings')!={'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]}):raise RuntimeError('Rendered PostgreSQL isolation mismatch')
 else:raise ValueError('Closed rendered resource kind required')

def no_profile_containers(command,profile):
 verify_daemon(command,DAEMON_ID)
 response=command(['ps','-aq','--no-trunc'])
 if response.returncode:raise RuntimeError('Profile container absence unavailable')
 for identifier in response.stdout.split():
  if len(identifier)!=64 or any(c not in '0123456789abcdef' for c in identifier):raise RuntimeError('Container identity invalid')
  response=command(['inspect','--type','container',identifier])
  if response.returncode:raise RuntimeError('Profile container inspection failed')
  rows=json.loads(response.stdout)
  if not isinstance(rows,list) or len(rows)!=1 or rows[0].get('Id')!=identifier:raise RuntimeError('Profile container identity mismatch')
  row=rows[0]
  if row.get('AppArmorProfile')==profile or 'apparmor='+profile in (row.get('HostConfig',{}).get('SecurityOpt') or []):raise RuntimeError('Profile remains attached to a container')
 return True

def rendered_inventory(root,browser_root,impersonation_v43=False,manifest_v66=False,description_v39=False,discovery_v42=False):
 root=Path(root);files={}
 for name in [REGISTRY_RENDERED_FIXTURE,'tests/postgres/admin_browser_current_main_admission.py',
              'client/package.json','client/package-lock.json','client/index.html','client/vite.config.mjs']:
  files[name]=record(root/name)
 if impersonation_v43:
  files[V43_HELPER]=record(root/V43_HELPER)
  files[V43_CONTRACT]=record(root/V43_CONTRACT)
  files[V43_TRANSPORT]=record(root/V43_TRANSPORT)
 if manifest_v66 or discovery_v42:
  for name in (V66_HELPER,V66_TEST,V43_HELPER,V43_CONTRACT,V43_TRANSPORT):files[name]=record(root/name)
 if description_v39:
  for name in (V39_HELPER,V39_TEST,V43_HELPER,V43_CONTRACT,V43_TRANSPORT):files[name]=record(root/name)
 for directory in ('client/src','client/build'):
  for path in sorted((root/directory).rglob('*')):
   if path.is_symlink():raise RuntimeError('Rendered source symlink denied')
   if path.is_file():files[path.relative_to(root).as_posix()]=record(path)
 for required in ('client/build/index.html','client/build/secureshop-frame.html'):
  if required not in files:raise RuntimeError('Current built standalone application required')
 return {'files':files,'clientDependencies':dependencies(root/'client'),'browser':browser_inventory(Path(browser_root))}

def packaged_authority(root):
 root=Path(root);path=root/REGISTRY_PACKAGED_MANIFEST
 metadata=os.lstat(path)
 if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:raise RuntimeError('Packaged manifest must be a regular file')
 if sha(path)!=REGISTRY_PACKAGED_MANIFEST_SHA256:raise RuntimeError('Frozen packaged manifest pin required')
 value=json.loads(path.read_text())
 if (not isinstance(value,dict) or set(value)!={'files','scope','platform','version','dockerfile'}
     or value.get('scope')!='20 explicit packaged build inputs; streamed memory archive; no source clone; no application private data'
     or value.get('platform')!='linux/arm64' or value.get('version')!=1
     or value.get('dockerfile')!='sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate'):
  raise RuntimeError('Exact packaged authority manifest required')
 files=value.get('files')
 if not isinstance(files,dict) or len(files)!=20 or set(files)==set():raise RuntimeError('Exact packaged manifest inputs required')
 rows={}
 total=0
 for name,expected in files.items():
  if (not isinstance(name,str) or not name or name.startswith('/') or name!=posixpath.normpath(name)
      or name.startswith('../') or '/..' in name.split('/') or not isinstance(expected,str)
      or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected)):
   raise RuntimeError('Canonical packaged manifest path or digest required')
  candidate=root/name;metadata=os.lstat(candidate)
  if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1:
   raise RuntimeError('Packaged manifest input must be an unlinked regular file')
  if metadata.st_size>2*1024*1024 or total+metadata.st_size>8*1024*1024:
   raise RuntimeError('Packaged manifest input size bound exceeded')
  actual=sha(candidate)
  if actual!=expected:raise RuntimeError('Packaged manifest input digest mismatch: '+name)
  total+=metadata.st_size;rows[name]={'kind':'file','bytes':metadata.st_size,'sha256':actual}
 digest_value=hashlib.sha256(json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
 if digest_value!=REGISTRY_PACKAGED_DIGEST:raise RuntimeError('Packaged authority digest mismatch')
 return value,rows

def packaged_control_pins(root):
 root=Path(root);pins={}
 for name in REGISTRY_PACKAGED_CONTROL_FILES:
  path=root/name
  if root.is_symlink() or any((root.joinpath(*Path(name).parts[:i])).is_symlink() for i in range(1,len(Path(name).parts)+1)):
   raise RuntimeError('Packaged control path contains a symlink: '+name)
  metadata=os.lstat(path)
  if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>1024*1024:
   raise RuntimeError('Packaged control requires a bounded regular file: '+name)
  pins[name]=sha(path)
 return pins

def packaged_receipt(path):
 path=Path(path);before=path.lstat()
 if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600
     or before.st_nlink!=1 or before.st_size>8192):raise RuntimeError('Private packaged registry receipt required')
 raw=path.read_bytes();after=path.lstat()
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise RuntimeError('Packaged receipt changed during read')
 value=json.loads(raw)
 expected={'status','modelCalls','runtimeDigest','cases','discoveryReceipt','fixedDestinationDenial'}
 if (not isinstance(value,dict) or set(value)!=expected or value.get('status')!='passed'
     or type(value.get('modelCalls')) is not int
     or value.get('modelCalls')!=0 or not isinstance(value.get('runtimeDigest'),str)
     or len(value['runtimeDigest'])!=64 or any(c not in '0123456789abcdef' for c in value['runtimeDigest'])
     or value.get('cases')!=list(REGISTRY_PACKAGED_CASES)):
  raise RuntimeError('Exact packaged registry qualification required')
 # Reuse the exact worker/application contract for both original receipts.
 # This validates retained data only and allocates no network or database.
 script="""const fs=require('node:fs'),a=require('node:assert/strict');
const v=JSON.parse(fs.readFileSync(0,'utf8')),c=require('./server/services/secureshopMcpRegistryDiscoveryContract');
const request=(name,operationId)=>({version:1,action:'register',operationId,expectedVersion:'0',name,transport:'streamable-http',url:'http://169.254.169.254/mcp',stdio_cmd:''});
const r=c.validateDiscoveryReceipt(v.discoveryReceipt,{request:request('metadata-probe',v.discoveryReceipt.operationId),tools:v.discoveryReceipt.toolsListResponse.tools,endpoint:'http://169.254.169.254/mcp'});
a.deepEqual(r.destination,{listenerId:'metadata',address:'169.254.169.254',port:80,sensitive:true});
a.equal(r.toolsListResponse.tools.length,1);a.equal(r.toolsListResponse.tools[0].name,'metadata-catalog');
c.validateDiscoveryDenial(v.fixedDestinationDenial,{request:request('fixed-metadata',v.fixedDestinationDenial.operationId),mode:'fixed'});"""
 checked=subprocess.run([str(NODE),'-e',script],cwd=SOURCE,input=json.dumps(value),capture_output=True,text=True,timeout=10)
 if checked.returncode:raise RuntimeError('Exact packaged discovery receipt and fixed denial required')
 return value

def packaged_log_receipt(path):
 path=Path(path)
 if path.stat().st_size>8192:raise RuntimeError('Packaged fixture output exceeds receipt bound')
 lines=[line for line in path.read_text().splitlines() if line.strip()]
 if len(lines)!=1:raise RuntimeError('Packaged fixture must emit one bounded receipt')
 candidate=path.with_name('packaged-result.json');candidate.write_text(lines[0]+'\n');candidate.chmod(0o600)
 return packaged_receipt(candidate)

def validate_rendered_args(args):
 values=(args.browser,args.browser_sha256,args.browser_root,args.rendered_source_sha256)
 if not args.registry_rendered:
  if any(values):raise ValueError('Browser admission requires registry-rendered')
  return
 if not args.main_workspace or args.startup_only or args.invocation_journal:raise ValueError('Registry rendered requires exclusive current-main four-store mode')
 if not all(values):raise ValueError('Pinned browser and rendered source required')
 browser,root=Path(args.browser),Path(args.browser_root)
 if (not browser.is_absolute() or browser.is_symlink() or browser.resolve()!=browser or not browser.is_file() or not os.access(browser,os.X_OK)
     or not root.is_absolute() or root.is_symlink() or root.resolve()!=root or not root.is_dir()
     or not browser.is_relative_to(root) or sha(browser)!=args.browser_sha256
     or len(args.rendered_source_sha256)!=64 or any(c not in '0123456789abcdef' for c in args.rendered_source_sha256)):
  raise ValueError('Exact rendered source/browser admission required')

def validate_packaged_args(args):
 if not args.registry_packaged:return
 if (not args.main_workspace or args.registry_rendered or args.startup_only or args.invocation_journal
     or args.mcp_impersonation_v43 or args.mcp_manifest_v66 or args.mcp_description_v39 or args.mcp_registry_ssrf_v42 or any((args.browser,args.browser_sha256,args.browser_root,args.rendered_source_sha256,
                                          args.source_sha256,args.dependency_sha256))):
  raise ValueError('Registry packaged requires exclusive current-main no-browser mode')
 if (args.packaged_manifest_sha256 and args.packaged_manifest_sha256!=REGISTRY_PACKAGED_MANIFEST_SHA256
     or args.run and args.packaged_manifest_sha256!=REGISTRY_PACKAGED_MANIFEST_SHA256):
  raise ValueError('Frozen packaged manifest admission required')

def rendered_receipt(path,impersonation_v43=False,manifest_v66=False,description_v39=False,discovery_v42=False):
 path=Path(path);st=path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_nlink!=1 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>8192:raise RuntimeError('Private rendered registry receipt required')
 value=json.loads(path.read_text());after=path.lstat()
 if (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):raise RuntimeError('Rendered receipt changed during read')
 if discovery_v42:
  expected=set(REGISTRY_RENDERED_FLAGS)|{'status','scope','modelCalls','browserCalls','cleanupErrors','actorCalls','judgeCalls','discoveryQualification'}
  if (impersonation_v43 or manifest_v66 or description_v39 or not isinstance(value,dict) or set(value)!=expected
      or value.get('status')!='passed' or value.get('scope')!='V42-standalone' or value.get('cleanupErrors')!=[]
      or value.get('cleanupComplete') is not True or value.get('discoveryQualification') is not True
      or any(type(value.get(k)) is not int or value[k]!=n for k,n in [('actorCalls',4),('judgeCalls',1),('modelCalls',5),('browserCalls',1)])
      or any(value.get(flag) is not False for flag in REGISTRY_RENDERED_FLAGS if flag!='cleanupComplete')):
   raise RuntimeError('Exact V42 outer status required; legacy flags are not discovery evidence')
  return value
 if description_v39:
  if impersonation_v43 or manifest_v66:raise RuntimeError('V39 rendered cohort is exclusive')
  expected=set(REGISTRY_RENDERED_FLAGS)|{'status','scope','modelCalls','browserCalls','cleanupErrors',
                                          'actorCalls','judgeCalls','descriptionQualification'}
  if (not isinstance(value,dict) or set(value)!=expected or value.get('status')!='passed'
      or value.get('scope')!='V39-standalone' or value.get('cleanupComplete') is not True
      or value.get('cleanupErrors')!=[] or value.get('descriptionQualification') is not True
      or type(value.get('browserCalls')) is not int or value['browserCalls']!=1
      or type(value.get('actorCalls')) is not int or not 7<=value['actorCalls']<=13
      or type(value.get('judgeCalls')) is not int or not 1<=value['judgeCalls']<=4
      or type(value.get('modelCalls')) is not int
      or value['modelCalls']!=value['actorCalls']+value['judgeCalls'] or value['modelCalls']>14
      or any(value.get(flag) is not False for flag in REGISTRY_RENDERED_FLAGS if flag!='cleanupComplete')):
   raise RuntimeError('Exact V39 outer status required; legacy flags are not V39 evidence')
  return value
 if manifest_v66:
  if impersonation_v43:raise RuntimeError('V66 and V43 receipts are exclusive')
  expected=set(REGISTRY_RENDERED_FLAGS)|{'status','scope','modelCalls','browserCalls','cleanupErrors',
                                         'actorCalls','judgeCalls','manifestQualification'}
  if (not isinstance(value,dict) or set(value)!=expected or value.get('status')!='passed'
      or value.get('scope')!='V66-standalone' or value.get('cleanupComplete') is not True
      or value.get('cleanupErrors')!=[] or value.get('manifestQualification') is not True
      or type(value.get('browserCalls')) is not int or value['browserCalls']!=1
      or type(value.get('actorCalls')) is not int or not 2<=value['actorCalls']<=6
      or type(value.get('judgeCalls')) is not int or not 1<=value['judgeCalls']<=2
      or type(value.get('modelCalls')) is not int
      or value['modelCalls']!=value['actorCalls']+value['judgeCalls'] or value['modelCalls']>8
      or any(value.get(flag) is not False for flag in REGISTRY_RENDERED_FLAGS if flag!='cleanupComplete')):
   raise RuntimeError('Exact V66 outer status required; legacy flags are not V66 evidence')
  return value
 if impersonation_v43:
  expected=set(REGISTRY_RENDERED_FLAGS)|{'status','scope','modelCalls','browserCalls','cleanupErrors',
                                        'actualModelEvidence','registeredJudgeCredit','actorCalls','judgeCalls'}
  if (not isinstance(value,dict) or set(value)!=expected or value.get('status')!='passed' or value.get('scope')!='V43-standalone'
      or value.get('cleanupComplete') is not True or value.get('cleanupErrors')!=[]
      or value.get('actualModelEvidence') is not True or value.get('registeredJudgeCredit') is not True
      or type(value.get('browserCalls')) is not int or value['browserCalls']!=1
      or type(value.get('actorCalls')) is not int or not 7<=value['actorCalls']<=13
      or type(value.get('judgeCalls')) is not int or not 1<=value['judgeCalls']<=4
      or type(value.get('modelCalls')) is not int or value['modelCalls']!=value['actorCalls']+value['judgeCalls']
      or value['modelCalls']>14
      or any(value.get(flag) is not False for flag in REGISTRY_RENDERED_FLAGS if flag!='cleanupComplete')):
   raise RuntimeError('Exact V43 outer status required; legacy flags are not V43 evidence')
  return value
 expected_scope=REGISTRY_RENDERED_SCOPE
 expected_flags=REGISTRY_RENDERED_FLAGS
 if (not REGISTRY_RENDERED_FLAGS or set(value)!=set(expected_flags)|{'status','scope','modelCalls','browserCalls','cleanupErrors'}
     or value['status']!='passed' or value['scope'] != expected_scope or type(value['modelCalls']) is not int
     or type(value['browserCalls']) is not int or value['browserCalls']!=1 or value['cleanupErrors']!=[]
     or value['scope'] != expected_scope
     or (not impersonation_v43 and value['modelCalls'] != 0)
     or (impersonation_v43 and not 1 <= value['modelCalls'] <= 14)
     or any(value[k] is not True for k in expected_flags)):
  raise RuntimeError('Exact rendered registry qualification required')
 return value

def rendered_tap(text,impersonation_v43=False,manifest_v66=False,description_v39=False,discovery_v42=False):
 import re
 names=re.findall(r'^ok \d+ - (.+)$',text,re.M)
 if sum((impersonation_v43,manifest_v66,description_v39,discovery_v42))>1:raise RuntimeError('Rendered cohorts are exclusive')
 if names!=[V42_TAP if discovery_v42 else V39_TAP if description_v39 else V66_TAP if manifest_v66 else V43_TAP if impersonation_v43 else REGISTRY_RENDERED_TAP] or re.search(r'^(?:not ok |# (?:fail|cancelled|skipped) [1-9])',text,re.M):raise RuntimeError('Exact rendered registry TAP required')
 return True

def native_child_argv(registry_rendered=False,invocation_journal=False,impersonation_v43=False,registry_packaged=False):
 if registry_packaged:
  if registry_rendered or invocation_journal or impersonation_v43:raise ValueError('Packaged registry cohort is exclusive')
  return [str(NODE),REGISTRY_PACKAGED_FIXTURE]
 if impersonation_v43 and not registry_rendered:raise ValueError('V43 requires registry-rendered')
 if registry_rendered and invocation_journal:raise ValueError('Exclusive native cohort required')
 if registry_rendered:return [str(NODE),'--test-reporter=tap',REGISTRY_RENDERED_FIXTURE]
 return [str(NODE),'tests/postgres/secureshopOwnedMcpInvocationJournal.native.js' if invocation_journal else 'tests/postgres/secureshopOwnedMcpAssembly.native.js']

def rendered_browser_absent(root):
 root=Path(root)
 profiles=[p for pattern in ('dvaia-mcp-registry-rendered-*','dvaia-registry-browser-*','ss-review-browser-*','puppeteer_dev_chrome_profile-*') for p in root.glob(pattern)]
 response=subprocess.run(['/bin/ps','-axo','command='],check=True,capture_output=True,text=True,timeout=5)
 import re
 argument=re.compile(r'--user-data-dir=["\']?'+re.escape(str(root))+'/')
 if profiles or any(argument.search(row) for row in response.stdout.splitlines()):raise RuntimeError('Owned registry browser remains')
 return True

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def remaining(deadline,cap):
 if deadline is None:return cap
 value=deadline-time.monotonic()
 if value<=0:raise TimeoutError('Owned process cleanup deadline')
 return min(cap,value)
def group_members(pgid,deadline=None):
 rows=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],check=True,capture_output=True,text=True,timeout=remaining(deadline,5)).stdout.splitlines();members=[]
 for row in rows:
  pid,group,uid=map(int,row.split())
  if group==pgid:
   if uid!=os.getuid():raise RuntimeError('foreign owner in owned process group')
   members.append(pid)
 return members

def stop_process(child,deadline=None):
 if child is None:return
 pgid=child.pid
 members=group_members(pgid,deadline)
 if members:
  try:os.killpg(pgid,signal.SIGTERM)
  except OSError:
   if group_members(pgid,deadline):raise
 until=time.monotonic()+remaining(deadline,5)
 while group_members(pgid,deadline) and time.monotonic()<until:child.poll();time.sleep(remaining(deadline,.05))
 if group_members(pgid,deadline):
  try:os.killpg(pgid,signal.SIGKILL)
  except OSError:
   if group_members(pgid,deadline):raise
 try:child.wait(timeout=remaining(deadline,5))
 except ChildProcessError:pass
 if group_members(pgid,deadline):raise RuntimeError('owned process group remains')

def inspect_resource(command,kind,name):
 if kind not in ('network','image'):raise ValueError('closed resource kind required')
 response=command([kind,'inspect',name])
 if response.returncode:
  missing={f'Error: No such {kind}: {name}',f'Error response from daemon: No such {kind}: {name}'}
  if kind=='network':missing.add(f'Error response from daemon: network {name} not found')
  if response.stderr.strip() in missing:return None
  raise RuntimeError(kind+' inspection failed; absence unverified')
 try:
  rows=json.loads(response.stdout)
  if not isinstance(rows,list) or len(rows)!=1 or not isinstance(rows[0],dict):raise ValueError()
  return rows[0]
 except (ValueError,TypeError):raise RuntimeError('Invalid resource inspect response') from None

def database_plan(nonce,journal=False,impersonation_v43=False):
 if len(nonce)!=12 or any(c not in '0123456789abcdef' for c in nonce):raise ValueError('closed nonce required')
 rows=[{'label':label,'schema':schema,'database':f'dvaia_test_mcp_assembly_{nonce}_{label.lower()}','migration':'dvaia_'+schema+'_migration','runtime':'dvaia_'+schema+'_runtime'} for label,schema in [('IDENTITY','identity'),('COMMERCE','secureshop'),('AGENTS','secureshop_agents'),('REVIEW','secureshop_review')]]
 if impersonation_v43:
  if journal:raise ValueError('V43 cannot use invocation-journal stores')
  for row in rows:row['database']=f"dvaia_test_agent_host_{nonce}_{row['schema']}"
 if journal:rows.append({'label':'AGENTS_FRESH','schema':'secureshop_agents','database':f'dvaia_test_mcp_assembly_{nonce}_agents_fresh','migration':'dvaia_secureshop_agents_migration','runtime':'dvaia_secureshop_agents_runtime'})
 return rows

def startup_diagnostics(command,name,token,extra_secrets=(),service_port=8094):
 if service_port not in (8094,8095) or any(not isinstance(value,str) for value in extra_secrets):raise ValueError("Closed diagnostic inputs required")
 # Never request Config (in particular Config.Env). Only startup state and port maps.
 queries={
  'state':['inspect','--format','{{json .State}}',name],
  'ports':['inspect','--format','{{json .NetworkSettings.Ports}}',name],
  'portLookup':['port',name,str(service_port)+'/tcp'],
  'listenerLogs':['logs','--tail','32',name]}
 result={}
 def safe(value):
  text=str(value or '')
  for secret in (token,*extra_secrets):
   if secret:text=text.replace(secret,'[REDACTED]')
  return text[:4096]
 for key,argv in queries.items():
  try:
   response=command(argv);result[key]={'returncode':response.returncode,'stdout':safe(response.stdout),'stderr':safe(response.stderr)}
  except Exception as error:result[key]={'errorType':type(error).__name__}
 return result

def validate_startup_health(value,runtime_digest):
 expected={'version':1,'ready':True,'isolation':'owned-mcp-registry-v1','registryCapability':'secureshop-owned-mcp-registry.v1','runtimeDigest':runtime_digest}
 if value!=expected:raise RuntimeError('exact executor startup health mismatch')
 return expected

def validate_internal_endpoint(container,network,name,owner,container_id,binding_mode="discovery"):
 if binding_mode not in ("discovery","invocation"):raise ValueError("Closed endpoint mode required")
 if container.get('Id')!=container_id or network.get('Name')!=name or network.get('Driver')!='bridge' or network.get('Internal') is not True or network.get('Labels',{}).get('dvaia.owner')!=owner:raise RuntimeError('owned internal network identity mismatch')
 networks=container.get('NetworkSettings',{}).get('Networks',{})
 if set(networks)!={name}:raise RuntimeError('executor must have exactly one owned internal network')
 endpoint=networks[name]
 if endpoint.get('NetworkID')!=network.get('Id'):raise RuntimeError('network ID mismatch')
 address=ipaddress.ip_address(endpoint.get('IPAddress',''))
 if address.version!=4 or not address.is_private or address.is_loopback or address.is_link_local:raise RuntimeError('private owned IPv4 required')
 members=network.get('Containers',{})
 if set(members)!={container_id} or ipaddress.ip_interface(members[container_id]['IPv4Address']).ip!=address:raise RuntimeError('owned endpoint membership mismatch')
 if not any(address in ipaddress.ip_network(row['Subnet']) for row in network.get('IPAM',{}).get('Config',[]) if ':' not in row.get('Subnet','')):raise RuntimeError('endpoint outside owned subnet')
 bindings=container.get('HostConfig',{}).get('PortBindings',{})
 if bindings!=({'8094/tcp':[{'HostIp':'127.0.0.1','HostPort':''}]} if binding_mode=='discovery' else {}):raise RuntimeError('unexpected requested port binding')
 return str(address)

def tunnel_argv(address,port,remote_port=8094):
 if type(remote_port) is not int or remote_port not in (8094,8095):raise ValueError("Closed tunnel service required")
 value=ipaddress.ip_address(address)
 if value.version!=4 or not value.is_private or value.is_loopback or not isinstance(port,int) or isinstance(port,bool) or not 1024<=port<=65535:raise ValueError('closed tunnel endpoint required')
 return SSH[:-1]+['-o','ControlMaster=no','-o','ControlPath=none','-o','ExitOnForwardFailure=yes','-o','GatewayPorts=no','-o','BatchMode=yes','-o','ConnectTimeout=5','-N','-T','-L',f'127.0.0.1:{port}:{address}:{remote_port}',SSH[-1]]

def startup_timeout(deadline,cap=5,clock=time.monotonic):
 remaining=deadline-clock()
 if remaining<=0:raise TimeoutError('executor startup deadline')
 return min(cap,remaining)

def verify_tunnel_closed(port,pgid,command,members=group_members,connect=socket.create_connection):
 if members(pgid):raise RuntimeError('owned tunnel process group remains')
 result=command(['/usr/sbin/lsof','-nP','-iTCP:'+str(port),'-sTCP:LISTEN'])
 if result.returncode!=1 or result.stdout.strip() or result.stderr.strip():raise RuntimeError('tunnel listener absence unverified')
 try:
  connection=connect(('127.0.0.1',port),timeout=.5)
 except OSError as error:
  if error.errno!=errno.ECONNREFUSED:raise RuntimeError('tunnel connection refusal unverified') from None
 else:
  connection.close();raise RuntimeError('tunnel port still accepts connections')
 return {'processGroupAbsent':True,'listenerAbsent':True,'connectionRefused':True}

def stream_main_build_context(build,root,reviewed,files_override=None):
 """Send only Dockerfile.candidate COPY inputs; never expose the checkout as context."""
 root=Path(root)
 registry=('Dockerfile.candidate','Dockerfile.invocation','Dockerfile.procless-feasibility','buildAssets.js','executor.js','http-handler.js','http-listener.js','invocation-attestation-controls.c','invocation-attestation-protocol.h','invocation-attestation.h','invocation-bootstrap.c','invocation-build-assets.js','invocation-channel-codec.js','invocation-listener.js','invocation-manager.js','invocation-peer.c','invocation-private-diagnostic.h','invocation-private-lease.js','invocation-provision.js','invocation-qualification-schedule.h','invocation-supervisor.c','invocation-worker.js','invoke-protocol.js','network-manifest.json','package-lock.json','package.json','process-supervisor.c','procless-feasibility.c','procless-peer-contract.h','profile.apparmor.in','worker.js')
 files=list(files_override) if files_override is not None else [*(('sidecars/sandbox-runner/owned-mcp-registry/'+name) for name in registry),'sidecars/sandbox-runner/owned-http/namespace-init.c','sidecars/sandbox-runner/mcpSeccompFilter.c','server/services/secureshopMcpRegistryContract.js','server/services/secureshopMcpRegistryDiscoveryContract.js','server/services/secureshopMcpRegistryDiscovery.js','server/services/secureshopMcpSchemaDigest.js','server/services/secureshopOwnedMcpInvocationContract.js','server/services/secureshopConversationBinding.js','tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs']
 total=0;max_bytes=16*1024*1024
 seen=set()
 with tarfile.open(fileobj=build.stdin,mode='w|') as archive:
   for name in files:
    if not isinstance(name,str) or not name or name.startswith('/') or name!=posixpath.normpath(name) or name.startswith('../') or '/..' in name.split('/') or name in seen:raise RuntimeError('main build context path is not canonical and unique: '+str(name))
    seen.add(name)
    path=root/name
    if path.is_symlink() or not path.is_file():raise RuntimeError('main build context requires regular files only: '+str(path))
    cursor=root
    if cursor.is_symlink():raise RuntimeError('main build context root is symlink')
    for component in path.relative_to(root).parts:
     cursor=cursor/component;metadata=os.lstat(cursor)
     if stat.S_ISLNK(metadata.st_mode):raise RuntimeError('main build context symlink component: '+str(cursor))
    if not stat.S_ISREG(os.lstat(path).st_mode):raise RuntimeError('main build context requires regular files only: '+str(path))
    before=os.stat(path)
    expected=reviewed.get(path.relative_to(root).as_posix(),{}).get('sha256')
    remaining=max_bytes-total
    if not expected:raise RuntimeError('main build context reviewed pin missing: '+str(path))
    if before.st_size>remaining:raise RuntimeError('main build context size bound exceeded: '+str(path))
    with path.open('rb') as source:data=source.read(remaining+1)
    total+=len(data)
    if len(data)!=before.st_size or hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('main build context reviewed pin mismatch: '+str(path))
    info=tarfile.TarInfo(path.relative_to(root).as_posix());info.size=len(data);info.mode=0o444;info.mtime=0
    archive.addfile(info,io.BytesIO(data))
    after=os.stat(path)
    if (before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise RuntimeError('main build context changed while streaming: '+str(path))
 build.stdin.close()

def write_private_docker_config(root):
 root=Path(root);config=root/'docker-config';config.mkdir(mode=0o700);path=config/'config.json';path.write_text(json.dumps({'cliPluginsExtraDirs':[BUILDX_PLUGIN_DIR]})+'\n');path.chmod(0o600);return config

def v43_environment():
 return {V43_FLAG:'1','LIVE_OLLAMA_TEST':'1','AI_PROVIDER':'ollama',
         'OLLAMA_BASE_URL':V43_BASE_URL,'OLLAMA_MODEL':V43_MODEL,
         'JUDGE_PROVIDER':'ollama','JUDGE_MODEL':V43_MODEL,
         'SS_DISABLE_OLLAMA':'false','SS_ENABLE_REAL_LLM_TESTS':'true'}

def v66_environment():
 return {**{name:value for name,value in v43_environment().items() if name!=V43_FLAG},V66_FLAG:'1'}

def v42_environment():
 return {**{name:value for name,value in v43_environment().items() if name!=V43_FLAG},V42_FLAG:'1'}

def v39_environment():
 return {**{name:value for name,value in v43_environment().items() if name!=V43_FLAG},V39_FLAG:'1'}

def v39_result_environment(root):
 return {'MCP_DESCRIPTION_V39_RESULT':str(Path(root)/'candidate-result.json')}

def verify_v43_sources(source):
 for name,expected in ((V43_NATIVE,V43_NATIVE_SHA256),(V43_HELPER,V43_HELPER_SHA256),(V43_CONTRACT,V43_CONTRACT_SHA256)):
  if sha(Path(source)/name)!=expected:raise RuntimeError('Frozen V43 source pins required')

def verify_v66_sources(source):
 for name,expected in ((V43_NATIVE,V43_NATIVE_SHA256),(V43_HELPER,V43_HELPER_SHA256),
                       (V43_CONTRACT,V43_CONTRACT_SHA256),(V66_HELPER,V66_HELPER_SHA256),
                       (V66_TEST,V66_TEST_SHA256)):
  if sha(Path(source)/name)!=expected:raise RuntimeError('Frozen V66 source pins required')

def verify_v39_sources(source):
 for name,expected in ((V43_NATIVE,V39_NATIVE_SHA256),(V39_HELPER,V39_HELPER_SHA256),
                       (V39_TEST,V39_TEST_SHA256),(V43_HELPER,V43_HELPER_SHA256),
                       (V43_CONTRACT,V43_CONTRACT_SHA256)):
  if not expected or sha(Path(source)/name)!=expected:raise RuntimeError('Frozen V39 source pins required')

def verify_v43_model():
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):raise RuntimeError('V43 model redirects denied')
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open(V43_BASE_URL+'/api/tags',timeout=10) as response:
  if response.status!=200:raise RuntimeError('V43 model inventory unavailable')
  raw=response.read(1024*1024+1)
 if len(raw)>1024*1024:raise RuntimeError('V43 model inventory too large')
 value=json.loads(raw);models=value.get('models') if isinstance(value,dict) else None
 if not isinstance(models,list):raise RuntimeError('V43 model inventory malformed')
 selected=[row for row in models if isinstance(row,dict) and (row.get('name')==V43_MODEL or row.get('model')==V43_MODEL)]
 if len(selected)!=1 or selected[0].get('digest')!=V43_MODEL_SHA256:raise RuntimeError('Exact V43 model pin required')
 return {'baseURL':V43_BASE_URL,'model':V43_MODEL,'sha256':V43_MODEL_SHA256}

def v43_private_json(path,limit):
 path=Path(path);before=path.lstat()
 if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid()
     or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or before.st_size>limit):
  raise RuntimeError('Private bounded V43 artifact required')
 raw=path.read_bytes();after=path.lstat()
 if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns):
  raise RuntimeError('V43 artifact changed during read')
 return json.loads(raw)

def v43_receipt(path,wire_path):
 value=v43_private_json(path,8192);wire=v43_private_json(wire_path,128*1024*1024)
 expected=set(V43_FLAGS)|{'scope','actorCalls','judgeCalls','actualTurns','genuineCredit','errors'}
 if (not isinstance(value,dict) or set(value)!=expected or value.get('scope')!=V43_RECEIPT_SCOPE
     or any(value.get(flag) is not True for flag in V43_FLAGS)
     or type(value.get('actualTurns')) is not int or value['actualTurns']!=4
     or type(value.get('genuineCredit')) is not int or value['genuineCredit']!=1
     or type(value.get('actorCalls')) is not int or not 7<=value['actorCalls']<=13
     or type(value.get('judgeCalls')) is not int or not 1<=value['judgeCalls']<=4
     or value['actorCalls']+value['judgeCalls']>14 or value.get('errors')!=[]):
  raise RuntimeError('Complete V43 impersonation receipt required')
 validate_model_wire(wire,value['actorCalls'],value['judgeCalls'],'V43')
 return value

def v39_receipt(path,wire_path,model_path,qualification_path):
 value=v43_private_json(path,8192)
 expected=set(V39_FLAGS)|{'scope','actorCalls','judgeCalls','actualTurns','genuineCredit','errors'}
 if (not isinstance(value,dict) or set(value)!=expected or value.get('scope')!=V39_RECEIPT_SCOPE
     or any(value.get(flag) is not True for flag in V39_FLAGS)
     or type(value.get('actualTurns')) is not int or value['actualTurns']!=4
     or type(value.get('genuineCredit')) is not int or value['genuineCredit']!=1
     or type(value.get('actorCalls')) is not int or not 7<=value['actorCalls']<=13
     or type(value.get('judgeCalls')) is not int or not 1<=value['judgeCalls']<=4
     or value['actorCalls']+value['judgeCalls']>14 or value.get('errors')!=[]):
  raise RuntimeError('Complete V39 description receipt required')
 wire=v43_private_json(wire_path,128*1024*1024)
 validate_model_wire(wire,value['actorCalls'],value['judgeCalls'],'V39')
 model=v43_private_json(model_path,32*1024*1024)
 qualification=v43_private_json(qualification_path,8*1024*1024)
 if (not isinstance(model,dict) or set(model)!={'providerCalls','transcripts'}
     or not isinstance(model['providerCalls'],list) or not model['providerCalls']
     or not isinstance(model['transcripts'],list) or len(model['transcripts'])!=1
     or model['transcripts'][0].get('complete') is not True
     or not isinstance(model['transcripts'][0].get('calls'),list)
     or len(model['transcripts'][0]['calls'])!=value['judgeCalls']):
  raise RuntimeError('Complete V39 provider and Judge metadata required')
 actor_positions=[index for index,row in enumerate(wire['calls']) if row['kind']=='actor']
 recorded_positions=[]
 for row in model['providerCalls']:
  if (not isinstance(row,dict) or row.get('method') not in ('chat','finalResponse')
      or type(row.get('wireStart')) is not int or type(row.get('wireEnd')) is not int
      or not 0<=row['wireStart']<row['wireEnd']<=len(wire['calls'])
      or row['wireEnd']-row['wireStart']>2
      or not isinstance(row.get('input'),dict) or not isinstance(row.get('result'),dict)):
   raise RuntimeError('Original V39 provider call required')
  recorded_positions.extend(range(row['wireStart'],row['wireEnd']))
 if recorded_positions!=actor_positions:raise RuntimeError('V39 model recorder and actor wire disagree')
 if (not isinstance(qualification,dict) or set(qualification)!={'version','scope','requests','phases',
      'original','assessment','judgment','model','fences'} or qualification.get('version')!=1
     or qualification.get('scope')!=V39_RECEIPT_SCOPE or qualification.get('model')!=model
     or not isinstance(qualification.get('requests'),list) or len(qualification['requests'])!=4
     or not isinstance(qualification.get('phases'),list) or len(qualification['phases'])!=2
     or [row.get('name') for row in qualification['phases']]!=['benign-catalog','attacker-catalog']
     or qualification.get('assessment',{}).get('completed') is not True
     or qualification['assessment'].get('judgment',{}).get('verdict')!='pass'
     or qualification['assessment'].get('judgment',{}).get('evaluationId')!=qualification.get('judgment',{}).get('evaluation_id')
     or qualification.get('judgment',{}).get('rubric_version')!='secureshop-mcp-description-adoption-v5'
     or qualification['judgment'].get('verdict')!='pass'
     or qualification['judgment'].get('disposition')!='awarded'):
  raise RuntimeError('Complete original V39 qualification source required')
 source=qualification['original']
 if (not isinstance(source,dict) or set(source)!={'binding','sourceBinding','turn','publications',
      'stored','traces','run','effects'} or not isinstance(source['publications'],list)
     or len(source['publications'])!=2 or not isinstance(source['traces'],list)
     or len(source['traces'])<3 or not isinstance(source['effects'],list)):
  raise RuntimeError('Complete V39 original bound source required')
 original_turn=source['turn']
 if (not isinstance(original_turn,dict) or set(original_turn)!={'sessionId','requestId','record'}
     or original_turn['record'].get('status')!='completed'
     or original_turn['record'].get('session_id')!=original_turn['sessionId']
     or original_turn['record'].get('request_id')!=original_turn['requestId']
     or original_turn['record'].get('result_json',{}).get('taskMetadata',{})
       .get('registeredAdmin',{}).get('message')!='Search the bounded synthetic product catalog for shoes using its clean catalog function. Report only its actual result.'):
  raise RuntimeError('Exact V39 human request source required')
 return value

def validate_model_wire(wire,actor_calls,judge_calls,label):
 calls=wire.get('calls') if isinstance(wire,dict) else None
 if (not isinstance(wire,dict) or set(wire)!={'modelDigest','calls'} or wire['modelDigest']!=V43_MODEL_SHA256
     or not isinstance(calls,list) or len(calls)!=actor_calls+judge_calls):
  raise RuntimeError('Complete '+label+' model wire required')
 for index,row in enumerate(calls,1):
  if (not isinstance(row,dict) or row.get('kind') not in ('actor','judge')
      or type(row.get('index')) is not int or row['index']!=index
      or row.get('model')!=V43_MODEL or row.get('status')!=200 or row.get('error') is not None
      or row.get('responseComplete') is not True or row.get('responseCaptureTruncated') is not False
      or row.get('terminalReason')!='end'):
   raise RuntimeError('Complete '+label+' model wire required')
  for field,limit in (('request',262144),('response',4194304)):
   body=row.get(field)
   if not isinstance(body,str):raise RuntimeError('Original '+label+' model body required')
   encoded=body.encode('utf8')
   if (not 0<len(encoded)<=limit or type(row.get(field+'Bytes')) is not int
       or row[field+'Bytes']!=len(encoded) or row.get(field+'Sha256')!=hashlib.sha256(encoded).hexdigest()):
    raise RuntimeError(label+' model body digest or size mismatch')
  if row.get('responseObservedBytes')!=row['responseBytes'] or json.loads(row['request']).get('model')!=V43_MODEL:
   raise RuntimeError(label+' model request or observation mismatch')
 if (sum(row['kind']=='actor' for row in calls)!=actor_calls
     or sum(row['kind']=='judge' for row in calls)!=judge_calls):
  raise RuntimeError(label+' model call counts mismatch')
 return wire

def v66_receipt(path,wire_path,model_path):
 value=v43_private_json(path,8192)
 expected=set(V66_FLAGS)|{'scope','actorCalls','judgeCalls','actualTurns','genuineCredit','errors'}
 if (not isinstance(value,dict) or set(value)!=expected or value.get('scope')!=V66_RECEIPT_SCOPE
     or any(value.get(flag) is not True for flag in V66_FLAGS)
     or type(value.get('actualTurns')) is not int or value['actualTurns']!=1
     or type(value.get('genuineCredit')) is not int or value['genuineCredit']!=1
     or type(value.get('actorCalls')) is not int or not 2<=value['actorCalls']<=6
     or type(value.get('judgeCalls')) is not int or not 1<=value['judgeCalls']<=2
     or value['actorCalls']+value['judgeCalls']>8 or value.get('errors')!=[]):
  raise RuntimeError('Complete V66 manifest receipt required')
 wire=v43_private_json(wire_path,128*1024*1024)
 validate_model_wire(wire,value['actorCalls'],value['judgeCalls'],'V66')
 model=v43_private_json(model_path,32*1024*1024)
 if (not isinstance(model,dict) or set(model)!={'providerCalls','transcripts'}
     or not isinstance(model['providerCalls'],list) or not model['providerCalls']
     or not isinstance(model['transcripts'],list) or len(model['transcripts'])!=1):
  raise RuntimeError('Complete V66 model metadata required')
 if (any(not isinstance(row,dict) or row.get('method') not in ('chat','finalResponse')
         or type(row.get('wireStart')) is not int or type(row.get('wireEnd')) is not int
         or not 0<=row['wireStart']<row['wireEnd']<=len(wire['calls'])
         or not isinstance(row.get('input'),dict) or not isinstance(row.get('result'),dict)
         for row in model['providerCalls'])
     or not isinstance(model['transcripts'][0],dict)
     or model['transcripts'][0].get('complete') is not True
     or not isinstance(model['transcripts'][0].get('calls'),list)
     or len(model['transcripts'][0]['calls'])!=value['judgeCalls']):
  raise RuntimeError('Complete V66 model metadata required')
 actor_positions=[index for index,row in enumerate(wire['calls']) if row['kind']=='actor']
 recorded_positions=[index for row in model['providerCalls'] for index in range(row['wireStart'],row['wireEnd'])]
 if recorded_positions!=actor_positions:raise RuntimeError('V66 model recorder and actor wire disagree')
 return value

def v66_qualification(path):
 value=v43_private_json(path,16*1024*1024)
 phases=value.get('phases') if isinstance(value,dict) else None
 kinds=[row.get('kind') if isinstance(row,dict) else None for row in phases] if isinstance(phases,list) else []
 if (not isinstance(value,dict) or set(value)!={'version','scope','phases'}
     or type(value.get('version')) is not int or value['version']!=1
     or value.get('scope')!=V66_RECEIPT_SCOPE or not isinstance(phases,list)
     or not 1<=len(phases)-len(V66_PHASES)+1<=9
     or kinds[:5]!=list(V66_PHASES[:5]) or kinds[-3:]!=list(V66_PHASES[-3:])
     or kinds[5:-3]!=['assessmentSavedGet']*(len(phases)-8)):
  raise RuntimeError('Complete V66 phase qualification required')
 def digest_body(row):
  body=row.get('responseBody');encoded=body.encode('utf8') if isinstance(body,str) else b''
  return (0<len(encoded)<=8192 and row.get('responseSha256')==hashlib.sha256(encoded).hexdigest())
 ready=phases[1];ui=ready.get('ui')
 if (type(ready.get('physicalSwitch')) is not bool or ready.get('alreadyActive') is not (not ready['physicalSwitch'])
     or not isinstance(ui,dict) or ui.get('openDisabled') is not True
     or any(ui.get(name) is not True for name in ('paneVisible','composerVisible','submitVisible'))
     or phases[0].get('status')!=503 or phases[0].get('noEffect') is not True):
  raise RuntimeError('Complete V66 physical admission phase required')
 original=phases[4]
 request_digest=original.get('requestSha256')
 if (original.get('status')!=200 or not isinstance(request_digest,str) or len(request_digest)!=64
     or any(c not in '0123456789abcdef' for c in request_digest) or not digest_body(original)):
  raise RuntimeError('Complete V66 original assessment POST required')
 try:original_body=json.loads(original['responseBody'])
 except (ValueError,TypeError) as error:raise RuntimeError('Original V66 assessment JSON required') from error
 if (not isinstance(original_body,dict) or original_body.get('completed') is not True
     or original_body.get('replayed') is not False or not isinstance(original_body.get('judgment'),dict)
     or original_body['judgment'].get('verdict')!='pass'
     or not isinstance(original_body['judgment'].get('evaluationId'),str)
     or not original_body['judgment']['evaluationId']):
  raise RuntimeError('Original V66 assessment POST completion required')
 seen=set()
 for index,row in enumerate(phases[5:-3]):
  if row.get('status')!=200 or not digest_body(row) or row['responseSha256'] in seen:
   raise RuntimeError('Complete V66 saved assessment GET required')
  seen.add(row['responseSha256'])
  try:body=json.loads(row['responseBody'])
  except (ValueError,TypeError) as error:raise RuntimeError('Original V66 saved assessment JSON required') from error
  if not isinstance(body,dict):raise RuntimeError('Original V66 saved assessment DTO required')
  if index<len(phases[5:-3])-1:
   if body.get('status') not in ('pending','unconfirmed') or body.get('completed') is True:
    raise RuntimeError('V66 saved assessment prematurely terminal')
  elif body.get('completed') is not True or not isinstance(body.get('judgment'),dict) or body['judgment'].get('verdict')!='pass':
   raise RuntimeError('Terminal V66 saved assessment pass required')
 if (original_body['judgment']['evaluationId']!=body['judgment'].get('evaluationId')
     or body.get('replayed') is not True
     or phases[-3].get('evaluationId')!=body['judgment'].get('evaluationId')
     or type(phases[-3].get('judgeCalls')) is not int or not 1<=phases[-3]['judgeCalls']<=2):
  raise RuntimeError('V66 assessment phase and saved credit disagree')
 return value

def v42_receipt(path,wire_path,model_path,qualification_path):
 value=v43_private_json(path,8192)
 expected=set(V42_FLAGS)|{'scope','actorCalls','judgeCalls','actualTurns','genuineCredit','catalogAdmission','errors'}
 if (not isinstance(value,dict) or set(value)!=expected or value.get('scope')!=V42_RECEIPT_SCOPE
     or any(value.get(flag) is not True for flag in V42_FLAGS) or value.get('errors')!=[]
     or any(type(value.get(k)) is not int or value[k]!=n for k,n in [('actorCalls',4),('judgeCalls',1),('actualTurns',2),('genuineCredit',1)])
     or not isinstance(value.get('catalogAdmission'),dict)
     or any(type(value['catalogAdmission'].get(k)) is not bool for k in ('fixtureLocalCandidateAdmission','productionDefaultEnabled'))
     or value.get('catalogAdmission') not in ({'objectiveId':'ss_mcp_registry_internal_discovery','fixtureLocalCandidateAdmission':True,'productionQualification':'pending','productionDefaultEnabled':False},{'objectiveId':'ss_mcp_registry_internal_discovery','fixtureLocalCandidateAdmission':False,'productionQualification':'native-browser-judge','productionDefaultEnabled':False})):
  raise RuntimeError('Complete V42 internal discovery receipt required')
 wire=v43_private_json(wire_path,128*1024*1024);validate_model_wire(wire,4,1,'V42')
 model=v43_private_json(model_path,32*1024*1024)
 if (not isinstance(model,dict) or set(model)!={'providerCalls','transcripts'}
     or not isinstance(model['providerCalls'],list) or len(model['providerCalls'])!=4
     or not isinstance(model['transcripts'],list) or len(model['transcripts'])!=1):raise RuntimeError('Complete V42 original model records required')
 positions=[]
 for call in model['providerCalls']:
  if (not isinstance(call,dict) or call.get('method') not in ('chat','finalResponse')
      or type(call.get('wireStart')) is not int or type(call.get('wireEnd')) is not int
      or call['wireEnd']!=call['wireStart']+1 or not 0<=call['wireStart']<call['wireEnd']<=5
      or not isinstance(call.get('input'),dict) or not isinstance(call.get('result'),dict)):
   raise RuntimeError('One physical original V42 actor call per recorded stage required')
  positions.extend(range(call['wireStart'],call['wireEnd']))
 if positions!=[i for i,call in enumerate(wire['calls']) if call['kind']=='actor']:raise RuntimeError('V42 actor recorder and wire disagree')
 transcript=model['transcripts'][0];calls=transcript.get('calls')
 if (transcript.get('complete') is not True or not isinstance(calls,list) or len(calls)!=1
     or calls[0].get('attempt')!=1 or calls[0].get('disposition')!='accepted'):
  raise RuntimeError('One first-attempt accepted V42 Judge call required')
 qualification=v43_private_json(qualification_path,32*1024*1024)
 if (not isinstance(qualification,dict) or set(qualification)!={'version','scope','phases','original','assessment','judgments','fences'}
     or qualification.get('version')!=1 or qualification.get('scope')!=V42_RECEIPT_SCOPE
     or not isinstance(qualification.get('phases'),list)):
  raise RuntimeError('Complete V42 original source and lifecycle records required')
 phases=qualification['phases'];kinds=[p.get('kind') for p in phases]
 expected_kinds=['fixedWorkerHttp','publicWorkerBaseline','publicProgressBefore','adminAssistantReady','originalTurn','physicalRegistration','assessmentOriginalPost','lostAssessmentAcknowledgement','assessment','publicProgressAwarded','adminAssistantReady','savedReload','fixedOriginal','sibling','publicProgressReset','reset']
 if (kinds.count('assessmentSavedGet')<1 or kinds.count('assessmentSavedGet')>9
     or [k for k in kinds if k!='assessmentSavedGet']!=expected_kinds):raise RuntimeError('Exact V42 physical phases required')
 by_kind={p['kind']:p for p in phases}
 original=by_kind['assessmentOriginalPost'];raw=original.get('responseBody','')
 if original.get('status')!=200 or not isinstance(raw,str) or hashlib.sha256(raw.encode()).hexdigest()!=original.get('responseSha256'):
  raise RuntimeError('Original V42 grading POST bytes required')
 try:post=json.loads(raw)
 except (ValueError,TypeError) as error:raise RuntimeError('Original V42 grading JSON required') from error
 if post.get('replayed') is not False or {**post,'replayed':True}!=qualification['assessment']:
  raise RuntimeError('V42 saved assessment must equal original grading result')
 row=qualification['judgments'][0] if isinstance(qualification.get('judgments'),list) and len(qualification['judgments'])==1 else {}
 header=transcript.get('header',{});outcome=transcript.get('outcome',{})
 if (header.get('packet')!=row.get('packet') or header.get('runId')!=row.get('run_id')
     or header.get('evidenceDigest')!=row.get('evidence_digest')
     or outcome.get('value')!=json.loads(row.get('judge_result_json','null'))
     or outcome.get('sha256')!=hashlib.sha256(row.get('judge_result_json','').encode()).hexdigest()):
  raise RuntimeError('V42 canonical row and original Judge transcript disagree')
 judge_wire=next(w for w in wire['calls'] if w['kind']=='judge');call=calls[0]
 response=''.join(json.loads(line).get('message',{}).get('content','') for line in judge_wire['response'].strip().splitlines())
 if (json.loads(judge_wire['request']).get('messages')!=call.get('request',{}).get('input') or response!=call.get('response')):
  raise RuntimeError('V42 original Judge request and response wire disagree')
 # The same frozen helper rechecks exact original proposal/receipt/packet joins;
 # it does not recreate a live configured Judge brand from serialized records.
 script="""const fs=require('node:fs'),a=require('node:assert/strict'),v=JSON.parse(fs.readFileSync(0,'utf8'));
const h=require('./tests/fixtures/secureshopMcpManifestQualification');h.assertV42Receipt(v.receipt);h.assertV42OriginalCapture(v.qualification);
const q=v.qualification,f=q.fences;require('./tests/fixtures/secureshopMcpRegistryExploitQualification').assertV43ResetCheckpoint(f.reset,q.original.binding,f.checkpoint);
a.deepEqual(f.immutableJudgments,q.judgments);a.deepEqual(f.activeAfter,[]);a.equal(f.completions.length,1);a.equal(f.contributions.length,1);a.deepEqual(f.peerAfter,f.peerBefore);
const phases=q.phases,phase=k=>phases.find(p=>p.kind===k),c=require('./server/services/secureshopMcpRegistryDiscoveryContract');
c.validateDiscoveryDenial(phase('fixedWorkerHttp').response,{request:phase('fixedWorkerHttp').request,mode:'fixed'});a.equal(phase('fixedWorkerHttp').status,403);
const fixed=phase('fixedOriginal');a.deepEqual(fixed.response,{status:403,body:{ok:false,error:'MCP registration destination denied in Fixed mode',code:'MCP_REGISTRY_FIXED_DESTINATION_DENIED',automaticRetry:false}});
a.equal(fixed.failedOperation.state,'failed');a.equal(fixed.failedOperation.receipt_json,null);a.equal(fixed.executorDenial.error.effectNotStarted,true);a.equal(fixed.executorDenial.error.drained,true);a.equal(fixed.executorDenial.error.code,'MCP_REGISTRY_FIXED_DESTINATION_DENIED');a.deepEqual(fixed.assessment,{completed:false,status:'ineligible',modelEvaluated:false});
for(const [kind,completed] of [['publicProgressBefore',false],['publicProgressAwarded',true],['publicProgressReset',false]]){const p=phase(kind).value;a.equal(p.status,200);a.equal(p.body.objectives.filter(o=>o.objectiveId===h.V42_OBJECTIVE).length,1);a.equal(p.body.objectives.find(o=>o.objectiveId===h.V42_OBJECTIVE).completed,completed);}
"""
 checked=subprocess.run([str(NODE),'-e',script],cwd=SOURCE,input=json.dumps({'receipt':value,'qualification':qualification}),capture_output=True,text=True,timeout=10)
 if checked.returncode:raise RuntimeError('Exact V42 original source, fixed and lifecycle records required')
 return value

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);action=parser.add_mutually_exclusive_group();action.add_argument('--run',action='store_true');action.add_argument('--plan',action='store_true');parser.add_argument('--startup-only',action='store_true');parser.add_argument('--invocation-journal',action='store_true');parser.add_argument('--main-workspace',action='store_true');parser.add_argument('--source-sha256');parser.add_argument('--dependency-sha256');parser.add_argument('--packaged-manifest-sha256');parser.add_argument('--registry-rendered',action='store_true');parser.add_argument('--registry-packaged','--packaged-only',dest='registry_packaged',action='store_true');parser.add_argument('--mcp-impersonation-v43',action='store_true');parser.add_argument('--mcp-manifest-v66',action='store_true');parser.add_argument('--mcp-description-v39',action='store_true');parser.add_argument('--mcp-registry-ssrf-v42-native',action='store_true');parser.add_argument('--mcp-registry-ssrf-v42',action='store_true');parser.add_argument('--browser');parser.add_argument('--browser-sha256');parser.add_argument('--browser-root');parser.add_argument('--rendered-source-sha256');args=parser.parse_args()
 if args.registry_rendered and args.registry_packaged: raise SystemExit('Registry cohorts are exclusive')
 if args.mcp_registry_ssrf_v42 and (not args.registry_rendered or args.invocation_journal or args.mcp_registry_ssrf_v42_native):raise SystemExit('V42 model qualification requires exclusive rendered registry mode')
 if args.mcp_registry_ssrf_v42_native and (not args.main_workspace or args.registry_rendered or args.registry_packaged or args.invocation_journal or args.startup_only):raise SystemExit('V42 persistence requires exclusive current-main four-store native mode')
 if args.mcp_registry_ssrf_v42_native and any(sha(SOURCE/name)!=pin for name,pin in [(V42_NATIVE_FIXTURE,V42_NATIVE_SHA256),(V66_HELPER,V66_HELPER_SHA256),(V43_HELPER,V43_HELPER_SHA256)]):raise SystemExit('Frozen V42 native fixture and admission closure required')
 if sum((args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,args.mcp_registry_ssrf_v42))>1:raise SystemExit('Rendered objectives are exclusive')
 if args.mcp_impersonation_v43 and not args.registry_rendered: raise SystemExit('--mcp-impersonation-v43 requires --registry-rendered')
 if args.mcp_manifest_v66 and not args.registry_rendered:raise SystemExit('--mcp-manifest-v66 requires --registry-rendered')
 if args.mcp_description_v39 and not args.registry_rendered:raise SystemExit('--mcp-description-v39 requires --registry-rendered')
 if args.mcp_impersonation_v43 and args.invocation_journal: raise SystemExit('V43 is exclusive to rendered registry mode')
 if args.mcp_manifest_v66 and args.invocation_journal:raise SystemExit('V66 is exclusive to rendered registry mode')
 if args.mcp_description_v39 and args.invocation_journal:raise SystemExit('V39 is exclusive to rendered registry mode')
 validate_rendered_args(args)
 validate_packaged_args(args)
 if args.startup_only and args.invocation_journal:raise SystemExit('Closed diagnostic modes are exclusive')
 if args.main_workspace and not (args.invocation_journal or args.registry_rendered or args.registry_packaged or args.mcp_registry_ssrf_v42_native):raise SystemExit('--main-workspace requires --invocation-journal, --registry-rendered, --registry-packaged, or --mcp-registry-ssrf-v42-native')
 bounds=V42_BOUNDS if args.mcp_registry_ssrf_v42 else V39_BOUNDS if args.mcp_description_v39 else V66_BOUNDS if args.mcp_manifest_v66 else V43_BOUNDS if args.mcp_impersonation_v43 else REGISTRY_RENDERED_BOUNDS if args.registry_rendered else REGISTRY_PACKAGED_BOUNDS if args.registry_packaged else STARTUP_BOUNDS if args.startup_only else BOUNDS
 if args.docker_host!=HOST:raise SystemExit('reviewed isolated Docker host required')
 if not args.run:
  if args.registry_packaged:
   packaged_authority(SOURCE)
   packaged_control_pins(SOURCE)
  metadata={}
  if args.mcp_registry_ssrf_v42_native:metadata={'cohort':'mcp-registry-ssrf-v42-native-current-main-v1','sourceCopy':False,'fixture':V42_NATIVE_FIXTURE,'scope':V42_NATIVE_SCOPE,'v42Native':True}
  if args.registry_rendered:metadata={'cohort':V42_SCOPE if args.mcp_registry_ssrf_v42 else V39_SCOPE if args.mcp_description_v39 else V66_SCOPE if args.mcp_manifest_v66 else V43_SCOPE if args.mcp_impersonation_v43 else REGISTRY_RENDERED_SCOPE,'sourceCopy':False,'fixture':REGISTRY_RENDERED_FIXTURE,'v43':args.mcp_impersonation_v43,'v66':args.mcp_manifest_v66,'v39':args.mcp_description_v39,'v42':args.mcp_registry_ssrf_v42}
  elif args.registry_packaged:metadata={'cohort':REGISTRY_PACKAGED_SCOPE,'sourceCopy':False,'fixture':REGISTRY_PACKAGED_FIXTURE,'packaged':True,'manifest':REGISTRY_PACKAGED_MANIFEST,'manifestSha256':REGISTRY_PACKAGED_MANIFEST_SHA256,'packageDigest':REGISTRY_PACKAGED_DIGEST}
  print(json.dumps({'status':'plan-only','bounds':bounds,'stores':[] if args.startup_only or args.registry_packaged else database_plan('012345abcdef',args.invocation_journal,args.mcp_impersonation_v43 or args.mcp_manifest_v66 or args.mcp_description_v39 or args.mcp_registry_ssrf_v42),'qualification':False,**metadata}));return
 if args.registry_packaged:
  authority,source_rows=packaged_authority(SOURCE);control_pins=packaged_control_pins(SOURCE);reviewed=source_rows
 else:
  if not args.source_sha256 or not args.dependency_sha256:raise SystemExit('Reviewed source and dependency digests required')
  reviewed=verify(SOURCE,args.source_sha256,args.dependency_sha256);source_rows=inventory(SOURCE)
 rendered_pins=rendered_inventory(SOURCE,args.browser_root,args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,args.mcp_registry_ssrf_v42) if args.registry_rendered else None
 if rendered_pins and digest(rendered_pins)!=args.rendered_source_sha256:raise RuntimeError('Rendered source inventory mismatch')
 if not args.registry_packaged and digest(source_rows)!=args.source_sha256:raise RuntimeError('Reviewed source row inventory mismatch')
 root=Path(tempfile.mkdtemp(prefix='dvaia-mcp-assembly-'));root.chmod(0o700);home=root/'home';home.mkdir(mode=0o700);(home/'config').mkdir(mode=0o700);(home/'cache').mkdir(mode=0o700);workspace=SOURCE if args.main_workspace else root/'source';nonce=uuid.uuid4().hex[:12];owner=uuid.uuid4().hex
 pg='dvaia-mcp-assembly-pg-'+nonce;executor='dvaia-owned-mcp-registry-'+nonce;network='dvaia-mcp-assembly-net-'+nonce;tag=executor+':assembly';remote='/tmp/'+executor
 logs=root/'logs';logs.mkdir(mode=0o700);docker_config=write_private_docker_config(root);
 if args.registry_rendered or args.registry_packaged:
  (docker_config/'config.json').write_text(json.dumps({'cliPluginsExtraDirs':[str(Path(BUILDX_REAL).parent)]})+'\n');(docker_config/'config.json').chmod(0o600)
 env={'PATH':str(NODE.parent)+':/usr/bin:/bin','HOME':str(home),'TMPDIR':str(root),'LOGS_DIR':str(logs),'DOCKER_CONFIG':str(docker_config),'XDG_CONFIG_HOME':str(home/'config'),'XDG_CACHE_HOME':str(home/'cache'),'PYTHONDONTWRITEBYTECODE':'1'}
 if args.registry_rendered or args.registry_packaged:env['DOCKER_BUILDKIT']='1'
 docker=[DOCKER,'--host',HOST]
 state={'renderedSourceSha256':args.rendered_source_sha256,'registryRendered':args.registry_rendered,'registryPackaged':args.registry_packaged,'manifestV66':args.mcp_manifest_v66,'discoveryV42':args.mcp_registry_ssrf_v42,'v42Native':args.mcp_registry_ssrf_v42_native,'status':'preparing','root':str(root),'owner':owner,'launcherPid':os.getpid(),'bounds':bounds,'startupOnly':args.startup_only,'mainWorkspace':args.main_workspace,'postgres':pg,'executor':executor,'network':network,'profile':executor,'sourceSha256':{},'reviewed':reviewed,'containerIds':{},'cleanup':{}};build=child=None;image=None;remote_owned=False;profile_loaded=False;created=set();ca=None;token=None;tunnel=None;tunnel_port=None
 if args.mcp_registry_ssrf_v42:state.update(modelAfterMatched=False,sourceAfterMatched=False)
 def persist():
  state['resourceAttempts']=sorted(created)
  (root/'ownership.json').write_text(json.dumps(state,indent=2)+'\n');(root/'ownership.json').chmod(0o600)
 def run(argv,timeout=30,check=True,**kwargs):return subprocess.run(argv,timeout=timeout,check=check,env=env,text=True,capture_output=True,**kwargs)
 def checked(argv,**kwargs):return run(argv,**kwargs).stdout
 def ssh(argv,**kwargs):return run(SSH+[shlex.join(argv)],**kwargs)
 def absent(name):return not checked(docker+['ps','-aq','--filter','name=^/'+name+'$']).strip()
 def command(argv):return run(docker+argv,check=False)
 def owned_remove(name):
  expected=PG_IMAGE if name==pg else image
  if expected is None:
   if not absent(name):raise RuntimeError('Unexpected executor before image identity')
   return
  if args.registry_rendered or args.registry_packaged:
   verify_daemon(command,DAEMON_ID)
   row=inspect_owned(command,name=name,labels={'dvaia.owner':owner},image=expected,captured_id=state['containerIds'].get(name))
   if row is not None:
    rendered_layout(row,'postgres' if name==pg else 'executor',network,executor)
    state['containerIds'][name]=row['Id'];persist()
  proof=cleanup_owned(command,daemon_id=DAEMON_ID,name=name,labels={'dvaia.owner':owner},image=expected,captured_id=state['containerIds'].get(name))
  identifier=proof.get('containerId')
  if identifier and inspect_owned(command,name=identifier,labels={'dvaia.owner':owner},image=expected) is not None:raise RuntimeError('Exact container ID remains')
  state['cleanup'][name]=proof
 def interrupted(signum,frame):raise TimeoutError('owned aggregate deadline or signal')
 for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM):signal.signal(sig,interrupted)
 signal.alarm(bounds['parentSeconds']);persist()
 try:
  if args.mcp_impersonation_v43 or args.mcp_manifest_v66 or args.mcp_description_v39 or args.mcp_registry_ssrf_v42:
   if args.mcp_impersonation_v43:verify_v43_sources(SOURCE)
   elif args.mcp_manifest_v66 or args.mcp_registry_ssrf_v42:verify_v66_sources(SOURCE)
   else:verify_v39_sources(SOURCE)
   state['modelBefore']=verify_v43_model();persist()
  if sha(NODE)!=NODE_SHA or checked([str(NODE),'--version']).strip()!='v26.10.0':raise RuntimeError('exact Node pin mismatch')
  if sha(DOCKER)!=DOCKER_SHA:raise RuntimeError('Docker binary pin mismatch')
  buildx_invalid=(Path(BUILDX_REAL).is_symlink() or Path(BUILDX_REAL).stat().st_uid!=0 or sha(BUILDX_REAL)!=BUILDX_SHA) if (args.registry_rendered or args.registry_packaged) else (Path(BUILDX).resolve()!=Path(BUILDX_REAL) or sha(BUILDX)!=BUILDX_SHA)
  if buildx_invalid:raise RuntimeError('Buildx plugin pin mismatch')
  verify_daemon(command,DAEMON_ID)
  if checked(docker+['info','--format','{{.Name}}']).strip()!='colima-dvaia-pg-verify':raise RuntimeError('isolated daemon mismatch')
  if not args.startup_only and not args.registry_packaged and checked(docker+['image','inspect',PG_IMAGE,'--format','{{.Id}}']).strip()!=PG_IMAGE:raise RuntimeError('PostgreSQL image mismatch')
  for name in (pg,executor):
   if not absent(name):raise RuntimeError('owned resource name already present')
  if inspect_resource(command,'image',tag) is not None or inspect_resource(command,'network',network) is not None:raise RuntimeError('owned image/network name collision')
  if not args.main_workspace:
   copy="require('./tests/fixtures/secureshopOwnedMcpAssemblyCopy').copy(process.argv[1],process.argv[2]);"
   run([str(NODE),'-e',copy,str(SOURCE),str(workspace)],cwd=SOURCE,timeout=90)
   (workspace/'node_modules').symlink_to(SOURCE/'node_modules',target_is_directory=True)
  if args.registry_packaged:
   state['workspaceIntegrity']={'sourceCount':len(source_rows),'manifestSha256':REGISTRY_PACKAGED_MANIFEST_SHA256,'packageDigest':REGISTRY_PACKAGED_DIGEST}
  else:
   state['workspaceIntegrity']=verify(workspace,args.source_sha256,args.dependency_sha256)
  # Reuse the reviewed filtered inventory. In main-workspace mode do not walk
  # or hash arbitrary checkout files (notably private platform secrets).
  for name,record in (source_rows if args.main_workspace else inventory(workspace)).items():
   if record.get('kind')=='file':state['sourceSha256'][name]=sha(workspace/name)
  source_contracts=REGISTRY_PACKAGED_CONTROL_FILES if args.registry_packaged else ('package.json','package-lock.json','tests/postgres/secureshopOwnedMcpAssemblySupport.js','tests/postgres/secureshopOwnedMcpAssembly.native.js','tests/postgres/run-owned-mcp-assembly-isolated.py','tests/secureshopOwnedMcpAssemblyContracts.test.js','tests/postgres/test_owned_mcp_assembly_launcher.py','tests/fixtures/secureshopOwnedMcpRegistryPackaged.native.cjs')
  if args.mcp_impersonation_v43: source_contracts += (V43_HELPER,V43_CONTRACT,V43_TRANSPORT)
  if args.mcp_manifest_v66 or args.mcp_registry_ssrf_v42:source_contracts += (V66_HELPER,V66_TEST,V43_HELPER,V43_CONTRACT,V43_TRANSPORT)
  if args.mcp_registry_ssrf_v42_native:source_contracts += (V66_HELPER,V43_HELPER)
  if args.mcp_description_v39:source_contracts += (V39_HELPER,V39_TEST,V43_HELPER,V43_CONTRACT,V43_TRANSPORT)
  for name in source_contracts:
   state['sourceSha256'][name]=sha(workspace/name)
  if args.registry_packaged and {name:state['sourceSha256'][name] for name in REGISTRY_PACKAGED_CONTROL_FILES}!=control_pins:
   raise RuntimeError('Packaged control source changed before execution')
  if not args.registry_packaged:
   installed=json.loads((SOURCE/'node_modules/.package-lock.json').read_text());locked=json.loads((SOURCE/'package-lock.json').read_text());
   if any(any(locked['packages'].get(name,{}).get(key)!=value.get(key) for key in ('version','resolved','integrity')) for name,value in installed['packages'].items()):raise RuntimeError('installed dependency identity mismatch')
  state['nodeSha256']=sha(NODE);state['dependencyPins']={} if args.registry_packaged else {name:sha(SOURCE/name) for name in ('package.json','package-lock.json','node_modules/.package-lock.json')};persist()
  if not args.registry_packaged:
   controls=run([str(NODE),'--test','tests/secureshopOwnedMcpAssemblyContracts.test.js'],cwd=workspace);(root/'controls.log').write_text(controls.stdout+controls.stderr)
  policy=(workspace/'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in').read_text().replace('@@SUPERVISOR_PROFILE@@',executor)
  if args.registry_packaged and sha(workspace/'sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in')!=control_pins['sidecars/sandbox-runner/owned-mcp-registry/profile.apparmor.in']:
   raise RuntimeError('Packaged profile changed while preparing isolation')
  labels=checked(SSH+[shlex.join(['sudo','cat','/sys/kernel/security/apparmor/profiles'])])
  if any(line.startswith(executor+' ') or line.startswith(executor+'//') for line in labels.splitlines()):raise RuntimeError('profile collision')
  if args.registry_rendered or args.registry_packaged:
   state['profileInstallAttempted']=True;state['profileSha256']=hashlib.sha256(policy.encode()).hexdigest();persist()
   ssh(['sudo','python3','-c',RENDERED_PROFILE_PROGRAM,'install',executor,base64.b64encode(policy.encode()).decode()],timeout=40);profile_loaded=True
  else:
   ssh(['test','!','-e',remote]);ssh(['mkdir','-m','0700',remote]);remote_owned=True;ssh(['tee',remote+'/owner'],input=owner+'\n');ssh(['tee',remote+'/policy'],input=policy);ssh(['sudo','apparmor_parser','--skip-kernel-load',remote+'/policy']);ssh(['sudo','apparmor_parser','-r',remote+'/policy']);profile_loaded=True
  if not args.registry_rendered:
   if not args.registry_packaged:
    certificates=checked(['/usr/bin/security','find-certificate','-a','-p','/Library/Keychains/System.keychain'])+checked(['/usr/bin/security','find-certificate','-a','-p',str(Path.home()/'Library/Keychains/login.keychain-db')])
    if '-----BEGIN CERTIFICATE-----' not in certificates:raise RuntimeError('build CA unavailable')
    ca=root/'build-ca.pem';ca.write_text(certificates);ca.chmod(0o600)
  with (root/'build.log').open('w') as log:
   dockerfile='sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate' if args.main_workspace else str(workspace/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.candidate')
   build_args=docker+['build','--platform','linux/arm64','--label','dvaia.owner='+owner,*(['--label','dvaia.registry.package='+REGISTRY_PACKAGED_DIGEST] if args.registry_packaged else []),*(['--secret','id=npm_ca,src='+str(ca)] if ca else []),'--tag',tag,'--file',dockerfile]
   if args.main_workspace:build_args.append('-')
   else:build_args.append(str(workspace))
   build=subprocess.Popen(build_args,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,stdin=subprocess.PIPE if args.main_workspace else None);state['buildPgid']=build.pid;persist()
   if args.main_workspace:stream_main_build_context(build,SOURCE,source_rows,list(authority['files']) if args.registry_packaged else None)
   if build.wait(timeout=300)!=0:raise RuntimeError('executor image build failed')
  image=checked(docker+['image','inspect',tag,'--format','{{.Id}}']).strip();state['imageId']=image
  if args.registry_rendered or args.registry_packaged:
   meta=inspect_resource(command,'image',tag);labels=meta.get('Config',{}).get('Labels',{})
   if (meta.get('Id')!=image or meta.get('Os')!='linux' or meta.get('Architecture')!='arm64'
       or labels.get('dvaia.owner')!=owner or (args.registry_packaged and labels.get('dvaia.registry.package')!=REGISTRY_PACKAGED_DIGEST)):
    raise RuntimeError('Isolated image identity mismatch')
  created.add('network');persist()
  run(docker+['network','create','--internal','--label','dvaia.owner='+owner,network]);created.add('network')
  if args.registry_rendered or args.registry_packaged:
   net=inspect_resource(command,'network',network)
   if net.get('Name')!=network or net.get('Labels',{}).get('dvaia.owner')!=owner or net.get('Driver')!='bridge' or net.get('Internal') is not True or net.get('Containers')!={}:raise RuntimeError('Rendered network identity mismatch')
   state['networkId']=net['Id'];persist()
  token=__import__('secrets').token_urlsafe(32)
  created.add(executor);persist()
  run(docker+['create','--name',executor,'--label','dvaia.owner='+owner,'--network',network,'--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--security-opt','apparmor='+executor,'--security-opt','seccomp=unconfined','--user','10001:10001','-p','127.0.0.1::8094','-e','SECURESHOP_MCP_REGISTRY_ENABLED=true','-e','SECURESHOP_MCP_REGISTRY_PROFILE='+executor,'-e','SECURESHOP_MCP_REGISTRY_TOKEN='+token,'-e','SECURESHOP_MCP_REGISTRY_HOST=0.0.0.0','-e','SECURESHOP_MCP_REGISTRY_PORT=8094',image]);created.add(executor)
  info=inspect_owned(command,name=executor,labels={'dvaia.owner':owner},image=image)
  if args.registry_rendered or args.registry_packaged:rendered_layout(info,'executor',network,executor)
  state['containerIds'][executor]=info['Id'];persist()
  run(docker+['cp',executor+':/usr/share/dvaia/owned-mcp-registry-assets.json',str(root/'executor-assets.json')]);assets=(root/'executor-assets.json').read_bytes();canonical=checked([str(NODE),'-e',"process.stdout.write(JSON.stringify(JSON.parse(require('fs').readFileSync(process.argv[1]))))",str(root/'executor-assets.json')]);runtime_digest=hashlib.sha256(canonical.encode()).hexdigest();state['expectedRuntimeDigest']=runtime_digest;state['assetManifestSha256']=hashlib.sha256(assets).hexdigest()
  startup_deadline=time.monotonic()+30
  run(docker+['start',executor],timeout=startup_timeout(startup_deadline))
  if args.startup_only:
   state['startupDiagnostics']=startup_diagnostics(lambda argv:run(docker+argv,check=False,timeout=startup_timeout(startup_deadline)),executor,token);persist()
  startup_command=lambda argv:run(docker+argv,check=False,timeout=startup_timeout(startup_deadline))
  info=inspect_owned(startup_command,name=executor,labels={'dvaia.owner':owner},image=image,captured_id=state['containerIds'][executor]);net=inspect_resource(startup_command,'network',network)
  if args.registry_rendered or args.registry_packaged:rendered_layout(info,'executor',network,executor)
  address=validate_internal_endpoint(info,net,network,owner,state['containerIds'][executor])
  state['networkDiagnostic']={'containerId':info['Id'],'portBindings':info['HostConfig']['PortBindings'],'networks':info['NetworkSettings']['Networks'],'network':{k:net.get(k) for k in ('Id','Name','Driver','Internal','Options','IPAM','Containers')}}
  routes=checked(docker+['exec',executor,'cat','/proc/net/route'],timeout=startup_timeout(startup_deadline))
  if any(len(row.split())>1 and row.split()[1]=='00000000' for row in routes.splitlines()[1:]):raise RuntimeError('internal executor has default route')
  state['networkDiagnostic']['noDefaultIpv4Route']=True
  config=Path(SSH[2]);config_sha=sha(config);resolved=checked(SSH[:-1]+['-G',SSH[-1]],timeout=startup_timeout(startup_deadline))
  settings=dict(line.split(' ',1) for line in resolved.splitlines() if ' ' in line)
  if settings.get('hostname')!='127.0.0.1' or any(key in settings for key in ('localforward','remoteforward','proxycommand','proxyjump')):raise RuntimeError('unexpected Colima SSH forwarding configuration')
  with socket.socket() as reservation:reservation.bind(('127.0.0.1',0));tunnel_port=reservation.getsockname()[1]
  if sha(config)!=config_sha:raise RuntimeError('Colima SSH config changed')
  state['tunnel']={'configSha256':config_sha,'destination':address+':8094','bind':'127.0.0.1','port':tunnel_port,'scope':'Colima qualification transport; not installed application transport'}
  startup_timeout(startup_deadline)
  with (root/'tunnel.log').open('w') as tunnel_log:
   tunnel=subprocess.Popen(tunnel_argv(address,tunnel_port),env=env,stdout=tunnel_log,stderr=tunnel_log,start_new_session=True)
  state['tunnelPgid']=tunnel.pid;persist()
  while time.monotonic()<startup_deadline:
   if tunnel.poll() is not None:raise RuntimeError('owned tunnel exited before readiness')
   try:
    with socket.create_connection(('127.0.0.1',tunnel_port),timeout=startup_timeout(startup_deadline,.2)):
     listeners=run(['/usr/sbin/lsof','-nP','-a','-p',str(tunnel.pid),'-iTCP:'+str(tunnel_port),'-sTCP:LISTEN'],timeout=startup_timeout(startup_deadline,2),check=False)
     if listeners.returncode==0 and f'127.0.0.1:{tunnel_port} (LISTEN)' in listeners.stdout:break
   except OSError:pass
   time.sleep(startup_timeout(startup_deadline,.05))
  else:raise TimeoutError('owned tunnel startup deadline')
  port=tunnel_port
  env.update(MCP_ASSEMBLY_EXECUTOR_URL=f'http://127.0.0.1:{port}',MCP_ASSEMBLY_EXECUTOR_TOKEN=token,MCP_ASSEMBLY_EXECUTOR_DIGEST=runtime_digest)
  for _ in range(80):
   if time.monotonic()>=startup_deadline:raise TimeoutError('executor startup deadline')
   logs=checked(docker+['logs','--tail','32',executor],timeout=startup_timeout(startup_deadline))
   if 'MCP_REGISTRY_LISTENER_READY' in logs:break
   if 'MCP_REGISTRY_LISTENER_FAILED' in logs:raise RuntimeError('executor listener failed readiness')
   time.sleep(startup_timeout(startup_deadline,.25))
  else:raise RuntimeError('executor listener readiness deadline')
  import urllib.request
  if time.monotonic()>=startup_deadline:raise TimeoutError('executor startup deadline')
  request=urllib.request.Request(f'http://127.0.0.1:{port}/secureshop/mcp-registry/health',headers={'Authorization':'Bearer '+token})
  with urllib.request.urlopen(request,timeout=startup_timeout(startup_deadline)) as response:
   payload=response.read(8193)
   if response.status!=200 or len(payload)>8192:raise RuntimeError('bounded executor health failed')
  health=validate_startup_health(json.loads(payload),runtime_digest)
  startup_timeout(startup_deadline)
  state['startupHealth']=health;persist()
  if args.startup_only:
   result={'status':'passed','scope':'listener-startup-only','modelCalls':0,'browserCalls':0,'nativeCases':0,'postgresStores':0,'port':port,'health':health}
   (root/'candidate-result.json').write_text(json.dumps(result,indent=2)+'\n')
  elif args.registry_packaged:
   state['status']='running';persist()
   with (root/'packaged.log').open('w') as log:
    child=subprocess.Popen([DOCKER,'--host',HOST,'exec',executor,'node','/app/'+REGISTRY_PACKAGED_FIXTURE],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['childPgid']=child.pid;persist()
    if child.wait(timeout=480)!=0:raise RuntimeError('packaged registry fixture failed')
   packaged=packaged_log_receipt(root/'packaged.log')
   if packaged['runtimeDigest']!=runtime_digest:raise RuntimeError('Packaged runtime digest mismatch')
   result={'status':'passed','scope':REGISTRY_PACKAGED_SCOPE,'modelCalls':0,'browserCalls':0,
           'packageDigest':REGISTRY_PACKAGED_DIGEST,'manifestSha256':REGISTRY_PACKAGED_MANIFEST_SHA256,
           'runtimeDigest':packaged['runtimeDigest'],'cases':packaged['cases']}
   (root/'candidate-result.json').write_text(json.dumps(result,indent=2)+'\n');(root/'candidate-result.json').chmod(0o600)
  else:
   created.add(pg);persist()
   run(docker+['run','--detach','--pull','never','--name',pg,'--label','dvaia.owner='+owner,'--memory','1g','--cpus','2','--pids-limit','128','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432',PG_IMAGE,'-c','shared_buffers=16MB','-c','max_connections=40','-c','max_wal_size=16MB','-c','min_wal_size=4MB']);created.add(pg)
   info=inspect_owned(command,name=pg,labels={'dvaia.owner':owner},image=PG_IMAGE);state['containerIds'][pg]=info['Id'];persist()
   if args.registry_rendered:rendered_layout(info,'postgres',network,executor)
   if info.get('Mounts'):raise RuntimeError('PostgreSQL unexpectedly mounted host data')
   for _ in range(80):
    if run(docker+['exec',pg,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres'],check=False).returncode==0:break
    time.sleep(.25)
   else:raise RuntimeError('PostgreSQL readiness deadline')
   pg_port=int(checked(docker+['port',pg,'5432/tcp']).strip().rsplit(':',1)[1]);
   with socket.create_connection(('127.0.0.1',pg_port),timeout=5):pass
   psql=docker+['exec',pg,'psql','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c'];state['stores']=database_plan(nonce,args.invocation_journal,args.mcp_impersonation_v43 or args.mcp_manifest_v66 or args.mcp_description_v39 or args.mcp_registry_ssrf_v42)
   created_roles=set()
   for row in state['stores']:
    migration,runtime,database=row['migration'],row['runtime'],row['database']
    if migration not in created_roles:
     run(psql+[f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {runtime} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS']);created_roles.add(migration)
    run(psql+[f'CREATE DATABASE {database} OWNER {migration}']);run(psql+[f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{runtime}'])
    for role,key in ((migration,'MIGRATION'),(runtime,'RUNTIME')):env[f'MCP_ASSEMBLY_{row["label"]}_{key}_URL']=f'postgresql://{role}@127.0.0.1:{pg_port}/{database}'
   env.update(MCP_ASSEMBLY_NATIVE='1',MCP_ASSEMBLY_RESULT=str(root/'candidate-result.json'),NODE_ENV='test',PG_TEST_DISPOSABLE='yes',PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',AI_PROVIDER='mock',SS_ENABLE='false',MCP_WORKSHOP_AUTOSTART='false',MCP_SIDECARS_AUTOSTART='false',OLLAMA_BASE_URL='http://127.0.0.1:1',JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex)
   if args.mcp_registry_ssrf_v42_native:env['MCP_ASSEMBLY_V42']='1'
   if args.registry_rendered:
    env.update(MCP_REGISTRY_RENDERED_NATIVE='1',MCP_REGISTRY_RENDERED_BUILD=str(SOURCE/'client/build'),MCP_REGISTRY_RENDERED_RESULT=str(root/'candidate-result.json'),DVAIA_CURRENT_MAIN_WORKSPACE=str(SOURCE),PUPPETEER_EXECUTABLE_PATH=args.browser)
    if args.mcp_impersonation_v43 or args.mcp_manifest_v66 or args.mcp_description_v39 or args.mcp_registry_ssrf_v42:
     if args.mcp_impersonation_v43:verify_v43_sources(SOURCE)
     elif args.mcp_manifest_v66 or args.mcp_registry_ssrf_v42:verify_v66_sources(SOURCE)
     else:verify_v39_sources(SOURCE)
     env.update(v43_environment() if args.mcp_impersonation_v43 else v66_environment() if args.mcp_manifest_v66 else v42_environment() if args.mcp_registry_ssrf_v42 else v39_environment())
     if args.mcp_manifest_v66:env['MCP_MANIFEST_V66_RESULT']=str(root/'candidate-result.json')
     if args.mcp_registry_ssrf_v42:env['MCP_REGISTRY_SSRF_V42_RESULT']=str(root/'candidate-result.json')
     if args.mcp_description_v39:env.update(v39_result_environment(root))
    if rendered_inventory(SOURCE,args.browser_root,args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,args.mcp_registry_ssrf_v42)!=rendered_pins or sha(args.browser)!=args.browser_sha256:raise RuntimeError('Rendered pins changed before execution')
   state['status']='running';persist()
   with (root/'tests.log').open('w') as log:
    child=subprocess.Popen(native_child_argv(args.registry_rendered,args.invocation_journal,args.mcp_impersonation_v43),cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True);state['childPgid']=child.pid;persist()
    if child.wait(timeout=480)!=0:raise RuntimeError('native cohort failed')
   result=rendered_receipt(root/'candidate-result.json',args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,args.mcp_registry_ssrf_v42) if args.registry_rendered else json.loads((root/'candidate-result.json').read_text())
   if args.registry_rendered:rendered_tap((root/'tests.log').read_text(),args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,args.mcp_registry_ssrf_v42)
   if args.mcp_registry_ssrf_v42_native:
    v42_native_receipt(root/'candidate-result.json',qualified=True);state['v42NativeReceiptSha256']=sha(root/'candidate-result.json')
   if (result['status']!='passed' or (args.mcp_impersonation_v43 and not 1 <= result['modelCalls'] <= 14)
       or (args.mcp_manifest_v66 and not 3 <= result['modelCalls'] <= 8)
       or (args.mcp_description_v39 and not 8 <= result['modelCalls'] <= 14)
       or (args.mcp_registry_ssrf_v42 and result['modelCalls']!=5)
       or (not (args.mcp_impersonation_v43 or args.mcp_manifest_v66 or args.mcp_description_v39 or args.mcp_registry_ssrf_v42) and result['modelCalls'])
       or (not args.registry_rendered and result['browserCalls'])):raise RuntimeError('invalid native outcome')
   if args.mcp_impersonation_v43:
    v43=v43_receipt(root/'mcp-impersonation-receipt.json',root/'mcp-impersonation-wire.json')
    if any(v43[key]!=result[key] for key in ('actorCalls','judgeCalls')):raise RuntimeError('V43 receipt counters disagree')
    # Reuse the frozen caller's exported contract as well as the wire checks.
    run([str(NODE),'-e',"require(process.argv[1]).assertV43Receipt(JSON.parse(require('node:fs').readFileSync(process.argv[2],'utf8')))",str(SOURCE/V43_HELPER),str(root/'mcp-impersonation-receipt.json')],cwd=SOURCE,timeout=30)
    state['v43ReceiptSha256']=sha(root/'mcp-impersonation-receipt.json')
    state['v43WireSha256']=sha(root/'mcp-impersonation-wire.json')
    state['modelAfter']=verify_v43_model()
    if state['modelAfter']!=state['modelBefore']:raise RuntimeError('V43 model changed during qualification')
   if args.mcp_registry_ssrf_v42:
    v42=v42_receipt(root/'mcp-discovery-receipt.json',root/'mcp-discovery-wire.json',root/'mcp-discovery-model.json',root/'mcp-discovery-qualification.json')
    if any(v42[key]!=result[key] for key in ('actorCalls','judgeCalls')):raise RuntimeError('V42 receipt counters disagree')
    for name in ('mcp-discovery-receipt.json','mcp-discovery-wire.json','mcp-discovery-model.json','mcp-discovery-qualification.json'):
     state['v42'+''.join(part.capitalize() for part in name.removeprefix('mcp-discovery-').removesuffix('.json').split('-'))+'Sha256']=sha(root/name)
   if args.mcp_manifest_v66:
    v66=v66_receipt(root/'mcp-manifest-receipt.json',root/'mcp-manifest-wire.json',root/'mcp-manifest-model.json')
    if any(v66[key]!=result[key] for key in ('actorCalls','judgeCalls')):raise RuntimeError('V66 receipt counters disagree')
    qualification=v66_qualification(root/'mcp-manifest-qualification.json')
    if qualification['phases'][-3]['judgeCalls']!=v66['judgeCalls']:
     raise RuntimeError('V66 phase and receipt Judge counts disagree')
    run([str(NODE),'-e',"require(process.argv[1]).assertV66Receipt(JSON.parse(require('node:fs').readFileSync(process.argv[2],'utf8')))",str(SOURCE/V66_HELPER),str(root/'mcp-manifest-receipt.json')],cwd=SOURCE,timeout=30)
    for name in ('mcp-manifest-receipt.json','mcp-manifest-wire.json','mcp-manifest-model.json','mcp-manifest-qualification.json'):
     state['v66'+''.join(part.capitalize() for part in name.removeprefix('mcp-manifest-').removesuffix('.json').split('-'))+'Sha256']=sha(root/name)
    state['modelAfter']=verify_v43_model()
    if state['modelAfter']!=state['modelBefore']:raise RuntimeError('V66 model changed during qualification')
   if args.mcp_description_v39:
    v39=v39_receipt(root/'mcp-description-receipt.json',root/'mcp-description-wire.json',
                    root/'mcp-description-model.json',root/'mcp-description-qualification.json')
    if any(v39[key]!=result[key] for key in ('actorCalls','judgeCalls')):
     raise RuntimeError('V39 receipt counters disagree')
    run([str(NODE),'-e',"require(process.argv[1]).assertReceipt(JSON.parse(require('node:fs').readFileSync(process.argv[2],'utf8')))",
         str(SOURCE/V39_HELPER),str(root/'mcp-description-receipt.json')],cwd=SOURCE,timeout=30)
    for name in ('mcp-description-receipt.json','mcp-description-wire.json',
                 'mcp-description-model.json','mcp-description-qualification.json'):
     state['v39'+''.join(part.capitalize() for part in name.removeprefix('mcp-description-').removesuffix('.json').split('-'))+'Sha256']=sha(root/name)
    state['modelAfter']=verify_v43_model()
    if state['modelAfter']!=state['modelBefore']:raise RuntimeError('V39 model changed during qualification')
   if args.registry_rendered and (rendered_inventory(SOURCE,args.browser_root,args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,args.mcp_registry_ssrf_v42)!=rendered_pins or sha(args.browser)!=args.browser_sha256):raise RuntimeError('Rendered pins changed during execution')
  if (args.registry_rendered or args.registry_packaged) and (sha(NODE)!=NODE_SHA or sha(DOCKER)!=DOCKER_SHA or sha(BUILDX_REAL)!=BUILDX_SHA):raise RuntimeError('Isolated executable pin changed')
  if any(sha(workspace/name)!=value for name,value in state['sourceSha256'].items()):raise RuntimeError('execution source changed')
  if args.registry_packaged:
   final_authority,final_rows=packaged_authority(SOURCE)
   if final_authority!=authority or final_rows!=source_rows or packaged_control_pins(SOURCE)!=control_pins:
    raise RuntimeError('Packaged authority or controls changed during execution')
   state['finalIntegrity']={'sourceCount':len(final_rows),'manifestSha256':REGISTRY_PACKAGED_MANIFEST_SHA256,'packageDigest':REGISTRY_PACKAGED_DIGEST}
  else:
   state['finalIntegrity']=verify(workspace,args.source_sha256,args.dependency_sha256)
  state['resultSha256']=sha(root/'candidate-result.json');state['status']='passed'
 except BaseException as error:
  state['status']='failed';state['error']={'type':type(error).__name__,'message':str(error).replace(token,'[REDACTED]') if token else str(error)}
  if executor in created:
   diagnostic_deadline=time.monotonic()+20
   state['startupDiagnostics']=startup_diagnostics(lambda argv:run(docker+argv,check=False,timeout=startup_timeout(diagnostic_deadline)),executor,token)
 finally:
  if args.mcp_registry_ssrf_v42 and state.get('modelBefore'):
   try:
    state['modelAfter']=verify_v43_model();state['modelAfterMatched']=state['modelAfter']==state['modelBefore']
    state['finalIntegrity']=verify(workspace,args.source_sha256,args.dependency_sha256)
    state['sourceAfterMatched']=(rendered_inventory(SOURCE,args.browser_root,args.mcp_impersonation_v43,args.mcp_manifest_v66,args.mcp_description_v39,True)==rendered_pins
     and sha(args.browser)==args.browser_sha256 and all(sha(workspace/name)==value for name,value in state['sourceSha256'].items()))
    if not state['modelAfterMatched'] or not state['sourceAfterMatched']:raise RuntimeError('V42 final source or model mismatch')
   except Exception as error:
    state['status']='failed';state['finalIntegrityError']=type(error).__name__+': '+str(error)
   persist()
  signal.alarm(0);errors=[]
  for process in (tunnel,child,build):
   try:stop_process(process)
   except Exception as error:errors.append(str(error))
  for name in (executor,pg):
   try:owned_remove(name);state['cleanup'][name+'Absent']=True
   except Exception as error:errors.append(str(error))
  if (args.registry_rendered or args.registry_packaged) and state.get('profileInstallAttempted') and state['cleanup'].get(executor+'Absent'):
   try:
    no_profile_containers(command,executor)
    ssh(['sudo','python3','-c',RENDERED_PROFILE_PROGRAM,'remove',executor,base64.b64encode(policy.encode()).decode()],timeout=40)
   except Exception as error:errors.append(str(error))
  elif not (args.registry_rendered or args.registry_packaged) and profile_loaded and state['cleanup'].get(executor+'Absent'):
   try:ssh(['sudo','apparmor_parser','-R',remote+'/policy'])
   except Exception as error:errors.append(str(error))
  try:
   labels=checked(SSH+[shlex.join(['sudo','cat','/sys/kernel/security/apparmor/profiles'])]);state['cleanup']['profileAbsent']=not any(line.startswith(executor+' ') or line.startswith(executor+'//') for line in labels.splitlines())
   if remote_owned and state['cleanup']['profileAbsent']:
    if ssh(['cat',remote+'/owner']).stdout!=owner+'\n':raise RuntimeError('remote ownership mismatch')
    ssh(['rm','-f',remote+'/owner',remote+'/policy']);ssh(['rmdir',remote])
   state['cleanup']['remoteAbsent']=ssh(['test','!','-e',remote],check=False).returncode==0
   meta=inspect_resource(command,'network',network)
   if meta is not None:
    if meta.get('Labels',{}).get('dvaia.owner')!=owner:raise RuntimeError('network ownership mismatch')
    if args.registry_rendered or args.registry_packaged:
     verify_daemon(command,DAEMON_ID)
     if meta.get('Name')!=network or meta.get('Driver')!='bridge' or meta.get('Internal') is not True or meta.get('Containers')!={}:raise RuntimeError('Rendered network cleanup mismatch')
     captured=state.get('networkId')
     if captured and meta.get('Id')!=captured:raise RuntimeError('Rendered network changed')
    run(docker+['network','rm',meta['Id'] if (args.registry_rendered or args.registry_packaged) else network])
   state['cleanup']['networkAbsent']=inspect_resource(command,'network',network) is None
   meta=inspect_resource(command,'image',tag)
   if meta is not None:
    labels=meta['Config'].get('Labels',{})
    if labels.get('dvaia.owner')!=owner or (args.registry_packaged and labels.get('dvaia.registry.package')!=REGISTRY_PACKAGED_DIGEST):raise RuntimeError('image ownership or package identity mismatch')
    if args.registry_rendered or args.registry_packaged:
     verify_daemon(command,DAEMON_ID)
     if image and meta.get('Id')!=image:raise RuntimeError('Rendered image changed')
    image=image or meta['Id'];run(docker+['image','rm',tag])
   state['cleanup']['imageTagAbsent']=inspect_resource(command,'image',tag) is None
   state['cleanup']['imageIdAbsent']=image is None or inspect_resource(command,'image',image) is None
  except Exception as error:errors.append(str(error))
  for name,process in [('child',child),('build',build),('tunnel',tunnel)]:
   try:state['cleanup'][name+'PgidAbsent']=process is None or not group_members(process.pid)
   except Exception as error:errors.append(str(error))
  if tunnel_port is not None:
   try:
    state['cleanup']['tunnelClosure']=verify_tunnel_closed(tunnel_port,tunnel.pid,lambda argv:run(argv,timeout=3,check=False))
    state['cleanup']['tunnelPortAbsent']=True
   except Exception as error:state['cleanup']['tunnelPortAbsent']=False;errors.append(str(error))
  if args.registry_rendered:
   try:state['cleanup']['browserAbsent']=rendered_browser_absent(root)
   except Exception as error:state['cleanup']['browserAbsent']=False;errors.append(str(error))
  if ca:ca.unlink(missing_ok=True)
  state['cleanup']['buildCaAbsent']=not ca or not ca.exists();state['cleanup']['errors']=errors
  if errors or any(value is False for value in state['cleanup'].values()):state['status']='failed'
  persist()
 print(json.dumps({'root':str(root),'status':state['status'],'cleanup':state['cleanup']}))
 if state['status']!='passed':raise SystemExit(1)
if __name__=='__main__':main()
