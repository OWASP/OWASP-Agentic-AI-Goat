'use strict';

// Read-only planning; provisioning is a separate explicit installer module.
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {createHash}=require('node:crypto');
const {workspaceId}=require('../application-data-root');
const {readLocalDockerAuthority,verifyDockerAuthority,authorityDigest}=require('../local-docker-authority');
const managed=require('../../server/services/secureshopSystemManagedConfiguration');
const {renderMcpSandboxAppArmor}=require('../render-mcp-sandbox-apparmor');
const BASE='sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1';
const FILES=Object.freeze(['Dockerfile.local','config-reader.js','contract.js','diagnostic-contract.js','diagnostic-executor.js',
  'diagnostic-http-handler.js','diagnostic-http-listener.js','diagnostic-init.c','diagnostic-receipt.js','diagnostic-result.js',
  'diagnostic-supervisor.c','diagnostic-wire.js','executor.js','health-contract.js','health-metrics.js','http-handler.js',
  'http-listener.js','local-listener-entry.js','process-supervisor.c','receipt.js','restart-command-executor.js','restart-contract.js',
  'restart-http-handler.js','restart-http-listener.js','restart-init.c','restart-manager.js','restart-service-child.c','restart-supervisor.c','restart-systemctl',
  'restart-target.js','restart-wire.js','system-init.c','worker.js',
  'upload-preview-contract.js','upload-preview-worker.js','upload-preview-executor.js','upload-preview-dependencies.js',
  'upload-preview-http-handler.js','upload-preview-http-listener.js','upload-preview-init.c','upload-preview-native-qualification.js',
  'upload-preview-runtime/package.json','upload-preview-runtime/package-lock.json'].sort());
const fail=code=>Object.assign(new Error('Owned System installation plan unavailable'),{code});
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function readRegular(file,limit){const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>limit)throw fail('SYSTEM_PACKAGE_SOURCE_INVALID');return fs.readFileSync(file);}
function sourceManifest(root){
  const directory=path.join(root,'sidecars/sandbox-runner/owned-system');
  const bytes=readRegular(path.join(directory,'local-package-manifest.json'),16384);let manifest;
  try{manifest=JSON.parse(bytes);}catch{throw fail('SYSTEM_PACKAGE_MANIFEST_INVALID');}
  if(!manifest||Object.keys(manifest).sort().join()!=='architecture,baseImage,files,qualification,version'
    ||manifest.version!==1||manifest.architecture!=='arm64'||manifest.baseImage!==BASE
    ||manifest.qualification!=='tasks/sidecar-owned-system-runtime-qualified-2026-09-26.json'
    ||!manifest.files||Object.keys(manifest.files).sort().join()!==FILES.join())throw fail('SYSTEM_PACKAGE_MANIFEST_INVALID');
  for(const file of FILES){if(!/^[a-f0-9]{64}$/.test(manifest.files[file])||sha(readRegular(path.join(directory,file),1048576))!==manifest.files[file])throw fail('SYSTEM_PACKAGE_SOURCE_CHANGED');}
  return Object.freeze({sha256:sha(bytes),baseImage:BASE,architecture:'arm64',qualification:manifest.qualification,fileCount:FILES.length,files:Object.freeze(Object.fromEntries(FILES.map(file=>[file,manifest.files[file]])))});
}
async function plan({root=path.resolve(__dirname,'../..'),home=os.homedir(),platform=process.platform,
  architecture,configPort=8090,diagnosticPort=8091,restartPort=8092,uploadPreviewPort,imageId,execute,environment=process.env}={}){
  if(!path.isAbsolute(root)||!path.isAbsolute(home)||!['darwin','linux'].includes(platform)||architecture!=='arm64')throw fail('SYSTEM_INSTALL_PLATFORM_UNQUALIFIED');
  const ports=[configPort,diagnosticPort,restartPort,...(uploadPreviewPort===undefined?[]:[uploadPreviewPort])];
  for(const port of ports)if(!Number.isInteger(port)||port<1024||port>65535)throw fail('SYSTEM_INSTALL_PORT_INVALID');
  if(new Set(ports).size!==ports.length)throw fail('SYSTEM_INSTALL_PORT_CONFLICT');
  if(imageId!==undefined&&!/^sha256:[a-f0-9]{64}$/.test(imageId))throw fail('SYSTEM_INSTALL_IMAGE_INVALID');
  const id=workspaceId(root),directory=path.join(home,'.dvaia',id);
  // Read recorded authority only: never discover or create an ambient selection.
  const authority=await readLocalDockerAuthority({directory,workspaceId:id,platform});
  if(!authority)throw fail('SYSTEM_INSTALL_AUTHORITY_REQUIRED');
  await verifyDockerAuthority({authority,execute,environment});
  const source=sourceManifest(root),dockerAuthoritySha256=authorityDigest(authority);
  const profileBytes=renderMcpSandboxAppArmor(readRegular(path.join(root,'sidecars/sandbox-runner/apparmor/dvaia-mcp-sandbox.apparmor.in'),65536).toString('utf8'),'dvaia-mcp-sandbox');
  const profile=Object.freeze({name:'dvaia-mcp-sandbox',sha256:sha(profileBytes)});
  const filePath=managed.managedPath({root,home}),existing=managed.load({filePath});
  const modes=Object.fromEntries([['config',configPort],['diagnostic',diagnosticPort],['restart',restartPort],...(uploadPreviewPort===undefined?[]:[['uploadPreview',uploadPreviewPort]])].map(([mode,port])=>[mode,Object.freeze({container:`dvaia-owned-system-${id}-${mode==='uploadPreview'?'upload-preview':mode}`,url:`http://127.0.0.1:${port}`})]));
  if(existing&&(existing.workspaceId!==id||existing.dockerAuthoritySha256!==dockerAuthoritySha256
    ||existing.sourceManifestSha256!==source.sha256||existing.profile.name!==profile.name||existing.profile.sha256!==profile.sha256
    ||(imageId!==undefined&&existing.imageId!==imageId)
    ||managed.modesFor(existing).join()!==Object.keys(modes).join()
    ||Object.keys(modes).some(mode=>existing[mode].container!==modes[mode].container||existing[mode].url!==modes[mode].url)))throw fail('SYSTEM_INSTALL_EXISTING_CONFLICT');
  return Object.freeze({version:1,mutating:false,workspaceId:id,managedPath:filePath,dockerAuthoritySha256,
    daemonIdentityVerified:true,architecture:'arm64',source,profile,config:modes.config,diagnostic:modes.diagnostic,restart:modes.restart,...(modes.uploadPreview?{uploadPreview:modes.uploadPreview}:{}),
    existing:existing!==null,enabled:existing?.enabled===true,imageId:existing?.imageId||imageId||null,
    namespaceProfileVerified:false,imageRuntimeVerified:false,requiresProvisioning:true,
    resources:Object.freeze({memoryBytes:536870912,cpu:1,pids:128,tmpfsBytes:134217728,user:'10001:10001',readOnlyRoot:true,hostMounts:false}),
    next:'Separate reviewed provisioning must verify actual image/profile/containers and all selected authenticated clients before activation.'});
}
module.exports={plan,sourceManifest};
